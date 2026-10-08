"""
ikev2_manager.py - IKEv2/IPsec (strongSwan) admin module for the SmartUI
panel, built to the same pattern as ws_epro_manager.py.

What it sets up
  * strongSwan (swanctl / charon-systemd) with a self-made CA + server
    certificate, EAP-MSCHAPv2 logins and a virtual-IP pool.
  * Logins are the panel's existing SSH accounts (see vpn_common.py) -
    nothing separate to manage, and a timer keeps them in sync.
  * Works with the built-in IKEv2 clients of Android 11+ ("IKEv2/IPSec
    MSCHAPv2"), Windows 10/11, iOS/macOS (a .mobileconfig can be exported),
    and strongSwan's own Android app.

Ports: IKEv2 is UDP 500 (IKE) + UDP 4500 (NAT-T). They belong to the single
charon process that L2TP/IPsec also uses, so changing them here changes them
for both (the menu says so). Standard clients only ever use 500/4500 - custom
ports are only useful with your own client.

Menu features match WS-EPRO and add more: install wizard, modify ports,
safe PORT MOD redirection, user access control, connected clients, client
setup/export, logs, restart, start/stop [ON]/[OFF], advanced (DNS, pool
subnet, routes, certificate, diagnostics) and a full uninstall.
"""

import os
import re
import json
import uuid
import base64
import shutil
from xml.sax.saxutils import escape as _xml

from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    get_public_ip, run_cmd as _run,
)
import vpn_common as vc

NAME = "IKEv2"
META_PATH = vc.VPN_DIR + "/ikev2.json"
CA_KEY = vc.SWANCTL_DIR + "/private/smartui-ikev2-ca.key"
CA_CERT = vc.SWANCTL_DIR + "/x509ca/smartui-ikev2-ca.pem"
SERVER_KEY = vc.SWANCTL_DIR + "/private/smartui-ikev2-server.key"
SERVER_CERT = vc.SWANCTL_DIR + "/x509/smartui-ikev2-server.pem"
CA_EXPORT_PATH = "/root/smartui-ikev2-ca.pem"
MOD_TAG = "ikev2-mod"
NAT_TAG = "ikev2"
SYSCTL_NAME = "ikev2"

DEFAULT_SUBNET = "10.30.0.0/24"
DNS_CHOICES = {"1": "1.1.1.1, 1.0.0.1", "2": "8.8.8.8, 8.8.4.4", "3": "9.9.9.9, 149.112.112.112"}

vc.register_known_keys({'IKEV2_PORT': ('ikev2', 'udp'), 'IKEV2_NATT_PORT': ('ikev2-natt', 'udp')})


# ---------------------------------------------------------------- state ----

def _load_meta():
    meta = vc.load_json(META_PATH)
    meta.setdefault("host", "")
    meta.setdefault("subnet", DEFAULT_SUBNET)
    meta.setdefault("dns", DNS_CHOICES["1"])
    meta.setdefault("routes", "0.0.0.0/0")
    return meta


def _save_meta(meta):
    vc.write_file(META_PATH, json.dumps(meta, indent=2), 0o600)


def _installed():
    return os.path.exists(vc.IKEV2_CONF)


def _service_active():
    return vc.service_active(vc.STRONGSWAN_UNIT) and _installed()


# ------------------------------------------------------------ PKI / conf ---

def _san_args(host):
    return ["--san", host]


def _generate_pki(host):
    """CA + server certificate with the exact extensions Android/Windows/iOS
    insist on (serverAuth + ikeIntermediate, host in SAN)."""
    for d in ("private", "x509ca", "x509"):
        os.makedirs(os.path.join(vc.SWANCTL_DIR, d), exist_ok=True)
    steps = [
        "pki --gen --type rsa --size 3072 --outform pem > %s" % CA_KEY,
        'pki --self --ca --lifetime 3650 --in %s --type rsa --dn "CN=SmartUI IKEv2 CA" --outform pem > %s' % (CA_KEY, CA_CERT),
        "pki --gen --type rsa --size 3072 --outform pem > %s" % SERVER_KEY,
        ('pki --pub --in %s --type rsa | pki --issue --lifetime 1825 --cacert %s --cakey %s '
         '--dn "CN=%s" --san %s --flag serverAuth --flag ikeIntermediate --outform pem > %s')
        % (SERVER_KEY, CA_CERT, CA_KEY, host, host, SERVER_CERT),
    ]
    for cmd in steps:
        res = _run(cmd)
        if res.returncode != 0:
            return False, "'%s' failed: %s" % (cmd.split(" ")[0] + " " + cmd.split(" ")[1], (res.stderr or "").strip()[-300:])
    for p in (CA_KEY, SERVER_KEY):
        os.chmod(p, 0o600)
    if not (os.path.getsize(CA_CERT) > 0 and os.path.getsize(SERVER_CERT) > 0):
        return False, "certificate files came out empty"
    return True, None


def _build_conf(meta):
    dns = ", ".join(x.strip() for x in meta["dns"].split(",") if x.strip())
    return f"""# smartui-ikev2 (managed by SmartUI - edit through the panel)
connections {{
    smartui-ikev2 {{
        version = 2
        local_addrs = %any
        pools = smartui-ikev2-pool
        fragmentation = yes
        # Android never sends a certificate request, and strongSwan then
        # leaves its certificate out of the reply, so the phone cannot verify
        # the server and silently gives up. Always send it.
        send_cert = always
        dpd_delay = 30s
        proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp1024,aes256gcm16-prfsha256-ecp256,default
        local {{
            auth = pubkey
            certs = smartui-ikev2-server.pem
            id = {meta['host']}
        }}
        remote {{
            auth = eap-mschapv2
            eap_id = %any
        }}
        children {{
            smartui-ikev2 {{
                local_ts = {meta['routes']}
                esp_proposals = aes256-sha256,aes256gcm16,aes128-sha1,default
                dpd_action = clear
            }}
        }}
    }}
}}
pools {{
    smartui-ikev2-pool {{
        addrs = {meta['subnet']}
        dns = {dns}
    }}
}}
"""


def _apply_safely(meta, ike_port, natt_port, description):
    """Write conf + charon ports, restart, verify both UDP ports, roll back
    to the previous files if anything fails."""
    backup = {p: vc.read_file(p) for p in (vc.IKEV2_CONF, vc.CHARON_PORTS_CONF)}

    def restore():
        for path, content in backup.items():
            if content is None:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
            else:
                vc.write_file(path, content)
        vc.restart_strongswan()

    vc.write_file(vc.IKEV2_CONF, _build_conf(meta))
    vc.write_charon_ports(ike_port, natt_port)
    if not vc.restart_strongswan():
        restore()
        return False, f"{description} failed to restart strongSwan - reverted to the previous working setup."
    if not (vc.wait_listening(ike_port, ("udp",)) and vc.wait_listening(natt_port, ("udp",))):
        restore()
        return False, f"{description} restarted, but UDP {ike_port}/{natt_port} never came up - reverted. Nothing was left broken."
    loaded = _run("swanctl --list-conns").stdout or ""
    if "smartui-ikev2" not in loaded:
        restore()
        return False, f"{description}: strongSwan refused the configuration (see option 6 logs) - reverted."
    return True, f"{description} applied and verified on UDP {ike_port}/{natt_port}."


def _routing_for(meta):
    """Forwarding + NAT for the client pool (needed for full AND split tunnel:
    the routed networks still have to be reachable through this server)."""
    iface = vc.default_interface()
    vc.ensure_ip_forwarding(SYSCTL_NAME)
    vc.ensure_nat(meta["subnet"], iface, NAT_TAG)
    return iface


# --------------------------------------------------------- client output ---

def _read_ca():
    return vc.read_file(CA_CERT, "") or ""


def _mobileconfig(host, username, password):
    import ssl
    ca_b64 = base64.b64encode(ssl.PEM_cert_to_DER_cert(_read_ca())).decode()
    u1, u2, u3 = str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper(), str(uuid.uuid4()).upper()
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array>
<dict>
 <key>PayloadCertificateFileName</key><string>smartui-ikev2-ca.cer</string>
 <key>PayloadContent</key><data>{ca_b64}</data>
 <key>PayloadDescription</key><string>SmartUI IKEv2 CA</string>
 <key>PayloadDisplayName</key><string>SmartUI IKEv2 CA</string>
 <key>PayloadIdentifier</key><string>com.smartui.ikev2.ca.{u1}</string>
 <key>PayloadType</key><string>com.apple.security.root</string>
 <key>PayloadUUID</key><string>{u1}</string>
 <key>PayloadVersion</key><integer>1</integer>
</dict>
<dict>
 <key>IKEv2</key><dict>
  <key>AuthenticationMethod</key><string>None</string>
  <key>ExtendedAuthEnabled</key><integer>1</integer>
  <key>AuthName</key><string>{_xml(username)}</string>
  <key>AuthPassword</key><string>{_xml(password)}</string>
  <key>RemoteAddress</key><string>{_xml(host)}</string>
  <key>RemoteIdentifier</key><string>{_xml(host)}</string>
  <key>ServerCertificateIssuerCommonName</key><string>SmartUI IKEv2 CA</string>
  <key>DeadPeerDetectionRate</key><string>Medium</string>
  <key>EnablePFS</key><integer>1</integer>
 </dict>
 <key>IPv4</key><dict><key>OverridePrimary</key><integer>1</integer></dict>
 <key>PayloadDescription</key><string>SmartUI IKEv2 VPN</string>
 <key>PayloadDisplayName</key><string>SmartUI IKEv2 ({_xml(host)})</string>
 <key>PayloadIdentifier</key><string>com.smartui.ikev2.vpn.{u2}</string>
 <key>PayloadType</key><string>com.apple.vpn.managed</string>
 <key>PayloadUUID</key><string>{u2}</string>
 <key>PayloadVersion</key><integer>1</integer>
 <key>UserDefinedName</key><string>SmartUI IKEv2 {_xml(host)}</string>
 <key>VPNType</key><string>IKEv2</string>
</dict>
</array>
<key>PayloadDisplayName</key><string>SmartUI IKEv2</string>
<key>PayloadIdentifier</key><string>com.smartui.ikev2.{u3}</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>{u3}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>
"""


def _connection_info(ports_dict):
    meta = _load_meta()
    ike, natt = vc.get_charon_ports()
    vc.header("IKEv2 CONNECTION INFO / CLIENT SETUP")
    print(f" Server address : {C_YELLOW}{meta['host']}{C_RESET}")
    print(f" Ports (UDP)    : IKE {ike}  |  NAT-T {natt}")
    print(f" Auth           : EAP-MSCHAPv2 - username/password = the customer's SSH account")
    print(f" CA certificate : {CA_CERT}")
    print("----------------------------------------------------------------")
    print(" ANDROID 11+ (built-in):  Settings > Network > VPN > Add")
    print("   Type: IKEv2/IPSec MSCHAPv2   Server: the address above")
    print("   IPSec identifier: (leave empty or the server address)")
    print("   IPSec CA certificate: install the CA first (Settings > Security >")
    print("   Encryption & credentials > Install a certificate > CA certificate),")
    print("   then pick it here.  Username / Password: the SSH login.")
    print(" WINDOWS 10/11: import the CA into 'Trusted Root Certification")
    print("   Authorities', Add VPN > Windows (built-in) > IKEv2 > user/pass.")
    print(" iOS / macOS: use option [M] below to export a ready .mobileconfig.")
    print(BAR_LINE)
    print(" [C] EXPORT / SHOW CA CERTIFICATE     [M] EXPORT .mobileconfig FOR A USER")
    print(" [0] RETURN")
    ch = input(" Enter an Option: ").strip().lower()
    if ch == 'c':
        if os.path.exists(CA_CERT):
            shutil.copyfile(CA_CERT, CA_EXPORT_PATH)
            print(f"{C_GREEN}[OK] Copied to {CA_EXPORT_PATH} - download it with SFTP and import on the device.{C_RESET}\n")
            print(_read_ca())
        vc.pause()
    elif ch == 'm':
        user = input(" SSH account name: ").strip()
        pw = vc.load_ssh_passwords().get(user)
        if not pw:
            print(f"{C_RED}[X] '{user}' has no stored SSH password.{C_RESET}")
        else:
            out = "/root/smartui-ikev2-%s.mobileconfig" % vc.sanitize_id(user)
            vc.write_file(out, _mobileconfig(meta["host"], user, pw), 0o600)
            print(f"{C_GREEN}[OK] Written to {out} (contains that user's password - handle with care).{C_RESET}")
        vc.pause()


BAR_LINE = "----------------------------------------------------------------"


# --------------------------------------------------------------- screens ---

def _diagnostics():
    meta = _load_meta()
    ike, natt = vc.get_charon_ports()
    iface = vc.default_interface()
    checks = [
        ("strongSwan service active", vc.service_active(vc.STRONGSWAN_UNIT)),
        (f"UDP {ike} listening", check_system_port_in_use(ike, ("udp",))),
        (f"UDP {natt} listening", check_system_port_in_use(natt, ("udp",))),
        ("IKEv2 connection loaded", "smartui-ikev2" in (_run("swanctl --list-conns").stdout or "")),
        ("server certificate present", os.path.exists(SERVER_CERT)),
        ("ip_forward = 1", (vc.read_file("/proc/sys/net/ipv4/ip_forward", "0") or "0").strip() == "1"),
        (f"NAT rule for {meta['subnet']} on {iface}", vc.nat_present(meta["subnet"], iface, NAT_TAG)),
        ("accounts allowed", len(vc.allowed_users("ikev2")) > 0),
    ]
    cert = _run(["openssl", "x509", "-in", SERVER_CERT, "-noout", "-checkend", str(30 * 86400)])
    checks.append(("server certificate valid for 30+ more days", cert.returncode == 0))
    vc.header("IKEv2 DIAGNOSTICS")
    for label, ok in checks:
        print(" %s %s" % (f"{C_GREEN}[ OK ]{C_RESET}" if ok else f"{C_RED}[FAIL]{C_RESET}", label))
    print("\n Tip: if clients connect but nothing loads, check the NAT line above and")
    print(" that your provider allows UDP 500/4500 inbound.")
    vc.pause()


def _advanced(ports_dict):
    while True:
        meta = _load_meta()
        vc.header("IKEv2 ADVANCED")
        print(f" DNS pushed to clients : {meta['dns']}")
        print(f" Client address pool   : {meta['subnet']}")
        print(f" Routes pushed (local_ts): {meta['routes']}")
        print(f" Server name in cert   : {meta['host']}")
        print(vc.BAR)
        print(" [1]> CHANGE DNS             [2]> CHANGE CLIENT POOL SUBNET")
        print(" [3]> CHANGE ROUTES (full tunnel / split)")
        print(" [4]> REGENERATE CERTIFICATES (new server name)")
        print(" [5]> DIAGNOSTICS")
        print(vc.BAR)
        print(" [0] RETURN")
        ch = input(" Enter an Option: ").strip()
        ike, natt = vc.get_charon_ports()
        if ch == '0':
            return
        if ch == '1':
            print(" 1) Cloudflare  2) Google  3) Quad9  4) custom")
            sel = input(" Choose: ").strip()
            meta["dns"] = DNS_CHOICES.get(sel) or input(" DNS servers (comma separated): ").strip() or meta["dns"]
        elif ch == '2':
            new = input(f" New pool CIDR [{meta['subnet']}]: ").strip() or meta["subnet"]
            if not re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', new):
                print(f"{C_RED}[X] Use CIDR form, e.g. 10.30.0.0/24{C_RESET}")
                vc.pause(); continue
            old = meta["subnet"]; meta["subnet"] = new
            vc.remove_nat(old, vc.default_interface(), NAT_TAG)
        elif ch == '3':
            new = input(f" Routes, comma separated [{meta['routes']}] (0.0.0.0/0 = full tunnel): ").strip() or meta["routes"]
            if not re.match(r'^[\d./, ]+$', new):
                print(f"{C_RED}[X] Invalid routes.{C_RESET}")
                vc.pause(); continue
            meta["routes"] = new
        elif ch == '4':
            new = input(f" New server name/IP [{meta['host']}]: ").strip() or meta["host"]
            if not re.match(r'^[A-Za-z0-9.\-]+$', new):
                print(f"{C_RED}[X] Use a hostname or IPv4 address only.{C_RESET}"); vc.pause(); continue
            meta["host"] = new
            ok, err = _generate_pki(new)
            if not ok:
                print(f"{C_RED}[X] {err}{C_RESET}"); vc.pause(); continue
            print(f"{C_YELLOW}[!] Clients must install the NEW CA certificate (option 5 > C).{C_RESET}")
        elif ch == '5':
            _diagnostics(); continue
        else:
            continue
        ok, msg = _apply_safely(meta, ike, natt, "Change")
        if ok:
            _save_meta(meta)
            _routing_for(meta)
            persist_firewall_rules()
        print(f"{C_GREEN if ok else C_RED}[{'OK' if ok else 'X'}] {msg}{C_RESET}")
        vc.pause()


def _modify_ports(ports_dict):
    while True:
        ike, natt = vc.get_charon_ports()
        meta = _load_meta()
        vc.header("IKEv2 - MODIFY PORT & TRAFFIC REDIRECTION")
        print(f" IKE port: {ike}/udp   NAT-T port: {natt}/udp")
        print(f" {C_YELLOW}Shared with L2TP/IPsec (same strongSwan process).{C_RESET}")
        print(BAR_LINE)
        print(" [1]> CHANGE IKE / NAT-T PORTS")
        print(" [2]> PORT REDIRECTION (extra port ranges -> IKE/NAT-T)  [safe PORT MOD]")
        print(" [3]> CLIENT ROUTING: full tunnel / split (current: %s)" % meta["routes"])
        print(vc.BAR)
        print(" [0] RETURN")
        ch = input(" Enter an Option: ").strip()
        if ch == '0':
            return
        if ch == '1':
            print(f"{C_YELLOW}[!] Standard Android/Windows/iOS clients ONLY use 500/4500. Custom ports")
            print(f"    work only with your own client or a redirection (option 2).{C_RESET}")
            new_ike = prompt_port(f" New IKE port [Current: {ike}]: ", default=ike)
            new_natt = prompt_port(f" New NAT-T port [Current: {natt}]: ", default=natt)
            if new_ike == new_natt:
                print(f"{C_RED}[X] The two ports must differ.{C_RESET}"); vc.pause(); continue
            conflict = [p for p, old in ((new_ike, ike), (new_natt, natt)) if p != old and check_system_port_in_use(p, ("udp",))]
            if conflict:
                print(f"{C_RED}[X] UDP {conflict[0]} is already in use by another service.{C_RESET}"); vc.pause(); continue
            open_firewall_port(new_ike, ("udp",)); open_firewall_port(new_natt, ("udp",)); persist_firewall_rules()
            ok, msg = _apply_safely(meta, new_ike, new_natt, f"Ports {new_ike}/{new_natt}")
            if ok:
                for old in {ike, natt} - {new_ike, new_natt}:
                    close_firewall_port(old, ("udp",))
                persist_firewall_rules()
                ports_dict['IKEV2_PORT'] = str(new_ike); ports_dict['IKEV2_NATT_PORT'] = str(new_natt)
                if 'L2TP_IKE_PORT' in ports_dict:
                    ports_dict['L2TP_IKE_PORT'] = str(new_ike); ports_dict['L2TP_NATT_PORT'] = str(new_natt)
                vc.save_state_now(ports_dict)
            else:
                for p in {new_ike, new_natt} - {ike, natt}:
                    close_firewall_port(p, ("udp",))
            print(f"{C_GREEN if ok else C_RED}[{'OK' if ok else 'X'}] {msg}{C_RESET}")
            vc.pause()
        elif ch == '2':
            vc.portmod_menu(MOD_TAG, "IKEv2", "udp", [("IKE", ike), ("NAT-T", natt)], ports_dict)
        elif ch == '3':
            new = input(f" Routes, comma separated [{meta['routes']}] (0.0.0.0/0 = everything through VPN): ").strip() or meta["routes"]
            if not re.match(r'^[\d./, ]+$', new):
                print(f"{C_RED}[X] Invalid routes.{C_RESET}"); vc.pause(); continue
            meta["routes"] = new
            ok, msg = _apply_safely(meta, ike, natt, "Routing change")
            if ok:
                _save_meta(meta)
            print(f"{C_GREEN if ok else C_RED}[{'OK' if ok else 'X'}] {msg}{C_RESET}")
            vc.pause()


def _install(ports_dict):
    vc.header("IKEv2 INSTALLATION WIZARD")
    if vc.starter_conflict():
        print(f"{C_RED}[X] The legacy strongSwan 'starter' (ipsec.conf) service is running here.")
        print(f"    It cannot coexist with this module. Disable it first (systemctl disable --now strongswan-starter).{C_RESET}")
        vc.pause(); return
    meta = _load_meta()
    ike, natt = vc.get_charon_ports()
    already = _installed()
    host = input(f" Server name or IP clients connect to [{meta['host'] or get_public_ip()}]: ").strip() or meta["host"] or get_public_ip()
    if not re.match(r'^[A-Za-z0-9.\-]+$', host):
        print(f"{C_RED}[X] Use a hostname or IPv4 address only.{C_RESET}"); vc.pause(); return
    print(" DNS for clients: 1) Cloudflare  2) Google  3) Quad9")
    meta["dns"] = DNS_CHOICES.get(input(" Choose [1]: ").strip() or "1", DNS_CHOICES["1"])
    meta["subnet"] = input(f" Client address pool [{meta['subnet']}]: ").strip() or meta["subnet"]
    if not re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', meta["subnet"]):
        print(f"{C_RED}[X] Pool must be CIDR, e.g. 10.30.0.0/24{C_RESET}"); vc.pause(); return
    ike = prompt_port(f" IKE UDP port (standard 500) [{ike}]: ", default=ike)
    natt = prompt_port(f" NAT-T UDP port (standard 4500) [{natt}]: ", default=natt)
    meta["host"] = host
    for p in (ike, natt):
        if check_system_port_in_use(p, ("udp",)) and not vc.service_active(vc.STRONGSWAN_UNIT):
            print(f"{C_RED}[X] UDP {p} is already in use by another service.{C_RESET}"); vc.pause(); return

    print(f"{C_CYAN}[i] Installing strongSwan packages (may take a minute)...{C_RESET}")
    ok, err = vc.ensure_strongswan_installed()
    if not ok:
        print(f"{C_RED}[X] {err}{C_RESET}"); vc.pause(); return
    print(f"{C_CYAN}[i] Creating the certificate authority and server certificate...{C_RESET}")
    ok, err = _generate_pki(host)
    if not ok:
        print(f"{C_RED}[X] Certificate generation failed: {err}{C_RESET}"); vc.pause(); return

    open_firewall_port(ike, ("udp",)); open_firewall_port(natt, ("udp",))
    vc.open_ipsec_protocols(); persist_firewall_rules()
    vc.set_access("ikev2", enabled=True)
    vc.ensure_sync_timer()
    vc.sync_all(reload=False)
    _run(f"systemctl enable {vc.STRONGSWAN_UNIT}")
    _routing_for(meta)

    ok, msg = _apply_safely(meta, ike, natt, f"IKEv2 on UDP {ike}/{natt}")
    if ok:
        _save_meta(meta)
        vc.swanctl_reload()
        ports_dict['IKEV2_PORT'] = str(ike); ports_dict['IKEV2_NATT_PORT'] = str(natt)
        vc.save_state_now(ports_dict)
        persist_firewall_rules()
        print(f"{C_GREEN}[OK] {msg}{C_RESET}")
        print(f" Next: option [5] shows the client setup and exports the CA certificate.")
        print(f" {len(vc.allowed_users('ikev2'))} SSH account(s) can log in right now.")
    else:
        vc.set_access("ikev2", enabled=False)
        if not already:
            for p in (ike, natt):
                close_firewall_port(p, ("udp",))
        print(f"{C_RED}[X] {msg}{C_RESET}")
    vc.pause()


def _uninstall(ports_dict):
    vc.header("UNINSTALL IKEv2")
    if input(" Are you sure you want to completely remove IKEv2? (y/n): ").strip().lower() != 'y':
        print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}"); vc.pause(); return
    meta = _load_meta()
    ike, natt = vc.get_charon_ports()
    l2tp_remains = vc.strongswan_in_use_by_other("ikev2")

    vc.portmod_disable(MOD_TAG)
    for p in (vc.IKEV2_CONF, vc.IKEV2_SECRETS_CONF, SERVER_CERT, SERVER_KEY, CA_CERT, CA_KEY, META_PATH):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    vc.drop_access("ikev2")
    vc.remove_nat(meta["subnet"], vc.default_interface(), NAT_TAG)
    vc.remove_ip_forwarding_dropin(SYSCTL_NAME)
    if l2tp_remains:
        vc.swanctl_reload()
        _run("swanctl --terminate --ike smartui-ikev2")
        print(f"{C_YELLOW}[i] strongSwan stays running - L2TP/IPsec still uses it (and UDP {ike}/{natt}).{C_RESET}")
    else:
        _run(f"systemctl stop {vc.STRONGSWAN_UNIT}")
        _run(f"systemctl disable {vc.STRONGSWAN_UNIT}")
        try:
            os.remove(vc.CHARON_PORTS_CONF)
        except FileNotFoundError:
            pass
        for p in (ike, natt):
            close_firewall_port(p, ("udp",))
        vc.close_ipsec_protocols()
        if input(" Also remove the strongSwan packages? (y/n): ").strip().lower() == 'y':
            _run("DEBIAN_FRONTEND=noninteractive apt-get remove -y strongswan-swanctl charon-systemd strongswan-pki")
    persist_firewall_rules()
    vc.remove_sync_timer_if_unused()
    for k in ('IKEV2_PORT', 'IKEV2_NATT_PORT'):
        ports_dict.pop(k, None)
    vc.save_state_now(ports_dict)
    print(f"{C_GREEN}[OK] IKEv2 purged successfully.{C_RESET}")
    vc.pause()


def ikev2_admin_manager(ports_dict):
    """IKEv2 Administrator Module."""
    while True:
        if _installed():
            _run(f"systemctl enable {vc.STRONGSWAN_UNIT}")
            vc.ensure_sync_timer()
            ike, natt = vc.get_charon_ports()
            if str(ports_dict.get('IKEV2_PORT')) != str(ike) or str(ports_dict.get('IKEV2_NATT_PORT')) != str(natt):
                print(f"{C_YELLOW}[!] The saved ports ({ports_dict.get('IKEV2_PORT') or 'none'}/{ports_dict.get('IKEV2_NATT_PORT') or 'none'}) didn't match what's actually")
                print(f"    running ({ike}/{natt}) - correcting the panel's records to match reality.{C_RESET}")
                ports_dict['IKEV2_PORT'] = str(ike); ports_dict['IKEV2_NATT_PORT'] = str(natt)
                vc.save_state_now(ports_dict)
                vc.pause()
            vc.sync_all()
            port_txt = f"{ike}/{natt}"
        else:
            port_txt = "Not configured"
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"
        allowed = len(vc.allowed_users("ikev2")) if _installed() else 0

        vc.header("IKEv2 ADMINISTRATOR")
        print(f"      PORTS (UDP): {port_txt}  |  ACCOUNTS ALLOWED: {allowed}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL IKEv2")
        print(" [2]> MODIFY PORT & TRAFFIC REDIRECTION")
        print(" [3]> MANAGE USER ACCESS")
        print(" [4]> CONNECTED CLIENTS")
        print(" [5]> CONNECTION INFO / CLIENT SETUP")
        print(" [6]> VIEW SERVICE LOGS")
        print(" [7]> RESTART IKEv2 SERVICE")
        print(f" [8]> START/STOP IKEv2 SERVICE [{status_label}]")
        print(" [9]> ADVANCED (DNS / POOL / ROUTES / CERT / DIAGNOSTICS)")
        print(vc.BAR)
        print(" [0] RETURN  [10] UNINSTALL IKEv2")
        print(vc.BAR)
        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            _install(ports_dict)
        elif choice in ('2', '3', '4', '5', '6', '7', '8', '9', '10') and not _installed():
            print(f"{C_RED}[X] Not configured yet - run option 1 first.{C_RESET}")
            vc.pause()
        elif choice == '2':
            _modify_ports(ports_dict)
        elif choice == '3':
            vc.user_access_menu("ikev2", "IKEv2", on_change=lambda: vc.sync_all())
        elif choice == '4':
            vc.header("IKEv2 CONNECTED CLIENTS")
            print(vc.list_ike_sas())
            vc.pause()
        elif choice == '5':
            _connection_info(ports_dict)
        elif choice == '6':
            vc.header("IKEv2 SERVICE LOGS")
            os.system(f"journalctl -u {vc.STRONGSWAN_UNIT} -n 60 --no-pager")
            vc.pause()
        elif choice == '7':
            if vc.restart_strongswan():
                print(f"{C_GREEN}[OK] IKEv2 service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] IKEv2 failed to restart - check 'journalctl -u {vc.STRONGSWAN_UNIT}'.{C_RESET}")
            vc.pause()
        elif choice == '8':
            if is_active:
                if vc.strongswan_in_use_by_other("ikev2"):
                    print(f"{C_YELLOW}[i] L2TP/IPsec runs on the same strongSwan process - stopping it stops both.{C_RESET}")
                _run(f"systemctl stop {vc.STRONGSWAN_UNIT}")
                print(f"{C_YELLOW}[!] IKEv2 service stopped.{C_RESET}")
            else:
                vc.restart_strongswan()
                if _service_active():
                    print(f"{C_GREEN}[OK] IKEv2 service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] IKEv2 failed to start - check 'journalctl -u {vc.STRONGSWAN_UNIT}'.{C_RESET}")
            vc.pause()
        elif choice == '9':
            _advanced(ports_dict)
        elif choice == '10':
            _uninstall(ports_dict)
        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            vc.pause()
