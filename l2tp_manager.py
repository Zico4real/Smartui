"""
l2tp_manager.py - L2TP (and L2TP/IPsec) admin module for the SmartUI panel,
built to the same pattern as ws_epro_manager.py.

Two modes (chosen in the install wizard, switchable later):
  * L2TP/IPsec (PSK)  - the standard. xl2tpd + pppd for the tunnel, strongSwan
    (swanctl, IKEv1 transport mode) for the IPsec layer. Public ports are
    UDP 500 + 4500 (+ ESP); L2TP's own UDP 1701 only travels INSIDE IPsec and
    plain-text 1701 from the outside is blocked by a firewall rule.
  * Plain L2TP        - no encryption. Only useful for custom clients that
    wrap it themselves, because UDP 1701 is then public and its port can be
    changed/redirected freely.

Logins are the panel's SSH accounts (vpn_common.py keeps /etc/ppp/chap-secrets
in sync with a managed block; the rest of that file is never touched).

strongSwan is SHARED with the IKEv2 module (one charon process). This module
never stops or removes it while IKEv2 still needs it.

Honest caveat: current Android versions no longer include a built-in
L2TP/IPsec client; Windows, macOS, iOS, Linux and third-party Android apps do.
"""

import os
import re
import json
import shutil
import secrets
import string
import ipaddress

from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    get_public_ip, run_cmd as _run,
)
import vpn_common as vc

NAME = "L2TP"
META_PATH = vc.VPN_DIR + "/l2tp.json"
XL2TPD_CONF = "/etc/xl2tpd/xl2tpd.conf"
XL2TPD_ORIG = XL2TPD_CONF + ".smartui-orig"
PPP_OPTIONS = "/etc/ppp/options.smartui-l2tp"
MOD_TAG = "l2tp-mod"
NAT_TAG = "l2tp"
IPSEC_ONLY_TAG = "smartui-l2tp-ipsec-only"
SYSCTL_NAME = "l2tp"
DEFAULT_PORT = 1701
DEFAULT_SUBNET = "10.31.0.0/24"
DNS_CHOICES = {"1": "1.1.1.1, 1.0.0.1", "2": "8.8.8.8, 8.8.4.4", "3": "9.9.9.9, 149.112.112.112"}
BAR_LINE = "----------------------------------------------------------------"

vc.register_known_keys({'L2TP_PORT': ('l2tp', 'udp')})


# ---------------------------------------------------------------- state ----

def _load_meta():
    meta = vc.load_json(META_PATH)
    meta.setdefault("mode", "ipsec")
    meta.setdefault("subnet", DEFAULT_SUBNET)
    meta.setdefault("dns", DNS_CHOICES["1"])
    meta.setdefault("mtu", 1280)
    meta.setdefault("psk", "")
    meta.setdefault("host", "")
    meta.setdefault("ipsec_only", True)
    return meta


def _save_meta(meta):
    vc.write_file(META_PATH, json.dumps(meta, indent=2), 0o600)


def _installed():
    return os.path.exists(META_PATH) and "smartui-l2tp-port=" in (vc.read_file(XL2TPD_CONF, "") or "")


def get_port():
    m = re.search(r'smartui-l2tp-port=(\d+)', vc.read_file(XL2TPD_CONF, "") or "")
    return int(m.group(1)) if m else DEFAULT_PORT


def _service_active(meta=None):
    meta = meta or _load_meta()
    if not (_installed() and vc.service_active("xl2tpd")):
        return False
    return vc.service_active(vc.STRONGSWAN_UNIT) if meta["mode"] == "ipsec" else True


def _random_psk(n=20):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


# ----------------------------------------------------------- config build --

def _pool(subnet):
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts()) if net.num_addresses <= 1024 else None
    if hosts:
        gw, first, last = hosts[0], hosts[min(8, len(hosts) - 2)], hosts[-1]
    else:
        base = int(net.network_address)
        gw, first, last = (ipaddress.ip_address(base + 1), ipaddress.ip_address(base + 10),
                           ipaddress.ip_address(base + 1000))
    return str(gw), str(first), str(last)


def _xl2tpd_conf(meta, port):
    gw, first, last = _pool(meta["subnet"])
    return f"""; managed by SmartUI - edit through the panel
; smartui-l2tp-port={port}
[global]
port = {port}

[lns default]
ip range = {first}-{last}
local ip = {gw}
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = no
pppoptfile = {PPP_OPTIONS}
length bit = yes
"""


def _ppp_options(meta):
    dns = [d.strip() for d in meta["dns"].split(",") if d.strip()]
    lines = ["# managed by SmartUI", "ipcp-accept-local", "ipcp-accept-remote",
             "require-mschap-v2", "refuse-pap", "refuse-chap", "refuse-mschap", "refuse-eap",
             "noccp", "auth", "hide-password", "proxyarp",
             "mtu %d" % meta["mtu"], "mru %d" % meta["mtu"],
             "lcp-echo-failure 4", "lcp-echo-interval 30", "connect-delay 5000"]
    lines += ["ms-dns " + d for d in dns]
    return "\n".join(lines) + "\n"


def _ipsec_conf(meta):
    return f"""# smartui-l2tp (managed by SmartUI - contains the pre-shared key)
connections {{
    smartui-l2tp {{
        version = 1
        local_addrs = %any
        dpd_delay = 30s
        proposals = aes256-sha1-modp1024,aes128-sha1-modp1024,aes256-sha1-modp2048,aes128-sha256-modp2048,3des-sha1-modp1024,default
        local {{
            auth = psk
        }}
        remote {{
            auth = psk
        }}
        children {{
            smartui-l2tp {{
                mode = transport
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic[udp/1701]
                esp_proposals = aes256-sha1,aes128-sha1,aes256-sha256,aes128-sha256,3des-sha1,default
                dpd_action = clear
            }}
        }}
    }}
}}
secrets {{
    ike-smartui-l2tp {{
        secret = "{meta['psk']}"
    }}
}}
"""


def _ipsec_only_rules(on, port=DEFAULT_PORT):
    """Plain-text L2TP from outside is dropped (only traffic that arrived
    through IPsec is accepted). Scoped strictly to this one UDP port."""
    base = ["-p", "udp", "--dport", str(port)]
    cmt = ["-m", "comment", "--comment", IPSEC_ONLY_TAG]
    accept = base + ["-m", "policy", "--dir", "in", "--pol", "ipsec"] + cmt + ["-j", "ACCEPT"]
    drop = base + cmt + ["-j", "DROP"]
    # always clear first so repeated calls never stack duplicates
    for spec in (accept, drop):
        for _ in range(5):
            if _run(["iptables", "-D", "INPUT"] + spec).returncode != 0:
                break
    if on:
        _run(["iptables", "-I", "INPUT", "1"] + drop)
        _run(["iptables", "-I", "INPUT", "1"] + accept)


# ------------------------------------------------------------- apply ------

FILES = (XL2TPD_CONF, PPP_OPTIONS, vc.L2TP_IPSEC_CONF, vc.CHARON_PORTS_CONF)


def _restart_all(meta):
    ok = True
    if meta["mode"] == "ipsec":
        ok = vc.restart_strongswan()
    return ok and vc.restart_unit("xl2tpd")


def _apply_safely(meta, port, ike, natt, description):
    backup = {p: vc.read_file(p) for p in FILES}

    def restore():
        for path, content in backup.items():
            if content is None:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
            else:
                vc.write_file(path, content, 0o600 if path == vc.L2TP_IPSEC_CONF else 0o644)
        old_mode = "ipsec" if backup[vc.L2TP_IPSEC_CONF] else "plain"
        if old_mode == "ipsec" or os.path.exists(vc.IKEV2_CONF):
            vc.restart_strongswan()
        vc.restart_unit("xl2tpd")

    vc.write_file(XL2TPD_CONF, _xl2tpd_conf(meta, port))
    vc.write_file(PPP_OPTIONS, _ppp_options(meta))
    if meta["mode"] == "ipsec":
        vc.write_file(vc.L2TP_IPSEC_CONF, _ipsec_conf(meta), 0o600)
        vc.write_charon_ports(ike, natt)
    else:
        try:
            os.remove(vc.L2TP_IPSEC_CONF)
        except FileNotFoundError:
            pass
    if not _restart_all(meta):
        restore()
        return False, f"{description} failed to restart - reverted to the previous working setup."
    if not vc.wait_listening(port, ("udp",)):
        restore()
        return False, f"{description} restarted, but UDP {port} (xl2tpd) never came up - reverted. Nothing was left broken."
    if meta["mode"] == "ipsec":
        if not (vc.wait_listening(ike, ("udp",)) and vc.wait_listening(natt, ("udp",))):
            restore()
            return False, f"{description}: IPsec ports {ike}/{natt} never came up - reverted."
        if "smartui-l2tp" not in (_run("swanctl --list-conns").stdout or ""):
            restore()
            return False, f"{description}: strongSwan refused the L2TP/IPsec connection (see logs) - reverted."
    return True, f"{description} applied and verified."


def _routing(meta):
    vc.ensure_ip_forwarding(SYSCTL_NAME)
    vc.ensure_nat(meta["subnet"], vc.default_interface(), NAT_TAG)


def _open_ports(meta, port, ike, natt):
    if meta["mode"] == "ipsec":
        open_firewall_port(ike, ("udp",)); open_firewall_port(natt, ("udp",)); vc.open_ipsec_protocols()
        _ipsec_only_rules(meta.get("ipsec_only", True), port)
    else:
        open_firewall_port(port, ("udp",))
        _ipsec_only_rules(False, port)
    persist_firewall_rules()


def _publish_ports(ports_dict, meta, port, ike, natt):
    ports_dict['L2TP_PORT'] = str(port)
    ports_dict['L2TP_MODE'] = meta["mode"]
    if meta["mode"] == "ipsec":
        ports_dict['L2TP_IKE_PORT'] = str(ike); ports_dict['L2TP_NATT_PORT'] = str(natt)
    else:
        ports_dict.pop('L2TP_IKE_PORT', None); ports_dict.pop('L2TP_NATT_PORT', None)
    vc.save_state_now(ports_dict)


# --------------------------------------------------------------- screens ---

def _diagnostics():
    meta = _load_meta()
    port = get_port()
    ike, natt = vc.get_charon_ports()
    iface = vc.default_interface()
    checks = [
        ("xl2tpd service active", vc.service_active("xl2tpd")),
        (f"UDP {port} listening (xl2tpd)", check_system_port_in_use(port, ("udp",))),
        ("/dev/ppp present", os.path.exists("/dev/ppp")),
        ("ip_forward = 1", (vc.read_file("/proc/sys/net/ipv4/ip_forward", "0") or "0").strip() == "1"),
        (f"NAT rule for {meta['subnet']} on {iface}", vc.nat_present(meta["subnet"], iface, NAT_TAG)),
        ("chap-secrets block present", vc.L2TP_BEGIN in (vc.read_file(vc.PPP_CHAP_SECRETS, "") or "")),
        ("accounts allowed", len(vc.allowed_users("l2tp")) > 0),
    ]
    if meta["mode"] == "ipsec":
        checks += [
            ("strongSwan service active", vc.service_active(vc.STRONGSWAN_UNIT)),
            (f"UDP {ike} listening (IKE)", check_system_port_in_use(ike, ("udp",))),
            (f"UDP {natt} listening (NAT-T)", check_system_port_in_use(natt, ("udp",))),
            ("L2TP/IPsec connection loaded", "smartui-l2tp" in (_run("swanctl --list-conns").stdout or "")),
        ]
    vc.header("L2TP DIAGNOSTICS")
    for label, ok in checks:
        print(" %s %s" % (f"{C_GREEN}[ OK ]{C_RESET}" if ok else f"{C_RED}[FAIL]{C_RESET}", label))
    vc.pause()


def _connection_info():
    meta = _load_meta()
    port = get_port()
    ike, natt = vc.get_charon_ports()
    vc.header("L2TP CONNECTION INFO / CLIENT SETUP")
    print(f" Server address : {C_YELLOW}{meta['host']}{C_RESET}")
    if meta["mode"] == "ipsec":
        print(f" Mode           : L2TP/IPsec PSK     (UDP {ike} + {natt}, ESP)")
        print(f" Pre-shared key : {C_YELLOW}{meta['psk']}{C_RESET}")
    else:
        print(f" Mode           : plain L2TP, NO encryption (UDP {port})")
    print(" Login          : the customer's SSH username / password (MS-CHAPv2)")
    print(BAR_LINE)
    print(" WINDOWS : Add VPN > Windows (built-in) > type 'L2TP/IPsec with pre-shared key'")
    print("           (if it fails behind NAT, set registry AssumeUDPEncapsulationContextOnSendRule=2)")
    print(" iOS/macOS: Settings > VPN > Add > L2TP: server, account, password, secret = PSK")
    print(" LINUX   : NetworkManager-l2tp plugin: gateway, user, password, IPsec PSK")
    print(" ANDROID : recent versions have NO built-in L2TP - use a third-party client.")
    vc.pause()


def _advanced(ports_dict):
    while True:
        meta = _load_meta()
        vc.header("L2TP ADVANCED")
        print(f" Mode: {meta['mode']}   DNS: {meta['dns']}   Pool: {meta['subnet']}   MTU: {meta['mtu']}")
        if meta["mode"] == "ipsec":
            print(f" Block plain-text L2TP from outside: {'YES' if meta.get('ipsec_only', True) else 'NO'}")
        print(vc.BAR)
        print(" [1]> CHANGE DNS            [2]> CHANGE CLIENT POOL SUBNET")
        print(" [3]> CHANGE MTU/MRU        [4]> CHANGE / REGENERATE PSK (IPsec mode)")
        print(" [5]> SWITCH MODE (L2TP/IPsec <-> plain L2TP)")
        print(" [6]> TOGGLE 'block plain-text L2TP' (IPsec mode)")
        print(" [7]> DIAGNOSTICS")
        print(vc.BAR)
        print(" [0] RETURN")
        ch = input(" Enter an Option: ").strip()
        port = get_port()
        ike, natt = vc.get_charon_ports()
        if ch == '0':
            return
        if ch == '7':
            _diagnostics(); continue
        if ch == '1':
            print(" 1) Cloudflare  2) Google  3) Quad9  4) custom")
            sel = input(" Choose: ").strip()
            meta["dns"] = DNS_CHOICES.get(sel) or input(" DNS servers (comma separated): ").strip() or meta["dns"]
        elif ch == '2':
            new = input(f" New pool CIDR [{meta['subnet']}]: ").strip() or meta["subnet"]
            try:
                ipaddress.ip_network(new, strict=False)
            except ValueError:
                print(f"{C_RED}[X] Invalid CIDR.{C_RESET}"); vc.pause(); continue
            vc.remove_nat(meta["subnet"], vc.default_interface(), NAT_TAG)
            meta["subnet"] = new
        elif ch == '3':
            raw = input(f" MTU [{meta['mtu']}] (1280-1500): ").strip()
            if raw:
                if not (raw.isdigit() and 1280 <= int(raw) <= 1500):
                    print(f"{C_RED}[X] Must be 1280-1500.{C_RESET}"); vc.pause(); continue
                meta["mtu"] = int(raw)
        elif ch == '4':
            if meta["mode"] != "ipsec":
                print(f"{C_YELLOW}[i] Only in L2TP/IPsec mode.{C_RESET}"); vc.pause(); continue
            raw = input(" New PSK (blank = generate random): ").strip()
            if raw and ('"' in raw or "\\" in raw or len(raw) < 8):
                print(f"{C_RED}[X] At least 8 characters, no quotes or backslashes.{C_RESET}"); vc.pause(); continue
            meta["psk"] = raw or _random_psk()
        elif ch == '5':
            new_mode = "plain" if meta["mode"] == "ipsec" else "ipsec"
            if new_mode == "plain":
                print(f"{C_RED}[!] Plain L2TP has NO encryption. Only continue if your client wraps it itself.{C_RESET}")
                if input(" Type YES to switch: ").strip() != "YES":
                    continue
            else:
                ok, err = vc.ensure_strongswan_installed()
                if not ok:
                    print(f"{C_RED}[X] {err}{C_RESET}"); vc.pause(); continue
                meta["psk"] = meta["psk"] or _random_psk()
            old_mode = meta["mode"]; meta["mode"] = new_mode
            if new_mode == "ipsec":
                _open_ports(meta, port, ike, natt)
            ok, msg = _apply_safely(meta, port, ike, natt, f"Switch to {new_mode}")
            if ok:
                _save_meta(meta)
                if old_mode == "plain":
                    close_firewall_port(port, ("udp",))
                else:
                    if not os.path.exists(vc.IKEV2_CONF):
                        for p in (ike, natt):
                            close_firewall_port(p, ("udp",))
                        _run(f"systemctl stop {vc.STRONGSWAN_UNIT}")
                    _ipsec_only_rules(False, port)
                _open_ports(meta, port, ike, natt)
                _publish_ports(ports_dict, meta, port, ike, natt)
            else:
                meta["mode"] = old_mode
            print(f"{C_GREEN if ok else C_RED}[{'OK' if ok else 'X'}] {msg}{C_RESET}")
            vc.pause(); continue
        elif ch == '6':
            meta["ipsec_only"] = not meta.get("ipsec_only", True)
            _save_meta(meta)
            _ipsec_only_rules(meta["ipsec_only"] and meta["mode"] == "ipsec", port)
            persist_firewall_rules()
            print(f"{C_GREEN}[OK] Plain-text L2TP is now {'BLOCKED' if meta['ipsec_only'] else 'allowed'}.{C_RESET}")
            vc.pause(); continue
        else:
            continue
        ok, msg = _apply_safely(meta, port, ike, natt, "Change")
        if ok:
            _save_meta(meta)
            _routing(meta)
            persist_firewall_rules()
        print(f"{C_GREEN if ok else C_RED}[{'OK' if ok else 'X'}] {msg}{C_RESET}")
        vc.pause()


def _modify_ports(ports_dict):
    while True:
        meta = _load_meta()
        port = get_port()
        ike, natt = vc.get_charon_ports()
        vc.header("L2TP - MODIFY PORT & TRAFFIC REDIRECTION")
        if meta["mode"] == "ipsec":
            print(f" PUBLIC (IPsec): UDP {ike} + {natt}   |   L2TP inside IPsec: UDP {port} (fixed)")
            print(f" {C_YELLOW}IKE/NAT-T are shared with IKEv2 (same strongSwan process).{C_RESET}")
        else:
            print(f" PUBLIC: UDP {port} (plain L2TP)")
        print(BAR_LINE)
        print(" [1]> CHANGE PORT(S)")
        print(" [2]> PORT REDIRECTION (extra port ranges -> real port)  [safe PORT MOD]")
        print(vc.BAR)
        print(" [0] RETURN")
        ch = input(" Enter an Option: ").strip()
        if ch == '0':
            return
        if ch == '1':
            new_port, new_ike, new_natt = port, ike, natt
            if meta["mode"] == "plain":
                new_port = prompt_port(f" New L2TP UDP port [Current: {port}]: ", default=port)
                if new_port != port and check_system_port_in_use(new_port, ("udp",)):
                    print(f"{C_RED}[X] UDP {new_port} is already in use.{C_RESET}"); vc.pause(); continue
            else:
                print(f"{C_YELLOW}[!] Standard clients only use 500/4500; custom ports need your own client.{C_RESET}")
                new_ike = prompt_port(f" New IKE port [Current: {ike}]: ", default=ike)
                new_natt = prompt_port(f" New NAT-T port [Current: {natt}]: ", default=natt)
                if new_ike == new_natt:
                    print(f"{C_RED}[X] The two ports must differ.{C_RESET}"); vc.pause(); continue
                clash = [p for p, old in ((new_ike, ike), (new_natt, natt)) if p != old and check_system_port_in_use(p, ("udp",))]
                if clash:
                    print(f"{C_RED}[X] UDP {clash[0]} is already in use.{C_RESET}"); vc.pause(); continue
            new_meta = dict(meta)
            if meta["mode"] == "plain":
                open_firewall_port(new_port, ("udp",))
            else:
                open_firewall_port(new_ike, ("udp",)); open_firewall_port(new_natt, ("udp",))
            persist_firewall_rules()
            ok, msg = _apply_safely(new_meta, new_port, new_ike, new_natt, "Port change")
            if ok:
                if meta["mode"] == "plain":
                    if new_port != port:
                        close_firewall_port(port, ("udp",))
                else:
                    for old in {ike, natt} - {new_ike, new_natt}:
                        close_firewall_port(old, ("udp",))
                    if os.path.exists(vc.IKEV2_CONF):
                        ports_dict['IKEV2_PORT'] = str(new_ike); ports_dict['IKEV2_NATT_PORT'] = str(new_natt)
                persist_firewall_rules()
                _publish_ports(ports_dict, meta, new_port, new_ike, new_natt)
            else:
                if meta["mode"] == "plain":
                    if new_port != port:
                        close_firewall_port(new_port, ("udp",))
                else:
                    for p in {new_ike, new_natt} - {ike, natt}:
                        close_firewall_port(p, ("udp",))
            print(f"{C_GREEN if ok else C_RED}[{'OK' if ok else 'X'}] {msg}{C_RESET}")
            vc.pause()
        elif ch == '2':
            if meta["mode"] == "ipsec":
                targets = [("IKE", ike), ("NAT-T", natt)]
            else:
                targets = [("L2TP", port)]
            vc.portmod_menu(MOD_TAG, "L2TP", "udp", targets, ports_dict)


def _install(ports_dict):
    vc.header("L2TP INSTALLATION WIZARD")
    if vc.starter_conflict():
        print(f"{C_RED}[X] The legacy strongSwan 'starter' (ipsec.conf) service is running here and cannot")
        print(f"    coexist with this module. Disable it first (systemctl disable --now strongswan-starter).{C_RESET}")
        vc.pause(); return
    meta = _load_meta()
    print(" Mode: 1) L2TP/IPsec with pre-shared key (recommended)")
    print("       2) Plain L2TP, no encryption (custom clients only)")
    meta["mode"] = "plain" if input(" Choose [1]: ").strip() == "2" else "ipsec"
    if meta["mode"] == "plain":
        print(f"{C_RED}[!] Plain L2TP is NOT encrypted - credentials and traffic are readable on the wire.{C_RESET}")
        if input(" Type YES to continue: ").strip() != "YES":
            return
    meta["host"] = input(f" Server name or IP shown to clients [{meta['host'] or get_public_ip()}]: ").strip() or meta["host"] or get_public_ip()
    print(" DNS for clients: 1) Cloudflare  2) Google  3) Quad9")
    meta["dns"] = DNS_CHOICES.get(input(" Choose [1]: ").strip() or "1", DNS_CHOICES["1"])
    meta["subnet"] = input(f" Client address pool [{meta['subnet']}]: ").strip() or meta["subnet"]
    try:
        ipaddress.ip_network(meta["subnet"], strict=False)
    except ValueError:
        print(f"{C_RED}[X] Invalid pool CIDR.{C_RESET}"); vc.pause(); return
    port = DEFAULT_PORT
    ike, natt = vc.get_charon_ports()
    if meta["mode"] == "plain":
        port = prompt_port(f" L2TP UDP port [{get_port()}]: ", default=get_port())
    else:
        raw = input(" Pre-shared key (blank = generate random): ").strip()
        if raw and ('"' in raw or "\\" in raw or len(raw) < 8):
            print(f"{C_RED}[X] At least 8 characters, no quotes or backslashes.{C_RESET}"); vc.pause(); return
        meta["psk"] = raw or meta["psk"] or _random_psk()
    # xl2tpd always binds its port; in IPsec mode that is 1701.
    if not vc.service_active("xl2tpd") and check_system_port_in_use(port, ("udp",)):
        print(f"{C_RED}[X] UDP {port} is already in use by another service.{C_RESET}"); vc.pause(); return
    if meta["mode"] == "ipsec" and not vc.service_active(vc.STRONGSWAN_UNIT):
        for p in (ike, natt):
            if check_system_port_in_use(p, ("udp",)):
                print(f"{C_RED}[X] UDP {p} is already in use by another service.{C_RESET}"); vc.pause(); return

    ok, why = vc.ensure_ppp_support()
    if not ok:
        print(f"{C_RED}[X] {why}{C_RESET}"); vc.pause(); return
    print(f"{C_CYAN}[i] Installing packages (xl2tpd, ppp{', strongSwan' if meta['mode'] == 'ipsec' else ''})...{C_RESET}")
    ok, err = vc.apt_install(["xl2tpd", "ppp"])
    if not ok:
        print(f"{C_RED}[X] Package install failed:\n{err}{C_RESET}"); vc.pause(); return
    if meta["mode"] == "ipsec":
        ok, err = vc.ensure_strongswan_installed()
        if not ok:
            print(f"{C_RED}[X] {err}{C_RESET}"); vc.pause(); return
    if os.path.exists(XL2TPD_CONF) and not os.path.exists(XL2TPD_ORIG) \
            and "smartui-l2tp-port=" not in (vc.read_file(XL2TPD_CONF, "") or ""):
        shutil.copyfile(XL2TPD_CONF, XL2TPD_ORIG)

    already = _installed()
    vc.set_access("l2tp", enabled=True)
    vc.ensure_sync_timer()
    vc.sync_l2tp()
    _run("systemctl enable xl2tpd")
    if meta["mode"] == "ipsec":
        _run(f"systemctl enable {vc.STRONGSWAN_UNIT}")
    _routing(meta)
    _open_ports(meta, port, ike, natt)

    ok, msg = _apply_safely(meta, port, ike, natt, f"L2TP ({'IPsec' if meta['mode'] == 'ipsec' else 'plain'}) on UDP {port}")
    if ok:
        _save_meta(meta)
        _publish_ports(ports_dict, meta, port, ike, natt)
        print(f"{C_GREEN}[OK] {msg}{C_RESET}")
        if meta["mode"] == "ipsec":
            print(f" PSK: {C_YELLOW}{meta['psk']}{C_RESET}   (shown again in option 5)")
        print(f" {len(vc.allowed_users('l2tp'))} SSH account(s) can log in right now.")
    else:
        vc.set_access("l2tp", enabled=False)
        vc.sync_l2tp()
        if not already:
            _ipsec_only_rules(False, port)
            close_firewall_port(port, ("udp",))
            if meta["mode"] == "ipsec" and not os.path.exists(vc.IKEV2_CONF):
                for p in (ike, natt):
                    close_firewall_port(p, ("udp",))
            persist_firewall_rules()
        print(f"{C_RED}[X] {msg}{C_RESET}")
    vc.pause()


def _uninstall(ports_dict):
    vc.header("UNINSTALL L2TP")
    if input(" Are you sure you want to completely remove L2TP? (y/n): ").strip().lower() != 'y':
        print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}"); vc.pause(); return
    meta = _load_meta()
    port = get_port()
    ike, natt = vc.get_charon_ports()
    ikev2_remains = os.path.exists(vc.IKEV2_CONF)

    vc.portmod_disable(MOD_TAG)
    _ipsec_only_rules(False, port)
    _run("systemctl stop xl2tpd"); _run("systemctl disable xl2tpd")
    if os.path.exists(XL2TPD_ORIG):
        shutil.move(XL2TPD_ORIG, XL2TPD_CONF)
    else:
        try:
            os.remove(XL2TPD_CONF)
        except FileNotFoundError:
            pass
    for p in (PPP_OPTIONS, vc.L2TP_IPSEC_CONF, META_PATH):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    vc.drop_access("l2tp")
    vc.sync_l2tp()  # access is gone -> managed chap-secrets block removed
    vc.remove_nat(meta["subnet"], vc.default_interface(), NAT_TAG)
    vc.remove_ip_forwarding_dropin(SYSCTL_NAME)
    close_firewall_port(port, ("udp",))
    if ikev2_remains:
        vc.swanctl_reload()
        print(f"{C_YELLOW}[i] strongSwan stays running - IKEv2 still uses it (and UDP {ike}/{natt}).{C_RESET}")
    else:
        _run(f"systemctl stop {vc.STRONGSWAN_UNIT}"); _run(f"systemctl disable {vc.STRONGSWAN_UNIT}")
        try:
            os.remove(vc.CHARON_PORTS_CONF)
        except FileNotFoundError:
            pass
        for p in (ike, natt):
            close_firewall_port(p, ("udp",))
        vc.close_ipsec_protocols()
    if input(" Also remove the xl2tpd package? (y/n): ").strip().lower() == 'y':
        _run("DEBIAN_FRONTEND=noninteractive apt-get remove -y xl2tpd")
    persist_firewall_rules()
    vc.remove_sync_timer_if_unused()
    for k in ('L2TP_PORT', 'L2TP_MODE', 'L2TP_IKE_PORT', 'L2TP_NATT_PORT'):
        ports_dict.pop(k, None)
    vc.save_state_now(ports_dict)
    print(f"{C_GREEN}[OK] L2TP purged successfully.{C_RESET}")
    vc.pause()


def _connected_clients():
    vc.header("L2TP CONNECTED CLIENTS")
    res = _run("ip -o addr show")
    rows = []
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[1].startswith("ppp") and parts[2] == "inet":
            peer = re.search(r'peer (\S+)', line)
            rows.append((parts[1], parts[3], peer.group(1) if peer else "?"))
    print(f" Active PPP sessions: {len(rows)}")
    for ifn, local, peer in rows:
        print(f"   {ifn:<8} server {local:<18} client {peer}")
    print(BAR_LINE)
    log = _run("journalctl -t pppd --since '1 day ago' --no-pager 2>/dev/null | "
               "grep -E 'authentication succeeded|peer from calling number|Connection terminated' | tail -n 12")
    print(" Recent logins/disconnects (last 24h):")
    print(log.stdout.strip() or "   (none logged)")
    print(BAR_LINE)
    print(" IPsec sessions:")
    print(vc.list_ike_sas() if _load_meta()["mode"] == "ipsec" else "   (plain mode - no IPsec)")
    vc.pause()


def l2tp_admin_manager(ports_dict):
    """L2TP Administrator Module."""
    while True:
        if _installed():
            meta = _load_meta()
            _run("systemctl enable xl2tpd")
            if meta["mode"] == "ipsec":
                _run(f"systemctl enable {vc.STRONGSWAN_UNIT}")
            vc.ensure_sync_timer()
            port = get_port()
            ike, natt = vc.get_charon_ports()
            if str(ports_dict.get('L2TP_PORT')) != str(port) or ports_dict.get('L2TP_MODE') != meta["mode"]:
                print(f"{C_YELLOW}[!] The saved L2TP settings didn't match what's actually running -")
                print(f"    correcting the panel's records to match reality.{C_RESET}")
                _publish_ports(ports_dict, meta, port, ike, natt)
                vc.pause()
            vc.sync_all()
            ports_txt = f"{ike}/{natt}+{port}" if meta["mode"] == "ipsec" else str(port)
            mode_txt = "L2TP/IPsec" if meta["mode"] == "ipsec" else "PLAIN"
        else:
            meta = _load_meta()
            ports_txt, mode_txt = "Not configured", "-"
        is_active = _service_active(meta)
        status_label = "ON" if is_active else "OFF"
        allowed = len(vc.allowed_users("l2tp")) if _installed() else 0

        vc.header("L2TP ADMINISTRATOR")
        print(f"      PORTS (UDP): {ports_txt}  |  MODE: {mode_txt}  |  ACCOUNTS: {allowed}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL L2TP")
        print(" [2]> MODIFY PORT & TRAFFIC REDIRECTION")
        print(" [3]> MANAGE USER ACCESS")
        print(" [4]> CONNECTED CLIENTS")
        print(" [5]> CONNECTION INFO / CLIENT SETUP")
        print(" [6]> VIEW SERVICE LOGS")
        print(" [7]> RESTART L2TP SERVICE")
        print(f" [8]> START/STOP L2TP SERVICE [{status_label}]")
        print(" [9]> ADVANCED (DNS / POOL / MTU / PSK / MODE / DIAGNOSTICS)")
        print(vc.BAR)
        print(" [0] RETURN  [10] UNINSTALL L2TP")
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
            vc.user_access_menu("l2tp", "L2TP", on_change=lambda: vc.sync_all())
        elif choice == '4':
            _connected_clients()
        elif choice == '5':
            _connection_info()
        elif choice == '6':
            vc.header("L2TP SERVICE LOGS")
            os.system("journalctl -u xl2tpd -n 40 --no-pager")
            if meta["mode"] == "ipsec":
                print("\n--- strongSwan (IPsec) ---")
                os.system(f"journalctl -u {vc.STRONGSWAN_UNIT} -n 25 --no-pager")
            vc.pause()
        elif choice == '7':
            if _restart_all(meta):
                print(f"{C_GREEN}[OK] L2TP service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] L2TP failed to restart - check 'journalctl -u xl2tpd'.{C_RESET}")
            vc.pause()
        elif choice == '8':
            if is_active:
                _run("systemctl stop xl2tpd")
                if meta["mode"] == "ipsec" and not os.path.exists(vc.IKEV2_CONF):
                    _run(f"systemctl stop {vc.STRONGSWAN_UNIT}")
                elif meta["mode"] == "ipsec":
                    print(f"{C_YELLOW}[i] IKEv2 still uses strongSwan, so only xl2tpd was stopped (L2TP is down).{C_RESET}")
                print(f"{C_YELLOW}[!] L2TP service stopped.{C_RESET}")
            else:
                _restart_all(meta)
                if _service_active(meta):
                    print(f"{C_GREEN}[OK] L2TP service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] L2TP failed to start - check 'journalctl -u xl2tpd'.{C_RESET}")
            vc.pause()
        elif choice == '9':
            _advanced(ports_dict)
        elif choice == '10':
            _uninstall(ports_dict)
        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            vc.pause()
