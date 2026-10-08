"""
sstp_manager.py - SSTP (Secure Socket Tunneling Protocol) admin module for
the SmartUI panel, built to the same pattern as ws_epro_manager.py.

Backend: accel-ppp (its native SSTP server). accel-ppp is not in the normal
Debian/Ubuntu repositories, so the install wizard builds it from source once
(a few minutes; the build is skipped if /usr/sbin/accel-pppd already exists)
and runs it as its own systemd unit, "smartui-sstp", with its own config
(/etc/accel-ppp/smartui-sstp.conf) - an accel-ppp you installed separately is
never touched.

SSTP is just PPP-over-HTTPS: the listening socket is TCP + TLS, so it can sit
on 443 (and pass most firewalls) or on any other port, and it can be put
behind the panel's HAProxy (SNI) / MULTIPLEX front ends like any TLS service.

Logins are the panel's SSH accounts (vpn_common.py regenerates
/etc/accel-ppp/smartui-sstp-chap-secrets automatically).

Clients: Windows has SSTP built in (needs the CA certificate trusted and the
server name to match the certificate), Linux via sstp-client /
NetworkManager-sstp. Android has no built-in SSTP.
"""

import os
import re
import json
import shutil
import ipaddress

from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    get_public_ip, run_cmd as _run,
)
import vpn_common as vc

NAME = "SSTP"
SERVICE = "smartui-sstp"
SERVICE_PATH = "/etc/systemd/system/smartui-sstp.service"
CONF_PATH = "/etc/accel-ppp/smartui-sstp.conf"
CERT_DIR = "/etc/accel-ppp/smartui-sstp"
CA_CERT = CERT_DIR + "/ca.crt"
CA_KEY = CERT_DIR + "/ca.key"
SERVER_CERT = CERT_DIR + "/server.crt"
SERVER_KEY = CERT_DIR + "/server.key"
META_PATH = vc.VPN_DIR + "/sstp.json"
CA_EXPORT_PATH = "/root/smartui-sstp-ca.crt"
SRC_DIR = "/usr/local/src/accel-ppp"
BUILD_LOG = "/var/log/smartui-sstp-build.log"
ACCEL_BIN = "/usr/sbin/accel-pppd"
CLI_PORT = 2001
MOD_TAG = "sstp-mod"
NAT_TAG = "sstp"
SYSCTL_NAME = "sstp"
DEFAULT_PORT = 443
DEFAULT_SUBNET = "10.32.0.0/24"
DNS_CHOICES = {"1": "1.1.1.1, 1.0.0.1", "2": "8.8.8.8, 8.8.4.4", "3": "9.9.9.9, 149.112.112.112"}
BAR_LINE = "----------------------------------------------------------------"

vc.register_known_keys({'SSTP_PORT': ('sstp', 'tcp')})


# ---------------------------------------------------------------- state ----

def _load_meta():
    meta = vc.load_json(META_PATH)
    meta.setdefault("host", "")
    meta.setdefault("subnet", DEFAULT_SUBNET)
    meta.setdefault("dns", DNS_CHOICES["1"])
    meta.setdefault("mtu", 1400)
    meta.setdefault("cert", "self")        # "self" (generated CA) or "custom"
    meta.setdefault("cert_file", SERVER_CERT)
    meta.setdefault("key_file", SERVER_KEY)
    meta.setdefault("sni_lock", False)
    return meta


def _save_meta(meta):
    vc.write_file(META_PATH, json.dumps(meta, indent=2), 0o600)


def _installed():
    return os.path.exists(CONF_PATH) and os.path.exists(META_PATH)


def get_port():
    m = re.search(r'smartui-sstp-port=(\d+)', vc.read_file(CONF_PATH, "") or "")
    return int(m.group(1)) if m else DEFAULT_PORT


def _service_active():
    return vc.service_active(SERVICE)


# ------------------------------------------------------------ build -------

def _accel_present():
    return os.path.exists(ACCEL_BIN) or shutil.which("accel-pppd") is not None


def _bin_path():
    return ACCEL_BIN if os.path.exists(ACCEL_BIN) else (shutil.which("accel-pppd") or ACCEL_BIN)


def _build_accel():
    """Builds and installs accel-ppp. Returns (ok, error)."""
    print(f"{C_CYAN}[i] accel-ppp is not installed - building it now (about 3-10 minutes).")
    print(f"    Full output goes to {BUILD_LOG}.{C_RESET}")
    ok, err = vc.apt_install(["build-essential", "cmake", "git", "pkg-config", "libssl-dev"])
    if not ok:
        return False, "build tools could not be installed:\n" + err
    if _run("DEBIAN_FRONTEND=noninteractive apt-get install -y libpcre3-dev").returncode != 0:
        if _run("DEBIAN_FRONTEND=noninteractive apt-get install -y libpcre2-dev").returncode != 0:
            return False, "neither libpcre3-dev nor libpcre2-dev could be installed"
    shutil.rmtree(SRC_DIR, ignore_errors=True)
    os.makedirs(os.path.dirname(SRC_DIR), exist_ok=True)
    jobs = str(max(1, min(4, os.cpu_count() or 1)))
    steps = [
        f"git clone --depth 1 https://github.com/accel-ppp/accel-ppp.git {SRC_DIR}",
        f"mkdir -p {SRC_DIR}/build",
        (f"cd {SRC_DIR}/build && cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release "
         f"-DBUILD_IPOE_DRIVER=FALSE -DBUILD_VLAN_MON_DRIVER=FALSE -DRADIUS=FALSE -DSHAPER=FALSE -DLUA=FALSE "
         f"-DCMAKE_POLICY_VERSION_MINIMUM=3.5 .."),
        f"cd {SRC_DIR}/build && make -j{jobs}",
        f"cd {SRC_DIR}/build && make install",
    ]
    open(BUILD_LOG, "w").close()
    for cmd in steps:
        print(f" ... {cmd.split('&&')[-1].strip()[:60]}")
        rc = os.system(f"({cmd}) >> {BUILD_LOG} 2>&1")
        if rc != 0:
            tail = _run(f"tail -n 15 {BUILD_LOG}").stdout
            return False, f"step failed: {cmd[:70]}\n{tail}"
    if not _accel_present():
        return False, "build finished but accel-pppd was not installed"
    os.makedirs("/var/log/accel-ppp", exist_ok=True)
    return True, None


# --------------------------------------------------------- certs / conf ---

def _generate_certs(host):
    os.makedirs(CERT_DIR, exist_ok=True)
    san = ("IP:%s" % host) if re.match(r'^\d+\.\d+\.\d+\.\d+$', host) else ("DNS:%s" % host)
    ext = f"subjectAltName={san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
    vc.write_file(CERT_DIR + "/ext.cnf", ext)
    steps = [
        f"openssl genrsa -out {CA_KEY} 3072",
        f'openssl req -x509 -new -nodes -key {CA_KEY} -sha256 -days 3650 -subj "/CN=SmartUI SSTP CA" -out {CA_CERT}',
        f"openssl genrsa -out {SERVER_KEY} 3072",
        f'openssl req -new -key {SERVER_KEY} -subj "/CN={host}" -out {CERT_DIR}/server.csr',
        (f"openssl x509 -req -in {CERT_DIR}/server.csr -CA {CA_CERT} -CAkey {CA_KEY} -CAcreateserial "
         f"-out {SERVER_CERT} -days 1825 -sha256 -extfile {CERT_DIR}/ext.cnf"),
    ]
    for cmd in steps:
        res = _run(cmd)
        if res.returncode != 0:
            return False, "%s failed: %s" % (" ".join(cmd.split()[:2]), (res.stderr or "").strip()[-300:])
    for p in (CA_KEY, SERVER_KEY):
        os.chmod(p, 0o600)
    return True, None


def _build_conf(meta, port):
    gw = str(list(ipaddress.ip_network(meta["subnet"], strict=False).hosts())[0])
    net = ipaddress.ip_network(meta["subnet"], strict=False)
    hosts = list(net.hosts())
    first, last = hosts[1], hosts[-1]
    if net.prefixlen == 24:
        pool_line = "%s-%s" % (first, str(last).split(".")[-1])
    else:
        pool_line = str(net)  # CIDR form is accepted by accel-ppp's ip-pool
    dns = [d.strip() for d in meta["dns"].split(",") if d.strip()]
    dns_lines = "\n".join("dns%d=%s" % (i + 1, d) for i, d in enumerate(dns[:2]))
    host_line = ("host-name=%s\n" % meta["host"]) if meta.get("sni_lock") else ""
    return f"""# managed by SmartUI - edit through the panel
# smartui-sstp-port={port}
[modules]
log_file
sstp
auth_mschap_v2
chap-secrets
ippool

[core]
log-error=/var/log/accel-ppp/smartui-sstp-core.log
thread-count=2

[common]

[ppp]
verbose=1
min-mtu=1000
mtu={meta['mtu']}
mru={meta['mtu']}
ipv4=require
lcp-echo-interval=30
lcp-echo-timeout=90

[auth]

[sstp]
verbose=1
accept=ssl
port={port}
ssl-pemfile={meta['cert_file']}
ssl-keyfile={meta['key_file']}
ppp-max-mtu={meta['mtu']}
{host_line}
[chap-secrets]
chap-secrets={vc.SSTP_CHAP_SECRETS}
encrypted=0
gw-ip-address={gw}

[ip-pool]
gw-ip-address={gw}
{pool_line}

[dns]
{dns_lines}

[client-ip-range]
0.0.0.0/0

[cli]
tcp=127.0.0.1:{CLI_PORT}

[log]
log-file=/var/log/accel-ppp/smartui-sstp.log
log-emerg=/var/log/accel-ppp/smartui-sstp-emerg.log
log-fail-file=/var/log/accel-ppp/smartui-sstp-auth-fail.log
copy=0
level=3
"""


def _unit_content():
    return f"""[Unit]
Description=SmartUI SSTP VPN (accel-ppp)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/smartui-sstp.pid
ExecStart={_bin_path()} -d -c {CONF_PATH} -p /run/smartui-sstp.pid
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"""


def _restart():
    return vc.restart_unit(SERVICE)


def _apply_safely(meta, port, description):
    backup = {p: vc.read_file(p) for p in (CONF_PATH, SERVICE_PATH)}

    def restore():
        for path, content in backup.items():
            if content is None:
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
            else:
                vc.write_file(path, content)
        _run("systemctl daemon-reload")
        if backup[CONF_PATH] is not None:
            _restart()

    os.makedirs("/var/log/accel-ppp", exist_ok=True)
    vc.write_file(CONF_PATH, _build_conf(meta, port))
    vc.write_file(SERVICE_PATH, _unit_content())
    _run("systemctl daemon-reload")
    if not _restart():
        restore()
        return False, f"{description} failed to restart SSTP - reverted to the previous working setup."
    if not vc.wait_listening(port, ("tcp",)):
        restore()
        return False, (f"{description} restarted, but TCP {port} never came up - reverted. "
                       f"(See /var/log/accel-ppp/smartui-sstp-core.log.) Nothing was left broken.")
    return True, f"{description} applied and verified on TCP {port}."


def _routing(meta):
    vc.ensure_ip_forwarding(SYSCTL_NAME)
    vc.ensure_nat(meta["subnet"], vc.default_interface(), NAT_TAG)


def _publish(ports_dict, port):
    ports_dict['SSTP_PORT'] = str(port)
    vc.save_state_now(ports_dict)


# --------------------------------------------------------------- screens ---

def _diagnostics():
    meta = _load_meta()
    port = get_port()
    iface = vc.default_interface()
    cert_ok = _run(["openssl", "x509", "-in", meta["cert_file"], "-noout", "-checkend", str(30 * 86400)]).returncode == 0
    tls = _run(f"echo | timeout 5 openssl s_client -connect 127.0.0.1:{port} 2>/dev/null | grep -c 'BEGIN CERTIFICATE'")
    checks = [
        ("accel-ppp (smartui-sstp) service active", _service_active()),
        (f"TCP {port} listening", check_system_port_in_use(port, ("tcp",))),
        ("TLS handshake answers locally", (tls.stdout or "0").strip() not in ("0", "")),
        ("server certificate valid for 30+ more days", cert_ok),
        ("/dev/ppp present", os.path.exists("/dev/ppp")),
        ("ip_forward = 1", (vc.read_file("/proc/sys/net/ipv4/ip_forward", "0") or "0").strip() == "1"),
        (f"NAT rule for {meta['subnet']} on {iface}", vc.nat_present(meta["subnet"], iface, NAT_TAG)),
        ("chap-secrets file present", os.path.exists(vc.SSTP_CHAP_SECRETS)),
        ("accounts allowed", len(vc.allowed_users("sstp")) > 0),
    ]
    vc.header("SSTP DIAGNOSTICS")
    for label, ok in checks:
        print(" %s %s" % (f"{C_GREEN}[ OK ]{C_RESET}" if ok else f"{C_RED}[FAIL]{C_RESET}", label))
    vc.pause()


def _connection_info():
    meta = _load_meta()
    port = get_port()
    vc.header("SSTP CONNECTION INFO / CLIENT SETUP")
    addr = meta["host"] if port == 443 else "%s:%d" % (meta["host"], port)
    print(f" Server         : {C_YELLOW}{addr}{C_RESET}   (TCP {port}, TLS)")
    print(" Login          : the customer's SSH username / password (MS-CHAPv2)")
    print(f" Certificate    : {'self-made CA (export it below)' if meta['cert'] == 'self' else 'your own: ' + meta['cert_file']}")
    print(BAR_LINE)
    print(" WINDOWS: import the CA into 'Local Computer > Trusted Root Certification")
    print("   Authorities', then Add VPN > Windows (built-in) > VPN type SSTP.")
    print("   The server name MUST equal the certificate name above.")
    print(" LINUX  : sstp-client or NetworkManager-sstp (same name rule).")
    print(" ANDROID: no built-in SSTP - needs SSTP support inside your own app.")
    print(" SHARING 443: put this on another port and route a hostname to it with the")
    print("   panel's HAPROXY (SNI) or MULTIPLEX, so SSTP and your other TLS services")
    print("   can all answer on 443.")
    print(BAR_LINE)
    print(" [C] EXPORT / SHOW CA CERTIFICATE     [0] RETURN")
    ch = input(" Enter an Option: ").strip().lower()
    if ch == 'c':
        src = CA_CERT if meta["cert"] == "self" else meta["cert_file"]
        if os.path.exists(src):
            shutil.copyfile(src, CA_EXPORT_PATH)
            print(f"{C_GREEN}[OK] Copied to {CA_EXPORT_PATH} - download it with SFTP and import it on the client.{C_RESET}\n")
            print(vc.read_file(src, ""))
        vc.pause()


def _connected_clients():
    vc.header("SSTP CONNECTED CLIENTS")
    res = _run(["accel-cmd", "-H", "127.0.0.1", "-p", str(CLI_PORT), "show", "sessions"])
    out = (res.stdout or "").strip()
    print(out if out and res.returncode == 0 else " (could not read sessions - is the service running?)")
    print(BAR_LINE)
    print(" [K] DISCONNECT A USER     [0] RETURN")
    ch = input(" Enter an Option: ").strip().lower()
    if ch == 'k':
        user = input(" Username to disconnect: ").strip()
        if user and re.match(r'^[A-Za-z0-9_.@-]+$', user):
            r = _run(["accel-cmd", "-H", "127.0.0.1", "-p", str(CLI_PORT), "terminate", "username", user])
            print(f"{C_GREEN}[OK] Requested.{C_RESET}" if r.returncode == 0 else f"{C_RED}[X] {r.stderr.strip() or r.stdout.strip()}{C_RESET}")
        vc.pause()


def _advanced(ports_dict):
    while True:
        meta = _load_meta()
        port = get_port()
        vc.header("SSTP ADVANCED")
        print(f" DNS: {meta['dns']}   Pool: {meta['subnet']}   MTU: {meta['mtu']}")
        print(f" Server name: {meta['host']}   Certificate: {meta['cert']}   SNI lock: {'ON' if meta['sni_lock'] else 'OFF'}")
        print(vc.BAR)
        print(" [1]> CHANGE DNS            [2]> CHANGE CLIENT POOL SUBNET")
        print(" [3]> CHANGE MTU            [4]> REGENERATE SELF-MADE CERTIFICATES")
        print(" [5]> USE MY OWN CERTIFICATE (e.g. Let's Encrypt)")
        print(" [6]> TOGGLE SNI LOCK (only accept the server name)")
        print(" [7]> DIAGNOSTICS")
        print(vc.BAR)
        print(" [0] RETURN")
        ch = input(" Enter an Option: ").strip()
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
                if ipaddress.ip_network(new, strict=False).num_addresses < 8:
                    raise ValueError
            except ValueError:
                print(f"{C_RED}[X] Invalid or too small CIDR.{C_RESET}"); vc.pause(); continue
            vc.remove_nat(meta["subnet"], vc.default_interface(), NAT_TAG)
            meta["subnet"] = new
        elif ch == '3':
            raw = input(f" MTU [{meta['mtu']}] (1280-1500): ").strip()
            if raw:
                if not (raw.isdigit() and 1280 <= int(raw) <= 1500):
                    print(f"{C_RED}[X] Must be 1280-1500.{C_RESET}"); vc.pause(); continue
                meta["mtu"] = int(raw)
        elif ch == '4':
            new = input(f" Server name/IP for the certificate [{meta['host']}]: ").strip() or meta["host"]
            if not re.match(r'^[A-Za-z0-9.\-]+$', new):
                print(f"{C_RED}[X] Use a hostname or IPv4 address only.{C_RESET}"); vc.pause(); continue
            ok, err = _generate_certs(new)
            if not ok:
                print(f"{C_RED}[X] {err}{C_RESET}"); vc.pause(); continue
            meta.update(host=new, cert="self", cert_file=SERVER_CERT, key_file=SERVER_KEY)
            print(f"{C_YELLOW}[!] Clients must trust the NEW CA certificate (option 5 > C).{C_RESET}")
        elif ch == '5':
            cert = input(" Full path to certificate (PEM, include chain if you have one): ").strip()
            key = input(" Full path to private key (PEM): ").strip()
            if not (os.path.isfile(cert) and os.path.isfile(key)):
                print(f"{C_RED}[X] One of those files does not exist.{C_RESET}"); vc.pause(); continue
            if _run(["openssl", "x509", "-in", cert, "-noout"]).returncode != 0:
                print(f"{C_RED}[X] That is not a readable PEM certificate.{C_RESET}"); vc.pause(); continue
            meta.update(cert="custom", cert_file=cert, key_file=key)
        elif ch == '6':
            meta["sni_lock"] = not meta["sni_lock"]
        else:
            continue
        ok, msg = _apply_safely(meta, port, "Change")
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
        vc.header("SSTP - MODIFY PORT & TRAFFIC REDIRECTION")
        print(f" SSTP listens on TCP {port} (TLS)")
        print(BAR_LINE)
        print(" [1]> CHANGE SSTP PORT")
        print(" [2]> PORT REDIRECTION (extra TCP port ranges -> SSTP port)  [safe PORT MOD]")
        print(vc.BAR)
        print(" [0] RETURN")
        ch = input(" Enter an Option: ").strip()
        if ch == '0':
            return
        if ch == '1':
            new_port = prompt_port(f" New SSTP TCP port [Current: {port}]: ", default=port)
            if new_port != port and check_system_port_in_use(new_port, ("tcp",)):
                print(f"{C_RED}[X] Port {new_port} is already in use by another service.{C_RESET}")
                vc.pause(); continue
            open_firewall_port(new_port, ("tcp",)); persist_firewall_rules()
            ok, msg = _apply_safely(meta, new_port, f"Port {port} -> {new_port}")
            if ok:
                if new_port != port:
                    close_firewall_port(port, ("tcp",)); persist_firewall_rules()
                _publish(ports_dict, new_port)
            else:
                if new_port != port:
                    close_firewall_port(new_port, ("tcp",))
            print(f"{C_GREEN if ok else C_RED}[{'OK' if ok else 'X'}] {msg}{C_RESET}")
            vc.pause()
        elif ch == '2':
            vc.portmod_menu(MOD_TAG, "SSTP", "tcp", [("SSTP", port)], ports_dict)


def _install(ports_dict):
    vc.header("SSTP INSTALLATION WIZARD")
    meta = _load_meta()
    default_port = get_port() if _installed() else (DEFAULT_PORT if not check_system_port_in_use(DEFAULT_PORT, ("tcp",)) else 8443)
    port = prompt_port(f" SSTP TCP port (443 is standard; share it via HAProxy/MULTIPLEX) [{default_port}]: ", default=default_port)
    if not (_installed() and port == get_port()) and check_system_port_in_use(port, ("tcp",)):
        print(f"{C_RED}[X] Port {port} is already in use by another service.{C_RESET}"); vc.pause(); return
    meta["host"] = input(f" Server name clients will type (must match the certificate) [{meta['host'] or get_public_ip()}]: ").strip() or meta["host"] or get_public_ip()
    if not re.match(r'^[A-Za-z0-9.\-]+$', meta["host"]):
        print(f"{C_RED}[X] Use a hostname or IPv4 address only.{C_RESET}"); vc.pause(); return
    print(" Certificate: 1) generate a CA + server certificate (clients import the CA)")
    print("              2) use my own certificate files (e.g. Let's Encrypt)")
    if input(" Choose [1]: ").strip() == "2":
        cert = input(" Full path to certificate PEM: ").strip()
        key = input(" Full path to private key PEM: ").strip()
        if not (os.path.isfile(cert) and os.path.isfile(key)) or _run(["openssl", "x509", "-in", cert, "-noout"]).returncode != 0:
            print(f"{C_RED}[X] Certificate/key not found or unreadable.{C_RESET}"); vc.pause(); return
        meta.update(cert="custom", cert_file=cert, key_file=key)
    else:
        meta.update(cert="self", cert_file=SERVER_CERT, key_file=SERVER_KEY)
    print(" DNS for clients: 1) Cloudflare  2) Google  3) Quad9")
    meta["dns"] = DNS_CHOICES.get(input(" Choose [1]: ").strip() or "1", DNS_CHOICES["1"])
    meta["subnet"] = input(f" Client address pool [{meta['subnet']}]: ").strip() or meta["subnet"]
    try:
        if ipaddress.ip_network(meta["subnet"], strict=False).num_addresses < 8:
            raise ValueError
    except ValueError:
        print(f"{C_RED}[X] Invalid or too small pool CIDR.{C_RESET}"); vc.pause(); return

    ok, why = vc.ensure_ppp_support()
    if not ok:
        print(f"{C_RED}[X] {why}{C_RESET}"); vc.pause(); return
    if not _accel_present():
        ok, err = _build_accel()
        if not ok:
            print(f"{C_RED}[X] Could not build accel-ppp: {err}{C_RESET}")
            vc.pause(); return
    if meta["cert"] == "self":
        print(f"{C_CYAN}[i] Generating the certificate authority and server certificate...{C_RESET}")
        ok, err = _generate_certs(meta["host"])
        if not ok:
            print(f"{C_RED}[X] Certificate generation failed: {err}{C_RESET}"); vc.pause(); return

    already = _installed()
    vc.set_access("sstp", enabled=True)
    vc.ensure_sync_timer()
    vc.sync_sstp()
    open_firewall_port(port, ("tcp",)); persist_firewall_rules()
    _routing(meta)
    _run(f"systemctl enable {SERVICE}")

    ok, msg = _apply_safely(meta, port, f"SSTP on TCP {port}")
    if ok:
        _save_meta(meta)
        _run(f"systemctl enable {SERVICE}")
        _publish(ports_dict, port)
        print(f"{C_GREEN}[OK] {msg}{C_RESET}")
        print(f" {len(vc.allowed_users('sstp'))} SSH account(s) can log in right now. Option [5] shows client setup.")
    else:
        vc.set_access("sstp", enabled=False)
        if not already:
            close_firewall_port(port, ("tcp",)); persist_firewall_rules()
        print(f"{C_RED}[X] {msg}{C_RESET}")
    vc.pause()


def _uninstall(ports_dict):
    vc.header("UNINSTALL SSTP")
    if input(" Are you sure you want to completely remove SSTP? (y/n): ").strip().lower() != 'y':
        print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}"); vc.pause(); return
    meta = _load_meta()
    port = get_port()
    vc.portmod_disable(MOD_TAG)
    _run(f"systemctl stop {SERVICE}"); _run(f"systemctl disable {SERVICE}")
    for p in (SERVICE_PATH, CONF_PATH, META_PATH, vc.SSTP_CHAP_SECRETS):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    shutil.rmtree(CERT_DIR, ignore_errors=True)
    _run("systemctl daemon-reload")
    vc.drop_access("sstp")
    vc.remove_nat(meta["subnet"], vc.default_interface(), NAT_TAG)
    vc.remove_ip_forwarding_dropin(SYSCTL_NAME)
    close_firewall_port(port, ("tcp",))
    persist_firewall_rules()
    if _accel_present() and input(" Also remove the accel-ppp program files (rebuilding takes minutes)? (y/n): ").strip().lower() == 'y':
        for p in ("/usr/sbin/accel-pppd", "/usr/bin/accel-cmd"):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass
        shutil.rmtree("/usr/lib/accel-ppp", ignore_errors=True)
        shutil.rmtree(SRC_DIR, ignore_errors=True)
    vc.remove_sync_timer_if_unused()
    ports_dict.pop('SSTP_PORT', None)
    vc.save_state_now(ports_dict)
    print(f"{C_GREEN}[OK] SSTP purged successfully.{C_RESET}")
    vc.pause()


def sstp_admin_manager(ports_dict):
    """SSTP Administrator Module."""
    while True:
        if _installed():
            _run(f"systemctl enable {SERVICE}")
            vc.ensure_sync_timer()
            live = get_port()
            if str(ports_dict.get('SSTP_PORT')) != str(live):
                print(f"{C_YELLOW}[!] The saved port ({ports_dict.get('SSTP_PORT') or 'none'}) didn't match what's actually")
                print(f"    running ({live}) - correcting the panel's records to match reality.{C_RESET}")
                _publish(ports_dict, live)
                vc.pause()
            vc.sync_all()
            port_txt = str(live)
        else:
            port_txt = "Not configured"
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"
        allowed = len(vc.allowed_users("sstp")) if _installed() else 0

        vc.header("SSTP ADMINISTRATOR")
        print(f"      PORT: {port_txt}  |  ACCOUNTS ALLOWED: {allowed}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL SSTP")
        print(" [2]> MODIFY PORT & TRAFFIC REDIRECTION")
        print(" [3]> MANAGE USER ACCESS")
        print(" [4]> CONNECTED CLIENTS")
        print(" [5]> CONNECTION INFO / CLIENT SETUP")
        print(" [6]> VIEW SERVICE LOGS")
        print(" [7]> RESTART SSTP SERVICE")
        print(f" [8]> START/STOP SSTP SERVICE [{status_label}]")
        print(" [9]> ADVANCED (DNS / POOL / MTU / CERT / SNI / DIAGNOSTICS)")
        print(vc.BAR)
        print(" [0] RETURN  [10] UNINSTALL SSTP")
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
            vc.user_access_menu("sstp", "SSTP", on_change=lambda: vc.sync_all())
        elif choice == '4':
            _connected_clients()
        elif choice == '5':
            _connection_info()
        elif choice == '6':
            vc.header("SSTP SERVICE LOGS")
            os.system(f"journalctl -u {SERVICE} -n 40 --no-pager")
            print("\n--- accel-ppp log ---")
            os.system("tail -n 25 /var/log/accel-ppp/smartui-sstp.log 2>/dev/null; tail -n 10 /var/log/accel-ppp/smartui-sstp-core.log 2>/dev/null")
            vc.pause()
        elif choice == '7':
            if _restart():
                print(f"{C_GREEN}[OK] SSTP service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] SSTP failed to restart - check 'journalctl -u {SERVICE}'.{C_RESET}")
            vc.pause()
        elif choice == '8':
            if is_active:
                _run(f"systemctl stop {SERVICE}")
                print(f"{C_YELLOW}[!] SSTP service stopped.{C_RESET}")
            else:
                _restart()
                if _service_active():
                    print(f"{C_GREEN}[OK] SSTP service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] SSTP failed to start - check 'journalctl -u {SERVICE}'.{C_RESET}")
            vc.pause()
        elif choice == '9':
            _advanced(ports_dict)
        elif choice == '10':
            _uninstall(ports_dict)
        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            vc.pause()
