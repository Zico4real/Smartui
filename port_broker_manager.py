"""
port_broker_manager.py - Port 443/80 multiplexing for the SmartUI panel,
using sslh (a real protocol demultiplexer that looks at the first bytes of
each new TCP connection and forwards the whole connection to the matching
backend).

What changed in this version
----------------------------
Before, the wizard asked four fixed yes/no questions (SSH, one TLS service,
OpenVPN, one HTTP tunnel) and only looked at a handful of ports_dict keys.
Now the wizard is port-first: pick port 443 or port 80 and it builds a LIVE
list of every TCP service on this server that can sit behind that port
(SSH, Dropbear, Stunnel ports, Xray inbounds, WS-EPRO, WEBSOCKET, Python
SOCKS ports, SSHGO, Squid, OpenVPN-TCP, HAProxy/Nginx in chained mode,
SSTP, and a manual "custom backend" entry). The admin ticks whichever ones
they want.

Each shared port runs as its OWN sslh instance (sslh-443.service and
sslh-80.service), so 443 and 80 can have different selections and can be
started/stopped/removed independently.

How sslh tells protocols apart - the one hard limit
---------------------------------------------------
sslh recognises a connection by what the client sends first. That gives five
"detection slots" per shared port, and ONE backend per slot:
    ssh      - SSH banner            (OpenSSH, Dropbear)
    openvpn  - OpenVPN TCP header
    http     - plain HTTP request    (WebSocket upgrade payloads, Python SOCKS,
                                      WS-EPRO, Squid CONNECT, ...)
    tls      - TLS ClientHello       (Stunnel, Xray TLS/REALITY, SSTP, ...)
    anyprot  - catch-all for anything else
If several selected services fall into the same slot, the wizard asks which
one gets it. To put MORE than one TLS service behind one slot, chain through
HAProxy (routes by domain/SNI) or Nginx (routes by URL path) - both already
exist in this panel in "chained" mode, and show up in the list as a single
TLS backend. UDP protocols can never be included (there is nothing to peek at
before a UDP datagram is already delivered).

A service that is currently listening ON the port being shared cannot be a
backend until it is moved to an internal port (it would be fighting sslh for
the same port). SSH is the one exception: the wizard can relocate it for you
using SSH Administrator's own tested port-change function.
"""

import os
import re
import json
import time
import shutil
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)

BROKER_DIR = "/etc/sslh-smartui"
OLD_PACKAGE_SERVICE = "sslh"
OLD_PACKAGE_CONFIG = "/etc/default/sslh"
SHARE_PORTS = (443, 80)

# Order matters: the FIRST protocol on sslh's command line is where a
# connection goes if the client sends nothing before the timeout (server-
# speaks-first clients), so ssh stays first, exactly as before.
CLASS_ORDER = ("ssh", "openvpn", "http", "tls", "anyprot")
CLASS_TITLE = {
    "ssh": "SSH banner",
    "openvpn": "OpenVPN-TCP",
    "http": "plain HTTP / WebSocket",
    "tls": "TLS / SSL",
    "anyprot": "anything else (catch-all)",
}
CLASS_FLAG = {"ssh": "--ssh", "openvpn": "--openvpn", "http": "--http",
              "tls": "--tls", "anyprot": "--anyprot"}


# ---------------------------------------------------------------- helpers

def _unit_name(port):
    return "sslh-%s" % port


def _unit_path(port):
    return "/etc/systemd/system/%s.service" % _unit_name(port)


def _cfg_path(port):
    return "%s/%s.json" % (BROKER_DIR, port)


def _load_cfg(port):
    try:
        with open(_cfg_path(port)) as f:
            return json.load(f)
    except Exception:
        return None


def _save_cfg(port, cfg):
    os.makedirs(BROKER_DIR, exist_ok=True)
    with open(_cfg_path(port), "w") as f:
        json.dump(cfg, f, indent=2)


def _configured_ports():
    return [p for p in SHARE_PORTS if os.path.exists(_cfg_path(p))]


def _unit_active(port):
    return _run(["systemctl", "is-active", "--quiet", _unit_name(port)]).returncode == 0


def _sync_ports_dict(ports_dict):
    """Keeps the Protocol Manager's MULTIPLEX line in step: BROKER_PORT is a
    comma list of the shared ports that are configured, BROKER_BACKENDS a
    short summary."""
    ports = _configured_ports()
    if not ports:
        ports_dict.pop('BROKER_PORT', None)
        ports_dict.pop('BROKER_BACKENDS', None)
        return
    ports_dict['BROKER_PORT'] = ",".join(str(p) for p in ports)
    parts = []
    for p in ports:
        cfg = _load_cfg(p) or {}
        names = [b.get("label", "?") for b in cfg.get("backends", [])]
        parts.append("%s: %s" % (p, "+".join(names) if names else "none"))
    ports_dict['BROKER_BACKENDS'] = "; ".join(parts)


def broker_status(ports_dict):
    """For the Protocol Manager's MULTIPLEX line. Returns (tag, detail)."""
    ports = _configured_ports()
    if not ports:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    up = [p for p in ports if _unit_active(p) and check_system_port_in_use(p, ("tcp",))]
    detail = ",".join(str(p) for p in ports)
    if len(up) == len(ports):
        return "%s[ON]%s" % (C_GREEN, C_RESET), detail
    if up:
        return "%s[ON?]%s" % (C_YELLOW, C_RESET), detail
    return "%s[OFF]%s" % (C_RED, C_RESET), None


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _sslh_bin():
    for name in ("sslh", "sslh-select", "sslh-fork"):
        found = shutil.which(name) or ("/usr/sbin/" + name if os.path.exists("/usr/sbin/" + name) else None)
        if found:
            return found
    return None


def _ensure_installed():
    if _sslh_bin():
        return True
    print("%s[i] Installing sslh...%s" % (C_CYAN, C_RESET))
    # DEBIAN_FRONTEND=noninteractive: the package raises a debconf prompt
    # (standalone vs inetd) that hangs forever with no terminal to answer it.
    # DPkg::Lock::Timeout: bounds the wait if unattended-upgrades holds the
    # dpkg lock, so it fails with a visible error instead of hanging silently.
    _run("DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 update && "
         "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y sslh")
    ok = _sslh_bin() is not None
    if not ok:
        print("%s[X] sslh did not install correctly - check network access.%s" % (C_RED, C_RESET))
    return ok


def _park_package_service():
    """The sslh package auto-starts its own 'sslh' service (often straight on
    port 443 with its default options). Each shared port here runs as its own
    sslh-<port> unit instead, so the package service must be off or it keeps
    the port and blocks ours."""
    if _run(["systemctl", "is-enabled", "--quiet", OLD_PACKAGE_SERVICE]).returncode == 0 \
            or _run(["systemctl", "is-active", "--quiet", OLD_PACKAGE_SERVICE]).returncode == 0:
        _run("systemctl stop %s" % OLD_PACKAGE_SERVICE)
        _run("systemctl disable %s" % OLD_PACKAGE_SERVICE)
        _run("systemctl reset-failed %s" % OLD_PACKAGE_SERVICE)


# ------------------------------------------------------ candidate discovery

def _split_ports(raw):
    return [int(x) for x in re.split(r'[,\s]+', str(raw or '')) if x.isdigit()]


def _ssh_live_port(ports_dict):
    port = ports_dict.get('SSH_PORT')
    if port and str(port).isdigit():
        return int(port)
    try:
        with open("/etc/ssh/sshd_config") as f:
            m = re.search(r'^\s*Port\s+(\d+)', f.read(), re.MULTILINE)
        return int(m.group(1)) if m else 22
    except Exception:
        return 22


def _json_file(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _discover_candidates(ports_dict):
    """Returns a list of dicts: label, port, cls, note, reloc (bool).
    Everything here is read from the live state of the other panel modules;
    nothing is changed."""
    cands = []

    def add(label, port, cls, note="", reloc=False):
        try:
            port = int(port)
        except (TypeError, ValueError):
            return
        if any(c["port"] == port and c["label"] == label for c in cands):
            return
        cands.append({"label": label, "port": port, "cls": cls, "note": note, "reloc": reloc})

    add("SSH", _ssh_live_port(ports_dict), "ssh", "OpenSSH", reloc=True)
    for p in _split_ports(ports_dict.get('DROPBEAR_PORTS')):
        add("DROPBEAR", p, "ssh", "Dropbear SSH")

    for p in _split_ports(ports_dict.get('STUNNEL_PORTS')):
        add("STUNNEL", p, "tls", "Stunnel SSL")

    for entry in str(ports_dict.get('PYSOCKS_INSTANCES', '')).split(','):
        parts = entry.split(':')
        if len(parts) == 3 and parts[1].isdigit():
            add("PYTHON SOCKS", parts[1], "http", "Python SOCKS (%s)" % parts[0])

    if ports_dict.get('WS_PORT'):
        add("WS-EPRO", ports_dict['WS_PORT'], "http", "WebSocket proxy")
    if ports_dict.get('WSTUNNEL_PORT'):
        add("WEBSOCKET", ports_dict['WSTUNNEL_PORT'], "http", "WebSocket tunnel")
    if ports_dict.get('SSHGO_PORT'):
        add("SSHGO", ports_dict['SSHGO_PORT'], "http", "SSH over WebSocket")
    if ports_dict.get('SQUID_PORT'):
        add("SQUID", ports_dict['SQUID_PORT'], "http", "HTTP proxy")
    if ports_dict.get('SSTP_PORT'):
        add("SSTP", ports_dict['SSTP_PORT'], "tls", "SSTP VPN (HTTPS)")
    if ports_dict.get('PSIPHON_GATE_PORT'):
        add("PSIPHON", ports_dict['PSIPHON_GATE_PORT'], "anyprot", "Psiphon gate")

    if str(ports_dict.get('OPENVPN_PROTO', 'udp')).lower() == 'tcp' and ports_dict.get('OPENVPN_PORT'):
        add("OPENVPN", ports_dict['OPENVPN_PORT'], "openvpn", "OpenVPN TCP mode")

    # Xray: only inbounds reachable from outside (loopback-only ones are
    # fallback targets that Xray itself already routes to) and only TCP-based.
    xcfg = _json_file("/usr/local/etc/xray/config.json") or {}
    for ib in xcfg.get("inbounds", []):
        port = ib.get("port")
        if not isinstance(port, int):
            continue
        if str(ib.get("listen", "")) in ("127.0.0.1", "::1", "localhost"):
            continue
        ss = ib.get("streamSettings", {}) or {}
        net = ss.get("network", "tcp")
        sec = ss.get("security", "none")
        if net in ("kcp", "mkcp", "quic"):
            continue
        proto = ib.get("protocol", "?")
        if proto in ("dokodemo-door", "http", "socks"):
            continue
        if sec in ("tls", "reality"):
            cls = "tls"
        elif net in ("ws", "httpupgrade", "xhttp", "splithttp"):
            cls = "http"
        else:
            cls = "anyprot"
        add("XRAY", port, cls, "%s/%s/%s" % (proto, net, sec))

    # HAProxy / Nginx in chained mode are the way to put several TLS services
    # behind the single TLS slot.
    hp_state = _json_file("/etc/haproxy-sni/state.json") or {}
    hp_routes = _json_file("/etc/haproxy-sni/routes.json") or {}
    if hp_routes and hp_state.get("listen_port", 443) not in (443, 80):
        add("HAPROXY (SNI router)", hp_state["listen_port"], "tls",
            "%d domain route(s) - several TLS services" % len(hp_routes))
    ng_state = _json_file("/etc/nginx-smartui/state.json") or {}
    if ng_state.get("domain") and ng_state.get("listen_port", 443) not in (443, 80):
        add("NGINX (path proxy)", ng_state["listen_port"], "tls",
            "TLS termination + path routes")

    return cands


def _occupied_by_other(public_port, candidate_port):
    return candidate_port == public_port


# ------------------------------------------------------------ build + apply

def _build_exec(public_port, backends):
    """backends: list of {"cls","label","port","host"}"""
    by_cls = {b["cls"]: b for b in backends}
    timeout = 5 if "openvpn" in by_cls else 2
    parts = [_sslh_bin() or "/usr/sbin/sslh", "-f",
             "--listen 0.0.0.0:%s" % public_port, "--timeout %s" % timeout]
    for cls in CLASS_ORDER:
        if cls in by_cls:
            b = by_cls[cls]
            parts.append("%s %s:%s" % (CLASS_FLAG[cls], b.get("host", "127.0.0.1"), b["port"]))
    return " ".join(parts)


def _unit_content(public_port, backends):
    return """[Unit]
Description=SmartUI port sharing (sslh) on port %s
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (public_port, _build_exec(public_port, backends))


def _apply_safely(public_port, backends):
    """Writes the unit, starts it, verifies the port really listens; on any
    failure restores the previous unit (or removes the new one on a first
    attempt) so a bad choice never leaves a broken config behind."""
    path = _unit_path(public_port)
    original = None
    if os.path.exists(path):
        with open(path) as f:
            original = f.read()
    with open(path, "w") as f:
        f.write(_unit_content(public_port, backends))
    _run("systemctl daemon-reload")
    _run("systemctl enable %s" % _unit_name(public_port))
    _run("systemctl reset-failed %s" % _unit_name(public_port))

    ok = _run("systemctl restart %s" % _unit_name(public_port)).returncode == 0 \
        and _wait_for_port_listening(public_port)
    if ok:
        return True, "Port %s sharing applied and verified." % public_port

    if original is not None:
        with open(path, "w") as f:
            f.write(original)
        _run("systemctl daemon-reload")
        _run("systemctl restart %s" % _unit_name(public_port))
        return False, ("Port %s sharing failed to come up - reverted to the previous working setup. "
                       "Check 'journalctl -u %s'." % (public_port, _unit_name(public_port)))
    _run("systemctl stop %s" % _unit_name(public_port))
    _run("systemctl disable %s" % _unit_name(public_port))
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    _run("systemctl daemon-reload")
    return False, ("Port %s sharing failed to come up - nothing was left installed. "
                   "Check 'journalctl -u %s'." % (public_port, _unit_name(public_port)))


# ------------------------------------------------------------------ wizard

def _print_candidates(public_port, cands):
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("%s       PROTOCOLS THAT CAN SHARE PORT %-5s                      %s" % (C_BOLD, public_port, C_RESET))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print(" %-4s %-22s %-7s %-10s %s" % ("#", "PROTOCOL", "PORT", "DETECTED", "STATUS"))
    print("----------------------------------------------------------------")
    for i, c in enumerate(cands, 1):
        if c["port"] == public_port and not c["reloc"]:
            status = "%sON this port - move it first%s" % (C_YELLOW, C_RESET)
        elif c["port"] == public_port and c["reloc"]:
            status = "%son this port - can be relocated%s" % (C_YELLOW, C_RESET)
        elif check_system_port_in_use(c["port"], ("tcp",)):
            status = "%srunning%s" % (C_GREEN, C_RESET)
        else:
            status = "%snot running yet%s" % (C_RED, C_RESET)
        print(" [%d]%s %-22s %-7s %-10s %s" % (i, " " * (3 - len(str(i))), c["label"], c["port"], c["cls"], status))
        if c["note"]:
            print("      %s%s%s" % (C_CYAN, c["note"], C_RESET))
    print("----------------------------------------------------------------")
    print(" [M] Add a custom TCP backend by hand")
    print(" Detection slots (one backend each): ssh | openvpn | http | tls | anyprot")
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))


def _resolve_selection(public_port, picked, ports_dict):
    """picked: candidate dicts. Returns list of backend dicts, or None to
    cancel. Handles relocation of SSH off the shared port and the
    one-backend-per-slot rule."""
    chosen = []
    for c in picked:
        b = {"cls": c["cls"], "label": c["label"], "port": c["port"], "host": c.get("host", "127.0.0.1")}
        if c["port"] == public_port:
            if not c["reloc"]:
                print("%s[X] %s is on port %s itself - move it to an internal port first. Skipped.%s"
                      % (C_RED, c["label"], public_port, C_RESET))
                continue
            print("%s[i] SSH is on port %s - relocating it to an internal port first (using SSH"
                  % (C_CYAN, public_port))
            print("    Administrator's own tested port-change logic).%s" % C_RESET)
            new_port = prompt_port(" Enter a new internal port for SSH (e.g. 2299): ", default=2299)
            if new_port == public_port:
                print("%s[X] That is the shared port. SSH skipped.%s" % (C_RED, C_RESET))
                continue
            from ssh_dropbear_manager import _change_ssh_port
            _change_ssh_port(new_port, str(c["port"]), ports_dict)
            if str(ports_dict.get('SSH_PORT')) != str(new_port):
                print("%s[X] SSH was not moved - skipping it so you don't lose access.%s" % (C_RED, C_RESET))
                continue
            b["port"] = new_port
        chosen.append(b)

    # one backend per detection slot
    final = []
    for cls in CLASS_ORDER:
        group = [b for b in chosen if b["cls"] == cls]
        if not group:
            continue
        if len(group) == 1:
            final.append(group[0])
            continue
        print("\n%s[!] %d services were picked for the '%s' slot (%s) - sslh can send that kind of"
              % (C_YELLOW, len(group), cls, CLASS_TITLE[cls]))
        print("    traffic to only ONE backend. Which one should get it?%s" % C_RESET)
        for i, b in enumerate(group, 1):
            print("   [%d] %s (port %s)" % (i, b["label"], b["port"]))
        print("   [0] none of them")
        if cls == "tls":
            print("   Tip: to share several TLS services, set up HAProxy (domain routing) or Nginx")
            print("   (path routing) in chained mode and pick that single entry instead.")
        sel = input(" Choose: ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(group):
            final.append(group[int(sel) - 1])
    return final


def _manual_backend(public_port):
    print("\n Custom backend - the service must already listen on an internal port.")
    print(" Detection slot: [1] ssh  [2] openvpn  [3] http  [4] tls  [5] anyprot")
    sel = input(" Slot: ").strip()
    slots = {"1": "ssh", "2": "openvpn", "3": "http", "4": "tls", "5": "anyprot"}
    if sel not in slots:
        return None
    label = input(" Name for it (e.g. MYAPP): ").strip().upper() or "CUSTOM"
    port = prompt_port(" Internal port it listens on: ", default=8443)
    if port == public_port:
        print("%s[X] That is the shared port itself.%s" % (C_RED, C_RESET))
        return None
    return {"label": label, "port": port, "cls": slots[sel], "note": "custom", "reloc": False}


def _configure_port(public_port, ports_dict):
    clear_screen()
    cands = _discover_candidates(ports_dict)
    manual = []
    existing = _load_cfg(public_port)

    while True:
        clear_screen()
        _print_candidates(public_port, cands + manual)
        if existing:
            names = ", ".join("%s:%s" % (b["label"], b["port"]) for b in existing.get("backends", []))
            print(" Currently shared on %s: %s" % (public_port, names or "none"))
            print(" (a new selection replaces it)")
        raw = input(" Enter numbers (e.g. 1,3,4), A = all eligible, M = custom, 0 = cancel: ").strip().lower()
        if raw in ("0", ""):
            return
        if raw == "m":
            m = _manual_backend(public_port)
            if m:
                manual.append(m)
            continue
        everything = cands + manual
        if raw == "a":
            picked = [c for c in everything if c["port"] != public_port]
        else:
            idx = []
            for tok in re.split(r'[,\s]+', raw):
                if tok.isdigit() and 1 <= int(tok) <= len(everything):
                    idx.append(int(tok) - 1)
                elif tok:
                    print("%s[!] Ignoring '%s'.%s" % (C_YELLOW, tok, C_RESET))
            picked = [everything[i] for i in dict.fromkeys(idx)]
        if not picked:
            print("%s[X] Nothing valid selected.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
            continue
        break

    backends = _resolve_selection(public_port, picked, ports_dict)
    if not backends:
        print("%s[X] No usable backends - nothing configured.%s" % (C_RED, C_RESET))
        input("\nPress Enter to continue...")
        return

    for b in backends:
        if not check_system_port_in_use(b["port"], ("tcp",)):
            print("%s[!] %s isn't listening on %s yet - traffic for it will fail until it is running.%s"
                  % (C_YELLOW, b["label"], b["port"], C_RESET))

    if not _unit_active(public_port) and check_system_port_in_use(public_port, ("tcp",)):
        print("%s[X] Port %s is already used by another service (and sslh isn't running on it)."
              % (C_RED, public_port))
        print("    Move that service to an internal port first, then run this again.%s" % C_RESET)
        input("\nPress Enter to continue...")
        return

    if not _ensure_installed():
        input("\nPress Enter to continue...")
        return
    _park_package_service()

    open_firewall_port(public_port, ("tcp",))
    persist_firewall_rules()
    ok, msg = _apply_safely(public_port, backends)
    if ok:
        _save_cfg(public_port, {"backends": [{"cls": b["cls"], "label": b["label"], "port": b["port"],
                                              "host": b.get("host", "127.0.0.1")} for b in backends]})
        _sync_ports_dict(ports_dict)
        print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
        for b in backends:
            print("     %-8s -> %s (127.0.0.1:%s)" % (b["cls"], b["label"], b["port"]))
    else:
        if not _load_cfg(public_port):
            close_firewall_port(public_port, ("tcp",))
            persist_firewall_rules()
        print("%s[X] %s%s" % (C_RED, msg, C_RESET))
    input("\nPress Enter to continue...")


def _remove_port(public_port, ports_dict):
    _run("systemctl stop %s" % _unit_name(public_port))
    _run("systemctl disable %s" % _unit_name(public_port))
    for path in (_unit_path(public_port), _cfg_path(public_port)):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    _run("systemctl daemon-reload")
    close_firewall_port(public_port, ("tcp",))
    persist_firewall_rules()
    _sync_ports_dict(ports_dict)


# -------------------------------------------------------------------- menu

def port_broker_manager(ports_dict):
    """Port 443/80 Multiplexing Administrator Module."""
    while True:
        ports = _configured_ports()
        for p in ports:
            _run("systemctl enable %s" % _unit_name(p))
        _sync_ports_dict(ports_dict)

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s            PORT 443/80 MULTIPLEXING (sslh)                 %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        if not ports:
            print("      SHARED PORTS: Not configured")
        for p in ports:
            cfg = _load_cfg(p) or {}
            tag = "%sON%s" % (C_GREEN, C_RESET) if _unit_active(p) else "%sOFF%s" % (C_RED, C_RESET)
            names = ", ".join("%s" % b["label"] for b in cfg.get("backends", [])) or "none"
            print("      PORT %-4s [%s]  %s" % (p, tag, names))
        print("%s      Only TCP protocols can share a port - UDP ones (Hysteria, WireGuard," % C_YELLOW)
        print("      BadVPN, ZIVPN, DNSTT, ICMP, OpenVPN-UDP) cannot be included.%s" % C_RESET)
        print("----------------------------------------------------------------")
        print(" [1]> SHARE PORT 443  (pick from all compatible protocols)")
        print(" [2]> SHARE PORT 80   (pick from all compatible protocols)")
        print(" [3]> VIEW CURRENT CONFIGURATION")
        print(" [4]> VIEW SERVICE LOGS")
        print(" [5]> RESTART SERVICES")
        print(" [6]> START/STOP SERVICES")
        print(" [7]> STOP SHARING ONE PORT")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [8] UNINSTALL / DISABLE ALL MULTIPLEXING")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice in ('1', '2'):
            _configure_port(443 if choice == '1' else 80, ports_dict)

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                CURRENT CONFIGURATION                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not ports:
                print("%s Not configured yet.%s" % (C_YELLOW, C_RESET))
            for p in ports:
                cfg = _load_cfg(p) or {}
                print("\n Port %s:" % p)
                for b in cfg.get("backends", []):
                    print("   %-8s -> %-14s 127.0.0.1:%s" % (b["cls"], b["label"], b["port"]))
                print("   command: %s" % _build_exec(p, cfg.get("backends", [])))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            for p in ports or []:
                print("--- %s ---" % _unit_name(p))
                os.system("journalctl -u %s -n 30 --no-pager" % _unit_name(p))
            if not ports:
                print("%s Not configured yet.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            if not ports:
                print("%s[X] Not configured yet.%s" % (C_RED, C_RESET))
            for p in ports:
                _run("systemctl reset-failed %s" % _unit_name(p))
                if _run("systemctl restart %s" % _unit_name(p)).returncode == 0 and _wait_for_port_listening(p):
                    print("%s[OK] Port %s restarted.%s" % (C_GREEN, p, C_RESET))
                else:
                    print("%s[X] Port %s failed - check 'journalctl -u %s'.%s" % (C_RED, p, _unit_name(p), C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            if not ports:
                print("%s[X] Not configured yet - use option 1 or 2 first.%s" % (C_RED, C_RESET))
            else:
                any_active = any(_unit_active(p) for p in ports)
                for p in ports:
                    if any_active:
                        _run("systemctl stop %s" % _unit_name(p))
                    else:
                        _run("systemctl reset-failed %s" % _unit_name(p))
                        _run("systemctl start %s" % _unit_name(p))
                print("%s[!] Stopped.%s" % (C_YELLOW, C_RESET) if any_active else
                      "%s[OK] Started.%s" % (C_GREEN, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            if not ports:
                print("%s[X] Nothing is being shared.%s" % (C_RED, C_RESET))
            else:
                for i, p in enumerate(ports, 1):
                    print(" [%d] Port %s" % (i, p))
                sel = input(" Stop sharing which one? (blank to cancel): ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(ports):
                    _remove_port(ports[int(sel) - 1], ports_dict)
                    print("%s[OK] Port %s is no longer shared. Services you moved to internal"
                          " ports stay there.%s" % (C_GREEN, ports[int(sel) - 1], C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            confirm = input(" Disable all port multiplexing and remove sslh? (y/n): ").strip().lower()
            if confirm == 'y':
                for p in SHARE_PORTS:
                    if os.path.exists(_unit_path(p)) or os.path.exists(_cfg_path(p)):
                        _remove_port(p, ports_dict)
                _run("systemctl stop %s" % OLD_PACKAGE_SERVICE)
                _run("systemctl disable %s" % OLD_PACKAGE_SERVICE)
                _run("DEBIAN_FRONTEND=noninteractive apt-get purge -y sslh")
                ports_dict.pop('BROKER_PORT', None)
                ports_dict.pop('BROKER_BACKENDS', None)
                print("%s[OK] Port multiplexing disabled and sslh removed.%s" % (C_GREEN, C_RESET))
                print("%s[!] Any services you relocated off the shared ports are still on their"
                      % C_YELLOW)
                print("    internal ports - reconfigure them individually if you want them")
                print("    back on a public port directly.%s" % C_RESET)
            else:
                print("%s[i] Cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
