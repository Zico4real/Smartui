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

Several services in the SAME slot (this version)
-------------------------------------------------
sslh can also run from a config file, where one slot may hold several backends
that are told apart by a second look at the first packet:
    TLS   -> by SNI hostname (the name the client puts in its TLS hello). One TLS
             backend with no hostname is the DEFAULT for every other name (put
             Stunnel there: clients with a spoofed SNI still land on it).
    HTTP  -> by URL path (first request line, e.g. "GET /vless ..."). One HTTP
             backend with no path is the DEFAULT for every other request.
Xray ws / httpupgrade / xhttp inbounds are picked up with the path stored in the
Xray config. Those with TLS are put behind Nginx (path proxy, one domain): the
route "https:PORT" is added to Nginx for each, so they all share the domain's
SNI entry. Reality inbounds use their own serverNames as SNI. A service that
cannot be told apart (same slot, no hostname/path) is listed as skipped - never
silently dropped.

ONE domain for everything (the "decrypting front")
--------------------------------------------------
TLS passthrough cannot tell Stunnel, SSTP and Xray apart when they all use the same domain: the
only things visible before decryption are the hostname and ALPN, and they are identical. So on
port 443 the wizard can put a small HAProxy ("smartui-front") behind sslh's TLS slot that
DECRYPTS the TLS with the domain's certificate and then looks at the first bytes:
    SSTP_DUPLEX_POST ...        -> SSTP   (re-encrypted to its own TLS port)
    "GET /vless ..." etc.       -> the Xray inbound owning that path (re-encrypted if it is TLS,
                                   plain if not), or a WS-EPRO / WEBSOCKET / ... path you chose
    any other HTTP request      -> the default HTTP tunnel you chose (Python SOCKS, ...)
    nothing within 2 seconds    -> SSH   (an SSH client waits for the server's banner, so
                                   SSH-over-TLS "stunnel style" lands here)
It is a separate service (smartui-front) with its own config; the packaged haproxy service and
the SNI router in haproxy_manager are not touched. Certificates renew through a certbot hook.

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
    for p in list(up):
        if any(b.get("front") for b in (_load_cfg(p) or {}).get("backends", [])) and not _front_active():
            up.remove(p)   # sslh is up but the one-domain front behind it is not
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

    def add(label, port, cls, note="", reloc=False, meta=None):
        try:
            port = int(port)
        except (TypeError, ValueError):
            return
        if any(c["port"] == port and c["label"] == label for c in cands):
            return
        cands.append({"label": label, "port": port, "cls": cls, "note": note, "reloc": reloc,
                      "meta": meta or {}})

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

    # Psiphon "MORE PROTOCOLS" SSL/WEBSOCKET fronts (psiphon_manager.py's own
    # per-instance extras). These never touch ports_dict at all - they live
    # entirely in their own file, /etc/psiphon/fronts.json, as
    # {instance_name: {"ssl": port, "ws": port}} - so unlike the OpenVPN
    # extras above, this isn't a missing ports_dict key, it's reading the
    # same kind of standalone state file Xray's inbounds are already read
    # from a few lines below. Same detection classes as the OpenVPN SSL/WS
    # fronts: "ssl" terminates its own TLS (cert-based, like Stunnel/SSTP),
    # "ws" answers the HTTP Upgrade request (like WEBSOCKET/WS-EPRO).
    _psiphon_fronts = _json_file("/etc/psiphon/fronts.json") or {}
    if isinstance(_psiphon_fronts, dict):
        for _instance, _kinds in _psiphon_fronts.items():
            if not isinstance(_kinds, dict):
                continue
            if _kinds.get("ssl"):
                add("PSIPHON SSL", _kinds["ssl"], "tls", "Psiphon SSL front (%s)" % _instance)
            if _kinds.get("ws"):
                add("PSIPHON WEBSOCKET", _kinds["ws"], "http", "Psiphon WebSocket front (%s)" % _instance)

    # HCR Custom / BHTTP: both speak plain HTTP on the wire when their own
    # SSL/TLS toggle is off (sslh can read the request line to tell them
    # apart from other "http" backends, same as WEBSOCKET/WS-EPRO above).
    # When their toggle is on, they terminate real TLS themselves, so from
    # sslh's point of view they look exactly like Stunnel/SSTP - it only
    # needs to see a TLS ClientHello and hand the raw encrypted bytes
    # through untouched, same "tls" class as those.
    if ports_dict.get('HCR_PORT'):
        hcr_tls = str(ports_dict.get('HCR_USE_TLS', '0')) == '1'
        add("HCR CUSTOM", ports_dict['HCR_PORT'], "tls" if hcr_tls else "http",
            "HCR long-poll tunnel (TLS)" if hcr_tls else "HCR long-poll tunnel")
    if ports_dict.get('BHTTP_PORT'):
        bhttp_tls = str(ports_dict.get('BHTTP_USE_TLS', '0')) == '1'
        add("BHTTP TUNNEL", ports_dict['BHTTP_PORT'], "tls" if bhttp_tls else "http",
            "BHTTP tunnel (TLS)" if bhttp_tls else "BHTTP tunnel")

    if str(ports_dict.get('OPENVPN_PROTO', 'udp')).lower() == 'tcp' and ports_dict.get('OPENVPN_PORT'):
        add("OPENVPN", ports_dict['OPENVPN_PORT'], "openvpn", "OpenVPN TCP mode")

    # OpenVPN "MORE PROTOCOLS" side instances (openvpn_manager.py's own TCP/
    # SSL/WEBSOCKET extras, run alongside the main UDP/TCP instance). These
    # are never the same ports_dict keys as the main instance above, and
    # were never read here before - stored as "role:port,role:port,..." in
    # OPENVPN_EXTRAS. UDP has no 'extras' role (it's always the main
    # instance, handled above) so it never reaches this loop.
    _OVPN_EXTRA_ROLE = {
        "tcp": ("OPENVPN TCP", "openvpn", "OpenVPN TCP (extra profile)"),
        # real TLS termination (loads its own cert/key) - same detection as
        # Stunnel/SSTP: sslh just needs the ClientHello, decryption happens
        # inside the OpenVPN-SSL front script itself.
        "ssl": ("OPENVPN SSL", "tls", "OpenVPN SSL front"),
        # answers the client's HTTP "Upgrade: websocket" request - same
        # detection as WEBSOCKET/WS-EPRO.
        "ws": ("OPENVPN WEBSOCKET", "http", "OpenVPN WebSocket front"),
    }
    for entry in str(ports_dict.get('OPENVPN_EXTRAS', '')).split(','):
        role, _, port = entry.partition(':')
        role = role.strip().lower()
        if role in _OVPN_EXTRA_ROLE and port.strip().isdigit():
            label, cls, note = _OVPN_EXTRA_ROLE[role]
            add(label, port.strip(), cls, note)

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
        meta = {}
        # path of web-style transports (read from the Xray config, so nothing is typed by hand)
        wpath = None
        if net == "ws":
            wpath = (ss.get("wsSettings") or {}).get("path")
        elif net == "httpupgrade":
            wpath = (ss.get("httpupgradeSettings") or {}).get("path")
        elif net in ("xhttp", "splithttp"):
            wpath = (ss.get("xhttpSettings") or ss.get("splithttpSettings") or {}).get("path")
        if wpath and sec in ("tls", "none"):
            meta["web"] = {"path": wpath if wpath.startswith("/") else "/" + wpath, "net": net}
        if sec == "reality":
            names = [n for n in ((ss.get("realitySettings") or {}).get("serverNames") or []) if n and n != "*"]
            if names:
                meta["sni"] = names
        note = "%s/%s/%s" % (proto, net, sec)
        if meta.get("web"):
            note += "  path %s" % meta["web"]["path"]
        elif meta.get("sni"):
            note += "  SNI %s" % ",".join(meta["sni"])
        label = "XRAY %s/%s/%s" % (proto, net, sec)
        add(label, port, cls, note, meta=meta)

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
            "TLS termination + path routes for %s" % ng_state["domain"],
            meta={"sni": [ng_state["domain"]], "nginx": True})

    return cands


def _occupied_by_other(public_port, candidate_port):
    return candidate_port == public_port


# ------------------------------------------------------------ build + apply

def _needs_cfg(backends):
    """sslh's command line takes ONE backend per slot. As soon as a slot holds several
    (told apart by hostname or path) the config-file form is needed."""
    per = {}
    for b in backends:
        per[b["cls"]] = per.get(b["cls"], 0) + 1
        if b.get("sni") or b.get("paths"):
            return True
    return any(n > 1 for n in per.values())


def _cfg_file(public_port):
    return "%s/%s.sslh.cfg" % (BROKER_DIR, public_port)


def _q(text):
    return '"%s"' % str(text).replace("\\", "\\\\").replace('"', '\\"')


def _ordered_entries(backends):
    """Order matters in sslh: the first matching entry wins. Specific entries (a TLS hostname,
    an HTTP path) must come BEFORE the generic one of the same kind."""
    out = []
    for b in backends:
        if b["cls"] == "ssh":
            out.append(b)
    for b in backends:
        if b["cls"] == "openvpn":
            out.append(b)
    out += [b for b in backends if b["cls"] == "tls" and b.get("sni")]
    out += [b for b in backends if b["cls"] == "http" and b.get("paths")]
    out += [b for b in backends if b["cls"] == "http" and not b.get("paths")]
    out += [b for b in backends if b["cls"] == "tls" and not b.get("sni")]
    out += [b for b in backends if b["cls"] == "anyprot"]
    return out


def _build_cfg_text(public_port, backends):
    timeout = 5 if any(b["cls"] == "openvpn" for b in backends) else 2
    lines = ["foreground: true;", "numeric: true;", "timeout: %s;" % timeout,
             'listen: ( { host: "0.0.0.0"; port: "%s"; } );' % public_port, "protocols: ("]
    entries = _ordered_entries(backends)
    for i, b in enumerate(entries):
        host = _q(b.get("host", "127.0.0.1"))
        port = _q(b["port"])
        if b["cls"] == "tls" and b.get("sni"):
            body = '{ name: "tls"; host: %s; port: %s; sni_hostnames: [ %s ]; }' % (
                host, port, ", ".join(_q(n) for n in b["sni"]))
        elif b["cls"] == "http" and b.get("paths"):
            pats = ", ".join(_q("^[A-Z][A-Z]* %s[ ?/]" % pth.rstrip("/")) for pth in b["paths"])
            body = '{ name: "regex"; host: %s; port: %s; regex_patterns: [ %s ]; }' % (host, port, pats)
        else:
            body = '{ name: "%s"; host: %s; port: %s; }' % (b["cls"], host, port)
        lines.append("    " + body + ("," if i < len(entries) - 1 else ""))
    lines.append(");")
    return "\n".join(lines) + "\n"


def _build_exec(public_port, backends):
    """backends: list of {"cls","label","port","host", optional "sni"/"paths"}"""
    if _needs_cfg(backends):
        return "%s -f -F %s" % (_sslh_bin() or "/usr/sbin/sslh", _cfg_file(public_port))
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
    """Writes the unit (+ the sslh config file when needed), starts it, verifies the port really
    listens; on any failure restores the previous unit/config (or removes the new ones on a first
    attempt) so a bad choice never leaves a broken config behind."""
    path = _unit_path(public_port)
    cfgp = _cfg_file(public_port)
    original = None
    if os.path.exists(path):
        with open(path) as f:
            original = f.read()
    original_cfg = None
    if os.path.exists(cfgp):
        with open(cfgp) as f:
            original_cfg = f.read()
    os.makedirs(BROKER_DIR, exist_ok=True)
    if _needs_cfg(backends):
        with open(cfgp, "w") as f:
            f.write(_build_cfg_text(public_port, backends))
    with open(path, "w") as f:
        f.write(_unit_content(public_port, backends))
    _run("systemctl daemon-reload")
    _run("systemctl enable %s" % _unit_name(public_port))
    _run("systemctl reset-failed %s" % _unit_name(public_port))

    ok = _run("systemctl restart %s" % _unit_name(public_port)).returncode == 0 \
        and _wait_for_port_listening(public_port)
    if ok:
        if not _needs_cfg(backends) and original_cfg is not None:
            try:
                os.remove(cfgp)
            except FileNotFoundError:
                pass
        return True, "Port %s sharing applied and verified." % public_port

    if original is not None:
        with open(path, "w") as f:
            f.write(original)
        if original_cfg is not None:
            with open(cfgp, "w") as f:
                f.write(original_cfg)
        else:
            try:
                os.remove(cfgp)
            except FileNotFoundError:
                pass
        _run("systemctl daemon-reload")
        _run("systemctl restart %s" % _unit_name(public_port))
        return False, ("Port %s sharing failed to come up - reverted to the previous working setup. "
                       "Check 'journalctl -u %s'." % (public_port, _unit_name(public_port)))
    _run("systemctl stop %s" % _unit_name(public_port))
    _run("systemctl disable %s" % _unit_name(public_port))
    for pth in (path, cfgp):
        try:
            os.remove(pth)
        except FileNotFoundError:
            pass
    _run("systemctl daemon-reload")
    return False, ("Port %s sharing failed to come up - nothing was left installed. "
                   "Check 'journalctl -u %s'." % (public_port, _unit_name(public_port)))


# ----------------------------------------------------- decrypting front (one domain)

FRONT_DIR = "/etc/smartui-front"
FRONT_CFG = FRONT_DIR + "/haproxy.cfg"
FRONT_PEM = FRONT_DIR + "/domain.pem"
FRONT_UNIT = "smartui-front"
FRONT_UNIT_PATH = "/etc/systemd/system/smartui-front.service"
FRONT_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/smartui-front.sh"
FRONT_DEFAULT_PORT = 5445
FRONT_WAIT = "2s"


def _haproxy_bin():
    for name in ("haproxy",):
        found = shutil.which(name) or ("/usr/sbin/haproxy" if os.path.exists("/usr/sbin/haproxy") else None)
        if found:
            return found
    return None


def _ensure_haproxy():
    if _haproxy_bin():
        return True
    print("%s[i] Installing haproxy...%s" % (C_CYAN, C_RESET))
    _run("DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 update && "
         "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y haproxy")
    return _haproxy_bin() is not None


def _find_cert(domain):
    """(fullchain, privkey) for the domain from certbot, or None."""
    base = "/etc/letsencrypt/live/%s" % domain
    c, k = base + "/fullchain.pem", base + "/privkey.pem"
    if os.path.isfile(c) and os.path.isfile(k):
        return c, k
    try:
        import nginx_manager as ngm
        st = ngm._load_state()
        if st.get("domain") == domain and os.path.isfile(st.get("cert_path", "")) and os.path.isfile(st.get("key_path", "")):
            return st["cert_path"], st["key_path"]
    except Exception:
        pass
    return None


def _route_label(r):
    return "%s -> %s :%s%s" % (r.get("path") or r["kind"], r["label"], r["port"], " (TLS)" if r.get("tls") else "")


def _front_cfg_text(front):
    """HAProxy config for the decrypting front. front: {domain, port, ssh_port, sstp_port,
    http_default:{port}, routes:[{path,port,tls,label}]}"""
    d = front["domain"]
    L = ["global", "    maxconn 8192", "",
         "defaults", "    mode tcp", "    timeout connect 5s", "    timeout client 12h",
         "    timeout server 12h", "    timeout tunnel 12h", "",
         "frontend smartui_front",
         "    bind 127.0.0.1:%s ssl crt %s ssl-min-ver TLSv1.0" % (front["port"], FRONT_PEM),
         "    mode tcp",
         "    tcp-request inspect-delay %s" % FRONT_WAIT,
         # decide at once when the first bytes are already there; otherwise wait (SSH clients send nothing first)
         "    tcp-request content accept if { req.len gt 3 }",
         "    tcp-request content accept if WAIT_END"]
    if front.get("sstp_port"):
        # "SSTP_DUPLEX_POST" as hex: exact match on the first 16 bytes
        L.append("    acl is_sstp req.payload(0,16) -m bin 535354505f4455504c45585f504f5354")
    # two lines with the same name = either one matches
    L.append("    acl is_http req.proto_http")
    # length 0 = "whatever has arrived": a fixed length (e.g. 200) makes HAProxy wait for that many
    # bytes and a short WebSocket request would never match
    L.append("    acl is_http req.payload(0,0) -m reg ^[A-Z]+[[:space:]]")
    for i, r in enumerate(front["routes"]):
        L.append("    acl path_%d req.payload(0,0) -m reg ^[A-Z]+[[:space:]]+%s([[:space:]?/])"
                 % (i, r["path"].rstrip("/")))
    if front.get("sstp_port"):
        L.append("    use_backend be_sstp if is_sstp")
    for i, r in enumerate(front["routes"]):
        L.append("    use_backend be_route_%d if path_%d" % (i, i))
    if front.get("http_default"):
        L.append("    use_backend be_http if is_http")
    L.append("    default_backend be_ssh")
    L.append("")
    L += ["backend be_ssh", "    server ssh 127.0.0.1:%s" % front["ssh_port"], ""]
    if front.get("sstp_port"):
        L += ["backend be_sstp", "    server sstp 127.0.0.1:%s ssl verify none sni str(%s)" % (front["sstp_port"], d), ""]
    for i, r in enumerate(front["routes"]):
        if r.get("tls"):
            L += ["backend be_route_%d" % i, "    server r%d 127.0.0.1:%s ssl verify none sni str(%s)" % (i, r["port"], d), ""]
        else:
            L += ["backend be_route_%d" % i, "    server r%d 127.0.0.1:%s" % (i, r["port"]), ""]
    if front.get("http_default"):
        L += ["backend be_http", "    server http 127.0.0.1:%s" % front["http_default"]["port"], ""]
    return "\n".join(L)


def _front_unit_text(cert, key):
    hb = _haproxy_bin() or "/usr/sbin/haproxy"
    return """[Unit]
Description=SmartUI one-domain TLS front (HAProxy) for port sharing
After=network.target

[Service]
Type=simple
User=root
ExecStartPre=/bin/sh -c 'cat "%s" "%s" > %s && chmod 600 %s'
ExecStartPre=%s -c -q -f %s
ExecStart=%s -f %s -db
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (cert, key, FRONT_PEM, FRONT_PEM, hb, FRONT_CFG, hb, FRONT_CFG)


def _front_active():
    return _run(["systemctl", "is-active", "--quiet", FRONT_UNIT]).returncode == 0


def _apply_front(front, cert, key):
    """Writes config + unit, checks the config, starts it, verifies it listens. Restores the previous
    front (or removes it) on any failure. Returns (ok, message)."""
    os.makedirs(FRONT_DIR, exist_ok=True)
    old = {}
    for pth in (FRONT_CFG, FRONT_UNIT_PATH):
        if os.path.exists(pth):
            with open(pth) as f:
                old[pth] = f.read()
    with open(FRONT_CFG, "w") as f:
        f.write(_front_cfg_text(front))
    # build the PEM now so the syntax check below can load it
    _run('cat "%s" "%s" > %s && chmod 600 %s' % (cert, key, FRONT_PEM, FRONT_PEM))
    chk = _run([_haproxy_bin() or "haproxy", "-c", "-q", "-f", FRONT_CFG])
    if chk.returncode != 0:
        _front_restore(old)
        err = (getattr(chk, "stderr", "") or getattr(chk, "stdout", "") or "").strip()
        return False, "HAProxy rejected the front config%s" % ((": " + err[:300]) if err else "")
    with open(FRONT_UNIT_PATH, "w") as f:
        f.write(_front_unit_text(cert, key))
    _run("systemctl daemon-reload")
    _run("systemctl enable %s" % FRONT_UNIT)
    _run("systemctl reset-failed %s" % FRONT_UNIT)
    if _run("systemctl restart %s" % FRONT_UNIT).returncode == 0 and _wait_for_port_listening(front["port"]):
        try:
            if os.path.isdir(os.path.dirname(FRONT_HOOK)):
                with open(FRONT_HOOK, "w") as f:
                    f.write("#!/bin/sh\nsystemctl restart %s\n" % FRONT_UNIT)
                os.chmod(FRONT_HOOK, 0o755)
        except Exception:
            pass
        return True, "One-domain front is running on 127.0.0.1:%s." % front["port"]
    _front_restore(old)
    return False, "The front did not start - check 'journalctl -u %s'." % FRONT_UNIT


def _front_restore(old):
    for pth in (FRONT_CFG, FRONT_UNIT_PATH):
        if pth in old:
            with open(pth, "w") as f:
                f.write(old[pth])
        else:
            try:
                os.remove(pth)
            except FileNotFoundError:
                pass
    _run("systemctl daemon-reload")
    if FRONT_UNIT_PATH in old:
        _run("systemctl restart %s" % FRONT_UNIT)
    else:
        _run("systemctl stop %s" % FRONT_UNIT)
        _run("systemctl disable %s" % FRONT_UNIT)


def _remove_front():
    _run("systemctl stop %s" % FRONT_UNIT)
    _run("systemctl disable %s" % FRONT_UNIT)
    for pth in (FRONT_UNIT_PATH, FRONT_CFG, FRONT_PEM, FRONT_HOOK):
        try:
            os.remove(pth)
        except FileNotFoundError:
            pass
    _run("systemctl daemon-reload")


def _sstp_cert_note(cert):
    """SSTP checks that the certificate it sends matches the one the client saw (crypto binding).
    Behind the front the client sees the DOMAIN certificate, so SSTP must use that same one."""
    try:
        import vpn_common as vc
        import sstp_manager as sm
        meta = sm._load_meta()
        if os.path.realpath(meta.get("cert_file", "")) == os.path.realpath(cert):
            return None
        return meta.get("cert_file", "?")
    except Exception:
        return "?"


def _free_front_port():
    port = FRONT_DEFAULT_PORT
    cfg_port = None
    if os.path.exists(FRONT_CFG):
        try:
            m = re.search(r'bind 127\.0\.0\.1:(\d+)', open(FRONT_CFG).read())
            cfg_port = int(m.group(1)) if m else None
        except Exception:
            pass
    if cfg_port:
        return cfg_port
    while check_system_port_in_use(port, ("tcp",)):
        port += 1
    return port


def _stunnel_target(accept_port):
    """Port that Stunnel forwards its decrypted traffic to (from its own config), or None."""
    for conf in ("/etc/stunnel/stunnel.conf",):
        try:
            txt = open(conf).read()
        except Exception:
            continue
        m = re.search(r'accept\s*=\s*%s\s*\n\s*connect\s*=\s*(?:[\w.]+:)?(\d+)' % int(accept_port), txt)
        if m:
            return int(m.group(1))
    return None


def _plan_front(ports_dict, group, http_plan, ssh_plan):
    """Offers and builds the one-domain front. Returns (backend dict or None, remaining group)."""
    web = [b for b in group if (b.get("meta") or {}).get("web")]
    sstp = [b for b in group if b["label"].startswith("SSTP")]
    absorbed = [b for b in group if b["label"].startswith("STUNNEL") or (b.get("meta") or {}).get("nginx")]
    if len(group) < 2 or not (web or sstp):
        return None, group
    print("\n%sONE DOMAIN FOR EVERYTHING%s" % (C_BOLD, C_RESET))
    print(" Stunnel, SSTP and Xray TLS cannot be told apart on the same hostname by passthrough.")
    print(" The front decrypts TLS on the server with your domain's certificate, then routes by")
    print(" what is inside: SSTP / URL path / SSH. Everything keeps working on ONE domain.")
    ans = input(" Build it? [Y/n]: ").strip().lower()
    if ans == "n":
        return None, group

    domain = ""
    try:
        import nginx_manager as ngm
        domain = ngm._load_state().get("domain", "")
    except Exception:
        pass
    domain = (input(" Your domain [%s]: " % domain).strip().lower() or domain) if domain else input(" Your domain: ").strip().lower()
    if not domain or not _HOST_RE.match(domain):
        print("%s[X] Invalid domain - front not built.%s" % (C_RED, C_RESET))
        return None, group
    cert = _find_cert(domain)
    if not cert:
        print("%s[X] No certificate found for %s in /etc/letsencrypt/live (get one with Nginx or Xray's"
              " certificate option first). Front not built.%s" % (C_RED, domain, C_RESET))
        return None, group

    # where "SSH over TLS" (what Stunnel carried) goes
    ssh_choices = [b for b in ssh_plan]
    ssh_port = None
    pref = next((b for b in ssh_choices if b["label"].startswith("DROPBEAR")), ssh_choices[0] if ssh_choices else None)
    if pref:
        ssh_port = pref["port"]
    else:
        drop = _split_ports(ports_dict.get('DROPBEAR_PORTS'))
        ssh_port = drop[0] if drop else _ssh_live_port(ports_dict)
    raw = input(" Port that SSH-over-TLS clients should reach [%s]: " % ssh_port).strip()
    if raw.isdigit():
        ssh_port = int(raw)

    routes = []
    for b in web:
        routes.append({"path": b["meta"]["web"]["path"], "port": b["port"], "tls": True, "label": b["label"], "kind": "route"})
    for b in http_plan:
        for pth in b.get("paths", []):
            routes.append({"path": pth, "port": b["port"], "tls": False, "label": b["label"], "kind": "route"})
    http_default = next((b for b in http_plan if b.get("default")), None)
    if not http_default:
        # Stunnel forwarded EVERYTHING (SSL + payload clients too) to one local port. Keep that behaviour
        # for HTTP-looking traffic that matches no path.
        for st in [b for b in group if b["label"].startswith("STUNNEL")]:
            tgt = _stunnel_target(st["port"])
            if tgt and tgt != ssh_port:
                http_default = {"port": tgt, "label": "STUNNEL target"}
                print("%s[i] Stunnel forwards to :%s - the front sends HTTP/payload traffic that matches no path"
                      " there too.%s" % (C_CYAN, tgt, C_RESET))
                break
    front = {"domain": domain, "port": _free_front_port(), "ssh_port": ssh_port,
             "sstp_port": sstp[0]["port"] if sstp else None,
             "routes": routes, "http_default": {"port": http_default["port"], "label": http_default["label"]} if http_default else None}

    if not _ensure_haproxy():
        print("%s[X] haproxy is not available - front not built.%s" % (C_RED, C_RESET))
        return None, group
    ok, msg = _apply_front(front, cert[0], cert[1])
    if not ok:
        print("%s[X] %s%s" % (C_RED, msg, C_RESET))
        return None, group
    print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))

    if sstp:
        other = _sstp_cert_note(cert[0])
        if other:
            print("\n%s[!] SSTP must use the SAME certificate as the domain, otherwise Windows rejects the"
                  " connection\n    (crypto binding). It currently uses: %s" % (C_YELLOW, other))
            print("    Fix: SSTP menu > use your own certificate, with:")
            print("      cert: %s\n      key : %s%s" % (cert[0], cert[1], C_RESET))

    children = ["SSH over TLS (no data in 2s) -> :%s" % ssh_port]
    if front["sstp_port"]:
        children.append("SSTP (SSTP_DUPLEX_POST) -> :%s (TLS)" % front["sstp_port"])
    for r in routes:
        children.append("https://%s%s -> %s :%s%s" % (domain, r["path"], r["label"], r["port"], " (TLS)" if r["tls"] else ""))
    if http_default:
        children.append("other HTTP/WebSocket -> %s :%s" % (http_default["label"], http_default["port"]))
    if absorbed:
        children.append("covers: " + ", ".join(b["label"] for b in absorbed))
    backend = {"cls": "tls", "label": "ONE-DOMAIN FRONT (%s)" % domain, "port": front["port"], "host": "127.0.0.1",
               "default": True, "children": children, "front": front}
    rest = [b for b in group if b not in web and b not in sstp and b not in absorbed]
    return backend, rest


# ------------------------------------------------------------------ wizard

def _print_candidates(public_port, cands, marked=()):
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
        star = "*" if (c["label"], c["port"]) in marked or (c["label"] == "SSH" and ("SSH", None) in marked) else " "
        print(" [%d]%s%s%-22s %-7s %-10s %s" % (i, " " * (3 - len(str(i))), star, c["label"], c["port"], c["cls"], status))
        if c["note"]:
            print("      %s%s%s" % (C_CYAN, c["note"], C_RESET))
    print("----------------------------------------------------------------")
    print(" [*] = already shared on this port (kept when you add more)")
    print(" [M] Add a custom TCP backend by hand")
    print(" ssh / openvpn / anyprot: one backend each.  tls: told apart by hostname (+1 default).")
    print(" http: told apart by URL path (+1 default).  Xray ws/xhttp paths are read automatically.")
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))


_HOST_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$')
_PATH_RE = re.compile(r'^/[A-Za-z0-9/_.-]*$')


def _nginx_info():
    """Nginx path proxy in chained mode (listening on an internal port) -> dict, else None."""
    try:
        import nginx_manager as ngm
        st = ngm._load_state()
    except Exception:
        return None
    if not st.get("domain") or not st.get("cert_path"):
        return None
    lp = st.get("listen_port", 443)
    if lp in (443, 80):
        return None
    return {"domain": st["domain"], "port": int(lp), "state": st}


def _nginx_change_routes(info, add=None, remove=None):
    """Adds / removes Nginx path routes in one verified step (Nginx's own safe-apply rolls back
    on failure). Returns (ok, message)."""
    import nginx_manager as ngm
    st = info["state"]
    registry = dict(ngm._load_registry())
    for pth in (remove or []):
        registry.pop(pth, None)
    for pth, target in (add or {}).items():
        registry[pth] = target
    ok, msg = ngm._apply_safely(st["domain"], st.get("cert_path"), st.get("key_path"), registry,
                                st.get("decoy_url", ngm.DEFAULT_DECOY), "Port sharing routes",
                                st.get("listen_port", 443))
    if ok:
        ngm._save_registry(registry)
    return ok, msg


def _ask_choice(title, group, allow_none=True, suggest=None):
    print("\n%s%s%s" % (C_YELLOW, title, C_RESET))
    for i, b in enumerate(group, 1):
        mark = "  (suggested)" if suggest is not None and b is suggest else ""
        print("   [%d] %s (port %s)%s" % (i, b["label"], b["port"], mark))
    if allow_none:
        print("   [0] none of them")
    sel = input(" Choose: ").strip()
    if sel.isdigit() and 1 <= int(sel) <= len(group):
        return group[int(sel) - 1]
    return None


def _plan_tls(public_port, group, nginx_routes_added, http_plan=None, ssh_plan=None, ports_dict=None):
    """TLS services -> sslh TLS entries. Returns the backend list (with sni / default)."""
    if not group:
        return []
    result = []
    front_backend = None
    if public_port == 443:
        front_backend, group = _plan_front(ports_dict or {}, group, http_plan or [], ssh_plan or [])
        if front_backend:
            result.append(front_backend)
    web = [b for b in group if (b.get("meta") or {}).get("web")]
    rest = [b for b in group if b not in web]
    explicit_nginx = [b for b in rest if (b.get("meta") or {}).get("nginx")]
    rest = [b for b in rest if b not in explicit_nginx]

    if web or explicit_nginx:
        info = _nginx_info()
        if not info:
            if web:
                print("\n%s[!] %d Xray TLS service(s) use WebSocket/HTTP-style transports and can share one"
                      % (C_YELLOW, len(web)))
                print("    domain by PATH, but Nginx (path proxy) is not set up in chained mode yet:%s" % C_RESET)
                for b in web:
                    print("      - %s port %s (%s)" % (b["label"], b["port"], b["meta"]["web"]["path"]))
                print("    Set it up first: Protocol Manager > NGINX (PROXY) > option 1, choose to chain it behind")
                print("    port sharing (internal port such as 5443). Then run this again. Skipped for now.")
            for b in explicit_nginx:
                print("%s[X] %s is not fully set up yet (needs a domain + certificate). Skipped.%s" % (C_RED, b["label"], C_RESET))
        else:
            ng = {"cls": "tls", "label": "NGINX (path proxy)", "port": info["port"], "host": "127.0.0.1",
                  "sni": [info["domain"]], "children": []}
            routes = {}
            for w in web:
                pth = w["meta"]["web"]["path"]
                routes[pth] = "https:%s" % w["port"]
            if routes:
                print("\n%s[i] Adding %d path route(s) to Nginx (%s) - each Xray TLS inbound keeps its own port"
                      % (C_CYAN, len(routes), info["domain"]))
                print("    and certificate; Nginx only forwards by path.%s" % C_RESET)
                ok, msg = _nginx_change_routes(info, add=routes)
                if ok:
                    nginx_routes_added.extend(routes.keys())
                    for w in web:
                        ng["children"].append("%s  https://%s%s" % (w["label"], info["domain"], w["meta"]["web"]["path"]))
                else:
                    print("%s[X] Nginx did not accept the routes: %s%s" % (C_RED, msg, C_RESET))
            result.append(ng)
            if not routes:
                pass

    # remaining TLS services: hostname (SNI) or the single default
    named = []
    for b in rest:
        names = (b.get("meta") or {}).get("sni") or []
        if names:
            b["sni"] = list(names)
            print("%s[i] %s uses its own server name(s): %s%s" % (C_CYAN, b["label"], ", ".join(names), C_RESET))
            named.append(b)
    needs = [b for b in rest if not b.get("sni")]
    used_names = set(n for r in result for n in (r.get("sni") or [])) | set(n for b in named for n in b["sni"])

    default = None
    if needs and front_backend:
        print("\n%sThe one-domain front is the default TLS backend, so each remaining TLS service needs its own"
              " hostname.%s" % (C_YELLOW, C_RESET))
        for b in needs:
            raw = input(" Hostname(s) clients use for %s (comma separated, blank = skip it): " % b["label"]).strip()
            names = [n.strip().lower() for n in raw.split(",") if n.strip()]
            good = [n for n in names if _HOST_RE.match(n) and n not in used_names and n != front_backend["front"]["domain"]]
            if good:
                b["sni"] = good
                used_names.update(good)
                named.append(b)
            else:
                print("%s[!] %s skipped (no usable hostname).%s" % (C_YELLOW, b["label"], C_RESET))
    elif needs:
        print("\n%sTLS services that share this port must be told apart. Exactly ONE of them can be the"
              " default" % C_YELLOW)
        print("(it receives every TLS connection whose hostname matches nothing else - give it the one whose"
              " clients\nuse spoofed/unknown SNI, usually STUNNEL). Every other one needs its own hostname.%s" % C_RESET)
        suggest = next((b for b in needs if b["label"].startswith("STUNNEL")), needs[0])
        if len(needs) == 1:
            ans = input(" Use %s as the default TLS backend? [Y/n]: " % needs[0]["label"]).strip().lower()
            default = needs[0] if ans != "n" else None
        else:
            default = _ask_choice("Which one is the DEFAULT TLS backend?", needs, suggest=suggest)
        for b in needs:
            if b is default:
                b["default"] = True
                continue
            raw = input(" Hostname(s) clients use for %s (comma separated, blank = skip it): " % b["label"]).strip()
            names = [n.strip().lower() for n in raw.split(",") if n.strip()]
            good = [n for n in names if _HOST_RE.match(n) and n not in used_names]
            if names and len(good) != len(names):
                print("%s[!] Ignored invalid or already-used names.%s" % (C_YELLOW, C_RESET))
            if good:
                b["sni"] = good
                used_names.update(good)
                named.append(b)
            else:
                print("%s[!] %s skipped (no hostname given).%s" % (C_YELLOW, b["label"], C_RESET))
    result += named
    if default:
        result.append(default)
    return result


def _plan_http(public_port, group):
    """Plain HTTP / WebSocket services -> path-matched entries + one default."""
    if not group:
        return []
    result = []
    rest = []
    for b in group:
        web = (b.get("meta") or {}).get("web")
        if web:
            b["paths"] = [web["path"]]
            result.append(b)
        else:
            rest.append(b)
    if rest:
        print("\n%sPlain HTTP / WebSocket services are told apart by the URL path in the first request."
              % C_YELLOW)
        print("Exactly ONE can be the default (every other request goes to it).%s" % C_RESET)
        suggest = next((b for b in rest if b["label"].startswith("PYTHON SOCKS")), rest[0])
        default = rest[0] if len(rest) == 1 else _ask_choice("Which one is the DEFAULT HTTP backend?", rest, suggest=suggest)
        used = set(pth for r in result for pth in r.get("paths", []))
        for b in rest:
            if b is default:
                b["default"] = True
                result.append(b)
                continue
            raw = input(" URL path clients send for %s (e.g. /ws-epro, blank = skip it): " % b["label"]).strip()
            if raw and not raw.startswith("/"):
                raw = "/" + raw
            if raw and _PATH_RE.match(raw) and raw not in used:
                b["paths"] = [raw]
                used.add(raw)
                result.append(b)
            elif raw:
                print("%s[!] Invalid or already-used path - %s skipped.%s" % (C_YELLOW, b["label"], C_RESET))
            else:
                print("%s[!] %s skipped.%s" % (C_YELLOW, b["label"], C_RESET))
    return result


def _resolve_selection(public_port, picked, ports_dict, nginx_routes_added=None):
    """picked: candidate dicts. Returns list of backend dicts. Handles relocation of SSH off the
    shared port, the one-backend rule for ssh/openvpn/catch-all, and the multi-backend planning for
    the TLS and HTTP slots."""
    if nginx_routes_added is None:
        nginx_routes_added = []
    chosen = []
    for c in picked:
        b = {"cls": c["cls"], "label": c["label"], "port": c["port"], "host": c.get("host", "127.0.0.1"),
             "note": c.get("note", ""), "meta": c.get("meta", {})}
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

    final = []
    for cls in ("ssh", "openvpn", "anyprot"):
        group = [b for b in chosen if b["cls"] == cls]
        if not group:
            continue
        if len(group) == 1:
            final.append(group[0])
            continue
        print("\n%s[!] %d services were picked for the '%s' slot (%s) - sslh can send that kind of"
              % (C_YELLOW, len(group), cls, CLASS_TITLE[cls]))
        print("    traffic to only ONE backend.%s" % C_RESET)
        pick = _ask_choice("Which one should get it?", group)
        if pick:
            final.append(pick)

    http_plan = _plan_http(public_port, [b for b in chosen if b["cls"] == "http"])
    ssh_plan = [b for b in final if b["cls"] == "ssh"]
    final += _plan_tls(public_port, [b for b in chosen if b["cls"] == "tls"], nginx_routes_added,
                       http_plan, ssh_plan, ports_dict)
    final += http_plan
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


def _clean_backend(b):
    out = {"cls": b["cls"], "label": b["label"], "port": b["port"], "host": b.get("host", "127.0.0.1")}
    for k in ("sni", "paths", "default", "children", "front"):
        if b.get(k):
            out[k] = b[k]
    return out


def _qualifier(b):
    if b.get("sni"):
        return "hostname " + ", ".join(b["sni"])
    if b.get("paths"):
        return "path " + ", ".join(b["paths"])
    if b.get("default"):
        return "default " + b["cls"].upper()
    return b["cls"]


def _summary_lines(cfg):
    """One line per assigned protocol (plus the routes behind Nginx), for every screen that lists them."""
    lines = []
    for b in cfg.get("backends", []):
        lines.append("%-22s :%-6s %s" % (b["label"], b["port"], _qualifier(b)))
        for ch in b.get("children", []):
            lines.append("    + %s" % ch)
    return lines


def _configure_port(public_port, ports_dict):
    clear_screen()
    cands = _discover_candidates(ports_dict)
    manual = []
    existing = _load_cfg(public_port)

    # What is already shared stays selected: new numbers are ADDED to it, so assigning Stunnel
    # and then VLESS ends with both. "R" starts over from nothing.
    prev = set()
    for sel in (existing or {}).get("selected", []):
        prev.add((sel["label"], int(sel["port"])) if sel.get("label") != "SSH" else ("SSH", None))
    if existing and not (existing or {}).get("selected"):
        for b in existing.get("backends", []):
            if not b.get("front") and not b["label"].startswith("NGINX"):
                prev.add((b["label"], int(b["port"])) if b["label"] != "SSH" else ("SSH", None))

    while True:
        clear_screen()
        _print_candidates(public_port, cands + manual, prev)
        if existing:
            print(" Currently shared on %s:" % public_port)
            for line in _summary_lines(existing) or ["none"]:
                print("   " + line)
            print(" (new picks are ADDED to it - enter R to start over)")
        raw = input(" Enter numbers to ADD (e.g. 1,3,4), A = all eligible, R = start over, M = custom, 0 = cancel: ").strip().lower()
        if raw in ("0", ""):
            return
        if raw == "r":
            prev = set()
            existing = dict(existing or {}, backends=[], selected=[])
            continue
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
        # keep what was already shared
        keep = [c for c in everything if ((c["label"], c["port"]) in prev or (c["label"] == "SSH" and ("SSH", None) in prev))
                and c not in picked and c["port"] != public_port]
        if prev and keep:
            print("%s[i] Keeping already-shared: %s%s" % (C_CYAN, ", ".join("%s:%s" % (c["label"], c["port"]) for c in keep), C_RESET))
        picked = picked + keep
        if not picked:
            print("%s[X] Nothing valid selected.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
            continue
        break

    # routes this wizard added to Nginx earlier for this port are dropped first (the new
    # selection re-adds whatever is still wanted), so nothing stale is left behind
    old_routes = (existing or {}).get("nginx_routes", [])
    if old_routes:
        info0 = _nginx_info()
        if info0:
            _nginx_change_routes(info0, remove=old_routes)
    nginx_routes_added = []
    backends = _resolve_selection(public_port, picked, ports_dict, nginx_routes_added)
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
        _save_cfg(public_port, {"backends": [_clean_backend(b) for b in backends],
                                "nginx_routes": nginx_routes_added,
                                "selected": [{"label": c["label"], "port": c["port"]} for c in picked]})
        _sync_ports_dict(ports_dict)
        print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
        for line in _summary_lines({"backends": [_clean_backend(b) for b in backends]}):
            print("   " + line)
    else:
        if not _load_cfg(public_port):
            close_firewall_port(public_port, ("tcp",))
            persist_firewall_rules()
        print("%s[X] %s%s" % (C_RED, msg, C_RESET))
    input("\nPress Enter to continue...")


def _remove_port(public_port, ports_dict):
    if any(b.get("front") for b in (_load_cfg(public_port) or {}).get("backends", [])):
        _remove_front()
    old = (_load_cfg(public_port) or {}).get("nginx_routes", [])
    if old:
        info = _nginx_info()
        if info:
            _nginx_change_routes(info, remove=old)
    _run("systemctl stop %s" % _unit_name(public_port))
    _run("systemctl disable %s" % _unit_name(public_port))
    for path in (_unit_path(public_port), _cfg_path(public_port), _cfg_file(public_port)):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    _run("systemctl daemon-reload")
    close_firewall_port(public_port, ("tcp",))
    persist_firewall_rules()
    _sync_ports_dict(ports_dict)


# ---------------------------------------------------------------- self-test

def _tls_probe(host, port, sni, send=None, wait=3.0):
    """Opens a TLS connection (certificate not verified), optionally sends bytes, returns
    (connected, first_bytes_or_empty, error_text)."""
    import socket
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except Exception:
        pass
    raw = None
    try:
        raw = socket.create_connection((host, port), timeout=5)
        tls = ctx.wrap_socket(raw, server_hostname=sni)
    except Exception as e:
        if raw:
            try:
                raw.close()
            except Exception:
                pass
        return False, b"", "%s" % e
    data = b""
    try:
        if send:
            tls.sendall(send)
        tls.settimeout(wait)
        data = tls.recv(512)
    except Exception:
        pass
    try:
        tls.close()
    except Exception:
        pass
    return True, data, ""


def _line(data):
    txt = data.split(b"\r\n", 1)[0][:70] if data else b""
    return txt.decode("latin-1", "replace") or "(nothing within the wait)"


def _selftest(ports_dict):
    clear_screen()
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("%s                 PORT SHARING SELF-TEST                       %s" % (C_BOLD, C_RESET))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    cfg = _load_cfg(443) or {}
    front = next((b.get("front") for b in cfg.get("backends", []) if b.get("front")), None)
    ok_c, bad_c = C_GREEN + "[PASS]" + C_RESET, C_RED + "[FAIL]" + C_RESET

    print(" sslh on 443      : %s" % (ok_c if _unit_active(443) and check_system_port_in_use(443, ("tcp",)) else bad_c))
    if not front:
        print(" No one-domain front is configured on 443 - nothing more to test here.")
        return
    domain = front["domain"]
    print(" front service    : %s" % (ok_c if _front_active() else bad_c + "  (journalctl -u %s -n 30)" % FRONT_UNIT))
    print(" front listening  : %s  (127.0.0.1:%s)" % (ok_c if check_system_port_in_use(front["port"], ("tcp",)) else bad_c, front["port"]))
    chk = _run([_haproxy_bin() or "haproxy", "-c", "-q", "-f", FRONT_CFG])
    print(" front config     : %s" % (ok_c if chk.returncode == 0 else bad_c))
    cert = _find_cert(domain)
    if cert:
        end = _run(["openssl", "x509", "-in", cert[0], "-noout", "-enddate"])
        print(" certificate      : %s" % ((getattr(end, "stdout", "") or "").strip() or cert[0]))
    else:
        print(" certificate      : %s no certificate for %s in /etc/letsencrypt/live" % (bad_c, domain))

    targets = [("front direct 127.0.0.1:%s" % front["port"], front["port"]), ("public path via sslh 127.0.0.1:443", 443)]
    ws_req = ("GET %s HTTP/1.1\r\nHost: " + domain + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
    for title, port in targets:
        print("\n --- %s ---" % title)
        okc, data, err = _tls_probe("127.0.0.1", port, domain, None, 3.5)
        if not okc:
            print("   TLS handshake    : %s %s" % (bad_c, err[:90]))
            continue
        print("   TLS handshake    : %s" % ok_c)
        print("   SSH over TLS     : %s  got: %s" % (ok_c if data.startswith(b"SSH-") else bad_c, _line(data)))
        okc, data, err = _tls_probe("127.0.0.1", port, domain,
                                    ("GET / HTTP/1.1\r\nHost: " + domain + "\r\nUpgrade: websocket\r\n\r\n").encode(), 3.5)
        print("   payload GET /    : answered by the default HTTP backend -> %s" % _line(data))
        for r in front.get("routes", []):
            okc, data, err = _tls_probe("127.0.0.1", port, domain, (ws_req % r["path"]).encode(), 4.0)
            good = data.startswith(b"HTTP/1.1 101") or data.startswith(b"HTTP/1.1 4") or data.startswith(b"HTTP/1.0")
            print("   %-16s : %s  got: %s" % (r["path"], ok_c if good and not data.startswith(b"SSH-") else bad_c, _line(data)))
    print("\n Reading the result: a path that answers 'SSH-2.0...' went to SSH instead of its Xray inbound")
    print(" (the front's path match did not fire); 'nothing within the wait' means the backend did not answer.")


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
            print("      PORT %-4s [%s]" % (p, tag))
            for line in _summary_lines(cfg) or ["none"]:
                print("         " + line)
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
        print(" [9]> SELF-TEST (check every route end to end)")
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
                for line in _summary_lines(cfg):
                    print("   " + line)
                print("   command: %s" % _build_exec(p, cfg.get("backends", [])))
                if os.path.exists(_cfg_file(p)):
                    print("   sslh config (%s):" % _cfg_file(p))
                    with open(_cfg_file(p)) as f:
                        for ln in f.read().splitlines():
                            print("      " + ln)
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

        elif choice == '9':
            _selftest(ports_dict)
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
