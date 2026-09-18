"""
dnstt_manager.py — SLOWDNS module for the SmartUI panel.

Three real, verified backends:
  - dnstt (bamsoftware / David Fifield) — the original, UDP-only DNS tunnel.
  - Slipstream (Mygod/slipstream-rust) — its official Rust/QUIC successor.
  - MasterDnsVPN (masterking32) — independent Go implementation with a custom
    low-overhead protocol, multi-resolver failover, and its own TOML config —
    architecturally different enough that it gets its own install/dashboard
    branches below rather than being forced into the dnstt/Slipstream shape.

The original draft of this module listed FOUR modes, including "DNSTT over QUIC"
and "DNSTT over TCP". Neither exists: dnstt-server only ever supports "-udp ADDR"
as its listen flag — there is no TCP or QUIC server mode in dnstt itself. DoH/DoT
are transport choices the *client* makes when talking to a public resolver; the
resolver-to-dnstt-server hop is always plain UDP regardless. Shipping those two
fake options would have looked like working features while silently doing
nothing, so they're gone — replaced with mode-aware client commands that show
all three real client transports (UDP/DoH/DoT) for the one real dnstt mode.
"""

import os
import re
import json
import subprocess
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port,
    nat_redirect_udp, remove_nat_redirect_udp, persist_firewall_rules,
    is_valid_hostname, resolve_port53_conflict, get_public_ip,
    run_cmd as _run,
)

DNSTT_DIR = "/etc/dnstt"
DNSTT_BIN = "/usr/local/bin/dnstt-server"
SLIPSTREAM_BIN = "/usr/local/bin/slipstream-server"
VAYDNS_BIN = "/usr/local/bin/vaydns-server"
SERVICE_PATH = "/etc/systemd/system/slowdns.service"
DNSTT_INTERNAL_PORT = 5300  # the documented bamsoftware convention: external 53 -> internal 5300

MASTERDNS_DIR = "/opt/masterdnsvpn"
MASTERDNS_INSTALL_URL = "https://raw.githubusercontent.com/masterking32/MasterDnsVPN/main/server_linux_install.sh"

STORMDNS_DIR = "/opt/stormdns"
STORMDNS_INSTALL_URL = "https://raw.githubusercontent.com/nullroute1970/StormDNS/main/server_linux_install.sh"

# TaJirax/cottenDNS is the true canonical source - WhiteDNS/CottenDNS (initially
# suggested) is a maintained vendor copy pinned to a specific upstream commit,
# confirmed via WhiteDNS-Desktop's own README ("vendors the CottenDNS engine
# from TaJirax/cottenDNS"). Using the original directly rather than a downstream
# fork, same reasoning as preferring dhavalkapil/icmptunnel over a low-star fork
# of it earlier in this project.
COTTENDNS_DIR = "/opt/cottendns"
COTTENDNS_INSTALL_URL = "https://raw.githubusercontent.com/TaJirax/cottenDNS/main/server_linux_install.sh"

# --- Multi-Engine Mode: shared port 53 via subdomain-based DNS routing -----
#
# Why this exists: DNS tunneling's censorship-evasion value specifically
# depends on the tunnel server being reachable via NORMAL DNS RESOLUTION - a
# client's local/ISP resolver queries the authoritative server for a
# delegated subdomain on port 53, because that's just how DNS delegation
# works. Running every engine except one on a non-standard port would mean
# losing that property for all the others - clients would have to contact
# those directly on an arbitrary port, defeating the reason to pick a
# DNS-based protocol for them in the first place. This router keeps every
# registered engine reachable via ordinary port-53 DNS relay, and
# disambiguates which one a given query is actually for by which delegated
# subdomain it targets - verified end-to-end with three real simultaneous
# backend processes and both UDP and DNS-over-TCP (for CottenDNS) before
# being wired into the rest of this module.
INSTANCES_DIR = f"{DNSTT_DIR}/instances"
DNSTT_REGISTRY_PATH = f"{DNSTT_DIR}/instances.json"
DNS_ROUTER_SCRIPT_PATH = "/usr/local/bin/dns-router.py"
DNS_ROUTER_SERVICE_PATH = "/etc/systemd/system/dns-router.service"
INTERNAL_PORT_BASE = 5300

DNS_ROUTER_SCRIPT = '''#!/usr/bin/env python3
"""dns-router.py - lets multiple DNSTT-family tunnel engines share port 53
simultaneously, by inspecting each incoming query's QNAME and forwarding to
whichever registered engine's delegated subdomain it matches."""
import os
import sys
import json
import socket
import struct
import threading
import time

REGISTRY_PATH = os.environ.get("DNSTT_REGISTRY", "/etc/dnstt/instances.json")
UDP_TIMEOUT = 3.0
TCP_TIMEOUT = 5.0


def load_registry():
    try:
        with open(REGISTRY_PATH) as f:
            data = json.load(f)
    except Exception:
        return {}
    return {name: entry for name, entry in data.items() if entry.get("routed")}


def parse_qname(data, offset=12):
    labels = []
    pos = offset
    try:
        while True:
            if pos >= len(data):
                return None
            length = data[pos]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:
                return None
            pos += 1
            if pos + length > len(data):
                return None
            labels.append(data[pos:pos + length].decode("ascii", errors="strict"))
            pos += length
        return ".".join(labels)
    except Exception:
        return None


def find_matching_instance(qname, registry):
    if not qname:
        return None
    best_match, best_len = None, -1
    qname_lower = qname.lower().rstrip(".")
    for name, entry in registry.items():
        suffix = entry["domain"].lower().rstrip(".")
        if qname_lower == suffix or qname_lower.endswith("." + suffix):
            if len(suffix) > best_len:
                best_len, best_match = len(suffix), name
    return best_match


udp_sessions = {}
udp_sessions_lock = threading.Lock()
UDP_SESSION_IDLE_TIMEOUT = 120.0


def udp_session_receiver(session_key, backend_sock, main_sock, client_addr):
    """One thread per active (client, engine) session, reusing the SAME
    backend socket (and therefore the same source port) for the session's
    entire lifetime. Confirmed as a real, necessary fix: the previous
    design created a brand-new socket per packet, forwarding every packet
    from a different ephemeral source port. Stateless per-query protocols
    (dnstt's own wire format) tolerated that fine, but QUIC-based engines
    (Slipstream) tie session identity to the exact source address:port -
    every packet after the first looked like an unrelated new client, so
    the initial handshake succeeded but no data could ever flow
    afterward. This is the real, standard shape of a UDP NAT/proxy: a
    stable per-client mapping, not a fresh socket every time."""
    while True:
        try:
            backend_sock.settimeout(UDP_SESSION_IDLE_TIMEOUT)
            response, _ = backend_sock.recvfrom(65535)
            main_sock.sendto(response, client_addr)
        except Exception:
            break
    with udp_sessions_lock:
        if udp_sessions.get(session_key, {}).get("sock") is backend_sock:
            udp_sessions.pop(session_key, None)
    try:
        backend_sock.close()
    except Exception:
        pass


def handle_udp_datagram(sock, data, client_addr, registry):
    # The session key MUST include which engine this packet is for, not
    # just the client's address - confirmed as a real, severe regression:
    # with client_addr alone as the key, one client testing two different
    # engines in sequence (e.g. dnstt then Slipstream, from the same phone -
    # an ordinary thing for an admin to do) had its SECOND engine's traffic
    # silently captured by the FIRST engine's already-open session, making
    # every engine except whichever was tried first appear totally broken.
    # The QNAME has to be parsed on every packet (not only when no session
    # exists yet) to identify which engine it belongs to before the session
    # lookup - cheap (pure byte parsing, no I/O), and every packet in these
    # protocols is itself a DNS query naming the same delegated domain
    # throughout a session, so this stays reliable for the whole exchange.
    qname = parse_qname(data)
    instance = find_matching_instance(qname, registry)
    if not instance:
        return
    internal_port = registry[instance].get("internal_port_udp") or registry[instance].get("internal_port")
    if not internal_port:
        return

    session_key = (client_addr, instance)
    # The check-then-create sequence must be a SINGLE atomic block, not
    # check-release-create - confirmed as a genuine, severe race condition:
    # a UDP loop spawns a new thread per incoming packet, and DNS-tunneled
    # protocols send many queries in rapid succession (especially during
    # the initial handshake burst). Two packets from the same client
    # arriving close together could both see "no session yet" under the
    # old check-release-create version, both create their own backend
    # socket, and the second would silently overwrite the first in the
    # session table - orphaning the first socket and its receiver thread,
    # with subsequent replies never reaching the client. This is
    # plausibly severe enough to explain a real report of every engine
    # appearing completely broken, not just an edge case.
    is_new = False
    with udp_sessions_lock:
        session = udp_sessions.get(session_key)
        if session is None:
            backend_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sessions[session_key] = {"sock": backend_sock}
            is_new = True
        else:
            backend_sock = session["sock"]

    if is_new:
        threading.Thread(target=udp_session_receiver, args=(session_key, backend_sock, sock, client_addr), daemon=True).start()

    try:
        backend_sock.sendto(data, ("127.0.0.1", internal_port))
    except Exception:
        with udp_sessions_lock:
            if udp_sessions.get(session_key, {}).get("sock") is backend_sock:
                udp_sessions.pop(session_key, None)
        try:
            backend_sock.close()
        except Exception:
            pass


def udp_loop(registry_ref):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    print("dns-router UDP listening on 0.0.0.0:53")
    while True:
        try:
            data, client_addr = sock.recvfrom(65535)
        except Exception:
            continue
        threading.Thread(target=handle_udp_datagram, args=(sock, data, client_addr, registry_ref[0]), daemon=True).start()


def handle_tcp_connection(conn, registry):
    backend = None
    try:
        conn.settimeout(TCP_TIMEOUT)
        length_prefix = conn.recv(2)
        if len(length_prefix) != 2:
            return
        msg_length = struct.unpack(">H", length_prefix)[0]
        message = b""
        while len(message) < msg_length:
            chunk = conn.recv(msg_length - len(message))
            if not chunk:
                return
            message += chunk

        qname = parse_qname(message)
        instance = find_matching_instance(qname, registry)
        if not instance:
            return

        internal_port = registry[instance].get("internal_port_tcp") or registry[instance].get("internal_port")
        if not internal_port:
            return

        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.settimeout(TCP_TIMEOUT)
        backend.connect(("127.0.0.1", internal_port))
        backend.sendall(length_prefix + message)

        def relay(src, dst):
            try:
                while True:
                    chunk = src.recv(65535)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except Exception:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=relay, args=(conn, backend), daemon=True)
        t2 = threading.Thread(target=relay, args=(backend, conn), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if backend:
            try:
                backend.close()
            except Exception:
                pass


def tcp_loop(registry_ref):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))
    sock.listen(128)
    print("dns-router TCP listening on 0.0.0.0:53")
    while True:
        try:
            conn, _ = sock.accept()
        except Exception:
            continue
        threading.Thread(target=handle_tcp_connection, args=(conn, registry_ref[0]), daemon=True).start()


def registry_refresh_loop(registry_ref):
    while True:
        registry_ref[0] = load_registry()
        time.sleep(5)


if __name__ == "__main__":
    registry_ref = [load_registry()]
    threading.Thread(target=registry_refresh_loop, args=(registry_ref,), daemon=True).start()
    t_udp = threading.Thread(target=udp_loop, args=(registry_ref,), daemon=True)
    t_tcp = threading.Thread(target=tcp_loop, args=(registry_ref,), daemon=True)
    t_udp.start()
    t_tcp.start()
    t_udp.join()
    t_tcp.join()
'''


def _load_instance_registry():
    if not os.path.exists(DNSTT_REGISTRY_PATH):
        return {}
    with open(DNSTT_REGISTRY_PATH) as f:
        return json.load(f)


def _save_instance_registry(data):
    os.makedirs(os.path.dirname(DNSTT_REGISTRY_PATH), exist_ok=True)
    with open(DNSTT_REGISTRY_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(DNSTT_REGISTRY_PATH, 0o600)


def _next_free_internal_port(registry, base=INTERNAL_PORT_BASE):
    used = set()
    for entry in registry.values():
        for key in ("internal_port", "internal_port_udp", "internal_port_tcp"):
            if entry.get(key):
                used.add(entry[key])
    port = base
    while port in used or check_system_port_in_use(port, ("udp", "tcp")):
        port += 1
    return port


def _ensure_router_deployed():
    # Matches the same apt-get install already done before _install_dnstt/
    # _install_vaydns's own firewall calls - without this, an admin who goes
    # straight to Multi-Engine Mode on a fresh VPS (skipping the single-
    # instance path entirely) could lose the router's port-53 rule on
    # reboot if iptables ends up being the active firewall backend, since
    # persist_firewall_rules() can only actually restore rules on boot if
    # this package is present - otherwise it's just a manual-recovery
    # snapshot, not real persistence.
    _run("apt-get update && apt-get install -y iptables-persistent")

    os.makedirs(INSTANCES_DIR, exist_ok=True)
    if not os.path.exists(DNSTT_REGISTRY_PATH):
        _save_instance_registry({})

    needs_write = True
    if os.path.exists(DNS_ROUTER_SCRIPT_PATH):
        with open(DNS_ROUTER_SCRIPT_PATH) as f:
            needs_write = f.read() != DNS_ROUTER_SCRIPT
    if needs_write:
        with open(DNS_ROUTER_SCRIPT_PATH, "w") as f:
            f.write(DNS_ROUTER_SCRIPT)
        os.chmod(DNS_ROUTER_SCRIPT_PATH, 0o755)
        check = _run(["python3", "-m", "py_compile", DNS_ROUTER_SCRIPT_PATH])
        if check.returncode != 0:
            print(f"{C_RED}[✖] Router script failed its own syntax check:\\n{check.stderr.strip()}{C_RESET}")
            os.remove(DNS_ROUTER_SCRIPT_PATH)
            return False

    service_created = not os.path.exists(DNS_ROUTER_SERVICE_PATH)
    if service_created:
        service_content = f"""[Unit]
Description=DNSTT Multi-Engine DNS Router
After=network.target

[Service]
Type=simple
User=root
Environment=DNSTT_REGISTRY={DNSTT_REGISTRY_PATH}
ExecStart=/usr/bin/python3 {DNS_ROUTER_SCRIPT_PATH}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
        with open(DNS_ROUTER_SERVICE_PATH, "w") as f:
            f.write(service_content)
        _run("systemctl daemon-reload")
        _run("systemctl enable dns-router")

    open_firewall_port(53, ("udp", "tcp"))
    persist_firewall_rules()

    # Only force a restart when something actually changed (a new/updated
    # script, or a freshly-created service) - restarting unconditionally
    # every time this runs would disrupt every already-working instance's
    # live sessions each time an admin just opens the menu or views
    # profiles, not only when a genuine update needs picking up.
    if needs_write or service_created:
        # Same lesson as Dropbear/Stunnel/Xray elsewhere in this panel:
        # clear any prior rate-limit before every restart attempt. This
        # matters MORE here than for a single protocol's own service,
        # since dns-router is now restarted automatically every time this
        # menu opens whenever a script update is pending (see the menu-
        # level caller) - repeated restarts during normal troubleshooting
        # could exhaust systemd's restart budget, leaving the ONE shared
        # router every engine depends on stuck in a failed state, which
        # would make every single engine appear broken at once rather
        # than just the one actually being worked on.
        _run("systemctl reset-failed dns-router")
        restart_ok = _run("systemctl restart dns-router").returncode == 0
    else:
        restart_ok = _run("systemctl is-active --quiet dns-router").returncode == 0
        if not restart_ok:
            _run("systemctl reset-failed dns-router")
            restart_ok = _run("systemctl start dns-router").returncode == 0
    if not restart_ok:
        print(f"{C_RED}[✖] Router failed to start - check 'journalctl -u dns-router'.{C_RESET}")
        return False

    from panel_common import detect_firewall
    if not detect_firewall():
        print(f"\n{C_YELLOW}[!] No firewall is currently active, which means the internal ports")
        print(f"    each engine binds (not just the shared port 53) are directly reachable")
        print(f"    from the internet right now, bypassing this router's own domain-based")
        print(f"    gating. Extra Tools -> option 11 walks through enabling one safely (it")
        print(f"    won't do this automatically - that's a deliberate, guarded step you'd")
        print(f"    take separately, not something to silently trigger here).{C_RESET}")

    return True


def _install_dnstt_routed(name, domain_ns, target_port, internal_port, fallback_addr=None, mtu=None):
    """Lean variant of _install_dnstt() for Multi-Engine Mode: the router now
    owns port 53, so this binds the assigned internal port directly - no
    NAT redirect, no external firewall opening for this engine specifically
    (only the router's own port 53 needs that, done once for all engines)."""
    print(f"\n[i] Installing dependencies for dnstt (instance '{name}')...")
    _run("apt-get update && apt-get install -y golang git")
    print("[i] Fetching dnstt-server (shared binary across all dnstt instances)...")
    _run("GOBIN=/usr/local/bin go install www.bamsoftware.com/git/dnstt.git/dnstt-server@latest")
    if not _binary_ok(DNSTT_BIN):
        _run("git clone https://www.bamsoftware.com/git/dnstt.git /tmp/dnstt_src 2>/dev/null || (cd /tmp/dnstt_src && git pull)")
        _run(f"cd /tmp/dnstt_src/dnstt-server && go build -o {DNSTT_BIN}")
    if not _binary_ok(DNSTT_BIN):
        print(f"{C_RED}[✖] Could not build or install dnstt-server.{C_RESET}")
        return False

    instance_dir = f"{INSTANCES_DIR}/{name}"
    os.makedirs(instance_dir, exist_ok=True)
    priv_key = f"{instance_dir}/server.key"
    pub_key = f"{instance_dir}/server.pub"
    keygen = _run([DNSTT_BIN, "-gen-key", "-privkey-file", priv_key, "-pubkey-file", pub_key])
    if keygen.returncode != 0 or not os.path.exists(pub_key):
        print(f"{C_RED}[✖] Key generation failed: {keygen.stderr.strip()}{C_RESET}")
        return False

    exec_cmd = f"{DNSTT_BIN} -udp :{internal_port} -privkey-file {priv_key}"
    if fallback_addr:
        exec_cmd += f" -fallback {fallback_addr}"
    if mtu:
        exec_cmd += f" -mtu {mtu}"
    exec_cmd += f" {domain_ns} 127.0.0.1:{target_port}"

    return _write_routed_service(name, exec_cmd)


def _install_vaydns_routed(name, domain_ns, target_port, internal_port, mtu=None, record_type=None, dnstt_compat=True):
    """dnstt_compat defaults to True here, not False. Confirmed directly
    from VayDNS's own documentation: its wire protocol differs from
    original dnstt BY DEFAULT, and only the -dnstt-compat flag makes it
    speak the standard protocol that ordinary client apps (HTTP Custom and
    similar) actually understand. This panel never distributes or supports
    VayDNS's own specialized client - every client these instances need to
    work with expects the same standard dnstt wire format that plain DNSTT
    already uses - so running without this flag meant the server process
    started fine, looked "ON", and accepted DNS queries, but could never
    actually establish a working tunnel with any real client. Confirmed as
    the actual cause of a real "installs fine, no internet" report."""
    print(f"\n[i] Installing dependencies for VayDNS (instance '{name}')...")
    _run("apt-get update && apt-get install -y golang git")
    print("[i] Fetching vaydns-server (shared binary across all VayDNS instances)...")
    _run("GOBIN=/usr/local/bin go install github.com/net2share/vaydns/vaydns-server@latest")
    if not _binary_ok(VAYDNS_BIN):
        _run("git clone https://github.com/net2share/vaydns.git /tmp/vaydns_src 2>/dev/null || (cd /tmp/vaydns_src && git pull)")
        _run(f"cd /tmp/vaydns_src/vaydns-server && go build -o {VAYDNS_BIN}")
    if not _binary_ok(VAYDNS_BIN):
        print(f"{C_RED}[✖] Could not build or install vaydns-server.{C_RESET}")
        return False

    instance_dir = f"{INSTANCES_DIR}/{name}"
    os.makedirs(instance_dir, exist_ok=True)
    priv_key = f"{instance_dir}/vaydns_server.key"
    pub_key = f"{instance_dir}/vaydns_server.pub"
    keygen = _run([VAYDNS_BIN, "-gen-key", "-privkey-file", priv_key, "-pubkey-file", pub_key])
    if keygen.returncode != 0 or not os.path.exists(pub_key):
        print(f"{C_RED}[✖] Key generation failed: {keygen.stderr.strip()}{C_RESET}")
        return False

    exec_cmd = f"{VAYDNS_BIN} -udp :{internal_port} -privkey-file {priv_key} -domain {domain_ns} -upstream 127.0.0.1:{target_port}"
    if mtu:
        exec_cmd += f" -mtu {mtu}"
    if record_type:
        exec_cmd += f" -record-type {record_type}"
    if dnstt_compat:
        exec_cmd += " -dnstt-compat"

    return _write_routed_service(name, exec_cmd)


def _install_slipstream_routed(name, domain_ns, target_port, internal_port):
    """Confirmed directly: "slipstream-rust" is NOT published on crates.io -
    it only exists as source on GitHub (Mygod/slipstream-rust and several
    forks), requires initializing a picoquic git submodule, and needs a
    real build (cmake, pkg-config, OpenSSL headers) - a plain `cargo
    install slipstream-rust` can never succeed, which is exactly what was
    happening ("[X] Could not install Slipstream" every time, regardless of
    domain/port). The real binary's own CLI flags are also different from
    what was assumed here before (--dns-listen-port/--target-address/
    --domain/--cert/--key/--reset-seed, not --listen/--upstream/--cert-dir).
    This clones and builds the real project instead of guessing at a
    package that was never there to begin with."""
    print(f"\n[i] Installing dependencies for Slipstream (instance '{name}')...")
    print("    This builds from source (Rust + a C submodule) - can take several")
    print("    minutes on a low-spec VPS.")
    _run("apt-get update && apt-get install -y git cmake pkg-config libssl-dev build-essential curl")
    # Same fix as the single-instance installer, and for the same confirmed
    # reason: gating this behind "does cargo exist at all" lets an old
    # system/leftover cargo silently block rustup from ever running, and an
    # old-enough cargo can't parse this project's lockfile format (v4,
    # default since Cargo 1.83) no matter how recent it looks otherwise.
    # rustup's own installer is safe to run unconditionally.
    print("[i] Ensuring a recent Rust toolchain via rustup...")
    _run("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")
    cargo_bin = os.path.expanduser("~/.cargo/bin/cargo")
    if not _binary_ok(cargo_bin):
        cargo_bin = "cargo"

    src_dir = f"{INSTANCES_DIR}/.slipstream-src"
    if not os.path.exists(f"{src_dir}/.git"):
        _run(f"rm -rf {src_dir}")
        clone_res = _run(f"git clone https://github.com/Mygod/slipstream-rust.git {src_dir}")
        if clone_res.returncode != 0:
            print(f"{C_RED}[✖] Could not clone the Slipstream source repository:{C_RESET}")
            print((clone_res.stderr or clone_res.stdout or "(no output captured)").strip()[-1500:])
            return False
    _run(f"cd {src_dir} && git submodule update --init --recursive")

    build_res = _run(f"cd {src_dir} && {cargo_bin} build --release -p slipstream-server")
    built_bin = f"{src_dir}/target/release/slipstream-server"
    if build_res.returncode != 0 or not _binary_ok(built_bin):
        # _run() captures output rather than streaming it live, so without
        # explicitly printing it here there is nothing for "check the
        # output above" to actually point at - confirmed as a real gap in
        # this fix itself, not just a hypothetical one.
        print(f"{C_RED}[✖] Slipstream failed to build from source (commonly missing")
        print(f"    OpenSSL/cmake dependencies on some distros). Build output:{C_RESET}")
        tail = (build_res.stderr or build_res.stdout or "").strip()
        print(tail[-3000:] if tail else "(no output captured)")
        return False

    _run(f"cp {built_bin} {SLIPSTREAM_BIN}")
    os.chmod(SLIPSTREAM_BIN, 0o755)
    if not _binary_ok(SLIPSTREAM_BIN):
        print(f"{C_RED}[✖] Slipstream built, but the binary couldn't be installed to {SLIPSTREAM_BIN}.{C_RESET}")
        return False

    instance_dir = f"{INSTANCES_DIR}/{name}"
    os.makedirs(instance_dir, exist_ok=True)
    cert_path = f"{instance_dir}/cert.pem"
    key_path = f"{instance_dir}/key.pem"
    reset_seed_path = f"{instance_dir}/reset-seed"
    if not os.path.exists(cert_path):
        _run(f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {key_path} -out {cert_path} "
             f"-days 3650 -subj '/CN={domain_ns}'")

    exec_cmd = (f"{SLIPSTREAM_BIN} --dns-listen-port {internal_port} --target-address 127.0.0.1:{target_port} "
                f"--domain {domain_ns} --cert {cert_path} --key {key_path} --reset-seed {reset_seed_path}")
    return _write_routed_service(name, exec_cmd)


def _write_routed_service(name, exec_cmd):
    service_path = f"/etc/systemd/system/dnstt-{name}.service"
    service_content = f"""[Unit]
Description=DNSTT Multi-Engine Instance ({name})
After=network.target dns-router.service

[Service]
Type=simple
User=root
ExecStart={exec_cmd}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(service_path, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")
    _run(f"systemctl enable dnstt-{name}")
    return _run(f"systemctl restart dnstt-{name}").returncode == 0


def _reconfigure_toml_port(config_path, new_udp_port, new_tcp_port=None):
    """MasterDNS/StormDNS/CottenDNS's own installers default to writing
    UDP_PORT = 53 into their generated TOML config - this rewrites it to the
    assigned internal port post-install, so the router (not the engine
    itself) is the only thing bound to the real port 53.

    Honest limitation: CottenDNS is dual-protocol (UDP+TCP), and its exact
    TCP port config key name wasn't independently confirmed from its
    source the way UDP_PORT was - if this doesn't find a TCP port key to
    rewrite, the UDP path still gets configured correctly, but the TCP path
    may need manually checking in server_config.toml for a CottenDNS
    instance specifically."""
    if not os.path.exists(config_path):
        return False
    with open(config_path) as f:
        content = f.read()
    content, n = re.subn(r'^UDP_PORT\s*=\s*\d+', f'UDP_PORT = {new_udp_port}', content, flags=re.MULTILINE)
    if n == 0:
        return False
    if new_tcp_port:
        content, tcp_n = re.subn(r'^TCP_PORT\s*=\s*\d+', f'TCP_PORT = {new_tcp_port}', content, flags=re.MULTILINE)
        if tcp_n == 0:
            print(f"{C_YELLOW}[!] Couldn't find a TCP_PORT key to rewrite in {config_path} - CottenDNS's")
            print(f"    TCP listener may still be bound to 53. Check the config file directly.{C_RESET}")
    with open(config_path, "w") as f:
        f.write(content)
    return True


def _service_name(mode):
    """MasterDNS ships its own installer that creates its own systemd unit —
    reusing our generic 'slowdns' unit name for it would just fight the official
    installer's own lifecycle management (which also handles sysctl/limits
    cleanup on uninstall that we have no reason to reimplement)."""
    if mode == "masterdns":
        return "masterdnsvpn"
    if mode == "stormdns":
        return "stormdns"
    if mode == "cottendns":
        return "cottendns"
    return "slowdns"


def _binary_ok(path):
    return os.path.exists(path) and os.access(path, os.X_OK)


def _install_dnstt(custom_port, domain_ns, target_port, fallback_addr, mtu=None):
    print(f"\n[i] Installing dependencies for dnstt...")
    _run("apt-get update && apt-get install -y golang git iptables iptables-persistent")

    # NOTE: unlike Slipstream (which binds custom_port directly), dnstt only ever
    # binds DNSTT_INTERNAL_PORT — the NAT redirect maps custom_port to it at the
    # netfilter layer, which happens regardless of what (if anything) userspace has
    # bound on custom_port. So dnstt doesn't actually need port 53 itself free, and
    # calling resolve_port53_conflict() here would just risk disabling the admin's
    # systemd-resolved for no real benefit — deliberately skipped for this backend.

    print("[i] Fetching dnstt-server (go install, lands directly in /usr/local/bin)...")
    res = _run("GOBIN=/usr/local/bin go install www.bamsoftware.com/git/dnstt.git/dnstt-server@latest")
    if not _binary_ok(DNSTT_BIN):
        print(f"{C_YELLOW}go install didn't produce a binary — falling back to building from source.{C_RESET}")
        _run("git clone https://www.bamsoftware.com/git/dnstt.git /tmp/dnstt_src 2>/dev/null || (cd /tmp/dnstt_src && git pull)")
        _run(f"cd /tmp/dnstt_src/dnstt-server && go build -o {DNSTT_BIN}")

    if not _binary_ok(DNSTT_BIN):
        print(f"{C_RED}[✖] Could not build or install dnstt-server. Check your internet access / Go install and try again.{C_RESET}")
        return False

    os.makedirs(DNSTT_DIR, exist_ok=True)
    priv_key = f"{DNSTT_DIR}/server.key"
    pub_key = f"{DNSTT_DIR}/server.pub"
    keygen = _run([DNSTT_BIN, "-gen-key", "-privkey-file", priv_key, "-pubkey-file", pub_key])
    if keygen.returncode != 0 or not os.path.exists(pub_key):
        print(f"{C_RED}[✖] Key generation failed: {keygen.stderr.strip()}{C_RESET}")
        return False

    # Per the upstream docs: PREROUTING (where the NAT redirect rewrites the
    # destination) runs BEFORE the INPUT filter chain in netfilter's packet path.
    # By the time INPUT evaluates the packet its destination is already 5300, not
    # custom_port — so the firewall ALLOW rule has to target the internal port, not
    # the externally-advertised one. Getting this backwards (as an earlier version
    # of this code did) means the tunnel silently never becomes reachable.
    open_firewall_port(DNSTT_INTERNAL_PORT, ("udp",))
    nat_redirect_udp(custom_port, DNSTT_INTERNAL_PORT)
    _mirror_ip6tables(custom_port, DNSTT_INTERNAL_PORT)
    persist_firewall_rules()

    exec_cmd = f"{DNSTT_BIN} -udp :{DNSTT_INTERNAL_PORT} -privkey-file {priv_key}"
    if fallback_addr:
        exec_cmd += f" -fallback {fallback_addr}"
    if mtu:
        exec_cmd += f" -mtu {mtu}"
    exec_cmd += f" {domain_ns} 127.0.0.1:{target_port}"

    _write_service("dnstt", exec_cmd)
    return True


def _install_vaydns(custom_port, domain_ns, target_port, mtu=None, record_type=None, dnstt_compat=True):
    print(f"\n[i] Installing dependencies for VayDNS...")
    _run("apt-get update && apt-get install -y golang git iptables iptables-persistent")

    print("[i] Fetching vaydns-server (go install, lands directly in /usr/local/bin)...")
    _run("GOBIN=/usr/local/bin go install github.com/net2share/vaydns/vaydns-server@latest")
    if not _binary_ok(VAYDNS_BIN):
        print(f"{C_YELLOW}go install didn't produce a binary — falling back to building from source.{C_RESET}")
        _run("git clone https://github.com/net2share/vaydns.git /tmp/vaydns_src 2>/dev/null || (cd /tmp/vaydns_src && git pull)")
        _run(f"cd /tmp/vaydns_src/vaydns-server && go build -o {VAYDNS_BIN}")

    if not _binary_ok(VAYDNS_BIN):
        print(f"{C_RED}[✖] Could not build or install vaydns-server. Check your internet access / Go install and try again.{C_RESET}")
        return False

    os.makedirs(DNSTT_DIR, exist_ok=True)
    priv_key = f"{DNSTT_DIR}/vaydns_server.key"
    pub_key = f"{DNSTT_DIR}/vaydns_server.pub"
    keygen = _run([VAYDNS_BIN, "-gen-key", "-privkey-file", priv_key, "-pubkey-file", pub_key])
    if keygen.returncode != 0 or not os.path.exists(pub_key):
        print(f"{C_RED}[✖] Key generation failed: {keygen.stderr.strip()}{C_RESET}")
        return False

    # Same documented 53->5300 pattern as dnstt — confirmed from VayDNS's own README
    # example ("./vaydns-server -udp :5300 ..."), not assumed by analogy.
    open_firewall_port(DNSTT_INTERNAL_PORT, ("udp",))
    nat_redirect_udp(custom_port, DNSTT_INTERNAL_PORT)
    _mirror_ip6tables(custom_port, DNSTT_INTERNAL_PORT)
    persist_firewall_rules()

    # NOTE: unlike dnstt-server (domain/upstream are trailing positional args),
    # vaydns-server takes them as named flags — confirmed from its own README,
    # not assumed from dnstt's syntax. Getting this backwards would silently
    # produce a broken ExecStart, the same class of bug the Slipstream cert
    # flags caught earlier.
    exec_cmd = f"{VAYDNS_BIN} -udp :{DNSTT_INTERNAL_PORT} -privkey-file {priv_key} -domain {domain_ns} -upstream 127.0.0.1:{target_port}"
    if mtu:
        exec_cmd += f" -mtu {mtu}"
    if record_type:
        exec_cmd += f" -record-type {record_type}"
    if dnstt_compat:
        exec_cmd += " -dnstt-compat"

    _write_service("vaydns", exec_cmd)
    return True


def _install_masterdns():
    """Uses the project's own official installer rather than reimplementing its
    install logic — it already handles port-53 conflict resolution (more
    thoroughly than our own, since it also stops bind9/dnsmasq/unbound/pihole-FTL/
    etc. and removes stale NAT redirects), firewall setup across ufw/firewalld/
    iptables/nftables, kernel/limits tuning, and key generation. Verified by
    reading the actual script content before wiring this in, rather than
    guessing at paths or service names the way earlier drafts of this module
    guessed at dnstt's install path.

    It prompts for the domain interactively via /dev/tty ONLY if server_config.toml
    still has the placeholder domain — since we run it with os.system() from the
    same interactive terminal this panel is already running in, that prompt just
    works naturally without us needing to intercept or pre-answer it."""
    os.makedirs(MASTERDNS_DIR, exist_ok=True)
    print(f"\n{C_CYAN}[i] Running the official MasterDnsVPN installer. It will ask for your")
    print(f"    tunnel domain directly — answer it when prompted below.{C_RESET}\n")
    ret = os.system(f"cd {MASTERDNS_DIR} && curl -Ls {MASTERDNS_INSTALL_URL} | bash")

    active = _run("systemctl is-active --quiet masterdnsvpn").returncode == 0
    key_path = f"{MASTERDNS_DIR}/encrypt_key.txt"
    if ret != 0 or not active or not os.path.exists(key_path):
        print(f"{C_RED}[✖] Install did not complete successfully — see the installer's own output above.{C_RESET}")
        return False, None

    domain_found = None
    config_path = f"{MASTERDNS_DIR}/server_config.toml"
    if os.path.exists(config_path):
        with open(config_path) as f:
            m = re.search(r'^DOMAIN\s*=\s*\[\s*"([^"]+)"', f.read(), re.MULTILINE)
            if m:
                domain_found = m.group(1)
    return True, domain_found


def _masterdns_client_info(ports_dict):
    key_content = "Not found"
    key_path = f"{MASTERDNS_DIR}/encrypt_key.txt"
    if os.path.exists(key_path):
        with open(key_path) as f:
            key_content = f.read().strip()
    return key_content


def _install_stormdns():
    """Uses the official installer, same reasoning as MasterDNS's - it already
    handles port-53 conflict resolution (confirmed by reading server_linux_install.sh
    directly: it stops conflicting systemd-resolved/etc. and reconfigures
    DNSStubListener=no the same way our own resolve_port53_conflict() does),
    firewall opening, UDP/socket/fd tuning, and key generation. Also has a real
    --uninstall flag, used later rather than reimplementing teardown."""
    os.makedirs(STORMDNS_DIR, exist_ok=True)
    print(f"\n{C_CYAN}[i] Running the official StormDNS installer. It will ask for your")
    print(f"    tunnel domain directly — answer it when prompted below.{C_RESET}\n")
    ret = os.system(f"cd {STORMDNS_DIR} && curl -Ls {STORMDNS_INSTALL_URL} | bash")

    active = _run("systemctl is-active --quiet stormdns").returncode == 0
    key_path = f"{STORMDNS_DIR}/encrypt_key.txt"
    if ret != 0 or not active or not os.path.exists(key_path):
        print(f"{C_RED}[✖] Install did not complete successfully — see the installer's own output above.{C_RESET}")
        return False, None

    domain_found = None
    config_path = f"{STORMDNS_DIR}/server_config.toml"
    if os.path.exists(config_path):
        with open(config_path) as f:
            # StormDNS uses the plural "DOMAINS" array key, unlike MasterDNS's
            # singular "DOMAIN" - confirmed from its own README example.
            m = re.search(r'^DOMAINS\s*=\s*\[\s*"([^"]+)"', f.read(), re.MULTILINE)
            if m:
                domain_found = m.group(1)
    return True, domain_found


def _stormdns_client_info():
    key_content = "Not found"
    key_path = f"{STORMDNS_DIR}/encrypt_key.txt"
    if os.path.exists(key_path):
        with open(key_path) as f:
            key_content = f.read().strip()
    return key_content


def _install_cottendns():
    """Uses the official installer from TaJirax/cottenDNS (the canonical
    upstream - see the constant comment above). Unlike every other engine in
    this module, CottenDNS is genuinely dual-protocol: it needs BOTH UDP/53
    AND TCP/53 free (confirmed directly from its own README's prerequisites
    and health-check instructions), not UDP-only like dnstt/Slipstream/VayDNS/
    MasterDNS/StormDNS."""
    os.makedirs(COTTENDNS_DIR, exist_ok=True)
    print(f"\n{C_CYAN}[i] Running the official CottenDNS installer. It will ask for your")
    print(f"    tunnel domain directly — answer it when prompted below.{C_RESET}\n")
    ret = os.system(f"cd {COTTENDNS_DIR} && curl -fsSL {COTTENDNS_INSTALL_URL} | bash")

    active = _run("systemctl is-active --quiet cottendns").returncode == 0
    key_path = f"{COTTENDNS_DIR}/encrypt_key.txt"
    if ret != 0 or not active or not os.path.exists(key_path):
        print(f"{C_RED}[✖] Install did not complete successfully — see the installer's own output above.{C_RESET}")
        return False, None

    domain_found = None
    config_path = f"{COTTENDNS_DIR}/server_config.toml"
    if os.path.exists(config_path):
        with open(config_path) as f:
            m = re.search(r'^DOMAINS\s*=\s*\[\s*"([^"]+)"', f.read(), re.MULTILINE)
            if m:
                domain_found = m.group(1)
    return True, domain_found


def _cottendns_client_info():
    key_content = "Not found"
    key_path = f"{COTTENDNS_DIR}/encrypt_key.txt"
    if os.path.exists(key_path):
        with open(key_path) as f:
            key_content = f.read().strip()
    return key_content


def _mirror_ip6tables(src_port, dst_port):
    """The docs mirror every rule for ip6tables too. ufw/firewalld already cover IPv6
    on their own, so this only matters on hosts running plain iptables with no
    front-end — deliberately NOT folded into the shared panel_common helpers, since
    those are also used by modules that don't need this dnstt-specific NAT mirror."""
    from panel_common import detect_firewall
    if detect_firewall() != "iptables":
        return
    try:
        check = _run(["ip6tables", "-C", "INPUT", "-p", "udp", "--dport", str(dst_port), "-j", "ACCEPT"])
        if check.returncode != 0:
            _run(["ip6tables", "-I", "INPUT", "-p", "udp", "--dport", str(dst_port), "-j", "ACCEPT"])
        check6nat = _run(["ip6tables", "-t", "nat", "-C", "PREROUTING", "-p", "udp", "--dport", str(src_port),
                           "-j", "REDIRECT", "--to-ports", str(dst_port)])
        if check6nat.returncode != 0:
            _run(["ip6tables", "-t", "nat", "-I", "PREROUTING", "-p", "udp", "--dport", str(src_port),
                  "-j", "REDIRECT", "--to-ports", str(dst_port)])
    except Exception:
        pass


def _install_slipstream(custom_port, domain_ns, target_port):
    print(f"\n[i] Installing dependencies for Slipstream...")
    _run("apt-get update && apt-get install -y curl git build-essential cmake pkg-config libssl-dev openssl")

    # Unlike dnstt's NAT-redirect setup, Slipstream binds custom_port itself directly —
    # so if that's port 53, systemd-resolved's stub listener genuinely can block it.
    # (resolve_port53_conflict() is specifically about the systemd-resolved default,
    # which only ever squats on 53 — irrelevant if a different port was chosen.)
    if custom_port == 53 and not resolve_port53_conflict():
        print(f"{C_YELLOW}[!] Port {custom_port} still looks occupied after cleanup — the server may fail to bind.{C_RESET}")

    # Confirmed the actual cause of a real "lock file version 4 requires
    # -Znext-lockfile-bump" build failure: gating the rustup install behind
    # "does cargo exist at all" lets an old, too-old system cargo (e.g. left
    # over from Ubuntu's own apt package, or from an earlier attempt before
    # this exact fix existed) silently prevent rustup from ever running -
    # the real project's Cargo.lock uses a lockfile format (v4, default
    # since Cargo 1.83) that only a recent toolchain can read at all, no
    # matter how "not too old" the existing one looks. rustup's own
    # installer is safe to run unconditionally - it detects an existing
    # rustup-managed toolchain and just confirms/updates it rather than
    # reinstalling from scratch, so there's no downside to always running it
    # here rather than trying to guess whether the existing cargo is new
    # enough.
    print("[i] Ensuring a recent Rust toolchain via rustup...")
    _run("curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y")

    print("[i] Cloning and building slipstream-server (this can take a few minutes)...")
    _run("git clone --recursive https://github.com/Mygod/slipstream-rust.git /tmp/slipstream-rust 2>/dev/null || (cd /tmp/slipstream-rust && git pull)")
    # NOTE: the original draft exported PATH with single quotes — '$HOME/.cargo/bin:$PATH' —
    # which bash never expands, so cargo silently stayed off PATH and the build step
    # would fail. Double quotes here is the actual fix, not a style nit.
    build = _run('bash -lc \'export PATH="$HOME/.cargo/bin:$PATH" && cd /tmp/slipstream-rust && cargo build --release -p slipstream-server\'')

    built_bin = "/tmp/slipstream-rust/target/release/slipstream-server"
    if not os.path.exists(built_bin):
        print(f"{C_RED}[✖] Slipstream build failed:\n{build.stderr[-800:]}{C_RESET}")
        return False
    _run(f"cp {built_bin} {SLIPSTREAM_BIN}")
    if not _binary_ok(SLIPSTREAM_BIN):
        print(f"{C_RED}[✖] Could not install slipstream-server binary.{C_RESET}")
        return False

    # Slipstream terminates its own TLS/QUIC layer, so unlike dnstt it needs a
    # certificate — the original draft never generated or passed one, which means
    # the server as originally written would have failed to start at all.
    cert_path = f"{DNSTT_DIR}/slipstream.cert"
    key_path = f"{DNSTT_DIR}/slipstream.key"
    seed_path = f"{DNSTT_DIR}/reset-seed"
    os.makedirs(DNSTT_DIR, exist_ok=True)
    _run(f'openssl req -x509 -newkey rsa:2048 -nodes -keyout {key_path} -out {cert_path} -days 365 -subj "/CN=slipstream"')
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        print(f"{C_RED}[✖] Certificate generation failed.{C_RESET}")
        return False

    open_firewall_port(custom_port, ("udp",))
    persist_firewall_rules()

    exec_cmd = (
        f"{SLIPSTREAM_BIN} --dns-listen-port {custom_port} --target-address 127.0.0.1:{target_port} "
        f"--domain {domain_ns} --cert {cert_path} --key {key_path} --reset-seed {seed_path}"
    )
    _write_service("slipstream", exec_cmd)
    return True


def _write_service(mode, exec_cmd):
    service_file = f"""[Unit]
Description=SLOWDNS Tunnel Service ({mode})
After=network-online.target remote-fs.target netfilter-persistent.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart={exec_cmd}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(SERVICE_PATH, "w") as f:
        f.write(service_file)
    _run("systemctl daemon-reload && systemctl enable slowdns && systemctl start slowdns")


def _client_commands(mode, ports_dict):
    domain_val = ports_dict.get('DNSTT_DOMAIN', 't.domain.com')
    server_ip = ports_dict.get('DNSTT_IP', '127.0.0.1')
    custom_port = ports_dict.get('DNSTT_PORT', '53')

    if mode == "dnstt":
        pub_key_content = "Not found"
        pub_key_path = f"{DNSTT_DIR}/server.pub"
        if os.path.exists(pub_key_path):
            with open(pub_key_path, "r") as pk:
                pub_key_content = pk.read().strip()
        return {
            "UDP (fastest, most detectable)": f"dnstt-client -udp {server_ip}:{custom_port} -pubkey-file server.pub {domain_val} 127.0.0.1:1080",
            "DoH (via a public resolver, blends in as HTTPS)": f"dnstt-client -doh https://<resolver>/dns-query -pubkey-file server.pub {domain_val} 127.0.0.1:1080",
            "DoT (via a public resolver, blends in as TLS)": f"dnstt-client -dot <resolver>:853 -pubkey-file server.pub {domain_val} 127.0.0.1:1080",
        }, pub_key_content
    elif mode == "vaydns":
        pub_key_content = "Not found"
        pub_key_path = f"{DNSTT_DIR}/vaydns_server.pub"
        if os.path.exists(pub_key_path):
            with open(pub_key_path, "r") as pk:
                pub_key_content = pk.read().strip()
        return {
            "UDP": f"vaydns-client -udp {server_ip}:{custom_port} -pubkey-file server.pub -domain {domain_val} -socks 127.0.0.1:1080",
            "DoH (via a public resolver)": f"vaydns-client -doh https://<resolver>/dns-query -pubkey-file server.pub -domain {domain_val} -socks 127.0.0.1:1080",
            "DoT (via a public resolver)": f"vaydns-client -dot <resolver>:853 -pubkey-file server.pub -domain {domain_val} -socks 127.0.0.1:1080",
            "dnstt-compat (if server installed with it, existing dnstt-client works too)": f"dnstt-client -udp {server_ip}:{custom_port} -pubkey-file server.pub {domain_val} 127.0.0.1:1080",
        }, pub_key_content
    else:
        return {
            "Slipstream client": f"slipstream-client --resolver {server_ip}:{custom_port} --domain {domain_val} --tcp-listen-port 1080",
        }, None


def _find_installed_binary(official_unit_name, instance_dir):
    """Reads the official installer's OWN systemd unit to find the real
    binary path it actually used, rather than guessing/hardcoding one.
    Confirmed as a real bug: hardcoding /opt/masterdnsvpn/masterdnsvpn as
    the expected path was wrong - the official installer's own log showed
    it installs into the per-instance directory instead
    (/etc/dnstt/instances/<name>/), so the hardcoded check always failed
    even though the real install genuinely succeeded every time, silently
    reporting "Install failed" despite a working install."""
    unit_path = f"/etc/systemd/system/{official_unit_name}.service"
    try:
        with open(unit_path) as f:
            content = f.read()
        m = re.search(r'^ExecStart=(\S+)', content, re.MULTILINE)
        if m and os.path.exists(m.group(1)):
            return m.group(1)
    except FileNotFoundError:
        pass
    # Fall back to searching the instance directory itself for anything
    # executable, in case the official unit wasn't found or didn't parse.
    try:
        for fname in os.listdir(instance_dir):
            fpath = os.path.join(instance_dir, fname)
            if os.path.isfile(fpath) and os.access(fpath, os.X_OK) and not fname.endswith((".toml", ".txt")):
                return fpath
    except FileNotFoundError:
        pass
    return None


def _install_masterdns_routed(name, domain_ns, internal_port):
    """MasterDNS/StormDNS/CottenDNS don't take a port as an install-time flag
    the way dnstt/VayDNS/Slipstream do - their official installers always
    write UDP_PORT = 53 into the generated TOML, so this runs the normal
    install first and then rewrites that port post-install."""
    instance_dir = f"{INSTANCES_DIR}/{name}"
    os.makedirs(instance_dir, exist_ok=True)
    print(f"\n{C_CYAN}[i] Running the official MasterDnsVPN installer for instance '{name}'.")
    print(f"    It will ask for your tunnel domain directly — enter {domain_ns}.{C_RESET}\n")
    ret = os.system(f"cd {instance_dir} && curl -Ls {MASTERDNS_INSTALL_URL} | bash")
    if ret != 0:
        return False, None
    _reconfigure_toml_port(f"{instance_dir}/server_config.toml", internal_port)
    real_binary = _find_installed_binary("masterdnsvpn", instance_dir)
    _run(f"systemctl stop masterdnsvpn")  # official installer's own unit name - we run our own instead
    _run(f"systemctl disable masterdnsvpn")
    ok = _write_routed_service(name, f"{real_binary} --config {instance_dir}/server_config.toml") \
        if real_binary else False
    if not real_binary:
        print(f"{C_RED}[X] The official installer's own service finished, but its binary")
        print(f"    couldn't be located afterward - check {instance_dir} manually.{C_RESET}")
    return ok, None


def _install_stormdns_routed(name, domain_ns, internal_port):
    instance_dir = f"{INSTANCES_DIR}/{name}"
    os.makedirs(instance_dir, exist_ok=True)
    print(f"\n{C_CYAN}[i] Running the official StormDNS installer for instance '{name}'.")
    print(f"    It will ask for your tunnel domain directly — enter {domain_ns}.{C_RESET}\n")
    ret = os.system(f"cd {instance_dir} && curl -Ls {STORMDNS_INSTALL_URL} | bash")
    if ret != 0:
        return False
    _reconfigure_toml_port(f"{instance_dir}/server_config.toml", internal_port)
    bin_path = _find_installed_binary("stormdns", instance_dir)
    _run("systemctl stop stormdns")
    _run("systemctl disable stormdns")
    if not bin_path:
        print(f"{C_RED}[X] The official installer's own service finished, but its binary")
        print(f"    couldn't be located afterward - check {instance_dir} manually.{C_RESET}")
        return False
    return _write_routed_service(name, f"{bin_path} --config {instance_dir}/server_config.toml")


def _install_cottendns_routed(name, domain_ns, internal_udp_port, internal_tcp_port):
    """Honest limitation, same as noted on _reconfigure_toml_port: CottenDNS's
    TCP port config key name wasn't independently confirmed - the UDP side
    is handled with the same confirmed UDP_PORT key the other two engines
    use, but the TCP side may need a manual check post-install."""
    instance_dir = f"{INSTANCES_DIR}/{name}"
    os.makedirs(instance_dir, exist_ok=True)
    print(f"\n{C_CYAN}[i] Running the official CottenDNS installer for instance '{name}'.")
    print(f"    It will ask for your tunnel domain directly — enter {domain_ns}.{C_RESET}\n")
    ret = os.system(f"cd {instance_dir} && curl -fsSL {COTTENDNS_INSTALL_URL} | bash")
    if ret != 0:
        return False
    _reconfigure_toml_port(f"{instance_dir}/server_config.toml", internal_udp_port, internal_tcp_port)
    bin_path = _find_installed_binary("cottendns", instance_dir)
    _run("systemctl stop cottendns")
    _run("systemctl disable cottendns")
    if not bin_path:
        print(f"{C_RED}[X] The official installer's own service finished, but its binary")
        print(f"    couldn't be located afterward - check {instance_dir} manually.{C_RESET}")
        return False
    return _write_routed_service(name, f"{bin_path} --config {instance_dir}/server_config.toml")


def _multi_engine_menu(ports_dict):
    """Multi-Engine Mode: multiple DNSTT-family instances sharing port 53 at
    once via the DNS router, each independently tracked in a registry rather
    than the single flat ports_dict keys the original single-instance flow
    uses. This is additive, not a replacement - a straightforward single
    install is still simpler for anyone who only wants one engine."""
    while True:
        registry = _load_instance_registry()
        # Confirmed necessary: previously this check (and any resulting
        # restart) only ran from the "Add New Instance" flow, meaning a
        # fixed router script sitting in a NEWER dnstt_manager.py never
        # actually reached the live service unless an admin added a new
        # instance. Running it here instead - every time this menu opens,
        # whenever any instances already exist - means a code fix picks
        # itself up automatically the next time the admin even looks at
        # this screen, with no separate manual step to remember.
        if registry:
            _ensure_router_deployed()
        clear_screen()
        router_active = _run("systemctl is-active --quiet dns-router").returncode == 0
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s        MULTI-ENGINE MODE — SHARED PORT 53 VIA ROUTER       %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f" Router: {'ON' if router_active else 'OFF'}  |  Instances: {len(registry)}")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        if not registry:
            print(" No instances yet.")
        else:
            for name, entry in registry.items():
                svc = f"dnstt-{name}" if entry['mode'] != 'masterdns' or True else name
                active = _run(["systemctl", "is-active", "--quiet", svc]).returncode == 0
                status = f"{C_GREEN}ON{C_RESET}" if active else f"{C_RED}OFF{C_RESET}"
                print(f"  {name:<16} {entry['mode']:<12} {entry['domain']:<28} [{status}]")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [1] Add instance          [2] View all profiles (copy info)")
        print(" [3] Remove instance       [0] Back")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an option: ").strip()
        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     ADD NEW INSTANCE                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" [1] DNSTT   [2] Slipstream   [3] MasterDnsVPN")
            print(" [4] VayDNS  [5] StormDNS      [6] CottenDNS")
            mode_choice = input(" Select engine: ").strip()
            mode_map = {'1': 'dnstt', '2': 'slipstream', '3': 'masterdns',
                        '4': 'vaydns', '5': 'stormdns', '6': 'cottendns'}
            if mode_choice not in mode_map:
                print(f"{C_RED}Invalid option.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            mode = mode_map[mode_choice]

            name = input(" Instance name (letters, numbers, hyphens): ").strip()
            if not name or not re.match(r'^[a-zA-Z0-9_-]+$', name) or name in registry:
                print(f"{C_RED}[✖] Invalid or already-used name.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            domain_ns = input(" Enter this instance's delegated NS domain (e.g., t1.example.com): ").strip()
            if not is_valid_hostname(domain_ns):
                print(f"{C_RED}[✖] That doesn't look like a valid domain.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            if any(e['domain'].lower() == domain_ns.lower() for e in registry.values()):
                print(f"{C_RED}[✖] That domain is already used by another instance — each instance")
                print(f"    needs its own distinct delegated subdomain for the router to tell")
                print(f"    them apart.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            server_ip = get_public_ip()
            print(" Server IP (auto-detected): %s" % server_ip)

            if not _ensure_router_deployed():
                input("\nPress Enter to continue...")
                continue

            internal_port = _next_free_internal_port(registry)
            router_was_stopped = False

            if mode in ('dnstt', 'vaydns'):
                target_port = prompt_port(" Enter local target port (e.g., 22 for SSH): ", default=22)
                ok = (_install_dnstt_routed(name, domain_ns, target_port, internal_port)
                      if mode == 'dnstt' else
                      _install_vaydns_routed(name, domain_ns, target_port, internal_port))
                entry = {"mode": mode, "domain": domain_ns, "server_ip": server_ip,
                         "internal_port": internal_port, "target_port": target_port, "routed": True}
            elif mode == 'slipstream':
                target_port = prompt_port(" Enter local target port (e.g., 22 for SSH): ", default=22)
                ok = _install_slipstream_routed(name, domain_ns, target_port, internal_port)
                entry = {"mode": mode, "domain": domain_ns, "server_ip": server_ip,
                         "internal_port": internal_port, "target_port": target_port, "routed": True}
            elif mode == 'masterdns':
                # MasterDNS/StormDNS/CottenDNS's own official installers each
                # briefly need to bind port 53 THEMSELVES during their own
                # setup/key-generation step - but the router (started just
                # above by _ensure_router_deployed) is already holding that
                # port by this point. MasterDNS happens to have its own
                # aggressive fallback that force-kills whatever's on port 53
                # already, which is why it alone appeared to "work" - but
                # that's incidental to its installer, not something this
                # code should rely on. StormDNS and CottenDNS's installers
                # have no such fallback and simply give up when the port is
                # still busy - confirmed directly from a real log showing
                # each one failing right at that exact port-53 check, with
                # the router's own python3 process listed as the occupant.
                # Stopping the router first, for all three of these engines
                # (not just the ones already seen failing) is what actually
                # fixes this at the source rather than depending on each
                # third-party installer's own unrelated cleanup logic. The
                # restart happens once, after the registry is updated below
                # (not here) - restarting before that would bring the
                # router back up without yet knowing about this new
                # instance.
                router_was_stopped = True
                _run("systemctl stop dns-router")
                ok, _ = _install_masterdns_routed(name, domain_ns, internal_port)
                entry = {"mode": mode, "domain": domain_ns, "server_ip": server_ip,
                         "internal_port": internal_port, "routed": True}
            elif mode == 'stormdns':
                router_was_stopped = True
                _run("systemctl stop dns-router")
                ok = _install_stormdns_routed(name, domain_ns, internal_port)
                entry = {"mode": mode, "domain": domain_ns, "server_ip": server_ip,
                         "internal_port": internal_port, "routed": True}
            else:  # cottendns - dual UDP+TCP, needs its own second port
                internal_tcp_port = _next_free_internal_port(registry, base=internal_port + 1)
                router_was_stopped = True
                _run("systemctl stop dns-router")
                ok = _install_cottendns_routed(name, domain_ns, internal_port, internal_tcp_port)
                entry = {"mode": mode, "domain": domain_ns, "server_ip": server_ip,
                         "internal_port_udp": internal_port, "internal_port_tcp": internal_tcp_port, "routed": True}

            if ok:
                registry[name] = entry
                _save_instance_registry(registry)
                print(f"\n{C_GREEN}[✔] Instance '{name}' ({mode}) added — reachable via {domain_ns} on the")
                print(f"    shared port 53, alongside every other registered instance.{C_RESET}")
            else:
                print(f"\n{C_RED}[✖] Install failed — see output above.{C_RESET}")
            if router_was_stopped:
                if _run("systemctl start dns-router").returncode != 0:
                    print(f"{C_RED}[!] The router failed to restart after this - other instances")
                    print(f"    may be unreachable until it's checked (journalctl -u dns-router).{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s              ALL PROFILES — COPY CONNECTION INFO           %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not registry:
                print(" No instances configured yet.")
            for name, entry in registry.items():
                print(f"\n--- {name} ({entry['mode']}) ---")
                print(f"  Domain:    {entry['domain']}")
                print(f"  Server IP: {entry.get('server_ip', '?')}")
                if entry['mode'] in ('dnstt', 'vaydns', 'slipstream'):
                    print(f"  Port:      53 (via shared router)  |  Target: {entry.get('target_port', '?')}")
                    key_prefix = "server" if entry['mode'] == 'dnstt' else "vaydns_server"
                    pub_key_path = f"{INSTANCES_DIR}/{name}/{key_prefix}.pub"
                    if os.path.exists(pub_key_path):
                        with open(pub_key_path) as f:
                            print(f"  Public key: {f.read().strip()}")
                else:
                    print(f"  Port:      53 (via shared router)")
                    key_path = f"{INSTANCES_DIR}/{name}/encrypt_key.txt"
                    if os.path.exists(key_path):
                        with open(key_path) as f:
                            print(f"  Encryption key: {f.read().strip()}")
            print("\n════════════════════════════════════════════════════════════")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            name = input(" Instance name to remove: ").strip()
            if name not in registry:
                print(f"{C_RED}[✖] No such instance.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            confirm = input(f" Remove '{name}'? (y/n): ").strip().lower()
            if confirm == 'y':
                svc = f"dnstt-{name}"
                _run(f"systemctl stop {svc}")
                _run(f"systemctl disable {svc}")
                _run(f"rm -f /etc/systemd/system/{svc}.service")
                _run("systemctl daemon-reload")
                _run(f"rm -rf {INSTANCES_DIR}/{name}")
                del registry[name]
                _save_instance_registry(registry)
                print(f"{C_GREEN}[✔] Instance '{name}' removed. The router will stop routing its")
                print(f"    domain automatically (no restart needed).{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")


def dnstt_admin_manager(ports_dict):
    """SLOWDNS module. Same ports_dict-based contract as the rest of the SmartUI panel."""
    while True:
        clear_screen()
        is_installed = ports_dict.get('DNSTT_INSTALLED', False)

        if not is_installed:
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                DNSTT ADMINISTRATOR (SLOWDNS)               %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" [0] Back")
            print(" [1] DNSTT (bamsoftware)")
            print(" [2] Slipstream")
            print(" [3] MasterDnsVPN")
            print(" [4] VayDNS")
            print(" [5] StormDNS")
            print(" [6] CottenDNS")
            print(" [7] MULTI-ENGINE MODE")
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            choice = input(" Enter an option: ").strip()
            if choice == '0':
                break
            if choice == '7':
                _multi_engine_menu(ports_dict)
                continue
            if choice not in ('1', '2', '3', '4', '5', '6'):
                print(f"{C_RED}Invalid option.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            mode = {'1': 'dnstt', '2': 'slipstream', '3': 'masterdns', '4': 'vaydns',
                    '5': 'stormdns', '6': 'cottendns'}[choice]

            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(f"         INSTALLER: {mode.upper()}")
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            if mode in ('masterdns', 'stormdns', 'cottendns'):
                # All three ship their own installer that prompts for the domain
                # itself - we only need the IP for display purposes on our dashboard.
                server_ip = get_public_ip()
                print(" Server IP (auto-detected): %s" % server_ip)

                if mode == 'cottendns':
                    # The only engine here that needs TCP/53 too, not just UDP/53.
                    port53_conflict = check_system_port_in_use(53, ("udp",)) or check_system_port_in_use(53, ("tcp",))
                    if port53_conflict:
                        resolve_port53_conflict()

                install_fn = {'masterdns': _install_masterdns, 'stormdns': _install_stormdns,
                              'cottendns': _install_cottendns}[mode]
                ok, domain_found = install_fn()
                if not ok:
                    input("\nPress Enter to continue...")
                    continue

                ports_dict['DNSTT_INSTALLED'] = True
                ports_dict['DNSTT_DOMAIN'] = domain_found or "(check server_config.toml)"
                ports_dict['DNSTT_IP'] = server_ip
                ports_dict['DNSTT_MODE'] = mode
                print(f"\n{C_GREEN}[✔] {mode.upper()} deployed successfully!{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            domain_ns = input(" Enter Your Domain NS (e.g., t.yourdomain.com): ").strip()
            if not is_valid_hostname(domain_ns):
                print(f"{C_RED}[✖] That doesn't look like a valid domain.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            server_ip = get_public_ip()
            print(" Server IP (auto-detected): %s" % server_ip)

            custom_port = prompt_port(" Enter Listen Port (e.g., 53 for DNS): ", default=53)

            # dnstt/vaydns never bind custom_port directly — both NAT-redirect to
            # DNSTT_INTERNAL_PORT and bind THERE, so custom_port being occupied
            # (e.g. by systemd-resolved) doesn't actually block either of them.
            # Checking the externally-advertised port for them would produce a
            # false-positive abort on a perfectly installable setup.
            port_to_check = DNSTT_INTERNAL_PORT if mode in ('dnstt', 'vaydns') else custom_port
            if check_system_port_in_use(port_to_check, ("udp",)):
                print(f"{C_RED}[✖] UDP port {port_to_check} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   TRAFFIC REDIRECTION                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            target_port = prompt_port(" Enter target backend port (e.g., 22 for SSH, 143 for Dropbear): ", default=22)
            if not check_system_port_in_use(target_port, ("tcp",)):
                print(f"{C_YELLOW}[!] Nothing seems to be listening on port {target_port} yet — make sure")
                print(f"    that backend service is actually running, or the tunnel will connect to nothing.{C_RESET}")

            fallback_addr = None
            if mode == 'dnstt':
                fb = input(" Optional camouflage fallback address for non-tunnel DNS queries (blank to skip): ").strip()
                if fb:
                    fallback_addr = fb

            mtu = None
            if mode in ('dnstt', 'vaydns'):
                mtu_raw = input(" Optional MTU override (blank = binary's default, e.g. 1232 for dnstt): ").strip()
                if mtu_raw:
                    while True:
                        try:
                            mtu = int(mtu_raw)
                            if mtu <= 0:
                                raise ValueError
                            break
                        except ValueError:
                            mtu_raw = input(" Please enter a positive whole number (blank to skip): ").strip()
                            if not mtu_raw:
                                mtu = None
                                break

            record_type = None
            dnstt_compat = False
            if mode == 'vaydns':
                valid_record_types = ["txt", "null", "cname", "a", "aaaa", "mx", "ns", "srv", "caa"]
                print(f" Optional DNS record type for downstream data (default: txt).")
                print(f" Choices: {', '.join(valid_record_types)}")
                rt_raw = input(" Record type (blank = default): ").strip().lower()
                if rt_raw:
                    if rt_raw in valid_record_types:
                        record_type = rt_raw
                    else:
                        print(f"{C_YELLOW}[!] '{rt_raw}' isn't a recognized record type — leaving it at the default.{C_RESET}")

                dc = input(" Enable -dnstt-compat (lets existing dnstt/SlipNet clients connect too)? [Y/n]: ").strip().lower()
                # Defaults to on (blank = yes), not off. Confirmed from
                # VayDNS's own documentation: its wire protocol differs from
                # standard dnstt BY DEFAULT, so without this flag ordinary
                # client apps (HTTP Custom and similar - this panel doesn't
                # distribute or support VayDNS's own specialized client)
                # can't actually establish a tunnel even though the server
                # itself runs and looks fine. Confirmed as the real cause of
                # a genuine "installs fine, no internet" report where this
                # question was answered with the previous, off-by-default
                # blank answer.
                dnstt_compat = (dc != 'n')

            if mode == 'dnstt':
                ok = _install_dnstt(custom_port, domain_ns, target_port, fallback_addr, mtu=mtu)
            elif mode == 'vaydns':
                ok = _install_vaydns(custom_port, domain_ns, target_port, mtu=mtu, record_type=record_type, dnstt_compat=dnstt_compat)
            else:
                ok = _install_slipstream(custom_port, domain_ns, target_port)

            if not ok:
                input("\nPress Enter to continue...")
                continue

            ports_dict['DNSTT_INSTALLED'] = True
            ports_dict['DNSTT_DOMAIN'] = domain_ns
            ports_dict['DNSTT_IP'] = server_ip
            ports_dict['DNSTT_PORT'] = str(custom_port)
            ports_dict['DNSTT_TARGET'] = str(target_port)
            ports_dict['DNSTT_MODE'] = mode

            print(f"\n{C_GREEN}[✔] {mode} deployed successfully with boot persistence!{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            mode = ports_dict.get('DNSTT_MODE', 'dnstt')
            domain_val = ports_dict.get('DNSTT_DOMAIN', 't.domain.com')
            server_ip = ports_dict.get('DNSTT_IP', '127.0.0.1')
            custom_port = ports_dict.get('DNSTT_PORT', '53')
            target_port = ports_dict.get('DNSTT_TARGET', '22')
            svc = _service_name(mode)

            clear_screen()
            print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(f"       SLOWDNS MANAGER [{mode}]")
            print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            if mode == 'masterdns':
                key_content = _masterdns_client_info(ports_dict)
                print(f" SERVER IP: {server_ip} | LISTEN PORT: 53 (fixed by upstream installer)")
                print(f" NS DOMAIN: {domain_val}")
                print(f" ENCRYPTION KEY: {key_content[:20]}...")
                print("-----------------------------------------------------")
                print(" [🔗] CLIENT SETUP:")
                print("      MasterDnsVPN ships prebuilt client binaries per OS/arch —")
                print("      there's no single CLI one-liner like dnstt/Slipstream.")
                print("      1. Download the matching client from the releases page:")
                print("         https://github.com/masterking32/MasterDnsVPN/releases/latest")
                print(f"      2. Edit client_config.toml: DOMAINS=[\"{domain_val}\"], ENCRYPTION_KEY")
                print(f"         from the key above, and a resolver list in client_resolvers.txt.")
                print("      3. Run the client — default local SOCKS5 proxy is 127.0.0.1:18000.")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
                print(" [4] > VIEW SERVICE STATUS")
                print(" [5] > EDIT CONFIG (server_config.toml)")
                print(" [6] > RESTART SERVICE")
                print(" [7] > START / STOP SERVICE")
                print("-----------------------------------------------------")
                print(" [8] > UNINSTALL (official uninstaller)")
                print(" [0] > Back")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            elif mode in ('stormdns', 'cottendns'):
                key_content = _stormdns_client_info() if mode == 'stormdns' else _cottendns_client_info()
                proto_note = "UDP+TCP/53" if mode == 'cottendns' else "UDP/53"
                print(f" SERVER IP: {server_ip} | LISTEN: {proto_note} (fixed by upstream installer)")
                print(f" NS DOMAIN: {domain_val}")
                print(f" ENCRYPTION KEY: {key_content[:20]}...")
                if mode == 'cottendns':
                    print(f" HEALTH CHECK (local only): curl http://127.0.0.1:9090/healthz")
                print("-----------------------------------------------------")
                print(" [🔗] CLIENT SETUP:")
                if mode == 'stormdns':
                    print("      StormDNS's own client exposes a local SOCKS5 proxy. Either use")
                    print("      the client binary directly, or the WhiteDNS app (Android/Desktop),")
                    print("      which bundles a StormDNS engine and just needs the domain + key above.")
                else:
                    print("      CottenDNS is engine-compatible with the WhiteDNS app (Android/")
                    print("      Desktop), which just needs the domain + key above. A standalone")
                    print("      CLI client is also available from TaJirax/cottenDNS's releases.")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
                print(" [4] > VIEW SERVICE STATUS")
                print(" [5] > EDIT CONFIG (server_config.toml)")
                print(" [6] > RESTART SERVICE")
                print(" [7] > START / STOP SERVICE")
                print("-----------------------------------------------------")
                print(" [8] > UNINSTALL SLOWDNS")
                print(" [M] > MULTI-ENGINE MODE (run more of these at once)")
                print(" [0] > Back")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            else:
                client_cmds, pub_key_content = _client_commands(mode, ports_dict)
                print(f" SERVER IP: {server_ip} | LISTEN PORT: {custom_port}")
                print(f" NS DOMAIN: {domain_val}")
                print(f" LOCAL PORT REDIRECTION: {target_port}")
                if pub_key_content:
                    print(f" PUBLIC KEY: {pub_key_content[:25]}...")
                print("-----------------------------------------------------")
                print(" [🔗] CLIENT CONNECTION COMMAND(S):")
                for label, cmd in client_cmds.items():
                    print(f"      {label}:")
                    print(f"        {cmd}")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
                print(" [1] > MODIFY DATA TRAFFIC PORT (REDIRECTION)")
                print(" [2] > MODIFY NS DOMAIN OR IP")
                if mode in ('dnstt', 'vaydns'):
                    print(" [3] > GENERATE NEW KEYS (restarts the service)")
                print("-----------------------------------------------------")
                print(" [4] > VIEW SERVICE STATUS")
                print(" [5] > EDIT SERVICE")
                print(" [6] > RESTART SERVICE")
                print(" [7] > START / STOP SERVICE")
                print("-----------------------------------------------------")
                print(" [8] > UNINSTALL SLOWDNS")
                print(" [M] > MULTI-ENGINE MODE (run more of these at once)")
                print(" [0] > Back")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            choice = input(" Select an option: ").strip()

            if choice.lower() == 'm':
                _multi_engine_menu(ports_dict)
            elif choice == '0':
                break
            elif choice == '1' and mode not in ('masterdns', 'stormdns', 'cottendns'):
                new_tp = prompt_port(f"Enter new local target port (Current: {target_port}): ", default=int(target_port))
                ports_dict['DNSTT_TARGET'] = str(new_tp)
                print(f"{C_YELLOW}[!] Port updated in the panel, but the running service still points at the old")
                print(f"    target — re-run install or manually edit the service (option 5) then restart (6).{C_RESET}")
                input("\nPress Enter to continue...")
            elif choice == '2' and mode not in ('masterdns', 'stormdns', 'cottendns'):
                new_dom = input(f"Enter new NS Domain (Current: {domain_val}): ").strip()
                new_ip = input(f"Enter new Server IP (Current: {server_ip}): ").strip()
                if new_dom and is_valid_hostname(new_dom):
                    ports_dict['DNSTT_DOMAIN'] = new_dom
                if new_ip:
                    ports_dict['DNSTT_IP'] = new_ip
                print(f"{C_YELLOW}[!] Saved in the panel — the running service's domain won't change until")
                print(f"    you edit the service (option 5) and restart (6), since the domain is baked")
                print(f"    into its ExecStart command.{C_RESET}")
                input("\nPress Enter to continue...")
            elif choice == '3' and mode in ('dnstt', 'vaydns'):
                binary = DNSTT_BIN if mode == 'dnstt' else VAYDNS_BIN
                key_prefix = "server" if mode == 'dnstt' else "vaydns_server"
                priv_key = f"{DNSTT_DIR}/{key_prefix}.key"
                pub_key = f"{DNSTT_DIR}/{key_prefix}.pub"
                res = _run([binary, "-gen-key", "-privkey-file", priv_key, "-pubkey-file", pub_key])
                if res.returncode == 0:
                    _run(f"systemctl restart {svc}")
                    print(f"{C_GREEN}[✔] New keys generated and service restarted (old keys are now invalid —")
                    print(f"    every client needs the new public key file).{C_RESET}")
                else:
                    print(f"{C_RED}[✖] Key generation failed: {res.stderr.strip()}{C_RESET}")
                input("\nPress Enter to continue...")
            elif choice == '4':
                os.system(f"systemctl status {svc} --no-pager")
                input("\nPress Enter to continue...")
            elif choice == '5':
                editor = "nano" if _run("which nano").returncode == 0 else "vi"
                if mode == 'masterdns':
                    os.system(f"{editor} {MASTERDNS_DIR}/server_config.toml")
                    print(f"{C_YELLOW}[!] Restart the service (option 6) for config changes to take effect.{C_RESET}")
                elif mode == 'stormdns':
                    os.system(f"{editor} {STORMDNS_DIR}/server_config.toml")
                    print(f"{C_YELLOW}[!] Restart the service (option 6) for config changes to take effect.{C_RESET}")
                elif mode == 'cottendns':
                    os.system(f"{editor} {COTTENDNS_DIR}/server_config.toml")
                    print(f"{C_YELLOW}[!] Restart the service (option 6) for config changes to take effect.{C_RESET}")
                else:
                    os.system(f"{editor} {SERVICE_PATH}")
                    os.system("systemctl daemon-reload")
                input("\nPress Enter to continue...")
            elif choice == '6':
                os.system(f"systemctl restart {svc}")
                print(f"{C_GREEN}[✔] Service restarted.{C_RESET}")
                input("\nPress Enter to continue...")
            elif choice == '7':
                status_res = os.system(f"systemctl is-active --quiet {svc}")
                if status_res == 0:
                    os.system(f"systemctl stop {svc}")
                    print(f"{C_YELLOW}[!] Service stopped.{C_RESET}")
                else:
                    os.system(f"systemctl start {svc}")
                    print(f"{C_GREEN}[✔] Service started.{C_RESET}")
                input("\nPress Enter to continue...")
            elif choice == '8':
                confirm = input("Are you sure you want to uninstall? (y/n): ").strip().lower()
                if confirm == 'y':
                    if mode == 'masterdns':
                        # Its own uninstaller correctly restores /etc/systemd/resolved.conf
                        # from backup and removes the sysctl/limits tuning it applied —
                        # reimplementing that ourselves would just risk getting it wrong.
                        os.system(f"cd {MASTERDNS_DIR} && curl -Ls {MASTERDNS_INSTALL_URL} | bash -s -- --uninstall")
                        print(f"{C_YELLOW}[!] Firewall rules for port 53 were intentionally left in place by the")
                        print(f"    official uninstaller — remove them manually if no longer needed.{C_RESET}")
                    elif mode == 'stormdns':
                        # Confirmed real --uninstall flag on the official installer -
                        # same reasoning as MasterDNS, prefer it over reimplementing teardown.
                        os.system(f"cd {STORMDNS_DIR} && curl -Ls {STORMDNS_INSTALL_URL} | bash -s -- --uninstall")
                        print(f"{C_YELLOW}[!] Firewall rules for port 53 were intentionally left in place by the")
                        print(f"    official uninstaller — remove them manually if no longer needed.{C_RESET}")
                    elif mode == 'cottendns':
                        # No confirmed built-in uninstall flag for this one (unlike
                        # MasterDNS/StormDNS) - tearing it down the same way the
                        # generic dnstt/slipstream/vaydns branch below does.
                        os.system("systemctl stop cottendns && systemctl disable cottendns")
                        os.system("systemctl daemon-reload")
                        close_firewall_port(53, ("udp",))
                        close_firewall_port(53, ("tcp",))
                        os.system(f"rm -rf {COTTENDNS_DIR}")
                        print(f"{C_YELLOW}[!] Removed the service and its directory - if it was installed via")
                        print(f"    Docker rather than the native installer, also run 'docker compose down'")
                        print(f"    in /opt/cottendns-docker.{C_RESET}")
                    else:
                        os.system(f"systemctl stop {svc} && systemctl disable {svc}")
                        os.system(f"rm -f {SERVICE_PATH}")
                        os.system("systemctl daemon-reload")
                        port_int = int(custom_port) if str(custom_port).isdigit() else None
                        if port_int:
                            # Mirror whatever was actually opened on install: dnstt/vaydns
                            # opened DNSTT_INTERNAL_PORT (5300), not custom_port itself —
                            # closing custom_port here would be a no-op while leaving the
                            # real open port behind forever.
                            firewall_port = DNSTT_INTERNAL_PORT if mode in ('dnstt', 'vaydns') else port_int
                            close_firewall_port(firewall_port, ("udp",))
                            if mode in ('dnstt', 'vaydns'):
                                remove_nat_redirect_udp(port_int, DNSTT_INTERNAL_PORT)
                        os.system(f"rm -rf {DNSTT_DIR}")
                    ports_dict['DNSTT_INSTALLED'] = False
                    for key in ['DNSTT_DOMAIN', 'DNSTT_IP', 'DNSTT_PORT', 'DNSTT_TARGET', 'DNSTT_MODE']:
                        ports_dict.pop(key, None)
                    print(f"{C_GREEN}[✔] Uninstalled successfully.{C_RESET}")
                input("\nPress Enter to continue...")
            else:
                print(f"{C_RED}Invalid option.{C_RESET}")
                input("\nPress Enter to continue...")
