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
import time
import shutil
import subprocess
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port,
    nat_redirect_udp, remove_nat_redirect_udp, persist_firewall_rules,
    is_valid_hostname, resolve_port53_conflict, get_public_ip,
    install_iptables_persistent,
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

# NoiseDNS / NoizDNS (anonvector/noizdns-deploy). Verified directly from the
# real deploy script (noizdns-deploy.sh) AND from the binary's own --help
# output (captured after a real crash-loop - see _install_noizdns_routed()'s
# docstring): it downloads the same dnstt-server binary (SHA256-verified
# prebuilt release, not bamsoftware's own go-install path), but unlike every
# other engine here, it takes NO CLI flags for its bind port or upstream
# target - it only runs in Tor's pluggable-transport managed mode, entirely
# via TOR_PT_* environment variables (see _write_routed_service()'s
# env_lines). That part IS required and IS replicated (via systemd
# Environment= directives, not a shell env-var prefix on ExecStart, which
# doesn't work). What's deliberately NOT replicated is noizdns-deploy.sh's
# own separate Dante SOCKS proxy + flat users.txt account file that it
# additionally stands up and points the tunnel at - TOR_PT_ORPORT is pointed
# straight at a local target port instead, same as every other engine here,
# so this panel's own existing credential model still applies rather than
# introducing a second, parallel user database just for this one engine.
NOIZDNS_DIR = "/etc/noizdns"
NOIZDNS_BIN = "/usr/local/bin/noizdns-server"
NOIZDNS_RELEASES_API = "https://api.github.com/repos/anonvector/noizdns-deploy/releases/latest"
NOIZDNS_DEFAULT_MTU = 1232

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
import selectors
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
        if not entry.get("domain"):
            continue
        suffix = entry["domain"].lower().rstrip(".")
        if qname_lower == suffix or qname_lower.endswith("." + suffix):
            if len(suffix) > best_len:
                best_len, best_match = len(suffix), name
    return best_match


slip_backends = {}   # instance name -> {"sock", "port", "pending": {txid: (client_addr, orig_txid, t)}, "next": int}
slip_by_fd = {}      # backend socket fileno -> instance name
SLIP_PENDING_TTL = 15.0

oneshot_sockets = {}  # backend socket fileno -> socket object - every OTHER engine
oneshot_meta = {}     # backend socket fileno -> (client_addr, created_at)
ONESHOT_TIMEOUT = 5.0
ONESHOT_MAX = 4000    # hard cap so a query flood can never exhaust file descriptors

selector = None       # selectors.DefaultSelector (epoll), created in udp_loop()


def _register(sock_obj, kind, ref):
    try:
        selector.register(sock_obj, selectors.EVENT_READ, (kind, ref))
        return True
    except Exception as e:
        print("dns-router: could not register socket with selector: %s" % e)
        return False


def _unregister(sock_obj):
    try:
        selector.unregister(sock_obj)
    except Exception:
        pass


def _close_slip_backend(instance):
    be = slip_backends.pop(instance, None)
    if be is None:
        return
    slip_by_fd.pop(be["sock"].fileno(), None)
    _unregister(be["sock"])
    try:
        be["sock"].close()
    except Exception:
        pass


def _get_slip_backend(instance, internal_port):
    # Slipstream (QUIC over DNS) gets exactly ONE long-lived UDP socket per
    # instance, shared by every client/resolver, with the DNS transaction ID
    # rewritten per query so each reply can be matched back to the resolver
    # that asked. This is the same multiplexing design SlipGate's own router
    # uses. The previous design opened one backend socket per resolver
    # source address:port - and real recursive resolvers use a fresh source
    # port for nearly every query, so sockets piled up (120 s idle timeout
    # each) until the process hit select()'s hard 1024-descriptor limit; from
    # that moment the whole UDP loop spun on an exception and NO engine
    # answered at all. The Slipstream server itself does not care which UDP
    # source address a query comes from (it swaps in a dummy peer address and
    # remembers the real one per query), so one socket is both safe and
    # sufficient.
    be = slip_backends.get(instance)
    if be is not None and be["port"] != internal_port:
        _close_slip_backend(instance)
        be = None
    if be is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setblocking(False)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
        except Exception:
            pass
        try:
            s.connect(("127.0.0.1", internal_port))
        except Exception as e:
            print("dns-router: cannot connect backend socket for '%s' (127.0.0.1:%s): %s" % (instance, internal_port, e))
            try:
                s.close()
            except Exception:
                pass
            return None
        be = {"sock": s, "port": internal_port, "pending": {}, "next": 0}
        if not _register(s, "slip", instance):
            s.close()
            return None
        slip_backends[instance] = be
        slip_by_fd[s.fileno()] = instance
        print("dns-router: slipstream backend socket opened for instance '%s' -> 127.0.0.1:%s" % (instance, internal_port))
    return be


def _forward_slipstream(instance, internal_port, data, client_addr):
    if len(data) < 12:
        return
    be = _get_slip_backend(instance, internal_port)
    if be is None:
        return
    pending = be["pending"]
    txid = None
    for _ in range(65536):
        be["next"] = (be["next"] + 1) & 0xFFFF
        if be["next"] not in pending:
            txid = be["next"]
            break
    if txid is None:
        print("dns-router: pending TXID space exhausted for '%s', dropping query from %s" % (instance, client_addr))
        return
    orig_txid = (data[0] << 8) | data[1]
    pending[txid] = (client_addr, orig_txid, time.monotonic())
    packet = bytes([txid >> 8, txid & 0xFF]) + data[2:]
    try:
        be["sock"].send(packet)
    except Exception as e:
        # Typically ConnectionRefusedError while the engine is restarting.
        # Drop this one query (the client retries); keep the socket.
        pending.pop(txid, None)
        print("dns-router: failed to forward packet to instance '%s' (127.0.0.1:%s): %s" % (instance, internal_port, e))


def _drain_slip_backend(main_sock, instance):
    be = slip_backends.get(instance)
    if be is None:
        return
    for _ in range(512):
        try:
            resp = be["sock"].recv(65535)
        except BlockingIOError:
            break
        except ConnectionRefusedError:
            continue
        except OSError as e:
            print("dns-router: read error on slipstream backend '%s': %s" % (instance, e))
            break
        if len(resp) < 2:
            continue
        txid = (resp[0] << 8) | resp[1]
        item = be["pending"].pop(txid, None)
        if item is None:
            continue  # stale or duplicate answer
        client_addr, orig_txid, _t = item
        out = bytes([orig_txid >> 8, orig_txid & 0xFF]) + resp[2:]
        try:
            main_sock.sendto(out, client_addr)
        except Exception:
            pass


# --- Pass-through multiplexing (non-DNS UDP protocols sharing port 53) -------
# Any UDP protocol that is not a registered DNS tunnel can share port 53:
# the packet is classified by (1) its DNS domain - existing engines, then
# (2) an existing per-client session, then (3) a protocol signature, and
# finally (4) the single "catch-all" backend (for protocols whose packets
# look like random noise, e.g. Hysteria2 with Salamander obfuscation).
pt_sessions = {}    # client_addr -> {"name", "port", "sock", "last"}
PT_IDLE = float(os.environ.get("DNS_ROUTER_PT_IDLE", "300"))
PT_MAX = 3000       # hard cap on concurrent pass-through client sessions
_prefix_cache = {}


def sig_match(sig, data):
    kind = sig.get("type")
    if kind == "wireguard":
        # Handshake initiation: type 1, three zero bytes, exactly 148 bytes.
        return len(data) == 148 and data[0] == 1 and data[1:4] == bytes(3)
    if kind == "openvpn":
        # P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7, key id 0 -> 0x38) /
        # _V3 (opcode 10 -> 0x50): the opcode byte stays unencrypted, even
        # with tls-auth / tls-crypt.
        return len(data) >= 14 and data[0] in (0x38, 0x50)
    if kind == "quic":
        # QUIC Initial: long header + fixed bit, non-zero version, and the
        # packet is padded to >= 1200 bytes by the protocol. The size floor
        # also keeps stray small DNS packets from opening sessions.
        return len(data) >= 1200 and (data[0] & 0xC0) == 0xC0 and data[1:5] != bytes(4)
    if kind == "prefix":
        hexstr = sig.get("hex", "")
        pref = _prefix_cache.get(hexstr)
        if pref is None:
            try:
                pref = bytes.fromhex(hexstr)
            except ValueError:
                pref = b""
            _prefix_cache[hexstr] = pref
        return bool(pref) and data.startswith(pref)
    return False


def pick_passthrough(data, registry):
    catch_all = None
    for name, entry in registry.items():
        if entry.get("mode") != "passthrough":
            continue
        sig = entry.get("signature")
        if sig:
            if sig_match(sig, data):
                return name
        elif entry.get("catch_all"):
            catch_all = name
    return catch_all


def _pt_close(client_addr):
    s = pt_sessions.pop(client_addr, None)
    if s is None:
        return
    _unregister(s["sock"])
    try:
        s["sock"].close()
    except Exception:
        pass


def _pt_forward(name, entry, data, client_addr):
    port = entry.get("internal_port")
    if not port:
        return
    s = pt_sessions.get(client_addr)
    if s is not None and (s["name"] != name or s["port"] != port):
        _pt_close(client_addr)
        s = None
    if s is None:
        if len(pt_sessions) >= PT_MAX:
            return
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.setblocking(False)
        try:
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        except Exception:
            pass
        try:
            sk.connect((entry.get("host", "127.0.0.1"), port))
        except Exception as e:
            print("dns-router: pass-through '%s': cannot reach backend port %s: %s" % (name, port, e))
            sk.close()
            return
        if not _register(sk, "pt", client_addr):
            sk.close()
            return
        s = {"name": name, "port": port, "sock": sk, "last": time.monotonic(), "replied": False}
        pt_sessions[client_addr] = s
        print("dns-router: pass-through session %s -> '%s' (127.0.0.1:%s)" % (client_addr, name, port))
    s["last"] = time.monotonic()
    try:
        s["sock"].send(data)
    except Exception:
        pass  # backend restarting; the client retransmits


def _pt_drain(main_sock, client_addr):
    s = pt_sessions.get(client_addr)
    if s is None:
        return
    for _ in range(256):
        try:
            resp = s["sock"].recv(65535)
        except BlockingIOError:
            break
        except ConnectionRefusedError:
            continue
        except OSError:
            break
        s["last"] = time.monotonic()
        s["replied"] = True
        try:
            main_sock.sendto(resp, client_addr)
        except Exception:
            pass


def _looks_like_dns_query(data):
    # Standard query only: QR=0, opcode 0, exactly one question.
    return len(data) >= 17 and (data[2] & 0xF8) == 0 and data[4] == 0 and data[5] == 1



def handle_udp_datagram(sock, data, client_addr, registry):
    # Dispatch order: (1) DNS tunnel by delegated domain, (2) existing
    # pass-through session for this client, (3) protocol signature or the
    # catch-all backend. DNS is checked FIRST so a real tunnel's resolver can
    # never be captured by a pass-through session.
    instance = None
    qname = None
    if _looks_like_dns_query(data):
        qname = parse_qname(data)
        instance = find_matching_instance(qname, registry)
    if not instance:
        sess = pt_sessions.get(client_addr)
        if sess is not None:
            pe = registry.get(sess["name"])
            if pe is None or pe.get("mode") != "passthrough":
                _pt_close(client_addr)
            elif sess["replied"]:
                # Sticky only once the backend has actually answered - until
                # then every packet is re-classified, so a first packet that
                # merely LOOKED like some signature (random noise from an
                # obfuscated protocol can) cannot trap the client on the
                # wrong backend.
                _pt_forward(sess["name"], pe, data, client_addr)
                return
        pname = pick_passthrough(data, registry)
        if pname:
            _pt_forward(pname, registry[pname], data, client_addr)
            return
        # Logged (not silently dropped): traffic reaching the router but
        # matching nothing is the most useful line for diagnosing "client
        # connects, nothing happens".
        print("dns-router: no matching instance for qname=%r from %s (registered domains: %s)" % (
            qname, client_addr, [e.get("domain") for e in registry.values() if e.get("domain")]))
        return
    entry = registry[instance]
    internal_port = entry.get("internal_port_udp") or entry.get("internal_port")
    if not internal_port:
        print("dns-router: instance '%s' matched but has no internal_port in its registry entry" % instance)
        return

    if entry.get("mode") == "slipstream":
        _forward_slipstream(instance, internal_port, data, client_addr)
        return

    # Every other engine (dnstt, vaydns, masterdns, stormdns, cottendns,
    # noizdns) is stateless at the UDP layer: a fresh non-blocking backend
    # socket per packet, closed as soon as its one response comes back (or
    # on timeout). Capped so a flood can never exhaust descriptors.
    if len(oneshot_sockets) >= ONESHOT_MAX:
        return
    backend_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    backend_sock.setblocking(False)
    try:
        backend_sock.sendto(data, ("127.0.0.1", internal_port))
    except Exception as e:
        print("dns-router: failed to forward packet to instance '%s' (127.0.0.1:%s): %s" % (instance, internal_port, e))
        try:
            backend_sock.close()
        except Exception:
            pass
        return
    fd = backend_sock.fileno()
    if not _register(backend_sock, "oneshot", fd):
        backend_sock.close()
        return
    oneshot_sockets[fd] = backend_sock
    oneshot_meta[fd] = (client_addr, time.monotonic())


def _close_oneshot(fd):
    sock_obj = oneshot_sockets.pop(fd, None)
    oneshot_meta.pop(fd, None)
    if sock_obj is not None:
        _unregister(sock_obj)
        try:
            sock_obj.close()
        except Exception:
            pass


def udp_loop(registry_ref):
    """Single-threaded, epoll-based event loop for ALL UDP traffic - client
    queries and backend responses. epoll (via selectors) instead of
    select.select() because select() raises ValueError for any descriptor
    number >= 1024, which the old loop swallowed in a bare except and then
    spun forever without serving a single packet."""
    global selector
    selector = selectors.DefaultSelector()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Large buffers: DNS tunnels need hundreds-to-thousands of small packets
    # per second; at the stock ~212KB default a short burst overflows the
    # receive queue and packets are dropped before this loop sees them.
    # (Actual size is capped by net.core.rmem_max/wmem_max - see the sysctl
    # bump in _apply_speed_tuning().)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
    except Exception:
        pass
    sock.bind(("0.0.0.0", 53))
    sock.setblocking(False)
    selector.register(sock, selectors.EVENT_READ, ("main", None))
    print("dns-router UDP listening on 0.0.0.0:53")

    next_expiry_check = time.monotonic() + 2.0

    while True:
        try:
            events = selector.select(2.0)
        except Exception as e:
            print("dns-router: selector error: %s" % e)
            time.sleep(0.2)
            continue

        for key, _mask in events:
            kind, ref = key.data
            try:
                if kind == "main":
                    for _ in range(512):
                        try:
                            data, client_addr = sock.recvfrom(65535)
                        except BlockingIOError:
                            break
                        except Exception:
                            break
                        try:
                            handle_udp_datagram(sock, data, client_addr, registry_ref[0])
                        except Exception as e:
                            print("dns-router: error handling packet from %s: %s" % (client_addr, e))
                elif kind == "slip":
                    _drain_slip_backend(sock, ref)
                elif kind == "pt":
                    _pt_drain(sock, ref)
                else:  # oneshot
                    fd = ref
                    client_addr, _ = oneshot_meta.get(fd, (None, None))
                    sock_obj = oneshot_sockets.get(fd)
                    if sock_obj is not None:
                        try:
                            response, _ = sock_obj.recvfrom(65535)
                            if client_addr is not None:
                                sock.sendto(response, client_addr)
                        except Exception:
                            pass
                    _close_oneshot(fd)
            except Exception as e:
                print("dns-router: event handler error: %s" % e)

        now = time.monotonic()
        if now >= next_expiry_check:
            next_expiry_check = now + 2.0
            for fd in list(oneshot_meta.keys()):
                _, created_at = oneshot_meta.get(fd, (None, now))
                if now - created_at > ONESHOT_TIMEOUT:
                    _close_oneshot(fd)
            live = registry_ref[0]
            for caddr in list(pt_sessions.keys()):
                ps = pt_sessions.get(caddr)
                if ps is None:
                    continue
                if now - ps["last"] > PT_IDLE or ps["name"] not in live:
                    _pt_close(caddr)
            for instance in list(slip_backends.keys()):
                be = slip_backends.get(instance)
                if be is None:
                    continue
                # Instance removed from the registry -> release its socket.
                if instance not in live:
                    _close_slip_backend(instance)
                    continue
                stale = [t for t, v in be["pending"].items() if now - v[2] > SLIP_PENDING_TTL]
                for t in stale:
                    be["pending"].pop(t, None)


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
            print("dns-router (TCP): no matching instance for qname=%r (registered domains: %s)" % (
                qname, [e.get("domain") for e in registry.values()]))
            return

        internal_port = registry[instance].get("internal_port_tcp") or registry[instance].get("internal_port")
        if not internal_port:
            print("dns-router (TCP): instance '%s' matched but has no internal_port_tcp/internal_port" % instance)
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


def _apply_speed_tuning():
    """"Very fast and stable" - not a literal always-increasing ratchet
    (there's no real congestion-control layer to ratchet for a plain UDP
    tunnel like dnstt/VayDNS/NoiseDNS - forcing one up regardless of real
    network conditions just means more loss/retransmission, i.e. LESS
    stable), but a set of standard, safe, real kernel-level tunings for a VPS
    that's pushing a lot of small UDP packets/sec plus a fair amount of TCP
    (SSH, the backend services every engine here tunnels to). Idempotent and
    persisted via sysctl.d so it survives reboot; safe to call from every
    single install path (single-instance dnstt/vaydns/noizdns AND the
    Multi-Engine router), not just once.

    - rmem/wmem max+default: raises the ceiling SO_RCVBUF/SO_SNDBUF (set in
      the router script's udp_loop(), and worth setting on any engine binary
      that supports it) are capped at - most stock distros cap this well
      under 1MB, which silently truncates a larger request down to whatever
      the ceiling allows, causing burst packet loss under load that looks
      identical to "slow tunnel" from a client's perspective.
    - netdev_max_backlog: raises how many packets the kernel will queue for
      the router process before dropping them when packets arrive faster
      than a single-threaded Python process can drain its socket - directly
      relevant here since this is genuinely a single process handling every
      engine's UDP traffic at once.
    - udp_rmem_min/udp_wmem_min: raises the PER-SOCKET floor specifically for
      UDP (separate from the general rmem/wmem knobs above), since a high
      packet rate on a single UDP socket is exactly this router's situation.
    - tcp_congestion_control=bbr + default_qdisc=fq: BBR is the standard,
      widely-deployed throughput/latency improvement over the kernel's
      default (usually cubic) - it matters here for CottenDNS's TCP side and
      for every backend service these tunnels forward into (SSH, Dropbear,
      etc.), not for the DNS-tunnel UDP hop itself. `fq` is BBR's documented
      companion qdisc; modprobe'd first since some kernels don't load
      tcp_bbr by default. If the running kernel doesn't support it, this
      fails safe - the sysctl write is skipped and everything else here
      still applies."""
    sysctl_conf = "/etc/sysctl.d/99-dnstt-speed.conf"
    lines = [
        "net.core.rmem_max = 16777216",
        "net.core.wmem_max = 16777216",
        "net.core.rmem_default = 8388608",
        "net.core.wmem_default = 8388608",
        "net.core.netdev_max_backlog = 5000",
        "net.ipv4.udp_rmem_min = 16384",
        "net.ipv4.udp_wmem_min = 16384",
    ]

    _run("modprobe tcp_bbr")
    available = _run("sysctl -n net.ipv4.tcp_available_congestion_control").stdout or ""
    if "bbr" in available:
        lines += ["net.core.default_qdisc = fq", "net.ipv4.tcp_congestion_control = bbr"]
    else:
        print(f"{C_YELLOW}[!] This kernel doesn't support BBR congestion control - skipping that")
        print(f"    part of the speed tuning (everything else still applies).{C_RESET}")

    needed = not os.path.exists(sysctl_conf)
    if not needed:
        with open(sysctl_conf) as f:
            existing = f.read()
        needed = any(line not in existing for line in lines)
    if needed:
        with open(sysctl_conf, "w") as f:
            f.write("\n".join(lines) + "\n")
        _run(f"sysctl -p {sysctl_conf}")


def _ensure_router_deployed():
    # Matches the same apt-get install already done before _install_dnstt/
    # _install_vaydns's own firewall calls - without this, an admin who goes
    # straight to Multi-Engine Mode on a fresh VPS (skipping the single-
    # instance path entirely) could lose the router's port-53 rule on
    # reboot if iptables ends up being the active firewall backend, since
    # persist_firewall_rules() can only actually restore rules on boot if
    # this package is present - otherwise it's just a manual-recovery
    # snapshot, not real persistence.
    _run("apt-get update")
    install_iptables_persistent()

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
    service_needs_rewrite = service_created
    if not service_created:
        with open(DNS_ROUTER_SERVICE_PATH) as f:
            existing_service_content = f.read()
        # Confirmed as a major, real bug: Python block-buffers stdout by
        # default whenever it isn't connected to a terminal - exactly the
        # case running under systemd. This script runs an infinite loop and
        # is killed (not exited cleanly) on every restart/stop, so anything
        # it ever printed - including its own unconditional "listening on
        # 0.0.0.0:53" startup message - was sitting in a buffer that never
        # got flushed to the journal at all. journalctl showing nothing was
        # never evidence that nothing was going wrong; it meant NOTHING the
        # script ever did was visible, full stop. Retrofitting existing
        # installs (not just fresh ones) since this masks real diagnosis
        # for anyone who installed before this fix existed.
        if "PYTHONUNBUFFERED" not in existing_service_content:
            service_needs_rewrite = True
        # FIX (reboot-persistence bug, see the new unit template below):
        # retrofit already-installed routers the same way the PYTHONUNBUFFERED
        # check above retrofits already-installed ones - an admin who
        # installed before this fix existed would otherwise never pick it up
        # until they manually reinstalled.
        if "StartLimitIntervalSec" not in existing_service_content:
            service_needs_rewrite = True
        if "LimitNOFILE" not in existing_service_content:
            service_needs_rewrite = True

    if service_needs_rewrite:
        # FIX (reboot-persistence bug): this unit previously had no
        # StartLimitIntervalSec override, and only "After=network.target" for
        # ordering. Confirmed as the real cause of "SLOWDNS always switches
        # off on reboot, only comes back after I open the menu": the ONLY
        # place in this whole module that ever runs `systemctl reset-failed
        # dns-router` is _ensure_router_deployed() above, which only executes
        # when an admin manually opens MULTI-ENGINE MODE. If this unit fails
        # even twice in its first few seconds at boot (a normal race - other
        # services still starting, firewall rules from netfilter-persistent
        # not yet reloaded, etc.), systemd's DEFAULT start-limit (5 restarts/
        # 10s) trips, the unit is marked "failed (start-limit-hit)", and
        # Restart=always stops retrying entirely - forever, until something
        # calls reset-failed. That exactly matches "off after every reboot,
        # fixed only by opening the menu". StartLimitIntervalSec=0 disables
        # that limit for this unit, so Restart=always can retry indefinitely
        # until whatever transient boot-time condition clears - the actual
        # behavior "Restart=always" was meant to provide. Also upgraded the
        # ordering to match the ALREADY-correct pattern _write_service() uses
        # for the single-instance slowdns.service below (network-online.target
        # + netfilter-persistent.service), rather than the weaker bare
        # network.target this router unit had - so it doesn't try to bind
        # port 53 before real connectivity/firewall state is ready either.
        service_content = f"""[Unit]
Description=DNSTT Multi-Engine DNS Router
After=network-online.target remote-fs.target netfilter-persistent.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Environment=DNSTT_REGISTRY={DNSTT_REGISTRY_PATH}
Environment=PYTHONUNBUFFERED=1
LimitNOFILE=65535
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

    _apply_speed_tuning()

    open_firewall_port(53, ("udp", "tcp"))
    persist_firewall_rules()

    # Only force a restart when something actually changed (a new/updated
    # script, or a freshly-created service) - restarting unconditionally
    # every time this runs would disrupt every already-working instance's
    # live sessions each time an admin just opens the menu or views
    # profiles, not only when a genuine update needs picking up.
    if needs_write or service_needs_rewrite:
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


def _noizdns_arch():
    """Same uname -m -> release-asset arch mapping as noizdns-deploy.sh's own
    detect_arch() - verified directly from its source rather than assumed."""
    machine = (_run("uname -m").stdout or "").strip()
    return {
        "x86_64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "armv7l": "arm", "armv6l": "arm",
        "i386": "386", "i686": "386",
    }.get(machine)


def _ensure_noizdns_binary():
    """Downloads and SHA256-verifies the real anonvector/noizdns-deploy
    prebuilt dnstt-server binary for this host's arch, exactly the way
    noizdns-deploy.sh's own download_binary() does it (same RELEASE_URL,
    same per-arch filename, same SHA256SUMS check) - confirmed by cloning
    and reading that script directly rather than guessing at a GitHub
    Releases API shape it doesn't actually use. This is genuinely the SAME
    dnstt-server Go binary already built for DNSTT_BIN above (NoizDNS ships
    no protocol fork of its own) - installed to its own NOIZDNS_BIN path
    anyway so this engine has its own binary/key material and can run
    alongside the plain "DNSTT (bamsoftware)" engine without the two ever
    sharing a file."""
    if _binary_ok(NOIZDNS_BIN):
        return True
    arch = _noizdns_arch()
    if not arch:
        print(f"{C_RED}[✖] Unrecognized CPU architecture for a NoizDNS prebuilt binary.{C_RESET}")
        return False
    filename = f"dnstt-server-linux-{arch}"
    release_url = "https://raw.githubusercontent.com/anonvector/noizdns-deploy/dev/bin"
    tmp_bin = f"/tmp/{filename}"
    dl = _run(["curl", "-fSL", "-o", tmp_bin, f"{release_url}/{filename}"])
    if dl.returncode != 0 or not os.path.exists(tmp_bin):
        print(f"{C_RED}[✖] Could not download the NoizDNS server binary.{C_RESET}")
        return False
    sums = _run(["curl", "-fsSL", f"{release_url}/SHA256SUMS"])
    if sums.returncode == 0 and sums.stdout:
        expected = None
        for line in sums.stdout.splitlines():
            if line.strip().endswith(filename):
                expected = line.split()[0].strip()
                break
        if expected:
            actual = _run(["sha256sum", tmp_bin]).stdout.split()[0].strip()
            if actual != expected:
                print(f"{C_RED}[✖] NoizDNS binary checksum mismatch - refusing to install it.{C_RESET}")
                os.remove(tmp_bin)
                return False
        else:
            print(f"{C_YELLOW}[!] Couldn't find {filename} in SHA256SUMS - proceeding without verification.{C_RESET}")
    else:
        print(f"{C_YELLOW}[!] Could not fetch SHA256SUMS - proceeding without verification.{C_RESET}")
    os.makedirs(os.path.dirname(NOIZDNS_BIN), exist_ok=True)
    _run(["cp", tmp_bin, NOIZDNS_BIN])
    os.chmod(NOIZDNS_BIN, 0o755)
    return _binary_ok(NOIZDNS_BIN)


def _install_noizdns_routed(name, domain_ns, target_port, internal_port, mtu=None):
    """NoiseDNS/NoizDNS, wired into Multi-Engine Mode.

    FIX (real, confirmed root cause of NoiseDNS permanently sitting at
    [OFF]): this used to invoke noizdns-server with dnstt-server's own
    "-udp :PORT ... domain upstream" CLI shape. That's wrong - confirmed
    directly from the binary's own --help output after it crash-looped:

        flag provided but not defined: -udp
        Usage:
          .../noizdns-server -gen-key -privkey-file PRIVKEYFILE -pubkey-file PUBKEYFILE
          TOR_PT_MANAGED_TRANSPORT_VER=1 TOR_PT_SERVER_TRANSPORTS=dnstt TOR_PT_SERVER_BINDADDR=dnstt-ADDR TOR_PT_ORPORT=UPSTREAMADDR .../noizdns-server -privkey-file server.key t.example.com

    noizdns-server doesn't take -udp, a bind port, or an upstream address
    as CLI flags/positional args at all - it only runs in Tor's
    pluggable-transport managed mode, entirely through environment
    variables, with just -privkey-file, optional -mtu, and the domain as
    real CLI args. This is a REQUIRED invocation shape, not the optional
    Dante-SOCKS extra the earlier comment here assumed it could skip -
    every earlier attempt to start it this way was doomed to
    "flag provided but not defined" every single time, regardless of
    restart count."""
    print(f"\n[i] Installing NoiseDNS (instance '{name}')...")
    if not _ensure_noizdns_binary():
        return False

    instance_dir = f"{INSTANCES_DIR}/{name}"
    os.makedirs(instance_dir, exist_ok=True)
    priv_key = f"{instance_dir}/noizdns_server.key"
    pub_key = f"{instance_dir}/noizdns_server.pub"
    keygen = _run([NOIZDNS_BIN, "-gen-key", "-privkey-file", priv_key, "-pubkey-file", pub_key])
    if keygen.returncode != 0 or not os.path.exists(pub_key):
        print(f"{C_RED}[✖] Key generation failed: {keygen.stderr.strip()}{C_RESET}")
        return False

    exec_cmd = f"{NOIZDNS_BIN} -privkey-file {priv_key} -mtu {mtu or NOIZDNS_DEFAULT_MTU} {domain_ns}"
    env_lines = [
        "TOR_PT_MANAGED_TRANSPORT_VER=1",
        "TOR_PT_SERVER_TRANSPORTS=dnstt",
        f"TOR_PT_SERVER_BINDADDR=dnstt-0.0.0.0:{internal_port}",
        f"TOR_PT_ORPORT=127.0.0.1:{target_port}",
    ]

    return _write_routed_service(name, exec_cmd, env_lines=env_lines)


def _install_noizdns(custom_port, domain_ns, target_port, mtu=None):
    """Single-instance NoiseDNS install - same documented 53->5300 NAT
    redirect pattern as _install_dnstt()/_install_vaydns() above (confirmed
    from noizdns-deploy.sh's own DNSTT_PORT="5300" default and its "Port 53
    -> SOCKS dnstt port" comment)."""
    print(f"\n[i] Installing dependencies for NoiseDNS...")
    _run("apt-get update && apt-get install -y iptables")
    install_iptables_persistent()
    _apply_speed_tuning()
    if not _ensure_noizdns_binary():
        return False

    os.makedirs(NOIZDNS_DIR, exist_ok=True)
    priv_key = f"{NOIZDNS_DIR}/noizdns_server.key"
    pub_key = f"{NOIZDNS_DIR}/noizdns_server.pub"
    keygen = _run([NOIZDNS_BIN, "-gen-key", "-privkey-file", priv_key, "-pubkey-file", pub_key])
    if keygen.returncode != 0 or not os.path.exists(pub_key):
        print(f"{C_RED}[✖] Key generation failed: {keygen.stderr.strip()}{C_RESET}")
        return False

    open_firewall_port(DNSTT_INTERNAL_PORT, ("udp",))
    nat_redirect_udp(custom_port, DNSTT_INTERNAL_PORT)
    _mirror_ip6tables(custom_port, DNSTT_INTERNAL_PORT)
    persist_firewall_rules()

    # FIX: same root-cause fix as _install_noizdns_routed() above -
    # noizdns-server has no -udp flag and takes its bind address/upstream
    # through Tor pluggable-transport environment variables, not CLI args.
    # See that function's docstring for the confirmed --help output.
    exec_cmd = f"{NOIZDNS_BIN} -privkey-file {priv_key} -mtu {mtu or NOIZDNS_DEFAULT_MTU} {domain_ns}"
    env_lines = [
        "TOR_PT_MANAGED_TRANSPORT_VER=1",
        "TOR_PT_SERVER_TRANSPORTS=dnstt",
        f"TOR_PT_SERVER_BINDADDR=dnstt-0.0.0.0:{DNSTT_INTERNAL_PORT}",
        f"TOR_PT_ORPORT=127.0.0.1:{target_port}",
    ]

    # FIX: report what actually happened instead of a hardcoded True - see
    # _write_service()'s own fix above for the full reasoning.
    return _write_service("noizdns", exec_cmd, env_lines=env_lines)


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


def _service_failure_reason(svc):
    """Best-effort one-line reason a just-(re)started instance unit isn't
    actually staying active, pulled straight from systemd/journald.

    FIX (real, confirmed gap): every caller here used to trust
    `systemctl restart <svc>`'s own return code as "it worked". For a
    Type=simple unit, systemd reports that call as successful the moment
    the process is FORKED - not once it's confirmed to still be running a
    moment later. A binary that starts and then immediately exits (bad
    flags, a missing dependency it needs at startup, etc.) still gets a
    0 exit code from `restart`, then quietly lands in "activating
    (auto-restart)" a few seconds later - which is exactly how an engine
    like NoiseDNS could sit there as [OFF] in this menu forever, surviving
    "Restart all instances" every time, with nothing telling the admin (or
    a future debugging pass) why. This pulls systemd's own Active: line
    plus its last real journal line so that reason is visible right here
    instead of requiring an SSH session and manual journalctl digging."""
    reason = None
    status_out = (_run(f"systemctl status {svc} --no-pager -l").stdout or "")
    for line in status_out.splitlines():
        line = line.strip()
        if line.startswith("Active:"):
            reason = line
            break

    # FIX: -n 3 was too narrow in practice - on a crash-looping unit, the
    # last 3 lines are almost always systemd's OWN wrapper messages
    # ("Scheduled restart job", "Failed with result 'exit-code'", etc.),
    # which only confirm THAT it died, not WHY. The program's own last
    # words (a bad flag, a missing file, a bind error) are usually a line
    # or two further back, pushed out by those. Pull a wider window and
    # specifically surface the program's own last output line, plus
    # systemd's "Main process exited" line (the one boilerplate line that
    # actually carries a real exit code/signal).
    log_out = (_run(f"journalctl -u {svc} -n 20 --no-pager").stdout or "")
    log_lines = [l.strip() for l in log_out.splitlines() if l.strip()]

    boilerplate_markers = (
        "Started ", "Stopping ", "Stopped ", "Scheduled restart job",
        "Failed with result", "Service RestartSec", "Consumed",
        "start request repeated too quickly", "Unit entered failed state",
    )
    program_lines = [l for l in log_lines if not any(m in l for m in boilerplate_markers)]
    exit_line = next((l for l in log_lines if "Main process exited" in l), None)

    detail = []
    if program_lines:
        detail.append(program_lines[-1])
    if exit_line and exit_line not in detail:
        detail.append(exit_line)
    if not detail and log_lines:
        detail.append(log_lines[-1])

    parts = [p for p in ([reason] + detail) if p]
    return " | ".join(parts) if parts else "no diagnostic output available - check journalctl manually"


def _write_routed_service(name, exec_cmd, env_lines=None, workdir=None):
    # env_lines: optional list of "VAR=value" strings rendered as separate
    # systemd Environment= directives. Needed for engines like NoiseDNS
    # that take their bind address/upstream through environment variables
    # (Tor pluggable-transport style) rather than CLI flags - ExecStart=
    # is NOT run through a shell, so a shell-style "VAR=val cmd" prefix on
    # exec_cmd itself would not work; this is the correct systemd
    # mechanism for it.
    service_path = f"/etc/systemd/system/dnstt-{name}.service"
    # FIX (reboot-persistence bug): same StartLimitIntervalSec=0 fix as
    # dns-router.service's own unit above, for the exact same reason - a
    # per-instance engine that fails once or twice in the first seconds of
    # boot (its own internal port not yet free, dns-router not quite up yet
    # despite the After= ordering hint, etc.) would otherwise hit systemd's
    # default 5-restarts/10s limit, land in "failed (start-limit-hit)", and
    # never come back on its own - indistinguishable from "switched off" in
    # the PROTOCOL MANAGER / MULTI-ENGINE MODE status display. Also widened
    # ordering from bare network.target to network-online.target, matching
    # the router's own unit, since these instances are just as dependent on
    # real connectivity being up as the router is.
    env_block = ("".join(f"Environment={line}\n" for line in env_lines)) if env_lines else ""
    # MasterDnsVPN-family engines now read their key from a RELATIVE path
    # (ENCRYPTION_KEY_FILE = "encrypt_key.txt"), so the service must run inside
    # the instance folder - otherwise a new random key is created in "/" and no
    # client can ever match the key shown in the panel.
    if workdir:
        env_block = f"WorkingDirectory={workdir}\n" + env_block
    service_content = f"""[Unit]
Description=DNSTT Multi-Engine Instance ({name})
After=network-online.target dns-router.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
{env_block}ExecStart={exec_cmd}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    needs_write = True
    if os.path.exists(service_path):
        with open(service_path) as f:
            needs_write = f.read() != service_content
    if needs_write:
        with open(service_path, "w") as f:
            f.write(service_content)
        _run("systemctl daemon-reload")
        _run(f"systemctl enable dnstt-{name}")
        _run(f"systemctl reset-failed dnstt-{name}")
    svc = f"dnstt-{name}"
    _run(f"systemctl restart {svc}")
    # FIX: don't trust restart's own return code (see _service_failure_reason
    # above) - give it a moment to either settle or crash-loop, then check
    # the real state.
    time.sleep(1.5)
    active = _run(["systemctl", "is-active", "--quiet", svc]).returncode == 0
    if not active:
        print(f"{C_RED}[✖] {svc} was started but isn't staying up: "
              f"{_service_failure_reason(svc)}{C_RESET}")
    return active


def _retrofit_instance_unit(name):
    """Patches an ALREADY-INSTALLED dnstt-<name>.service in place to add the
    StartLimitIntervalSec=0 reboot-persistence fix, without needing to know
    (or reconstruct) its original ExecStart command line - the registry
    doesn't store that, only the install-time parameters, and rebuilding an
    exact ExecStart from those would risk drifting from whatever the admin
    may have hand-edited since (option 5, EDIT SERVICE). Only rewrites the
    two directives that matter for this fix and leaves everything else -
    including ExecStart - untouched. Returns True if a rewrite happened."""
    service_path = f"/etc/systemd/system/dnstt-{name}.service"
    if not os.path.exists(service_path):
        return False
    with open(service_path) as f:
        content = f.read()
    if "StartLimitIntervalSec" in content:
        return False
    new_content = content.replace(
        "After=network.target dns-router.service",
        "After=network-online.target dns-router.service\nWants=network-online.target\nStartLimitIntervalSec=0",
    )
    if new_content == content:
        # Ordering line didn't match verbatim (hand-edited) - fall back to
        # just appending the start-limit fix under [Unit] without touching
        # whatever ordering the admin already set up.
        new_content = content.replace("[Unit]\n", "[Unit]\nStartLimitIntervalSec=0\n", 1)
        if new_content == content:
            return False
    with open(service_path, "w") as f:
        f.write(new_content)
    _run("systemctl daemon-reload")
    _run(f"systemctl reset-failed dnstt-{name}")
    return True


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


def _pin_toml_key_file(config_path, instance_dir):
    """Newer MasterDnsVPN-family configs use ENCRYPTION_KEY_FILE = "encrypt_key.txt" (relative to the
    working directory). Make it absolute so the engine always reads the key this panel shows."""
    if not os.path.exists(config_path):
        return False
    with open(config_path) as f:
        content = f.read()
    key_abs = f"{instance_dir}/encrypt_key.txt"
    new, n = re.subn(r'^ENCRYPTION_KEY_FILE\s*=.*$', f'ENCRYPTION_KEY_FILE = "{key_abs}"', content, flags=re.MULTILINE)
    if n == 0 or new == content:
        return n > 0
    with open(config_path, "w") as f:
        f.write(new)
    return True


def _retrofit_toml_engine(name, entry):
    """Already-installed MasterDNS/StormDNS/CottenDNS instances: add WorkingDirectory to the unit and pin the
    key file path (fixes 'server runs but no client can connect'). True if the unit was changed."""
    if entry.get("mode") not in ("masterdns", "stormdns", "cottendns"):
        return False
    instance_dir = f"{INSTANCES_DIR}/{name}"
    _pin_toml_key_file(f"{instance_dir}/server_config.toml", instance_dir)
    service_path = f"/etc/systemd/system/dnstt-{name}.service"
    if not os.path.exists(service_path):
        return False
    with open(service_path) as f:
        content = f.read()
    if "WorkingDirectory=" in content:
        return False
    new_content = content.replace("[Service]\n", f"[Service]\nWorkingDirectory={instance_dir}\n", 1)
    if new_content == content:
        return False
    with open(service_path, "w") as f:
        f.write(new_content)
    _run("systemctl daemon-reload")
    _run(f"systemctl reset-failed dnstt-{name}")
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
    _run("apt-get update && apt-get install -y golang git iptables")
    install_iptables_persistent()
    _apply_speed_tuning()

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

    # FIX: report what actually happened instead of a hardcoded True.
    return _write_service("dnstt", exec_cmd)


def _install_vaydns(custom_port, domain_ns, target_port, mtu=None, record_type=None, dnstt_compat=True):
    print(f"\n[i] Installing dependencies for VayDNS...")
    _run("apt-get update && apt-get install -y golang git iptables")
    install_iptables_persistent()
    _apply_speed_tuning()

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

    # FIX: report what actually happened instead of a hardcoded True.
    return _write_service("vaydns", exec_cmd)


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


# --- Slipstream server -----------------------------------------------------
#
# FIX (root cause of "Slipstream connects but I can't browse" / works with
# SlipGate but not with this panel): there are TWO unrelated "slipstream-
# server" programs. EndPositive/slipstream is the C/picoquic original; the
# one SlipNet's Android client library (libslipstream.so - the same library
# this app bundles) is built to talk to, and the one SlipGate deploys, is the
# Rust implementation published in anonvector/slipgate's releases. They share
# a name and a goal, not an implementation: the panel was installing the C
# one, so the app could complete the first QUIC exchange and then stall.
# SlipGate (confirmed working with the app) uses the Rust build, so that is
# what this panel installs now - fetched from the same release assets
# SlipGate itself downloads (slipstream-server-linux-<amd64|arm64>).
#
# Second fix: Slipstream is a raw TCP pipe, not a proxy. The app's local
# listener forwards bytes to the server's --target-address and speaks SOCKS5
# over them, so the far end must BE a SOCKS5 server. Pointing it at SSH (22)
# gives exactly "connected, no internet". A small loopback-only SOCKS5 server
# (below) is installed as the default backend, the way SlipGate's built-in
# `socks serve` is.

SLIPGATE_RELEASE_BASE = "https://github.com/anonvector/slipgate/releases/latest/download"
SLIPSTREAM_SOCKS_SCRIPT_PATH = "/usr/local/bin/slipstream-socks.py"
SLIPSTREAM_SOCKS_SERVICE = "slipstream-socks"
SLIPSTREAM_SOCKS_SERVICE_PATH = "/etc/systemd/system/slipstream-socks.service"
SLIPSTREAM_SOCKS_PORT = 10800

SLIPSTREAM_SOCKS_SCRIPT = r'''#!/usr/bin/env python3
"""slipstream-socks.py - tiny SOCKS5 (CONNECT) server for the Slipstream backend.

Slipstream only carries a raw TCP pipe: whatever the client app connects to on
its local listener comes out at the server's --target-address. The Android
app speaks SOCKS5 over that pipe, so the far end has to be a SOCKS5 server.
This is it. It binds 127.0.0.1 only - the only way in is through the tunnel.
"""
import argparse
import asyncio
import ipaddress
import socket
import sys

HANDSHAKE_TIMEOUT = 20
CONNECT_TIMEOUT = 15


def _blocked(ip):
    # Tunnel users must not be able to reach services bound to the VPS's own
    # loopback (panel, databases, ...) through this proxy.
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast


async def _reply(writer, code):
    writer.write(bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0]))
    await writer.drain()


async def _pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except Exception:
            pass


async def handle(reader, writer):
    remote_writer = None
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

        head = await asyncio.wait_for(reader.readexactly(2), HANDSHAKE_TIMEOUT)
        if head[0] != 5:
            return
        methods = await asyncio.wait_for(reader.readexactly(head[1]), HANDSHAKE_TIMEOUT)
        if 0 in methods:
            writer.write(b"\x05\x00")
            await writer.drain()
        elif 2 in methods:
            # Username/password offered but we do not check it: the listener
            # is loopback-only, so the tunnel itself is the access control.
            writer.write(b"\x05\x02")
            await writer.drain()
            ver = await asyncio.wait_for(reader.readexactly(2), HANDSHAKE_TIMEOUT)
            await asyncio.wait_for(reader.readexactly(ver[1]), HANDSHAKE_TIMEOUT)
            plen = await asyncio.wait_for(reader.readexactly(1), HANDSHAKE_TIMEOUT)
            await asyncio.wait_for(reader.readexactly(plen[0]), HANDSHAKE_TIMEOUT)
            writer.write(b"\x01\x00")
            await writer.drain()
        else:
            writer.write(b"\x05\xff")
            await writer.drain()
            return

        req = await asyncio.wait_for(reader.readexactly(4), HANDSHAKE_TIMEOUT)
        if req[0] != 5:
            return
        if req[1] != 1:  # only CONNECT
            await _reply(writer, 7)
            return
        atyp = req[3]
        if atyp == 1:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode("ascii", "ignore")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            await _reply(writer, 8)
            return
        port = int.from_bytes(await reader.readexactly(2), "big")

        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), CONNECT_TIMEOUT)
        except Exception:
            await _reply(writer, 4)
            return

        remote_reader = None
        allowed = False
        for family, _t, _p, _c, sockaddr in infos:
            if _blocked(sockaddr[0]):
                continue
            allowed = True
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(sockaddr[0], sockaddr[1], family=family),
                    CONNECT_TIMEOUT)
                break
            except Exception:
                remote_reader = None
                continue
        if remote_reader is None:
            await _reply(writer, 5 if allowed else 2)
            return

        rs = remote_writer.get_extra_info("socket")
        if rs is not None:
            try:
                rs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

        await _reply(writer, 0)
        await asyncio.gather(_pipe(reader, remote_writer), _pipe(remote_reader, writer))
    except Exception:
        pass
    finally:
        for w in (remote_writer, writer):
            if w is not None:
                try:
                    w.close()
                except Exception:
                    pass


async def main(host, port):
    server = await asyncio.start_server(handle, host, port, backlog=512, limit=1 << 16)
    print("slipstream-socks listening on %s:%d" % (host, port), flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=10800)
    a = ap.parse_args()
    try:
        asyncio.run(main(a.host, a.port))
    except KeyboardInterrupt:
        sys.exit(0)
'''


def _slipstream_arch():
    """Maps uname -m to the release-asset arch naming SlipGate publishes its
    Slipstream server under: slipstream-server-linux-amd64 / -arm64."""
    machine = (_run("uname -m").stdout or "").strip()
    return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)


def _slipstream_is_rust_build(path):
    """True only for the Rust server the app's client library is built for.
    Told apart from the old C build by its --dns-listen-host option."""
    if not _binary_ok(path):
        return False
    res = _run([path, "--help"])
    text = ((res.stdout or "") + (res.stderr or "")).lower()
    return "dns-listen-host" in text


def _slipstream_key_is_ec(key_path):
    try:
        with open(key_path) as f:
            return "BEGIN EC PRIVATE KEY" in f.read(200)
    except OSError:
        return False


def _generate_slipstream_cert(cert_dir, domain_ns, force=False):
    """Self-signed ECDSA P-256 certificate, the same kind SlipGate generates
    for its Slipstream tunnels (the old RSA-2048 one worked for the server to
    start but is not what the working setup uses). The client does not
    validate it against a CA. An existing EC pair is kept so a re-run does
    not needlessly rotate it; an old RSA pair is replaced."""
    os.makedirs(cert_dir, exist_ok=True)
    cert_path = f"{cert_dir}/slipstream.crt"
    key_path = f"{cert_dir}/slipstream.key"
    if not force and os.path.exists(cert_path) and _slipstream_key_is_ec(key_path):
        return True, cert_path, key_path
    gen = _run(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", key_path])
    if gen.returncode == 0:
        req = _run(["openssl", "req", "-new", "-x509", "-key", key_path, "-out", cert_path,
                    "-subj", f"/CN={domain_ns}", "-days", "3650",
                    "-addext", f"subjectAltName=DNS:{domain_ns}"])
        if req.returncode != 0:  # very old openssl without -addext
            req = _run(["openssl", "req", "-new", "-x509", "-key", key_path, "-out", cert_path,
                        "-subj", f"/CN={domain_ns}", "-days", "3650"])
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    ok = os.path.exists(cert_path) and os.path.exists(key_path) and _slipstream_key_is_ec(key_path)
    return ok, cert_path, key_path


def _ensure_slipstream_binary(arch=None):
    """Installs SlipGate's Rust slipstream-server, replacing the C build if
    that is what is currently installed (kept as a .c-build.bak copy). The
    new file is staged next to the target and renamed into place, which works
    even while the old binary is running (a plain copy would fail with 'text
    file busy')."""
    if _slipstream_is_rust_build(SLIPSTREAM_BIN):
        return True
    arch = arch or _slipstream_arch()
    if not arch:
        print(f"{C_RED}[✖] Unrecognized CPU architecture for a Slipstream prebuilt binary.{C_RESET}")
        return False
    filename = f"slipstream-server-linux-{arch}"
    url = f"{SLIPGATE_RELEASE_BASE}/{filename}"
    tmp_bin = f"/tmp/{filename}.download"
    print(f"[i] Downloading the Slipstream server used by SlipGate/SlipNet ({filename})...")
    dl = _run(["curl", "-fSL", "--retry", "3", "-o", tmp_bin, url])
    if dl.returncode != 0 or not os.path.exists(tmp_bin):
        print(f"{C_RED}[✖] Could not download the Slipstream server binary from {url}{C_RESET}")
        return False
    os.chmod(tmp_bin, 0o755)
    if not _slipstream_is_rust_build(tmp_bin):
        print(f"{C_RED}[✖] The downloaded file does not look like the expected Slipstream server "
              f"(missing --dns-listen-host). Not installing it.{C_RESET}")
        try:
            os.remove(tmp_bin)
        except OSError:
            pass
        return False
    os.makedirs(os.path.dirname(SLIPSTREAM_BIN), exist_ok=True)
    if os.path.exists(SLIPSTREAM_BIN):
        try:
            shutil.copy2(SLIPSTREAM_BIN, SLIPSTREAM_BIN + ".c-build.bak")
        except OSError:
            pass
    staged = SLIPSTREAM_BIN + ".new"
    shutil.copy2(tmp_bin, staged)
    os.chmod(staged, 0o755)
    os.replace(staged, SLIPSTREAM_BIN)
    try:
        os.remove(tmp_bin)
    except OSError:
        pass
    if not _slipstream_is_rust_build(SLIPSTREAM_BIN):
        print(f"{C_RED}[✖] Slipstream server installed but does not run correctly at {SLIPSTREAM_BIN}.{C_RESET}")
        return False
    return True


def _slipstream_exec_cmd(listen_host, listen_port, target_port, domain_ns, cert_path, key_path, seed_path):
    # --reset-seed: keeps QUIC stateless-reset keys across restarts, so
    # connected clients recover immediately after a server restart instead
    # of waiting out their idle timeout.
    return (f"{SLIPSTREAM_BIN} --dns-listen-host {listen_host} --dns-listen-port {listen_port} "
            f"--target-address 127.0.0.1:{target_port} --domain {domain_ns} "
            f"--cert {cert_path} --key {key_path} --reset-seed {seed_path}")


def _socks_handshake_ok(port):
    import socket as _s
    try:
        with _s.create_connection(("127.0.0.1", port), timeout=3) as c:
            c.sendall(b"\x05\x01\x00")
            return c.recv(2) == b"\x05\x00"
    except OSError:
        return False


def _ensure_slipstream_socks():
    """Installs/updates/starts the loopback SOCKS5 backend. Returns its port,
    or None on failure."""
    wrote = True
    if os.path.exists(SLIPSTREAM_SOCKS_SCRIPT_PATH):
        with open(SLIPSTREAM_SOCKS_SCRIPT_PATH) as f:
            wrote = f.read() != SLIPSTREAM_SOCKS_SCRIPT
    if wrote:
        with open(SLIPSTREAM_SOCKS_SCRIPT_PATH, "w") as f:
            f.write(SLIPSTREAM_SOCKS_SCRIPT)
        os.chmod(SLIPSTREAM_SOCKS_SCRIPT_PATH, 0o755)
        check = _run(["python3", "-m", "py_compile", SLIPSTREAM_SOCKS_SCRIPT_PATH])
        if check.returncode != 0:
            print(f"{C_RED}[✖] SOCKS5 helper failed its syntax check: {check.stderr.strip()}{C_RESET}")
            return None

    unit = f"""[Unit]
Description=Slipstream SOCKS5 backend (loopback only)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {SLIPSTREAM_SOCKS_SCRIPT_PATH} --host 127.0.0.1 --port {SLIPSTREAM_SOCKS_PORT}
Environment=PYTHONUNBUFFERED=1
LimitNOFILE=65535
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    unit_changed = True
    if os.path.exists(SLIPSTREAM_SOCKS_SERVICE_PATH):
        with open(SLIPSTREAM_SOCKS_SERVICE_PATH) as f:
            unit_changed = f.read() != unit
    if unit_changed:
        with open(SLIPSTREAM_SOCKS_SERVICE_PATH, "w") as f:
            f.write(unit)
        _run("systemctl daemon-reload")
        _run(f"systemctl enable {SLIPSTREAM_SOCKS_SERVICE}")

    active = _run(["systemctl", "is-active", "--quiet", SLIPSTREAM_SOCKS_SERVICE]).returncode == 0
    if not active and check_system_port_in_use(SLIPSTREAM_SOCKS_PORT, ("tcp",)):
        print(f"{C_RED}[✖] TCP port {SLIPSTREAM_SOCKS_PORT} (used for the Slipstream SOCKS5 backend) is "
              f"already taken by something else.{C_RESET}")
        return None
    _run(f"systemctl reset-failed {SLIPSTREAM_SOCKS_SERVICE}")
    if wrote or unit_changed or not active:
        _run(f"systemctl restart {SLIPSTREAM_SOCKS_SERVICE}")
    time.sleep(1.0)
    if not _socks_handshake_ok(SLIPSTREAM_SOCKS_PORT):
        print(f"{C_RED}[✖] The SOCKS5 backend did not answer on 127.0.0.1:{SLIPSTREAM_SOCKS_PORT}: "
              f"{_service_failure_reason(SLIPSTREAM_SOCKS_SERVICE)}{C_RESET}")
        return None
    return SLIPSTREAM_SOCKS_PORT


def _prompt_slipstream_backend():
    """Asks what the Slipstream server should forward to. Returns
    (target_port, kind) with kind 'socks' or 'port', or (None, None)."""
    print("\n Slipstream carries a raw TCP pipe. What should the server end of it connect to?")
    print("  [1] Built-in SOCKS5 proxy (recommended - this is what the Android app needs to browse)")
    print("  [2] A custom local TCP port (e.g. 22 for SSH) - only for clients that handle that themselves")
    pick = input(" Select backend [1]: ").strip() or "1"
    if pick == "2":
        port = prompt_port(" Enter local target port: ", default=22)
        if not check_system_port_in_use(port, ("tcp",)):
            print(f"{C_YELLOW}[!] Nothing seems to be listening on port {port} yet.{C_RESET}")
        return port, "port"
    port = _ensure_slipstream_socks()
    if port is None:
        return None, None
    print(f"{C_GREEN}[✔] SOCKS5 backend running on 127.0.0.1:{port} (loopback only).{C_RESET}")
    return port, "socks"


def _slipstream_probe(domain_ns, port, label):
    """Sends a plain DNS TXT query for the bare tunnel domain to
    127.0.0.1:<port> and reports whether the Slipstream server (or the
    router in front of it) answered. The server replies NXDOMAIN to a bare
    domain, so ANY well-formed reply with the same ID proves the whole chain
    - router match, backend socket, server - is alive. (Silence is what a
    dead engine, a wrong domain or a stuck router looks like.)"""
    import socket as _s
    import struct as _st
    txid = 0x5A5A
    qname = b"".join(bytes([len(p)]) + p.encode() for p in domain_ns.strip(".").split(".")) + b"\0"
    packet = (_st.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 1) + qname + _st.pack(">HH", 16, 1)
              + b"\0" + _st.pack(">HHIH", 41, 1232, 0, 0))
    sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(packet, ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
        ok = len(data) >= 12 and _st.unpack(">H", data[:2])[0] == txid
    except OSError:
        ok = False
    finally:
        sock.close()
    if ok:
        print(f"  {C_GREEN}[✔]{C_RESET} {label}: answered")
    else:
        print(f"  {C_RED}[✖]{C_RESET} {label}: NO answer")
    return ok


def _install_slipstream_routed(name, domain_ns, target_port, internal_port):
    """Slipstream as a Multi-Engine instance: the Rust server binds only
    127.0.0.1:<internal_port>, the DNS router owns public port 53."""
    print(f"\n[i] Installing Slipstream (instance '{name}')...")
    if not _ensure_slipstream_binary():
        return False

    instance_dir = f"{INSTANCES_DIR}/{name}"
    cert_ok, cert_path, key_path = _generate_slipstream_cert(instance_dir, domain_ns)
    if not cert_ok:
        print(f"{C_RED}[✖] Certificate generation failed - cannot proceed without one.{C_RESET}")
        return False

    exec_cmd = _slipstream_exec_cmd("127.0.0.1", internal_port, target_port, domain_ns,
                                    cert_path, key_path, f"{instance_dir}/slipstream.seed")
    return _write_routed_service(name, exec_cmd)


def _install_slipstream(custom_port, domain_ns, target_port):
    print(f"\n[i] Installing Slipstream...")
    _apply_speed_tuning()

    # Unlike dnstt's NAT-redirect setup, Slipstream binds custom_port itself directly -
    # so if that's port 53, systemd-resolved's stub listener genuinely can block it.
    if custom_port == 53 and not resolve_port53_conflict():
        print(f"{C_YELLOW}[!] Port {custom_port} still looks occupied after cleanup - the server may fail to bind.{C_RESET}")

    if not _ensure_slipstream_binary():
        return False

    open_firewall_port(custom_port, ("udp",))
    persist_firewall_rules()

    cert_ok, cert_path, key_path = _generate_slipstream_cert(DNSTT_DIR, domain_ns)
    if not cert_ok:
        print(f"{C_RED}[✖] Certificate generation failed - cannot proceed without one.{C_RESET}")
        return False

    exec_cmd = _slipstream_exec_cmd("0.0.0.0", custom_port, target_port, domain_ns,
                                    cert_path, key_path, f"{DNSTT_DIR}/slipstream.seed")
    return _write_service("slipstream", exec_cmd)


def _fix_routed_slipstream(registry, name, interactive=True):
    """One-shot repair/upgrade for an EXISTING Multi-Engine Slipstream
    instance: swaps in the Rust server, re-issues an ECDSA cert, points the
    instance at the built-in SOCKS5 backend, restarts it, then probes the
    whole chain. Returns True on success (registry entry updated in place)."""
    entry = registry[name]
    domain_ns = entry["domain"]
    print(f"\n{C_CYAN}[i] Repairing Slipstream instance '{name}' ({domain_ns})...{C_RESET}")
    if interactive:
        target_port, kind = _prompt_slipstream_backend()
    else:
        target_port, kind = _ensure_slipstream_socks(), "socks"
    if target_port is None:
        return False
    if not _install_slipstream_routed(name, domain_ns, target_port, entry["internal_port"]):
        return False
    entry["target_port"] = target_port
    entry["backend"] = kind
    _save_instance_registry(registry)
    time.sleep(1.0)
    print("\n Checking the chain end to end:")
    ok_direct = _slipstream_probe(domain_ns, entry["internal_port"], f"Slipstream server (127.0.0.1:{entry['internal_port']})")
    ok_router = _slipstream_probe(domain_ns, 53, "DNS router (127.0.0.1:53) -> server")
    if ok_direct and ok_router:
        print(f"{C_GREEN}[✔] Slipstream instance '{name}' is up and answering through the router.{C_RESET}")
    elif ok_direct:
        print(f"{C_YELLOW}[!] The server answers but the router does not forward to it - check 'journalctl -u dns-router -n 30'.{C_RESET}")
    else:
        print(f"{C_RED}[✖] The server is not answering - check 'journalctl -u dnstt-{name} -n 30'.{C_RESET}")
    return ok_direct


_slipstream_auto_tried = set()


def _slipstream_instance_is_legacy(entry):
    """An instance made before the SOCKS5 backend existed has no 'backend'
    key (it forwards to a plain port such as SSH, which the Android app
    cannot use). An instance whose admin explicitly chose a custom port
    carries backend='port' and is left alone."""
    return entry.get("mode") == "slipstream" and not entry.get("backend")


def _auto_upgrade_legacy_slipstream(registry):
    """Run every time the Multi-Engine menu opens: upgrades old Slipstream
    instances (C server and/or a plain-port backend) to the Rust server with
    the built-in SOCKS5 backend, with no menu option to remember. Each
    instance is tried once per session so a failure does not loop. Returns
    True if anything was changed."""
    changed = False
    for name, entry in list(registry.items()):
        if not _slipstream_instance_is_legacy(entry) or name in _slipstream_auto_tried:
            continue
        _slipstream_auto_tried.add(name)
        print(f"{C_YELLOW}[i] Slipstream instance '{name}' uses the old setup (no SOCKS5 backend) - "
              f"upgrading it automatically...{C_RESET}")
        if _fix_routed_slipstream(registry, name, interactive=False):
            changed = True
        else:
            print(f"{C_RED}[✖] Automatic upgrade of '{name}' failed. Use option [5] to retry and see why.{C_RESET}")
    return changed


def _fix_single_slipstream(ports_dict):
    """Same repair for the single-instance (non-Multi-Engine) install."""
    domain_ns = ports_dict.get('DNSTT_DOMAIN')
    custom_port = int(ports_dict.get('DNSTT_PORT', 53))
    if not domain_ns:
        print(f"{C_RED}[✖] No domain recorded for this install.{C_RESET}")
        return False
    target_port, kind = _prompt_slipstream_backend()
    if target_port is None:
        return False
    _run("systemctl stop slowdns")
    if not _install_slipstream(custom_port, domain_ns, target_port):
        return False
    ports_dict['DNSTT_TARGET'] = str(target_port)
    _save_state_now(ports_dict)
    time.sleep(1.0)
    print("\n Checking the server:")
    ok = _slipstream_probe(domain_ns, custom_port, f"Slipstream server (127.0.0.1:{custom_port})")
    if ok:
        print(f"{C_GREEN}[✔] Slipstream is up and answering.{C_RESET}")
    else:
        print(f"{C_RED}[✖] The server is not answering - check 'journalctl -u slowdns -n 30'.{C_RESET}")
    return ok


def _write_service(mode, exec_cmd, env_lines=None):
    # FIX (reboot-persistence bug): this unit already had the right ordering
    # (network-online.target + netfilter-persistent.service) but was still
    # missing StartLimitIntervalSec=0 - same class of bug as dns-router.service
    # and dnstt-<name>.service above, just for single-instance mode.
    # env_lines: see _write_routed_service()'s own docstring - same
    # mechanism, needed for NoiseDNS's Tor-pluggable-transport-style
    # environment-variable invocation.
    env_block = ("".join(f"Environment={line}\n" for line in env_lines)) if env_lines else ""
    service_file = f"""[Unit]
Description=SLOWDNS Tunnel Service ({mode})
After=network-online.target remote-fs.target netfilter-persistent.service
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
{env_block}ExecStart={exec_cmd}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(SERVICE_PATH, "w") as f:
        f.write(service_file)
    _run("systemctl daemon-reload")
    _run("systemctl enable slowdns")
    _run("systemctl reset-failed slowdns")
    _run("systemctl restart slowdns")
    # FIX (real, confirmed gap - same class as _write_routed_service()'s own
    # fix above, for Multi-Engine Mode): this never checked whether the
    # service it just restarted actually stayed up, and every one of its
    # 4 callers (_install_dnstt/_install_vaydns/_install_slipstream/
    # _install_noizdns) unconditionally `return True` right after calling
    # this, regardless of what actually happened. A single-instance engine
    # whose binary starts and immediately exits - NoiseDNS included - would
    # silently be reported as installed successfully with no indication
    # anything was wrong. Give it the same brief settle window and report
    # the real state back to the caller instead.
    time.sleep(1.5)
    active = _run(["systemctl", "is-active", "--quiet", "slowdns"]).returncode == 0
    if not active:
        print(f"{C_RED}[✖] The {mode} service was started but isn't staying up: "
              f"{_service_failure_reason('slowdns')}{C_RESET}")
    return active


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
    elif mode == "noizdns":
        pub_key_content = "Not found"
        pub_key_path = f"{NOIZDNS_DIR}/noizdns_server.pub"
        if os.path.exists(pub_key_path):
            with open(pub_key_path, "r") as pk:
                pub_key_content = pk.read().strip()
        return {
            "UDP (fastest, most detectable)": f"dnstt-client -udp {server_ip}:{custom_port} -pubkey-file server.pub {domain_val} 127.0.0.1:1080",
            "DoH (via a public resolver, blends in as HTTPS)": f"dnstt-client -doh https://<resolver>/dns-query -pubkey-file server.pub {domain_val} 127.0.0.1:1080",
            "DoT (via a public resolver, blends in as TLS)": f"dnstt-client -dot <resolver>:853 -pubkey-file server.pub {domain_val} 127.0.0.1:1080",
            "SlipNet app (NoizDNS's own Android client)": f"Domain: {domain_val}  |  Server: {server_ip}:{custom_port}  |  Public key: see below",
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
        # Slipstream: the Android app (SlipNet's libslipstream) is the
        # supported client. Needs only the domain + a resolver. The CLI line
        # is for testing with a Rust slipstream-client build.
        return {
            "Android app (Slipstream engine)": f"Domain: {domain_val}  |  Resolver: any DNS resolver or {server_ip}:{custom_port}  |  server backend is SOCKS5",
            "CLI (Rust slipstream-client)": f"slipstream-client --resolver {server_ip}:{custom_port} --domain {domain_val} --tcp-listen-port 1080 --congestion-control bbr",
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
    _pin_toml_key_file(f"{instance_dir}/server_config.toml", instance_dir)
    real_binary = _find_installed_binary("masterdnsvpn", instance_dir)
    _run(f"systemctl stop masterdnsvpn")  # official installer's own unit name - we run our own instead
    _run(f"systemctl disable masterdnsvpn")
    ok = _write_routed_service(name, f"{real_binary} -config {instance_dir}/server_config.toml", workdir=instance_dir) \
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
    _pin_toml_key_file(f"{instance_dir}/server_config.toml", instance_dir)
    bin_path = _find_installed_binary("stormdns", instance_dir)
    _run("systemctl stop stormdns")
    _run("systemctl disable stormdns")
    if not bin_path:
        print(f"{C_RED}[X] The official installer's own service finished, but its binary")
        print(f"    couldn't be located afterward - check {instance_dir} manually.{C_RESET}")
        return False
    return _write_routed_service(name, f"{bin_path} -config {instance_dir}/server_config.toml", workdir=instance_dir)


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
    _pin_toml_key_file(f"{instance_dir}/server_config.toml", instance_dir)
    bin_path = _find_installed_binary("cottendns", instance_dir)
    _run("systemctl stop cottendns")
    _run("systemctl disable cottendns")
    if not bin_path:
        print(f"{C_RED}[X] The official installer's own service finished, but its binary")
        print(f"    couldn't be located afterward - check {instance_dir} manually.{C_RESET}")
        return False
    return _write_routed_service(name, f"{bin_path} -config {instance_dir}/server_config.toml", workdir=instance_dir)


# --- Pass-through multiplexer: registry helpers + menu flow ------------------
#
# The shared router on UDP/53 can carry more than DNS tunnels. Besides the
# delegated-domain engines it routes NON-DNS UDP protocols to a local port:
#   * by a protocol SIGNATURE (WireGuard, OpenVPN, plain QUIC, custom prefix),
#   * or as the single CATCH-ALL for protocols whose packets look like random
#     noise (Hysteria2/Hysteria 1 with obfuscation, ZIVPN, ...).
# Entries live in the same instances.json registry; the router reloads it
# every 5 seconds, so adding/removing one needs no restart.

PASSTHROUGH_SIGNATURES = {
    "wireguard": "WireGuard handshake",
    "openvpn": "OpenVPN (UDP) handshake",
    "quic": "plain QUIC (Hysteria2 WITHOUT obfuscation, TUIC, ...)",
    "prefix": "custom first bytes",
}


def passthrough_registered(name):
    entry = _load_instance_registry().get(name)
    return bool(entry and entry.get("mode") == "passthrough")


def _passthrough_catch_all_owner(registry, except_name=None):
    for n, e in registry.items():
        if e.get("mode") == "passthrough" and e.get("catch_all") and n != except_name:
            return n
    return None


def register_passthrough(name, label, port, signature=None, catch_all=False):
    """Adds/updates a pass-through protocol on the shared port 53. Returns
    (ok, message). Exactly one of `signature` or `catch_all` must be set."""
    if bool(signature) == bool(catch_all):
        return False, "Internal error: give either a signature or catch-all, not both/neither."
    if not _ensure_router_deployed():
        return False, "The DNS router could not be started."
    registry = _load_instance_registry()
    existing = registry.get(name)
    if existing and existing.get("mode") != "passthrough":
        return False, f"'{name}' is already used by a DNS tunnel instance - pick another name."
    if catch_all:
        owner = _passthrough_catch_all_owner(registry, except_name=name)
        if owner:
            return False, (f"'{owner}' is already the catch-all. Only one protocol can take "
                           f"unrecognised packets - give the other one a signature or its own port.")
    registry[name] = {"mode": "passthrough", "label": label, "internal_port": int(port),
                      "signature": signature if signature else None,
                      "catch_all": bool(catch_all), "routed": True}
    _save_instance_registry(registry)
    how = "catch-all (every packet that is not DNS or another signature)" if catch_all \
        else "signature: " + PASSTHROUGH_SIGNATURES.get(signature.get("type"), signature.get("type", "?"))
    return True, f"{label} now shares UDP 53 -> local port {port} [{how}]. Live within ~5 seconds."


def unregister_passthrough(name):
    registry = _load_instance_registry()
    entry = registry.get(name)
    if not entry or entry.get("mode") != "passthrough":
        return False
    del registry[name]
    _save_instance_registry(registry)
    return True


def _add_passthrough_flow(registry, ports_dict):
    clear_screen()
    print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("%s              ADD PROTOCOL TO PORT 53 (MULTIPLEXER)         %s" % (C_BOLD, C_RESET))
    print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print(" The protocol keeps running on its own port - the router just also")
    print(" accepts its traffic on UDP 53 and hands it over locally.")
    print()
    print(" [1] Hysteria 2        [2] Hysteria 1")
    print(" [3] WireGuard         [4] OpenVPN (UDP)")
    print(" [5] Plain QUIC (TUIC, Hysteria without obfs, ...)")
    print(" [6] Custom - match on first bytes (hex)")
    print(" [7] Custom - catch-all (noise-like / obfuscated protocol)")
    print(" [0] Cancel")
    pick = input(" Select protocol: ").strip()
    if pick in ("", "0"):
        return
    presets = {
        "1": ("hysteria2", "Hysteria2", ports_dict.get('HYSTERIA_PORT'), bool(ports_dict.get('HYSTERIA_OBFS'))),
        "2": ("hysteria1", "Hysteria 1", ports_dict.get('HYSTERIA1_PORT'), bool(ports_dict.get('HYSTERIA1_OBFS'))),
        "3": ("wireguard", "WireGuard", None, None),
        "4": ("openvpn-udp", "OpenVPN UDP", None, None),
        "5": ("quic", "QUIC", None, None),
        "6": ("custom", "Custom (prefix)", None, None),
        "7": ("custom-catchall", "Custom catch-all", None, None),
    }
    if pick not in presets:
        print(f"{C_RED}Invalid option.{C_RESET}")
        input("\nPress Enter to continue...")
        return
    default_name, label, saved_port, saved_obfs = presets[pick]

    signature, catch_all = None, False
    if pick in ("1", "2"):
        default_obfs = "Y" if saved_obfs else "N"
        ans = input(f" Does it use OBFS/obfuscation? [{default_obfs}]: ").strip().upper() or default_obfs
        if ans.startswith("Y"):
            catch_all = True
        else:
            signature = {"type": "quic"}
    elif pick == "3":
        signature = {"type": "wireguard"}
    elif pick == "4":
        signature = {"type": "openvpn"}
    elif pick == "5":
        signature = {"type": "quic"}
    elif pick == "6":
        hx = input(" First bytes as hex (e.g. deadbeef): ").strip().lower().replace(" ", "")
        try:
            raw = bytes.fromhex(hx)
        except ValueError:
            raw = b""
        if len(raw) < 2:
            print(f"{C_RED}[✖] Need at least 2 bytes of valid hex - a shorter match would catch random traffic.{C_RESET}")
            input("\nPress Enter to continue...")
            return
        signature = {"type": "prefix", "hex": hx}
    else:
        catch_all = True

    name = input(f" Name for this entry [{default_name}]: ").strip() or default_name
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        print(f"{C_RED}[✖] Invalid name.{C_RESET}")
        input("\nPress Enter to continue...")
        return
    default_port = int(saved_port) if saved_port and str(saved_port).isdigit() else None
    port = prompt_port(" UDP port the protocol itself listens on (local): ", default=default_port or 443)
    if not check_system_port_in_use(port, ("udp",)):
        print(f"{C_YELLOW}[!] Nothing is listening on UDP {port} right now - the entry is saved anyway, "
              f"but nothing will answer until that service is running.{C_RESET}")
    if port == 53:
        print(f"{C_RED}[✖] That is the shared port itself - pick the protocol's own port.{C_RESET}")
        input("\nPress Enter to continue...")
        return

    if signature and signature.get("type") in ("quic", "openvpn") and _passthrough_catch_all_owner(registry, name):
        print(f"{C_YELLOW}[!] A catch-all protocol exists. Its noise-like packets will occasionally look like "
              f"this signature; the router re-checks until a backend actually answers, so those "
              f"clients simply connect on their second packet.{C_RESET}")
    ok, msg = register_passthrough(name, label, port, signature, catch_all)
    print(f"\n{C_GREEN if ok else C_RED}[{'✔' if ok else '✖'}] {msg}{C_RESET}")
    if ok:
        server_ip = get_public_ip()
        print(f"\n Client side: connect to {server_ip} on UDP port 53 (same password/keys/obfs as before).")
        print(" Make sure the VPS firewall allows UDP 53 (the router opens it).")
    input("\nPress Enter to continue...")


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
            # Same "pick up a code fix automatically the next time the admin
            # even looks at this screen" reasoning as _ensure_router_deployed()
            # above, applied to each already-installed instance's own unit
            # file for the StartLimitIntervalSec reboot-persistence fix.
            retrofitted_any = False
            for inst_name, inst_entry in registry.items():
                svc = f"dnstt-{inst_name}"
                if _retrofit_toml_engine(inst_name, inst_entry):
                    retrofitted_any = True
                    _run(f"systemctl restart {svc}")
                if _retrofit_instance_unit(inst_name):
                    retrofitted_any = True
                    if _run(["systemctl", "is-active", "--quiet", svc]).returncode == 0:
                        _run(f"systemctl restart {svc}")
                    else:
                        _run(f"systemctl start {svc}")
            if _auto_upgrade_legacy_slipstream(registry):
                registry = _load_instance_registry()
                input("\nPress Enter to continue...")
        else:
            retrofitted_any = False
        clear_screen()
        router_active = _run("systemctl is-active --quiet dns-router").returncode == 0
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s        MULTI-ENGINE MODE — SHARED PORT 53 VIA ROUTER       %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        if retrofitted_any:
            print(f"{C_GREEN}[i] Applied the reboot-persistence fix to existing instance unit(s).{C_RESET}")
        print(f" Router: {'ON' if router_active else 'OFF'}  |  Instances: {len(registry)}")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        if not registry:
            print(" No instances yet.")
        else:
            for name, entry in registry.items():
                # Every routed engine (dnstt/vaydns/noizdns/slipstream/
                # masterdns/stormdns/cottendns) goes through the shared
                # _write_routed_service() above and always lands on
                # "dnstt-{name}" regardless of mode - there's no per-mode
                # naming left to branch on here.
                svc = f"dnstt-{name}"
                if entry['mode'] == 'passthrough':
                    pt_up = check_system_port_in_use(entry.get('internal_port', 0), ("udp",))
                    pt_status = f"{C_GREEN}ON{C_RESET}" if pt_up else f"{C_RED}OFF{C_RESET}"
                    pt_desc = "catch-all" if entry.get('catch_all') else \
                        "sig:" + str((entry.get('signature') or {}).get('type', '?'))
                    print(f"  {name:<16} {'passthru':<12} {(pt_desc + ' -> :' + str(entry.get('internal_port'))):<28} [{pt_status}]")
                    if not pt_up:
                        print(f"      {C_YELLOW}└─ nothing is listening on UDP {entry.get('internal_port')} "
                              f"(start that protocol's own service){C_RESET}")
                    continue
                active = _run(["systemctl", "is-active", "--quiet", svc]).returncode == 0
                status = f"{C_GREEN}ON{C_RESET}" if active else f"{C_RED}OFF{C_RESET}"
                print(f"  {name:<16} {entry['mode']:<12} {entry['domain']:<28} [{status}]")
                if not active:
                    # FIX: show WHY, right here, instead of a bare [OFF] the
                    # admin has to go SSH in and dig for - see
                    # _service_failure_reason()'s own docstring for the full
                    # reasoning (this is the exact symptom that motivated it).
                    print(f"      {C_YELLOW}└─ {_service_failure_reason(svc)}{C_RESET}")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [1] Add instance          [2] View all profiles (copy info)")
        print(" [3] Remove instance       [4] Restart all instances")
        print(" [5] Fix / upgrade a Slipstream instance (Rust server + SOCKS5 backend)")
        print(" [6] Add protocol to port 53 (Hysteria2, WireGuard, OpenVPN, QUIC, custom)")
        print(" [0] Back")
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
            print(" [7] NoiseDNS")
            mode_choice = input(" Select engine: ").strip()
            mode_map = {'1': 'dnstt', '2': 'slipstream', '3': 'masterdns',
                        '4': 'vaydns', '5': 'stormdns', '6': 'cottendns',
                        '7': 'noizdns'}
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
            if any(e.get('domain', '').lower() == domain_ns.lower() for e in registry.values()):
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

            if mode in ('dnstt', 'vaydns', 'noizdns'):
                target_port = prompt_port(" Enter local target port (e.g., 22 for SSH): ", default=22)
                if mode == 'dnstt':
                    ok = _install_dnstt_routed(name, domain_ns, target_port, internal_port)
                elif mode == 'vaydns':
                    ok = _install_vaydns_routed(name, domain_ns, target_port, internal_port)
                else:
                    ok = _install_noizdns_routed(name, domain_ns, target_port, internal_port)
                entry = {"mode": mode, "domain": domain_ns, "server_ip": server_ip,
                         "internal_port": internal_port, "target_port": target_port, "routed": True}
            elif mode == 'slipstream':
                target_port, backend_kind = _prompt_slipstream_backend()
                if target_port is None:
                    input("\nPress Enter to continue...")
                    continue
                ok = _install_slipstream_routed(name, domain_ns, target_port, internal_port)
                entry = {"mode": mode, "domain": domain_ns, "server_ip": server_ip,
                         "internal_port": internal_port, "target_port": target_port,
                         "backend": backend_kind, "routed": True}
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
                if entry['mode'] == 'passthrough':
                    print(f"\n--- {name} (pass-through: {entry.get('label', '?')}) ---")
                    print(f"  Server IP: {entry.get('server_ip') or get_public_ip()}")
                    print(f"  Port:      53 (UDP, via shared router)  ->  local port {entry.get('internal_port')}")
                    print(f"  Matching:  " + ("catch-all (anything not DNS/other signature)" if entry.get('catch_all')
                          else str((entry.get('signature') or {}).get('type', '?')) + " signature"))
                    continue
                print(f"\n--- {name} ({entry['mode']}) ---")
                print(f"  Domain:    {entry['domain']}")
                print(f"  Server IP: {entry.get('server_ip', '?')}")
                if entry['mode'] in ('dnstt', 'vaydns', 'slipstream', 'noizdns'):
                    print(f"  Port:      53 (via shared router)  |  Target: {entry.get('target_port', '?')}")
                    if entry['mode'] == 'slipstream':
                        kind = entry.get('backend')
                        if kind == 'socks' or entry.get('target_port') == SLIPSTREAM_SOCKS_PORT:
                            print(f"  Backend:   built-in SOCKS5 (127.0.0.1:{SLIPSTREAM_SOCKS_PORT}, loopback only)")
                        else:
                            print(f"  Backend:   custom TCP port {entry.get('target_port', '?')} "
                                  f"(the Android app needs a SOCKS5 backend - use option [5] to switch)")
                    key_prefix = {"dnstt": "server", "vaydns": "vaydns_server",
                                  "noizdns": "noizdns_server"}.get(entry['mode'], "server")
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

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  RESTART ALL INSTANCES                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not registry:
                print(" No instances to restart.")
            else:
                confirm = input(f" Restart all {len(registry)} instance(s)? (y/n): ").strip().lower()
                if confirm == 'y':
                    for inst_name, entry in registry.items():
                        if entry['mode'] == 'passthrough':
                            continue  # no service of its own - the protocol's own manager restarts it
                        # Same svc naming this menu's own status display
                        # already uses, so an instance shown as [ON]/[OFF]
                        # here restarts the exact service that status
                        # reflects.
                        svc = f"dnstt-{inst_name}"
                        _run(f"systemctl restart {svc}")
                        # FIX: this used to trust `systemctl restart`'s own
                        # return code as proof the instance came back up -
                        # for a Type=simple unit that's true the moment the
                        # process is forked, not once it's confirmed to
                        # still be running. That's exactly how an engine
                        # could restart "successfully" every time and still
                        # sit at [OFF] a moment later (see
                        # _service_failure_reason()'s docstring). Give it
                        # the same brief settle window as a fresh install
                        # and check the real state before reporting it.
                        time.sleep(1.5)
                        ok = _run(["systemctl", "is-active", "--quiet", svc]).returncode == 0
                        if ok:
                            print(f"{C_GREEN}[✔] {inst_name} ({entry['mode']}) restarted.{C_RESET}")
                        else:
                            print(f"{C_RED}[✖] {inst_name} ({entry['mode']}) restarted but isn't staying "
                                  f"up: {_service_failure_reason(svc)}{C_RESET}")
                    # The router itself sits in front of every instance on
                    # the shared port 53 - restarting it too so a
                    # bulk-restart genuinely clears any stuck state at
                    # that layer as well, not just the instances behind it.
                    router_ok = _run("systemctl restart dns-router").returncode == 0
                    if router_ok:
                        print(f"{C_GREEN}[✔] Router restarted.{C_RESET}")
                    else:
                        print(f"{C_RED}[✖] Router failed to restart - check 'systemctl status "
                              f"dns-router' for details.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            _add_passthrough_flow(registry, ports_dict)

        elif choice == '5':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s            FIX / UPGRADE SLIPSTREAM INSTANCE               %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            slip_names = [n for n, e in registry.items() if e.get('mode') == 'slipstream']
            if not slip_names:
                print(" No Slipstream instances to fix.")
            else:
                print(" Slipstream instances: " + ", ".join(slip_names))
                pick = input(" Instance name (blank = all): ").strip()
                targets = slip_names if not pick else ([pick] if pick in slip_names else [])
                if not targets:
                    print(f"{C_RED}[✖] No such Slipstream instance.{C_RESET}")
                for tname in targets:
                    _fix_routed_slipstream(registry, tname)
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")


def _save_state_now(ports_dict):
    """Persists ports_dict to disk immediately, rather than waiting for the
    main menu loop to save it after this whole module returns. Confirmed as
    the real, direct cause of a genuine bug report: the main loop only ever
    calls save_ports_dict() as its very last line, once a submenu function
    fully returns - so an admin who installs something here and then stays
    inside this module's own screens (e.g. viewing the connection info
    right after install, exactly what the install flow itself invites them
    to do) has that change sitting only in memory. If the session ends
    before they navigate all the way back to the main menu - SSH drops, the
    VPS reboots, the terminal closes - it's silently lost, even though the
    actual service the change describes keeps running fine on disk,
    independent of the panel. Lazy-imported to avoid a circular import,
    since smartui_main.py is what imports this module, not the reverse."""
    try:
        from smartui_main import save_ports_dict
        save_ports_dict(ports_dict)
    except Exception:
        pass


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
            print(" [7] NoiseDNS")
            print(" [8] MULTI-ENGINE MODE")
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            choice = input(" Enter an option: ").strip()
            if choice == '0':
                break
            if choice == '8':
                _multi_engine_menu(ports_dict)
                continue
            if choice not in ('1', '2', '3', '4', '5', '6', '7'):
                print(f"{C_RED}Invalid option.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            mode = {'1': 'dnstt', '2': 'slipstream', '3': 'masterdns', '4': 'vaydns',
                    '5': 'stormdns', '6': 'cottendns', '7': 'noizdns'}[choice]

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
                _save_state_now(ports_dict)
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
            port_to_check = DNSTT_INTERNAL_PORT if mode in ('dnstt', 'vaydns', 'noizdns') else custom_port
            if check_system_port_in_use(port_to_check, ("udp",)):
                print(f"{C_RED}[✖] UDP port {port_to_check} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   TRAFFIC REDIRECTION                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if mode == 'slipstream':
                target_port, _kind = _prompt_slipstream_backend()
                if target_port is None:
                    input("\nPress Enter to continue...")
                    continue
            else:
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
            if mode in ('dnstt', 'vaydns', 'noizdns'):
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
            elif mode == 'noizdns':
                ok = _install_noizdns(custom_port, domain_ns, target_port, mtu=mtu)
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
            _save_state_now(ports_dict)

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
                print(f" ENCRYPTION KEY: {key_content}")
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
                print(f" ENCRYPTION KEY: {key_content}")
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
                print(" [9] > MULTI-ENGINE MODE (run more of these at once)")
                print(" [0] > Back")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            else:
                client_cmds, pub_key_content = _client_commands(mode, ports_dict)
                print(f" SERVER IP: {server_ip} | LISTEN PORT: {custom_port}")
                print(f" NS DOMAIN: {domain_val}")
                print(f" LOCAL PORT REDIRECTION: {target_port}")
                if pub_key_content:
                    print(f" PUBLIC KEY: {pub_key_content}")
                print("-----------------------------------------------------")
                print(" [🔗] CLIENT CONNECTION COMMAND(S):")
                for label, cmd in client_cmds.items():
                    print(f"      {label}:")
                    print(f"        {cmd}")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
                print(" [1] > MODIFY DATA TRAFFIC PORT (REDIRECTION)")
                print(" [2] > MODIFY NS DOMAIN OR IP")
                if mode in ('dnstt', 'vaydns', 'noizdns'):
                    print(" [3] > GENERATE NEW KEYS (restarts the service)")
                if mode == 'slipstream':
                    print(" [3] > FIX / UPGRADE SLIPSTREAM (Rust server + SOCKS5 backend)")
                print("-----------------------------------------------------")
                print(" [4] > VIEW SERVICE STATUS")
                print(" [5] > EDIT SERVICE")
                print(" [6] > RESTART SERVICE")
                print(" [7] > START / STOP SERVICE")
                print("-----------------------------------------------------")
                print(" [8] > UNINSTALL SLOWDNS")
                print(" [9] > MULTI-ENGINE MODE (run more of these at once)")
                print(" [0] > Back")
                print("%s═════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            choice = input(" Select an option: ").strip()

            if choice == '9':
                _multi_engine_menu(ports_dict)
            elif choice == '0':
                break
            elif choice == '1' and mode not in ('masterdns', 'stormdns', 'cottendns'):
                new_tp = prompt_port(f"Enter new local target port (Current: {target_port}): ", default=int(target_port))
                ports_dict['DNSTT_TARGET'] = str(new_tp)
                _save_state_now(ports_dict)
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
                _save_state_now(ports_dict)
                print(f"{C_YELLOW}[!] Saved in the panel — the running service's domain won't change until")
                print(f"    you edit the service (option 5) and restart (6), since the domain is baked")
                print(f"    into its ExecStart command.{C_RESET}")
                input("\nPress Enter to continue...")
            elif choice == '3' and mode in ('dnstt', 'vaydns', 'noizdns'):
                binary = {"dnstt": DNSTT_BIN, "vaydns": VAYDNS_BIN, "noizdns": NOIZDNS_BIN}[mode]
                key_prefix = {"dnstt": "server", "vaydns": "vaydns_server", "noizdns": "noizdns_server"}[mode]
                key_dir = NOIZDNS_DIR if mode == 'noizdns' else DNSTT_DIR
                priv_key = f"{key_dir}/{key_prefix}.key"
                pub_key = f"{key_dir}/{key_prefix}.pub"
                res = _run([binary, "-gen-key", "-privkey-file", priv_key, "-pubkey-file", pub_key])
                if res.returncode == 0:
                    _run(f"systemctl restart {svc}")
                    print(f"{C_GREEN}[✔] New keys generated and service restarted (old keys are now invalid —")
                    print(f"    every client needs the new public key file).{C_RESET}")
                else:
                    print(f"{C_RED}[✖] Key generation failed: {res.stderr.strip()}{C_RESET}")
                input("\nPress Enter to continue...")
            elif choice == '3' and mode == 'slipstream':
                _fix_single_slipstream(ports_dict)
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
                os.system(f"systemctl reset-failed {svc}")
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
                            firewall_port = DNSTT_INTERNAL_PORT if mode in ('dnstt', 'vaydns', 'noizdns') else port_int
                            close_firewall_port(firewall_port, ("udp",))
                            if mode in ('dnstt', 'vaydns', 'noizdns'):
                                remove_nat_redirect_udp(port_int, DNSTT_INTERNAL_PORT)
                        # NoiseDNS keeps its own key material under NOIZDNS_DIR
                        # (not DNSTT_DIR) so it can coexist with a separate
                        # plain-DNSTT single install without either clobbering
                        # the other's keys.
                        os.system(f"rm -rf {NOIZDNS_DIR if mode == 'noizdns' else DNSTT_DIR}")
                    ports_dict['DNSTT_INSTALLED'] = False
                    for key in ['DNSTT_DOMAIN', 'DNSTT_IP', 'DNSTT_PORT', 'DNSTT_TARGET', 'DNSTT_MODE']:
                        ports_dict.pop(key, None)
                    _save_state_now(ports_dict)
                    print(f"{C_GREEN}[✔] Uninstalled successfully.{C_RESET}")
                input("\nPress Enter to continue...")
            else:
                print(f"{C_RED}Invalid option.{C_RESET}")
                input("\nPress Enter to continue...")
