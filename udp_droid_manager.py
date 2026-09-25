"""
udp_droid_manager.py - UDP Droid tunnel admin module for the SmartUI panel.
Completely replaces the previous UDP2RAW/libfarikudp.so port-scanning
implementation with a new, independent protocol matching this panel's own
ICMP tunnel design (icmp_manager.py) - AES-256-GCM encrypted frames,
automatic per-customer key derivation from each customer's own real SSH
password - but deliberately a separate, standalone module: own magic
bytes, own TUN device (tun2, not tun1) and subnet (10.9.0.0/24, not
10.8.0.0/24), own gate/iptables chain/state file, own systemd services.
Nothing here is wired to or shares a process with the ICMP tunnel - both
can run on the same VPS simultaneously with zero collision.

Two independent layers, same design as the ICMP tunnel:

1. The gate: the wire protocol itself has no login step of its own, so
   gating happens the same way as the Psiphon/WebSocket/ICMP gates -
   closed by default (dedicated iptables chain, DROP), and a small HTTP
   service grants a client's source IP temporary access after they
   authenticate using the REAL system SSH accounts via PAM (python-pam),
   not a separate credential store.

2. AES-256-GCM encryption of the tunnel traffic itself - but with NO
   separate tunnel password of any kind, for the same reason this panel
   has already eliminated that friction for Psiphon, Squid, and the ICMP
   tunnel: nobody wants to hand-manage or distribute a shared secret for
   potentially thousands of real customers. Each customer's personal
   AES-GCM key is derived automatically from their own real SSH password:
   the gate above records WHICH username unlocked each source IP, and the
   tunnel server reads that same state to look up the matching username's
   real password from ssh_user_manager.py's own plaintext password store
   (the same one Squid/Psiphon/ICMP already reuse) at decrypt time. An IP
   with no gate entry gets no key derived for it at all - the frame is
   simply dropped. Nothing here ever prints, stores, or requires typing
   any customer's username or password - it is read automatically from
   the store that already has it.

Unlike the ICMP tunnel (which has no port of its own - ICMP has no port
concept), UDP Droid needs an explicit UDP port configured at install time,
since that's what the Android client connects to directly.

Install step: writes the server file, and additionally installs the
'cryptography' package (pip3 install cryptography --break-system-packages)
the AES-GCM layer depends on - the tunnel server itself otherwise only
uses Python standard library (argparse, fcntl, hashlib, json, os, select,
socket, struct, subprocess, time) - no compilation, no other third-party
download.
"""

import os
import re
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, run_cmd as _run, get_public_ip,
    persist_firewall_rules, open_firewall_port, close_firewall_port,
    get_live_port_from_service, check_system_port_in_use,
)
from openvpn_manager import _default_interface

UDPDROID_DIR = "/etc/udp-droid-vpn"
SERVER_SCRIPT_PATH = "/usr/local/bin/udp-droid-vpn-server.py"
SERVICE_PATH = "/etc/systemd/system/udp-droid-vpn.service"
GATE_SCRIPT_PATH = "/usr/local/bin/udp-droid-vpn-gate.py"
GATE_SERVICE_PATH = "/etc/systemd/system/udp-droid-vpn-gate.service"
GATE_STATE_PATH = f"{UDPDROID_DIR}/gate_state.json"
CLEANUP_SCRIPT_PATH = "/usr/local/bin/udp-droid-vpn-gate-cleanup.py"
CLEANUP_CRON_PATH = "/etc/cron.d/udp-droid-vpn-gate-cleanup"
GATE_CHAIN = "udpdroidgate"
GATE_PORT_DEFAULT = 7001
TUNNEL_PORT_DEFAULT = 7000
TUN_DEVICE = "tun2"
TUNNEL_NETWORK = "10.9.0.0/24"  # hardcoded in the server script itself, matching the Android client

SERVER_SCRIPT = '#!/usr/bin/env python3\n"""UDP Droid VPN server for the matching Android client (UdpDroidVpnService).\n\nSame protocol design as this panel\'s own ICMP tunnel (icmp_manager.py) -\nAES-256-GCM encrypted frames, automatic per-customer key derivation from\neach customer\'s own real SSH password via a gate-unlock mechanism - but a\ngenuinely separate, independent file and process: its own magic bytes,\nown TUN device and subnet, own gate/iptables chain/state file, so both\ntunnels can run on the same VPS at once with zero collision or shared\nstate between them.\n\nCreates a TUN interface, NATs 10.9.0.0/24 (not 10.8.0.0/24 - deliberately\ndifferent from the ICMP tunnel\'s own subnet) to the Internet interface,\nand carries framed, AES-256-GCM-encrypted IPv4 packets inside plain UDP\ndatagrams on a configurable port - simpler than the ICMP tunnel\'s own\necho-wrapping, since UDP needs no OS-level raw-socket wrapping at all.\n\nNo separate tunnel password of any kind - every customer\'s key is derived\nautomatically from their own real SSH password (the same account already\nused for SSH/Dropbear/Squid/Psiphon/ICMP elsewhere in this panel), looked\nup at decrypt time via this tunnel\'s own gate state file: the gate (a\nseparate, existing-pattern script, own port/chain/state - not shared with\nthe ICMP tunnel\'s own gate) already requires a customer to authenticate\nwith real SSH credentials before their source IP gets unlocked, and\nrecords *which* username did the unlocking. This server reads that same\nstate file to map a source IP to a username, then reads the username\'s\nreal password straight from ssh_user_manager.py\'s own plaintext password\nstore to derive that customer\'s personal AES-GCM key.\n\nFrame layout (32-byte header, all fields big-endian, header itself is\nNOT encrypted - only the payload is):\n    magic(8="UDPDROID1") + version(1) + type(1) + session(4) + pid(4)\n    + seq(8) + fragIndex(2) + fragCount(2) + dataLen(2) + data(encrypted)\n\nEncryption: AES/GCM/NoPadding, 128-bit tag.\n    key      = SHA256("UDPDROID-AES-GCM-v1" + ssh_password + server + dir_index)\n    nonce    = session(4 bytes BE) + seq(8 bytes BE)   [12 bytes, GCM standard]\n    dir_index=1 -> "client-to-server" key (client encrypts, server decrypts)\n    dir_index=2 -> "server-to-client" key (server encrypts, client decrypts)\nDeliberately a different magic and a different key-derivation label from\nthe ICMP tunnel\'s own protocol, even though the design is otherwise\nidentical - guarantees a frame from one tunnel type can never be mistaken\nfor, or accidentally processed by, the other.\n"""\nimport argparse, fcntl, hashlib, json, os, select, socket, struct, subprocess, time\n\ntry:\n    from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nexcept ImportError:\n    raise SystemExit(\n        "Missing dependency: pip3 install cryptography --break-system-packages"\n    )\n\nMAGIC = b"UDPDROID"\nVERSION = 1\nTYPE_DATA = 1\nTYPE_ACK = 2\nTYPE_KEEPALIVE = 3\nHEADER_SIZE = 32\nMAX_PAYLOAD = 1320\nMAX_DATA = MAX_PAYLOAD - HEADER_SIZE - 16  # 16 = AES-GCM tag overhead\nTUNSETIFF = 0x400454CA\nIFF_TUN = 0x0001\nIFF_NO_PI = 0x1000\n\nGATE_STATE_PATH = "/etc/udp-droid-vpn/gate_state.json"\nSSH_PASSWORD_STORE_PATH = "/etc/ssh_users/plaintext_passwords.json"\n\n\ndef load_json(path):\n    try:\n        with open(path) as f:\n            return json.load(f)\n    except Exception:\n        return {}\n\n\ndef lookup_username_for_ip(source_ip):\n    state = load_json(GATE_STATE_PATH)\n    entry = state.get(source_ip)\n    if isinstance(entry, dict):\n        return entry.get("username")\n    return None\n\n\ndef derive_key(password, server, dir_index):\n    h = hashlib.sha256()\n    h.update(b"UDPDROID-AES-GCM-v1")\n    h.update(password.encode("utf-8"))\n    h.update(server.encode("utf-8"))\n    h.update(struct.pack("!I", dir_index))\n    return h.digest()\n\n\ndef make_nonce(session, seq):\n    return struct.pack("!I", session) + struct.pack("!Q", seq)\n\n\ndef encrypt(aesgcm, session, seq, plaintext):\n    return aesgcm.encrypt(make_nonce(session, seq), plaintext, None)\n\n\ndef decrypt(aesgcm, session, seq, ciphertext):\n    return aesgcm.decrypt(make_nonce(session, seq), ciphertext, None)\n\n\ndef create_tun(name):\n    fd = os.open(\'/dev/net/tun\', os.O_RDWR)\n    res = fcntl.ioctl(fd, TUNSETIFF, struct.pack(\'16sH\', name.encode(), IFF_TUN | IFF_NO_PI))\n    actual = struct.unpack(\'16sH\', res)[0].split(b\'\\0\', 1)[0].decode()\n    return fd, actual\n\n\ndef sh(*args): subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n\n\ndef setup_network(tun, external):\n    try: sh(\'ip\', \'addr\', \'add\', \'10.9.0.1/24\', \'dev\', tun)\n    except subprocess.CalledProcessError: pass\n    sh(\'ip\', \'link\', \'set\', \'dev\', tun, \'up\')\n    sh(\'sysctl\', \'-w\', \'net.ipv4.ip_forward=1\')\n    for rule in [\n        (\'iptables\', \'-A\', \'FORWARD\', \'-i\', tun, \'-j\', \'ACCEPT\'),\n        (\'iptables\', \'-A\', \'FORWARD\', \'-o\', tun, \'-m\', \'state\', \'--state\', \'ESTABLISHED,RELATED\', \'-j\', \'ACCEPT\'),\n        (\'iptables\', \'-t\', \'nat\', \'-A\', \'POSTROUTING\', \'-s\', \'10.9.0.0/24\', \'-o\', external, \'-j\', \'MASQUERADE\')]:\n        try: sh(*rule)\n        except subprocess.CalledProcessError: pass\n\n\ndef build_frame(typ, session, pid, seq, fi, fc, data):\n    return MAGIC + bytes((VERSION, typ)) + struct.pack(\'!IIQHHH\', session, pid, seq, fi, fc, len(data)) + data\n\n\ndef parse_frame(p):\n    if len(p) < HEADER_SIZE or p[:8] != MAGIC or p[8] != VERSION: return None\n    typ = p[9]\n    session, pid, seq, fi, fc, n = struct.unpack(\'!IIQHHH\', p[10:32])\n    if fc < 1 or fc > 64 or fi >= fc or n != len(p) - HEADER_SIZE: return None\n    return typ, session, pid, seq, fi, fc, p[HEADER_SIZE:]\n\n\ndef valid_ipv4(p):\n    if len(p) < 20 or p[0] >> 4 != 4: return False\n    ihl = (p[0] & 15) * 4\n    if ihl < 20 or ihl > len(p): return False\n    total = (p[2] << 8) | p[3]\n    return ihl <= total <= len(p) and total <= 1400\n\n\ndef iptables_packet_counters(tun_name):\n    forward = 0; nat = 0\n    try:\n        out = subprocess.check_output([\'iptables\', \'-nvx\', \'-L\', \'FORWARD\'], stderr=subprocess.DEVNULL, text=True)\n        for line in out.splitlines():\n            parts = line.split()\n            if len(parts) >= 8 and parts[0].isdigit() and parts[1].isdigit() and tun_name in line:\n                forward += int(parts[0])\n    except Exception:\n        pass\n    try:\n        out = subprocess.check_output([\'iptables\', \'-t\', \'nat\', \'-nvx\', \'-L\', \'POSTROUTING\'], stderr=subprocess.DEVNULL, text=True)\n        for line in out.splitlines():\n            parts = line.split()\n            if len(parts) >= 8 and parts[0].isdigit() and parts[1].isdigit() and \'MASQUERADE\' in line:\n                nat += int(parts[0])\n    except Exception:\n        pass\n    try:\n        with open(\'/proc/sys/net/ipv4/ip_forward\', \'r\') as f:\n            ip_forward = int(f.read().strip() or \'0\')\n    except Exception:\n        ip_forward = -1\n    return ip_forward, forward, nat\n\n\nclass Client:\n    __slots__ = (\'last\', \'addr\', \'internal_ip\', \'decrypt_aead\', \'encrypt_aead\', \'assemblies\')\n\n    def __init__(self, decrypt_aead, encrypt_aead):\n        self.last = 0.0\n        self.addr = None\n        self.internal_ip = None\n        self.decrypt_aead = decrypt_aead\n        self.encrypt_aead = encrypt_aead\n        self.assemblies = {}\n\n\ndef get_or_create_client(clients, addr_ip, session, server_name):\n    """Only ever creates a Client once we can resolve a real SSH password\n    for this source IP - an IP with no gate entry (never unlocked, or its\n    window expired) gets nothing. Module-level (not a closure) so it\'s\n    directly testable without spinning up sockets/TUN."""\n    client_key = (addr_ip, session)\n    client = clients.get(client_key)\n    if client is not None:\n        return client\n    username = lookup_username_for_ip(addr_ip)\n    if not username:\n        return None\n    passwords = load_json(SSH_PASSWORD_STORE_PATH)\n    password = passwords.get(username)\n    if not password:\n        return None\n    client_to_server_key = derive_key(password, server_name, 1)\n    server_to_client_key = derive_key(password, server_name, 2)\n    client = Client(AESGCM(client_to_server_key), AESGCM(server_to_client_key))\n    clients[client_key] = client\n    print(f\'[+] New client {addr_ip} session={session} authenticated as \\\'{username}\\\'\')\n    return client\n\n\ndef run(args):\n    if os.geteuid() != 0: raise SystemExit(\'Run as root.\')\n    tun_fd, tun_name = create_tun(args.tun); setup_network(tun_name, args.interface)\n    print(f\'[+] TUN ready: {tun_name}\'); print(f\'[+] NAT interface: {args.interface}\')\n    ipfwd, fwd_pkts, nat_pkts = iptables_packet_counters(tun_name)\n    print(f\'[+] ip_forward={ipfwd} FORWARD_pkts={fwd_pkts} NAT_pkts={nat_pkts}\')\n\n    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n    udp_sock.bind((\'0.0.0.0\', args.port))\n    udp_sock.setblocking(False)\n    print(f\'[+] UDP socket ready on port {args.port}\')\n\n    clients = {}  # (addr_ip, session) -> Client\n    server_rx_frames = 0; server_rx_bytes = 0; server_tx_frames = 0; server_tx_bytes = 0\n    server_tun_out = 0; server_tun_in = 0; server_drops = 0; server_auth_fail = 0; server_no_gate_entry = 0\n    next_stats = 0.0\n    print(\'[+] Waiting for UDP Droid VPN clients (each must be gate-unlocked first)...\')\n\n    def handle_frame(raw, addr):\n        nonlocal server_rx_frames, server_rx_bytes, server_tun_out, server_drops, server_auth_fail, server_no_gate_entry\n        parsed = parse_frame(raw)\n        if not parsed: return\n        typ, session, pid, seq, fi, fc, enc_data = parsed\n\n        client = get_or_create_client(clients, addr[0], session, args.server_name)\n        if client is None:\n            server_no_gate_entry += 1\n            return\n        client.last = time.monotonic()\n        client.addr = addr\n\n        try:\n            data = decrypt(client.decrypt_aead, session, seq, bytes(enc_data)) if enc_data else b\'\'\n        except Exception:\n            server_auth_fail += 1\n            return\n\n        if typ == TYPE_KEEPALIVE:\n            udp_sock.sendto(build_frame(TYPE_KEEPALIVE, session, pid, seq, 0, 1,\n                                         encrypt(client.encrypt_aead, session, seq, b\'\')), addr)\n            return\n        if typ == TYPE_ACK:\n            return\n        if typ != TYPE_DATA:\n            return\n\n        server_rx_frames += 1; server_rx_bytes += len(data)\n        if fc == 1:\n            full = data\n        else:\n            a = client.assemblies.get(pid)\n            if a is None or a[1] != fc:\n                a = (time.monotonic(), fc, [None] * fc)\n                client.assemblies[pid] = a\n            a[2][fi] = data\n            full = None\n            if all(x is not None for x in a[2]):\n                full = b\'\'.join(a[2])\n                client.assemblies.pop(pid, None)\n        if full is not None:\n            if valid_ipv4(full):\n                client.internal_ip = socket.inet_ntoa(full[12:16])\n                os.write(tun_fd, full)\n                server_tun_out += 1\n            else:\n                server_drops += 1\n\n        udp_sock.sendto(build_frame(TYPE_ACK, session, pid, seq, 0, 1,\n                                     encrypt(client.encrypt_aead, session, seq, b\'\')), addr)\n\n    try:\n        while True:\n            readable, _, _ = select.select([udp_sock, tun_fd], [], [], 0.5)\n            now = time.monotonic()\n\n            for ck, c in list(clients.items()):\n                for pid, a in list(c.assemblies.items()):\n                    if now - a[0] > 15:\n                        c.assemblies.pop(pid, None)\n                        server_drops += 1\n\n            for ck in [k for k, c in clients.items() if now - c.last > 120]:\n                clients.pop(ck, None)\n\n            if now >= next_stats:\n                next_stats = now + 5.0\n                if server_no_gate_entry or server_auth_fail:\n                    print(f\'[i] {server_no_gate_entry} frame(s) from non-gate-unlocked IPs, \'\n                          f\'{server_auth_fail} decrypt failure(s) since start.\')\n\n            if udp_sock in readable:\n                packet, addr = udp_sock.recvfrom(65535)\n                handle_frame(packet, addr)\n\n            if tun_fd in readable:\n                data = os.read(tun_fd, 65535)\n                if data and clients:\n                    server_tun_in += 1\n                    match = None\n                    if valid_ipv4(data):\n                        dest_ip = socket.inet_ntoa(data[16:20])\n                        for ck, c in clients.items():\n                            if c.internal_ip == dest_ip:\n                                match = (ck, c); break\n                    if match is None:\n                        match = max(clients.items(), key=lambda x: x[1].last)\n                    (client_ip, session), client = match\n\n                    pid = int(time.monotonic() * 1000000) & 0xffffffff\n                    fc = (len(data) + MAX_DATA - 1) // MAX_DATA\n                    for fi, off in enumerate(range(0, len(data), MAX_DATA)):\n                        chunk = data[off:off + MAX_DATA]\n                        seq = int(time.monotonic_ns()) & 0xffffffffffffffff\n                        enc_chunk = encrypt(client.encrypt_aead, session, seq, chunk)\n                        frame = build_frame(TYPE_DATA, session, pid, seq, fi, fc, enc_chunk)\n                        server_tx_frames += 1; server_tx_bytes += len(chunk)\n                        udp_sock.sendto(frame, client.addr)\n                    print(f\'[TX] {client_ip} session={session} pid={pid} packet={len(data)} frags={fc}\')\n    finally:\n        udp_sock.close()\n        os.close(tun_fd)\n\n\nif __name__ == \'__main__\':\n    p = argparse.ArgumentParser()\n    p.add_argument(\'-i\', \'--interface\', \'--iface\', dest=\'interface\', required=True)\n    p.add_argument(\'-t\', \'--tun\', dest=\'tun\', default=\'tun2\')\n    p.add_argument(\'-p\', \'--port\', dest=\'port\', type=int, required=True)\n    p.add_argument(\'--server-name\', dest=\'server_name\', required=True,\n                    help=\'The hostname/IP the client connects to - must match the client\\\'s own "server" field exactly, since it feeds key derivation.\')\n    run(p.parse_args())\n'

GATE_SCRIPT = '#!/usr/bin/env python3\n"""UDP Droid tunnel access gate. GET /unlock?user=X&pass=Y -> verifies the\ncredentials against the REAL system SSH accounts via PAM (the same accounts\nssh_user_manager.py already manages - no separate credential store), and on\nsuccess inserts a time-limited iptables ACCEPT rule for that client\'s source\nIP ahead of the default DROP rule for the UDP Droid tunnel port. Own,\nseparate chain/state file from the ICMP tunnel\'s own gate - not shared.\n\nAlso records WHICH username unlocked each IP, not just the expiry - the\ntunnel server itself reads this same state to automatically derive each\ncustomer\'s personal AES-GCM key from their own real SSH password, looked\nup by username, with nothing extra to configure and no separate\ntunnel-wide password of any kind to manage for any number of customers.\n"""\nimport os\nimport json\nimport time\nimport subprocess\nimport http.server\nimport socketserver\nimport urllib.parse\n\ntry:\n    import pam\nexcept ImportError:\n    pam = None\n\nGATE_STATE_PATH = "/etc/udp-droid-vpn/gate_state.json"\nGATE_CHAIN = "udpdroidgate"\nACCEPT_WINDOW_MINUTES = 15\nPORT = int(os.environ.get("UDPDROID_GATE_PORT", "7001"))\n\n_fail_counts = {}\n_fail_window = 60\n_fail_limit = 10\n\n\ndef run(cmd):\n    return subprocess.run(cmd, capture_output=True, text=True)\n\n\ndef load_gate_state():\n    try:\n        with open(GATE_STATE_PATH) as f:\n            return json.load(f)\n    except Exception:\n        return {}\n\n\ndef save_gate_state(state):\n    os.makedirs(os.path.dirname(GATE_STATE_PATH), exist_ok=True)\n    with open(GATE_STATE_PATH, "w") as f:\n        json.dump(state, f, indent=2)\n\n\ndef grant_access(source_ip, username):\n    check = run(["iptables", "-C", GATE_CHAIN, "-s", source_ip, "-j", "ACCEPT"])\n    if check.returncode != 0:\n        run(["iptables", "-I", GATE_CHAIN, "1", "-s", source_ip, "-j", "ACCEPT"])\n    state = load_gate_state()\n    state[source_ip] = {"expiry": time.time() + ACCEPT_WINDOW_MINUTES * 60, "username": username}\n    save_gate_state(state)\n\n\ndef _rate_limited(addr):\n    now = time.time()\n    entry = [t for t in _fail_counts.get(addr, []) if now - t < _fail_window]\n    _fail_counts[addr] = entry\n    return len(entry) >= _fail_limit\n\n\ndef _record_failure(addr):\n    _fail_counts.setdefault(addr, []).append(time.time())\n\n\nclass GateHandler(http.server.BaseHTTPRequestHandler):\n    def log_message(self, fmt, *args):\n        pass  # the query string carries the password - never let it reach a log file\n\n    def do_GET(self):\n        client_addr = self.client_address[0]\n        if _rate_limited(client_addr):\n            self.send_response(429)\n            self.end_headers()\n            return\n\n        if pam is None:\n            self.send_response(500)\n            self.end_headers()\n            self.wfile.write(b\'{"error":"pam module not installed on server"}\')\n            return\n\n        parsed = urllib.parse.urlparse(self.path)\n        params = urllib.parse.parse_qs(parsed.query)\n        user = params.get("user", [""])[0]\n        password = params.get("pass", [""])[0]\n\n        valid = False\n        if user and password:\n            try:\n                valid = pam.pam().authenticate(user, password, service="login")\n            except Exception:\n                valid = False\n\n        if not valid:\n            _record_failure(client_addr)\n            self.send_response(401)\n            self.end_headers()\n            return\n\n        grant_access(client_addr, user)\n        body = json.dumps({"status": "granted", "valid_for_minutes": ACCEPT_WINDOW_MINUTES}).encode()\n        self.send_response(200)\n        self.send_header("Content-type", "application/json")\n        self.send_header("Content-length", str(len(body)))\n        self.end_headers()\n        self.wfile.write(body)\n\n\nclass ReusableTCPServer(socketserver.ThreadingTCPServer):\n    allow_reuse_address = True\n    daemon_threads = True\n\n\nif __name__ == "__main__":\n    with ReusableTCPServer(("0.0.0.0", PORT), GateHandler) as httpd:\n        print("udp-droid-vpn-gate listening on 0.0.0.0:%d" % PORT)\n        httpd.serve_forever()\n'

CLEANUP_SCRIPT = '#!/usr/bin/env python3\n"""Expires temporary per-IP UDP Droid ACCEPT rules once their window has\npassed - same cadence pattern as the other gate cleanups in this panel,\nrun periodically via cron. Own, separate state file from the ICMP\ntunnel\'s own cleanup - not shared."""\nimport json\nimport time\nimport subprocess\n\nGATE_STATE_PATH = "/etc/udp-droid-vpn/gate_state.json"\nGATE_CHAIN = "udpdroidgate"\n\n\ndef run(cmd):\n    return subprocess.run(cmd, capture_output=True, text=True)\n\n\ndef entry_expiry(entry):\n    if isinstance(entry, dict):\n        return entry.get("expiry", 0)\n    return entry\n\n\ndef main():\n    try:\n        with open(GATE_STATE_PATH) as f:\n            state = json.load(f)\n    except Exception:\n        return\n\n    now = time.time()\n    changed = False\n    for ip, entry in list(state.items()):\n        if now >= entry_expiry(entry):\n            run(["iptables", "-D", GATE_CHAIN, "-s", ip, "-j", "ACCEPT"])\n            del state[ip]\n            changed = True\n\n    if changed:\n        with open(GATE_STATE_PATH, "w") as f:\n            json.dump(state, f, indent=2)\n\n\nif __name__ == "__main__":\n    main()\n'

def _service_active(name):
    return _run(["systemctl", "is-active", "--quiet", name]).returncode == 0


def _deploy_script(path, content):
    needs_write = True
    if os.path.exists(path):
        with open(path) as f:
            needs_write = f.read() != content
    if needs_write:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o755)
    return True


def _ensure_pam_installed():
    check = _run(["python3", "-c", "import pam"])
    if check.returncode == 0:
        return True
    print(f"{C_CYAN}[i] Installing python3-pampy (real SSH/system-account auth, no separate{C_RESET}")
    print(f"{C_CYAN}    credential store)...{C_RESET}")
    _run("apt-get update && apt-get install -y python3-pampy")
    check2 = _run(["python3", "-c", "import pam"])
    if check2.returncode != 0:
        print(f"{C_YELLOW}[!] apt package unavailable - trying pip instead...{C_RESET}")
        _run("pip3 install python-pam --break-system-packages")
        check2 = _run(["python3", "-c", "import pam"])
    return check2.returncode == 0


def _write_server_service(interface, server_name, tunnel_port):
    service_content = f"""[Unit]
Description=UDP Droid VPN Server (AES-256-GCM, per-customer keys via SSH credentials)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {SERVER_SCRIPT_PATH} -i {interface} -t {TUN_DEVICE} -p {tunnel_port} --server-name {server_name}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _write_gate_service(gate_port):
    service_content = f"""[Unit]
Description=UDP Droid VPN Access Gate
After=network.target

[Service]
Type=simple
User=root
Environment=UDPDROID_GATE_PORT={gate_port}
ExecStart=/usr/bin/python3 {GATE_SCRIPT_PATH}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    with open(GATE_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _ensure_gate_chain(tunnel_port):
    """Default-DROP chain for the UDP Droid tunnel port - only source IPs
    the gate has explicitly granted (via a temporary ACCEPT inserted ahead
    of this) get through."""
    _run(["iptables", "-N", GATE_CHAIN])
    check_jump = _run(["iptables", "-C", "INPUT", "-p", "udp", "--dport", str(tunnel_port), "-j", GATE_CHAIN])
    if check_jump.returncode != 0:
        _run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", str(tunnel_port), "-j", GATE_CHAIN])
    check_drop = _run(["iptables", "-C", GATE_CHAIN, "-j", "DROP"])
    if check_drop.returncode != 0:
        _run(["iptables", "-A", GATE_CHAIN, "-j", "DROP"])


def _remove_gate_chain(tunnel_port):
    _run(["iptables", "-D", "INPUT", "-p", "udp", "--dport", str(tunnel_port), "-j", GATE_CHAIN])
    _run(["iptables", "-F", GATE_CHAIN])
    _run(["iptables", "-X", GATE_CHAIN])


def _wait_for_tun_up(tries=8, delay=1):
    for _ in range(tries):
        result = _run(["ip", "addr", "show", "dev", TUN_DEVICE])
        if result.returncode == 0 and re.search(r"inet \d+\.\d+\.\d+\.\d+", result.stdout):
            return True
        time.sleep(delay)
    return False


def udp_droid_admin_manager(ports_dict):
    """UDP Droid VPN (custom protocol) Administrator Module."""
    while True:
        live_gate_port = get_live_port_from_service(GATE_SERVICE_PATH, r'Environment=UDPDROID_GATE_PORT=(\d+)')
        recorded_gate_port = ports_dict.get("UDPDROID_GATE_PORT")
        if live_gate_port and str(recorded_gate_port) != str(live_gate_port):
            print(f"{C_YELLOW}[!] The saved gate port ({recorded_gate_port or 'none'}) didn't match what's")
            print(f"    actually running ({live_gate_port}) - correcting the panel's records.{C_RESET}")
            ports_dict["UDPDROID_GATE_PORT"] = live_gate_port
            input("\nPress Enter to continue...")

        gate_port = ports_dict.get("UDPDROID_GATE_PORT", "Not configured")
        tunnel_port = ports_dict.get("UDPDROID_TUNNEL_PORT", "Not configured")
        is_active = _service_active("udp-droid-vpn")
        gate_active = _service_active("udp-droid-vpn-gate")

        clear_screen()
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print("%s                 UDP DROID TUNNEL ADMINISTRATOR             %s" % (C_BOLD, C_RESET))
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print(f"      NETWORK: {TUNNEL_NETWORK} (fixed - matches the Android client)")
        print(f"      TUNNEL PORT: {tunnel_port}  |  GATE PORT: {gate_port}")
        print(f"{C_YELLOW}      This protocol has no login of its own - clients must unlock their")
        print(f"      IP via the gate (using their real SSH username/password) before the")
        print(f"      tunnel will respond to them at all. Every customer automatically uses")
        print(f"      their own existing SSH credentials - nothing separate to manage.{C_RESET}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL UDP DROID TUNNEL")
        print(" [2]> VIEW CONNECTION INFO")
        print(" [3]> VIEW SERVICE LOGS")
        print(" [4]> RESTART SERVICES")
        print(f" [5]> START/STOP SERVICES [{'ON' if is_active else 'OFF'}]")
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [6] UNINSTALL UDP DROID TUNNEL")
        print("%s================================================================%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == "0":
            break

        elif choice == "1":
            clear_screen()
            print("%s================================================================%s" % (C_CYAN, C_RESET))
            print("%s            UDP DROID TUNNEL INSTALLATION                   %s" % (C_BOLD, C_RESET))
            print("%s================================================================%s" % (C_CYAN, C_RESET))
            print(f"{C_CYAN}[i] Every customer automatically uses their own existing SSH")
            print(f"    username/password to connect - nothing separate to set or hand")
            print(f"    out, and nothing here lists any customer's credentials.{C_RESET}\n")

            interface = _default_interface()
            gate_port = int(ports_dict.get("UDPDROID_GATE_PORT", GATE_PORT_DEFAULT))
            server_name = get_public_ip()

            existing_tunnel_port = ports_dict.get("UDPDROID_TUNNEL_PORT")
            default_port = int(existing_tunnel_port) if existing_tunnel_port else TUNNEL_PORT_DEFAULT
            port_input = input(f" UDP tunnel port (blank = {default_port}): ").strip()
            tunnel_port = int(port_input) if port_input.isdigit() else default_port
            if str(tunnel_port) != str(existing_tunnel_port) and check_system_port_in_use(tunnel_port, ("udp",)):
                print(f"{C_RED}[X] Port {tunnel_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            print(f"\n{C_CYAN}[i] Installing 'cryptography' (needed for AES-256-GCM)...{C_RESET}")
            if _run("pip3 install cryptography --break-system-packages").returncode != 0:
                print(f"{C_RED}[X] Could not install the 'cryptography' package - check network access.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            if not _deploy_script(SERVER_SCRIPT_PATH, SERVER_SCRIPT):
                input("\nPress Enter to continue...")
                continue
            if not _ensure_pam_installed():
                print(f"{C_RED}[X] Could not install PAM support - the gate needs this to check")
                print(f"    SSH credentials. Aborting.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            if not _deploy_script(GATE_SCRIPT_PATH, GATE_SCRIPT):
                input("\nPress Enter to continue...")
                continue
            if not _deploy_script(CLEANUP_SCRIPT_PATH, CLEANUP_SCRIPT):
                input("\nPress Enter to continue...")
                continue
            if not os.path.exists(CLEANUP_CRON_PATH):
                with open(CLEANUP_CRON_PATH, "w") as f:
                    f.write("* * * * * root /usr/bin/python3 %s\n" % CLEANUP_SCRIPT_PATH)
                os.chmod(CLEANUP_CRON_PATH, 0o644)

            _write_server_service(interface, server_name, tunnel_port)
            _write_gate_service(gate_port)
            _ensure_gate_chain(tunnel_port)
            open_firewall_port(gate_port, ("tcp",))
            open_firewall_port(tunnel_port, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable udp-droid-vpn")
            _run("systemctl enable udp-droid-vpn-gate")

            server_ok = _run("systemctl restart udp-droid-vpn").returncode == 0
            gate_ok = _run("systemctl restart udp-droid-vpn-gate").returncode == 0

            if server_ok and _wait_for_tun_up() and gate_ok:
                ports_dict["UDPDROID_GATE_PORT"] = str(gate_port)
                ports_dict["UDPDROID_TUNNEL_PORT"] = str(tunnel_port)
                print(f"{C_GREEN}[OK] UDP Droid tunnel and gate installed and verified.{C_RESET}\n")
                print(f" Server IP/name: {server_name}  (this is what customers enter as \"server\" in the app)")
                print(f" Tunnel port: {tunnel_port}")
                print(f" Gate URL: http://{server_name}:{gate_port}/unlock?user=SSH_USERNAME&pass=SSH_PASSWORD")
                print(f"\n Every customer hits that gate URL once (from the same network they'll")
                print(f" tunnel from) using their own real SSH username/password, then connects")
                print(f" via the Android app - the app itself needs only the server name and")
                print(f" tunnel port above plus the customer's own SSH username/password. No")
                print(f" separate tunnel password of any kind exists to distribute or manage.")
            else:
                _remove_gate_chain(tunnel_port)
                close_firewall_port(gate_port, ("tcp",))
                close_firewall_port(tunnel_port, ("udp",))
                print(f"{C_RED}[X] Install did not complete successfully - check")
                print(f"    'journalctl -u udp-droid-vpn' and 'journalctl -u udp-droid-vpn-gate'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == "2":
            clear_screen()
            if not os.path.exists(SERVER_SCRIPT_PATH):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            server_ip = get_public_ip()
            print(f" Server IP/name: {server_ip}  (this is what customers enter as \"server\" in the app)")
            print(f" Tunnel port: {tunnel_port}")
            print(f" Gate URL: http://{server_ip}:{gate_port}/unlock?user=SSH_USERNAME&pass=SSH_PASSWORD")
            print(f"\n Every customer authenticates with their own real SSH username/password -")
            print(f" the same accounts already used for SSH/Dropbear, nothing separate to")
            print(f" manage here. Each customer's tunnel encryption key is derived")
            print(f" automatically from their own password once the gate unlocks their IP -")
            print(f" there is no separate tunnel password of any kind to distribute.")
            input("\nPress Enter to continue...")

        elif choice == "3":
            clear_screen()
            os.system("journalctl -u udp-droid-vpn -n 30 --no-pager")
            print()
            os.system("journalctl -u udp-droid-vpn-gate -n 20 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == "4":
            ok1 = _run("systemctl restart udp-droid-vpn").returncode == 0
            ok2 = _run("systemctl restart udp-droid-vpn-gate").returncode == 0
            if ok1 and ok2:
                print(f"{C_GREEN}[OK] Both services restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] One or both failed to restart - check the logs.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == "5":
            if is_active:
                _run("systemctl stop udp-droid-vpn")
                _run("systemctl stop udp-droid-vpn-gate")
                print(f"{C_YELLOW}[!] UDP Droid tunnel and gate stopped.{C_RESET}")
            else:
                if not os.path.exists(SERVER_SCRIPT_PATH):
                    print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start udp-droid-vpn")
                _run("systemctl start udp-droid-vpn-gate")
                print(f"{C_GREEN}[OK] UDP Droid tunnel and gate started.{C_RESET}" if _service_active("udp-droid-vpn")
                      else f"{C_RED}[X] Failed to start - check the logs.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == "6":
            clear_screen()
            confirm = input(" Are you sure you want to completely remove the UDP Droid tunnel? (y/n): ").strip().lower()
            if confirm == "y":
                _run("systemctl stop udp-droid-vpn")
                _run("systemctl stop udp-droid-vpn-gate")
                _run("systemctl disable udp-droid-vpn")
                _run("systemctl disable udp-droid-vpn-gate")
                _run(f"rm -f {SERVICE_PATH} {GATE_SERVICE_PATH} {CLEANUP_CRON_PATH}")
                _run("systemctl daemon-reload")
                saved_tunnel_port = ports_dict.get("UDPDROID_TUNNEL_PORT")
                _remove_gate_chain(saved_tunnel_port if saved_tunnel_port else TUNNEL_PORT_DEFAULT)
                if str(gate_port).isdigit():
                    close_firewall_port(int(gate_port), ("tcp",))
                if saved_tunnel_port and str(saved_tunnel_port).isdigit():
                    close_firewall_port(int(saved_tunnel_port), ("udp",))
                persist_firewall_rules()
                _run(f"rm -rf {UDPDROID_DIR} {SERVER_SCRIPT_PATH} {GATE_SCRIPT_PATH} {CLEANUP_SCRIPT_PATH}")
                ports_dict.pop("UDPDROID_GATE_PORT", None)
                ports_dict.pop("UDPDROID_TUNNEL_PORT", None)
                print(f"{C_GREEN}[OK] UDP Droid tunnel removed and purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
