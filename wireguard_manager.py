"""
wireguard_manager.py - WireGuard admin module for the SmartUI panel.

The single most severe bug found here: every new peer was assigned the exact
same hardcoded address:
    AllowedIPs = 10.7.0.2/32
Adding a second client peer would give it the IDENTICAL IP address as the
first one - a fundamental, immediately-breaking correctness bug for the core
"add multiple clients" use case of a VPN server, not an edge case. Fixed by
scanning the existing config for already-allocated addresses and assigning
each new peer the next genuinely free one.

Other real bugs found:

1. The server's own interface address was computed via a naive string
   replace: server_subnet.replace('0/24', '1/24'). This "worked" by luck
   only for the exact suggested default (a /24 subnet ending in ".0/24") -
   for any other prefix length (/16, /22, /28...), str.replace() finds no
   match and silently returns the input UNCHANGED, meaning the server's own
   "Address" line would end up being the network address itself (e.g.
   10.7.0.0/16) - not a valid host address, and wg-quick would either refuse
   to bring the interface up or behave incorrectly. Fixed using the
   ipaddress module for real subnet arithmetic, correct for any prefix.

2. "MANAGE CLIENT PEERS (Add/Revoke)" only implemented Add - there was no way
   to actually revoke a peer despite the menu's own label promising it. Also,
   what "Add" produced wasn't usable on its own: it printed the client's raw
   keys to the terminal without ever assembling a real, importable client
   .conf file (which needs the SERVER's public key and endpoint too - neither
   of which were shown anywhere in that flow). Fixed with real revocation
   (removes the matching [Peer] block and re-syncs live via wg syncconf) and
   a complete, ready-to-import client .conf, matching the pattern already
   used for OpenVPN's client profiles.

3. A peer's private key was piped through a shell command as a literal
   argument (echo '{key}' | wg pubkey) - briefly visible to any other local
   user on the box via ps aux during that command's execution window. Fixed
   by piping the key directly via stdin instead of as a command argument.

4. Same IP-forwarding persistence bug as OpenVPN: sed-patching the exact
   commented line in /etc/sysctl.conf silently no-ops if that line isn't
   present. Fixed with a dedicated /etc/sysctl.d/ drop-in file instead.

5. No install verification, no restart-verify-rollback, no port-conflict
   check, raw ufw/iptables instead of the shared firewall helpers, and
   uninstall never closed the port on the firewall - same classes of bug
   fixed in every other module in this panel.
"""

import os
import re
import time
import sys
import ipaddress
import subprocess
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)
from openvpn_manager import _default_interface

WG_DIR = "/etc/wireguard"
WG_CONF_PATH = "%s/wg0.conf" % WG_DIR
SYSCTL_DROPIN_PATH = "/etc/sysctl.d/99-wireguard-forward.conf"


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "wg-quick@wg0"]).returncode == 0


def _restart_wg():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt.
    _run("systemctl reset-failed wg-quick@wg0")
    return _run("systemctl restart wg-quick@wg0").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("udp",)):
            return True
        time.sleep(delay)
    return False


def _genkey():
    return _run("wg genkey").stdout.strip()


def _pubkey_from(private_key):
    """Pipes the private key via stdin, never as a command-line argument -
    a key passed as an argument is briefly visible to other local users via
    ps aux during the command's execution window."""
    result = subprocess.run(["wg", "pubkey"], input=private_key, capture_output=True, text=True)
    return result.stdout.strip()


def _ensure_ip_forwarding():
    _run("sysctl -w net.ipv4.ip_forward=1")
    with open(SYSCTL_DROPIN_PATH, "w") as f:
        f.write("net.ipv4.ip_forward=1\n")
    _run("sysctl -p %s" % SYSCTL_DROPIN_PATH)


def _server_address_for_subnet(subnet_str):
    """Real subnet arithmetic instead of a string-replace hack that only
    happened to work for the one suggested default value."""
    network = ipaddress.ip_network(subnet_str, strict=False)
    server_ip = network.network_address + 1
    return "%s/%s" % (server_ip, network.prefixlen)


def _allocated_addresses(config_content):
    """Every address already in use - the server's own Address line, plus
    every peer's AllowedIPs - so a new peer never collides with one that
    already exists."""
    used = set()
    for m in re.finditer(r'^Address\s*=\s*([\d.]+)', config_content, re.MULTILINE):
        used.add(m.group(1))
    for m in re.finditer(r'^AllowedIPs\s*=\s*([\d.]+)', config_content, re.MULTILINE):
        used.add(m.group(1))
    return used


def _next_free_address(config_content, subnet_str):
    network = ipaddress.ip_network(subnet_str, strict=False)
    used = _allocated_addresses(config_content)
    for host in network.hosts():
        if str(host) not in used:
            return str(host)
    return None


WG_NAT_COMMENT = "smartui-wireguard"


def _wg_post_lines(interface, subnet_str):
    """PostUp/PostDown that are safe to run any number of times.

    The old lines used a bare `iptables -A ...` on every start, so each
    restart (or a crash that skipped PostDown) stacked another identical
    `-o eth0 -j MASQUERADE` rule in the nat table - the source of the
    ever-growing duplicate list. These check with -C first, and the NAT rule
    now belongs to WireGuard's own subnet (with a comment tag) instead of
    being a catch-all that every other tunnel could silently depend on."""
    net = str(ipaddress.ip_network(subnet_str, strict=False))
    fwd = "-i wg0 -j ACCEPT"
    nat = "-s %s -o %s -m comment --comment %s -j MASQUERADE" % (net, interface, WG_NAT_COMMENT)
    up = ("iptables -C FORWARD %s 2>/dev/null || iptables -A FORWARD %s; "
          "iptables -t nat -C POSTROUTING %s 2>/dev/null || iptables -t nat -A POSTROUTING %s"
          % (fwd, fwd, nat, nat))
    down = ("iptables -D FORWARD %s 2>/dev/null || true; "
            "iptables -t nat -D POSTROUTING %s 2>/dev/null || true" % (fwd, nat))
    return up, down


def _write_server_config(listen_port, subnet_str, private_key, interface):
    server_address = _server_address_for_subnet(subnet_str)
    post_up, post_down = _wg_post_lines(interface, subnet_str)
    config = """[Interface]
Address = %s
ListenPort = %s
PrivateKey = %s
PostUp = %s
PostDown = %s
""" % (server_address, listen_port, private_key, post_up, post_down)
    with open(WG_CONF_PATH, "w") as f:
        f.write(config)
    os.chmod(WG_CONF_PATH, 0o600)


def _repair_wg_conf_rules():
    """Upgrade path for servers installed with the old PostUp/PostDown lines:
    rewrites only those two firewall lines in the existing wg0.conf (keys,
    peers and any other custom lines are left exactly as they are). Does NOT
    restart WireGuard, so connected clients are not interrupted - the new
    lines are used the next time it starts; the current rules are brought in
    line right now. Returns True if the file was changed."""
    if not os.path.exists(WG_CONF_PATH):
        return False
    with open(WG_CONF_PATH) as f:
        conf = f.read()
    m = re.search(r'^Address\s*=\s*([\d.]+/\d+)', conf, re.MULTILINE)
    if not m:
        return False
    try:
        subnet = str(ipaddress.ip_network(m.group(1), strict=False))
    except ValueError:
        return False
    mi = re.search(r'-o\s+(\S+)\s+-j\s+MASQUERADE', conf)
    interface = mi.group(1) if mi else _default_interface()
    post_up, post_down = _wg_post_lines(interface, subnet)

    def is_ours(line):
        return "-i wg0 -j ACCEPT" in line and "MASQUERADE" in line

    out, changed, seen_up, seen_down = [], False, False, False
    for line in conf.split("\n"):
        mm = re.match(r'^(PostUp|PostDown)\s*=\s*(.*)$', line)
        if mm and is_ours(mm.group(2)):
            want = post_up if mm.group(1) == "PostUp" else post_down
            new_line = "%s = %s" % (mm.group(1), want)
            if mm.group(1) == "PostUp":
                seen_up = True
            else:
                seen_down = True
            if line != new_line:
                changed = True
            out.append(new_line)
        else:
            out.append(line)
    if not changed:
        return False
    with open(WG_CONF_PATH, "w") as f:
        f.write("\n".join(out))
    os.chmod(WG_CONF_PATH, 0o600)
    # bring the live tables in line right away (idempotent; no restart)
    _run(["sh", "-c", post_up])
    return True


def _apply_safely(description, check_port):
    """No standalone config-syntax-test exists for wg-quick either - same
    restart-verify-rollback pattern as Stunnel/Hysteria/OpenVPN/FileBrowser."""
    if not _restart_wg():
        return False, "%s failed to restart - check 'wg-quick up wg0' manually for the error." % description

    if not _wait_for_port_listening(check_port):
        return False, "%s restarted, but port %s never came up." % (description, check_port)

    return True, "%s applied and verified on port %s." % (description, check_port)


# ---------------------------------------------------------------------------
# Peer bookkeeping, live connection info and config viewing
# ---------------------------------------------------------------------------

CLIENTS_DIR = "%s/clients" % WG_DIR
ONLINE_WINDOW = 180      # seconds: a handshake newer than this = "connected"


def _safe_name(name):
    """Peer names become file names (clients/<name>.conf), so only a safe
    character set is allowed - a name like ../../etc/x must never reach a path."""
    name = re.sub(r'[^A-Za-z0-9_.-]', '_', (name or '').strip())
    return name.strip('.') or "peer"


def _read_conf():
    try:
        with open(WG_CONF_PATH) as f:
            return f.read()
    except OSError:
        return ""


def _parse_peers(conf):
    """Every [Peer] block of wg0.conf as a dict: name (from the '# name'
    comment this panel writes), pubkey, allowed (AllowedIPs), ip (first
    address, no mask) and the (start, end) line span of the block."""
    lines = conf.split("\n")
    peers, i = [], 0
    while i < len(lines):
        if lines[i].strip().lower() == "[peer]":
            start = i
            j = i + 1
            while j < len(lines) and lines[j].strip().lower() not in ("[peer]", "[interface]"):
                j += 1
            block = lines[start + 1:j]
            name, pub, allowed = "", "", ""
            for ln in block:
                s = ln.strip()
                if s.startswith("#") and not name:
                    name = s.lstrip("#").strip()
                m = re.match(r'^PublicKey\s*=\s*(\S+)', s)
                if m:
                    pub = m.group(1)
                m = re.match(r'^AllowedIPs\s*=\s*(.+)$', s)
                if m:
                    allowed = m.group(1).strip()
            ip = allowed.split(",")[0].split("/")[0].strip() if allowed else ""
            peers.append({"name": name, "pubkey": pub, "allowed": allowed, "ip": ip, "span": (start, j)})
            i = j
        else:
            i += 1
    return peers


def _remove_peer_block(conf, peer):
    """wg0.conf text with that one peer's block (and its leading blank line) removed."""
    lines = conf.split("\n")
    start, end = peer["span"]
    text = "\n".join(lines[:start] + lines[end:])
    text = re.sub(r'([^\n])\n\[Peer\]', r'\1\n\n[Peer]', text)   # keep one blank line before each [Peer]
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.rstrip("\n") + "\n"


def _sync_live():
    """Applies wg0.conf to the running interface without dropping other
    clients. The stripped config (which contains the private key) goes through
    a pipe, not a /tmp file anyone could read."""
    r = _run(["bash", "-c", "wg syncconf wg0 <(wg-quick strip wg0)"])
    if r.returncode != 0:
        return _restart_wg()
    return True


def _live_peers():
    """{public key: {...}} from `wg show wg0 dump`; {} when the interface is down."""
    try:
        out = subprocess.run(["wg", "show", "wg0", "dump"], capture_output=True, text=True, timeout=10)
    except Exception:
        return {}
    if out.returncode != 0:
        return {}
    info = {}
    for ln in out.stdout.strip().split("\n")[1:]:      # first line = the interface itself
        f = ln.split("\t")
        if len(f) < 8:
            continue
        try:
            hs = int(f[4])
            rx, tx = int(f[5]), int(f[6])
        except ValueError:
            continue
        info[f[0]] = {"endpoint": f[2] if f[2] != "(none)" else "", "handshake": hs, "rx": rx, "tx": tx,
                      "keepalive": f[7]}
    return info


def _fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.2f %s" % (n, unit))
        n /= 1024.0


def _fmt_ago(ts):
    if not ts:
        return "never"
    d = max(0, int(time.time()) - ts)
    if d < 60:
        return "%ds ago" % d
    if d < 3600:
        return "%dm %ds ago" % (d // 60, d % 60)
    if d < 86400:
        return "%dh %dm ago" % (d // 3600, (d % 3600) // 60)
    return "%dd %dh ago" % (d // 86400, (d % 86400) // 3600)


def _is_online(live):
    return bool(live) and live["handshake"] > 0 and (time.time() - live["handshake"]) < ONLINE_WINDOW


def _peer_counts():
    """(configured peers, peers connected right now)."""
    peers = _parse_peers(_read_conf())
    live = _live_peers()
    online = sum(1 for p in peers if _is_online(live.get(p["pubkey"])))
    return len(peers), online


def _server_public_ip():
    try:
        r = subprocess.run(["curl", "-4", "-s", "-m", "6", "ifconfig.me"], capture_output=True, text=True, timeout=10)
        ip = r.stdout.strip()
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            return ip
    except Exception:
        pass
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        for tok in r.stdout.split():
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', tok):
                return tok
    except Exception:
        pass
    return "YOUR_SERVER_IP"


def _client_conf_path(name):
    return "%s/%s.conf" % (CLIENTS_DIR, _safe_name(name))


def _print_plain_config(title, text):
    """Printed as plain lines - no colours or box characters inside - so the
    whole block can be selected with the mouse and pasted straight into the
    app's WireGuard box (or saved as a .conf file)."""
    print("\n%s---------- %s ----------%s" % (C_CYAN, title, C_RESET))
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    print("%s---------- end ----------%s" % (C_CYAN, C_RESET))


def _show_qr(text):
    if _run("which qrencode").returncode != 0:
        ans = input(" qrencode is not installed. Install it now? (y/n): ").strip().lower()
        if ans != 'y':
            return
        _run("apt-get install -y qrencode")
        if _run("which qrencode").returncode != 0:
            print("%s[X] Could not install qrencode.%s" % (C_RED, C_RESET))
            return
    subprocess.run(["qrencode", "-t", "ansiutf8"], input=text, text=True)


def _export_config(name, text):
    os.makedirs("/root/wireguard-export", exist_ok=True)
    path = "/root/wireguard-export/%s.conf" % _safe_name(name)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)
    return path


def _mask_private_key(text):
    return re.sub(r'(?m)^(PrivateKey\s*=\s*).+$', r'\1<hidden>', text)


def _show_status_table():
    """Option 4: service state, peer totals and one line per peer."""
    conf = _read_conf()
    peers = _parse_peers(conf)
    live = _live_peers()
    active = _service_active()
    online = [p for p in peers if _is_online(live.get(p["pubkey"]))]
    tot_rx = sum(v["rx"] for v in live.values())
    tot_tx = sum(v["tx"] for v in live.values())
    print(" Service        : %s" % (("%sRUNNING%s" % (C_GREEN, C_RESET)) if active else ("%sSTOPPED%s" % (C_RED, C_RESET))))
    print(" Peers          : %d configured, %s%d connected now%s (handshake within %ds)"
          % (len(peers), C_GREEN, len(online), C_RESET, ONLINE_WINDOW))
    print(" Total traffic  : received %s | sent %s (since the interface came up)" % (_fmt_bytes(tot_rx), _fmt_bytes(tot_tx)))
    print("----------------------------------------------------------------")
    if not peers:
        print(" No peers yet - add one from option 2.")
        return peers, live
    print(" %-3s %-14s %-14s %-9s %-14s" % ("#", "NAME", "VPN IP", "STATE", "LAST HANDSHAKE"))
    for i, p in enumerate(peers, 1):
        lv = live.get(p["pubkey"])
        if _is_online(lv):
            state = "%sONLINE %s" % (C_GREEN, C_RESET)
        elif lv and lv["handshake"]:
            state = "%sIDLE   %s" % (C_YELLOW, C_RESET)
        else:
            state = "%sNEVER  %s" % (C_RED, C_RESET)
        print(" %-3d %-14s %-14s %s %-14s" % (i, (p["name"] or "(unnamed)")[:14], p["ip"] or "-", state,
                                             _fmt_ago(lv["handshake"]) if lv else "never"))
    return peers, live


def _show_peer_details(p, live):
    lv = live.get(p["pubkey"])
    print("\n Name            : %s" % (p["name"] or "(unnamed)"))
    print(" VPN address     : %s" % (p["allowed"] or "-"))
    print(" Public key      : %s" % p["pubkey"])
    if lv:
        print(" State           : %s" % ("ONLINE" if _is_online(lv) else ("idle (no recent handshake)" if lv["handshake"] else "never connected")))
        print(" Last handshake  : %s" % _fmt_ago(lv["handshake"]))
        print(" Client address  : %s" % (lv["endpoint"] or "-"))
        print(" Received (from client): %s" % _fmt_bytes(lv["rx"]))
        print(" Sent (to client)      : %s" % _fmt_bytes(lv["tx"]))
    else:
        print(" State           : interface is down or the peer is not loaded")
    print(" Client config   : %s" % ("saved at " + _client_conf_path(p["name"]) if p["name"] and os.path.exists(_client_conf_path(p["name"])) else "not stored on this server"))


def _status_and_connections():
    while True:
        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s            WIREGUARD STATUS / PEERS / CONNECTIONS              %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        peers, live = _show_status_table()
        print("----------------------------------------------------------------")
        print(" Type a peer number for its full connection details,")
        print(" [r] refresh   [0] back")
        sel = input(" Select: ").strip().lower()
        if sel in ("0", "q", "b"):
            return
        if sel in ("", "r"):
            continue
        if sel.isdigit() and 1 <= int(sel) <= len(peers):
            _show_peer_details(peers[int(sel) - 1], live)
            input("\nPress Enter to continue...")


def _view_copy_configs(wg_port):
    """Option 8: show a peer's client config (plain text, ready to copy), a QR
    code, an exported file, or the server's own wg0.conf (private key hidden)."""
    while True:
        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                 VIEW / COPY WIREGUARD CONFIGS                  %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        conf = _read_conf()
        if not conf:
            print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
            return
        peers = _parse_peers(conf)
        for i, p in enumerate(peers, 1):
            has = p["name"] and os.path.exists(_client_conf_path(p["name"]))
            print(" [%d] %-16s %-14s %s" % (i, (p["name"] or "(unnamed)")[:16], p["ip"] or "-",
                                          "client config saved" if has else "%s(no saved config)%s" % (C_YELLOW, C_RESET)))
        if not peers:
            print(" No peers yet.")
        print("----------------------------------------------------------------")
        print(" Type a peer number to open its client config")
        print(" [s] server config (wg0.conf)   [0] back")
        sel = input(" Select: ").strip().lower()
        if sel in ("0", "q", "b", ""):
            return

        if sel == 's':
            _print_plain_config("SERVER wg0.conf (PrivateKey hidden)", _mask_private_key(conf))
            print(" Server public key : %s" % (_pubkey_from(_server_priv(conf)) or "?"))
            print(" Endpoint          : %s:%s" % (_server_public_ip(), wg_port))
            if input("\n Show the real PrivateKey too? (y/n): ").strip().lower() == 'y':
                _print_plain_config("SERVER wg0.conf (FULL - keep it secret)", conf)
            input("\nPress Enter to continue...")
            continue

        if not (sel.isdigit() and 1 <= int(sel) <= len(peers)):
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
            continue

        p = peers[int(sel) - 1]
        path = _client_conf_path(p["name"]) if p["name"] else ""
        if not path or not os.path.exists(path):
            print("\n%s[!] No client config is stored for '%s'.%s" % (C_YELLOW, p["name"] or p["pubkey"][:12], C_RESET))
            print("    The server never keeps a client's private key, so a peer that was not created")
            print("    with this panel cannot be rebuilt. Revoke it and add it again to get a new config.")
            input("\nPress Enter to continue...")
            continue
        with open(path) as f:
            text = f.read()
        while True:
            _print_plain_config("CLIENT CONFIG: %s" % p["name"], text)
            print(" Select the text above with the mouse to copy it, then paste it into the")
            print(" app's WireGuard box.")
            print(" [q] show as QR code   [e] export to a file   [0] back")
            act = input(" Select: ").strip().lower()
            if act == 'q':
                _show_qr(text)
            elif act == 'e':
                print("%s[OK] Saved to %s (download it with scp / SFTP).%s" % (C_GREEN, _export_config(p["name"], text), C_RESET))
            else:
                break


def _server_priv(conf):
    m = re.search(r'^PrivateKey\s*=\s*(\S+)', conf, re.MULTILINE)
    return m.group(1) if m else ""



# ---------------------------------------------------------------------------
# WireGuard over DNSTT bridge
#
# The app can carry WireGuard through its DNSTT paths: every WireGuard datagram
# is framed (2-byte length + packet) and sent over several TCP streams. This
# service is the server end: it listens on a TCP port and gives each frame to
# the local WireGuard as a real UDP datagram, returning the answers on the same
# stream. The TCP port must be the SAME number as the WireGuard Endpoint port
# in the app's config (TCP and UDP ports do not clash).
# ---------------------------------------------------------------------------

BRIDGE_SCRIPT = "/usr/local/bin/wg-dnstt-bridge.py"
BRIDGE_UNIT = "wg-dnstt-bridge"
BRIDGE_UNIT_PATH = "/etc/systemd/system/%s.service" % BRIDGE_UNIT

BRIDGE_SCRIPT_CONTENT = r'''#!/usr/bin/env python3
"""wg-dnstt-bridge.py - UDP-over-TCP bridge for "WireGuard over DNSTT" (SPEEDMAX PRO).
usage: wg-dnstt-bridge.py <tcp-listen-port> <wireguard-udp-port> [host]"""
import asyncio
import sys

LISTEN_PORT = int(sys.argv[1])
UDP_PORT = int(sys.argv[2])
UDP_HOST = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"


class Back(asyncio.DatagramProtocol):
    def __init__(self, writer):
        self.writer = writer

    def datagram_received(self, data, addr):
        try:
            self.writer.write(len(data).to_bytes(2, "big") + data)
        except Exception:
            pass


async def handle(reader, writer):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: Back(writer), remote_addr=(UDP_HOST, UDP_PORT))
    try:
        while True:
            hdr = await reader.readexactly(2)
            data = await reader.readexactly(int.from_bytes(hdr, "big"))
            transport.sendto(data)
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        transport.close()
        writer.close()


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", LISTEN_PORT, backlog=128)
    print("wg-dnstt-bridge: TCP %d -> UDP %s:%d" % (LISTEN_PORT, UDP_HOST, UDP_PORT), flush=True)
    async with server:
        await server.serve_forever()


asyncio.run(main())
'''


def _wg_live_port(ports_dict):
    m = re.search(r'^ListenPort\s*=\s*(\d+)', _read_conf(), re.MULTILINE)
    if m:
        return int(m.group(1))
    p = ports_dict.get('WIREGUARD_PORT')
    return int(p) if str(p).isdigit() else None


def _bridge_active():
    return _run(["systemctl", "is-active", "--quiet", BRIDGE_UNIT]).returncode == 0


def _bridge_wait_tcp(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _install_bridge(tcp_port, udp_port):
    with open(BRIDGE_SCRIPT, "w") as f:
        f.write(BRIDGE_SCRIPT_CONTENT)
    os.chmod(BRIDGE_SCRIPT, 0o755)
    original = None
    if os.path.exists(BRIDGE_UNIT_PATH):
        with open(BRIDGE_UNIT_PATH) as f:
            original = f.read()
    py = "/usr/bin/python3"
    with open(BRIDGE_UNIT_PATH, "w") as f:
        f.write("""[Unit]
Description=SmartUI WireGuard-over-DNSTT bridge (TCP %s -> UDP %s)
After=network.target wg-quick@wg0.service

[Service]
Type=simple
User=root
ExecStart=%s %s %s %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (tcp_port, udp_port, py, BRIDGE_SCRIPT, tcp_port, udp_port))
    _run("systemctl daemon-reload")
    _run("systemctl enable %s" % BRIDGE_UNIT)
    _run("systemctl reset-failed %s" % BRIDGE_UNIT)
    if _run("systemctl restart %s" % BRIDGE_UNIT).returncode == 0 and _bridge_wait_tcp(tcp_port):
        return True, "Bridge is listening on TCP %s and forwards to WireGuard UDP %s." % (tcp_port, udp_port)
    if original is not None:
        with open(BRIDGE_UNIT_PATH, "w") as f:
            f.write(original)
        _run("systemctl daemon-reload")
        _run("systemctl restart %s" % BRIDGE_UNIT)
    else:
        _remove_bridge()
    return False, "Bridge did not come up on TCP %s - check 'journalctl -u %s'." % (tcp_port, BRIDGE_UNIT)


def _remove_bridge():
    _run("systemctl stop %s" % BRIDGE_UNIT)
    _run("systemctl disable %s" % BRIDGE_UNIT)
    for path in (BRIDGE_UNIT_PATH, BRIDGE_SCRIPT):
        try:
            os.remove(path)
        except OSError:
            pass
    _run("systemctl daemon-reload")


def _bridge_menu(ports_dict):
    clear_screen()
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("%s        WIREGUARD OVER DNSTT BRIDGE (TCP -> UDP)                %s" % (C_BOLD, C_RESET))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print(" Needed by the app's 'WireGuard over DNSTT'. Runs as a service (starts on boot).")
    udp_port = _wg_live_port(ports_dict)
    if not os.path.exists(WG_CONF_PATH) or not udp_port:
        print("%s[X] WireGuard is not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
        input("\nPress Enter to continue...")
        return
    cur = ports_dict.get('WG_BRIDGE_PORT')
    if cur:
        print("\n Installed: TCP %s -> UDP %s   [%s]" % (cur, udp_port, "ON" if _bridge_active() else "OFF"))
        print(" [1] Reinstall / re-point to the current WireGuard port   [2] Restart   [3] Remove   [0] Back")
        sub = input(" Select option: ").strip()
        if sub == '2':
            ok = _run("systemctl restart %s" % BRIDGE_UNIT).returncode == 0
            print("%s[OK] Restarted.%s" % (C_GREEN, C_RESET) if ok else "%s[X] Restart failed.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
            return
        if sub == '3':
            _remove_bridge()
            ports_dict.pop('WG_BRIDGE_PORT', None)
            print("%s[OK] Bridge removed.%s" % (C_GREEN, C_RESET))
            input("\nPress Enter to continue...")
            return
        if sub != '1':
            return
    print("\n The TCP port is the same number as the WireGuard port (%s): that is the Endpoint port in the app config." % udp_port)
    if str(cur) != str(udp_port) and check_system_port_in_use(udp_port, ("tcp",)):
        print("%s[X] TCP port %s is already in use by another service.%s" % (C_RED, udp_port, C_RESET))
        input("\nPress Enter to continue...")
        return
    ok, msg = _install_bridge(udp_port, udp_port)
    if ok:
        ports_dict['WG_BRIDGE_PORT'] = str(udp_port)
        print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
        print(" No firewall port is needed: DNSTT reaches it from this server itself.")
    else:
        print("%s[X] %s%s" % (C_RED, msg, C_RESET))
    input("\nPress Enter to continue...")


def wireguard_admin_manager(ports_dict):
    """WireGuard Administrator Module."""
    if _repair_wg_conf_rules():
        print("%s[OK] WireGuard firewall lines updated so they no longer pile up duplicate rules.%s" % (C_GREEN, C_RESET))
        print("%s    Takes full effect the next time WireGuard restarts (nothing was interrupted).%s" % (C_CYAN, C_RESET))
        input("\nPress Enter to continue...")

    while True:
        wg_port = ports_dict.get('WIREGUARD_PORT', 'Not configured')
        wg_subnet = ports_dict.get('WIREGUARD_SUBNET', '10.7.0.0/24')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"
        peer_count, online_count = _peer_counts()

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                  WIREGUARD ADMINISTRATOR                   %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      PORT: %s  |  SUBNET: %s  |  PEERS: %s (%s%d online%s)" % (wg_port, wg_subnet, peer_count, C_GREEN, online_count, C_RESET))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL WIREGUARD (Wizard)")
        print(" [2]> MANAGE CLIENT PEERS (Add/Revoke)")
        print(" [3]> CHANGE LISTEN PORT")
        print(" [4]> STATUS / PEERS / CONNECTIONS")
        print(" [5]> RESTART WIREGUARD SERVICE")
        print(" [6]> START/STOP WIREGUARD SERVICE [%s]" % status_label)
        print(" [8]> VIEW / COPY CONFIGS (client + server)")
        print(" [9]> WIREGUARD OVER DNSTT BRIDGE  %s" % (("TCP %s [%s]" % (ports_dict['WG_BRIDGE_PORT'], "ON" if _bridge_active() else "OFF")) if ports_dict.get('WG_BRIDGE_PORT') else "not installed"))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL WIREGUARD")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s           WIREGUARD INSTALLATION WIZARD                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter desired WireGuard listen port (e.g., 51820): ", default=51820)
            if str(listen_port) != str(wg_port) and check_system_port_in_use(listen_port, ("udp",)):
                print("%s[X] UDP port %s is already in use by another service.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            subnet_raw = input(" Enter VPN subnet [default 10.7.0.0/24]: ").strip() or "10.7.0.0/24"
            try:
                ipaddress.ip_network(subnet_raw, strict=False)
            except ValueError:
                print("%s[X] '%s' isn't a valid subnet (e.g. 10.7.0.0/24).%s" % (C_RED, subnet_raw, C_RESET))
                input("\nPress Enter to continue...")
                continue

            print("\n[i] Installing WireGuard...")
            _run("apt-get update && apt-get install -y wireguard iptables")
            if _run("which wg-quick").returncode != 0:
                print("%s[X] WireGuard did not install correctly - check network access.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            os.makedirs(WG_DIR, exist_ok=True)
            server_private_key = _genkey()
            if not server_private_key:
                print("%s[X] Key generation failed.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            interface = _default_interface()
            _write_server_config(listen_port, subnet_raw, server_private_key, interface)
            _ensure_ip_forwarding()

            open_firewall_port(listen_port, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable wg-quick@wg0")

            ok, msg = _apply_safely("WireGuard on port %s" % listen_port, listen_port)
            if ok:
                ports_dict['WIREGUARD_PORT'] = str(listen_port)
                ports_dict['WIREGUARD_SUBNET'] = subnet_raw
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("%s    NAT/MASQUERADE enabled on %s so peers reach the internet.%s" % (C_CYAN, interface, C_RESET))
            else:
                close_firewall_port(listen_port, ("udp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                MANAGE WIREGUARD CLIENT PEERS               %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(WG_CONF_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            print(" [1] Add a peer")
            print(" [2] Revoke a peer")
            print(" [0] Back")
            sub = input(" Select option: ").strip()

            if sub == '1':
                peer_name = _safe_name(input(" Enter a name for this peer (for your own reference): ").strip() or "peer")
                config_content = _read_conf()
                if any(p["name"] == peer_name for p in _parse_peers(config_content)):
                    print("%s[X] A peer called '%s' already exists - pick another name.%s" % (C_RED, peer_name, C_RESET))
                    input("\nPress Enter to continue...")
                    continue

                peer_address = _next_free_address(config_content, wg_subnet)
                if not peer_address:
                    print("%s[X] No free addresses left in subnet %s.%s" % (C_RED, wg_subnet, C_RESET))
                    input("\nPress Enter to continue...")
                    continue

                server_private_key = _server_priv(config_content) or None
                server_public_key = _pubkey_from(server_private_key) if server_private_key else None
                m = re.search(r'^ListenPort\s*=\s*(\d+)', config_content, re.MULTILINE)
                server_port = m.group(1) if m else wg_port

                if not server_public_key:
                    print("%s[X] Could not read the server's key from wg0.conf.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue

                client_private_key = _genkey()
                client_public_key = _pubkey_from(client_private_key)

                peer_block = "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n" % (peer_name, client_public_key, peer_address)
                with open(WG_CONF_PATH, "a") as f:
                    f.write(peer_block)
                _sync_live()

                prefix = ipaddress.ip_network(wg_subnet, strict=False).prefixlen
                server_ip = _server_public_ip()
                client_conf = """[Interface]
PrivateKey = %s
Address = %s/%s
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = %s:%s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
""" % (client_private_key, peer_address, prefix, server_public_key, server_ip, server_port)
                os.makedirs(CLIENTS_DIR, exist_ok=True)
                client_path = _client_conf_path(peer_name)
                with open(client_path, "w") as f:
                    f.write(client_conf)
                os.chmod(client_path, 0o600)

                print("%s[OK] Peer '%s' added with address %s.%s" % (C_GREEN, peer_name, peer_address, C_RESET))
                print("     Saved at %s" % client_path)
                print("     Open it any time from option 8 (VIEW / COPY CONFIGS).")
                _print_plain_config("CLIENT CONFIG: %s" % peer_name, client_conf)
            elif sub == '2':
                config_content = _read_conf()
                peers = _parse_peers(config_content)
                if not peers:
                    print("%s No peers to revoke.%s" % (C_YELLOW, C_RESET))
                else:
                    for i, p in enumerate(peers, 1):
                        print("  [%d] %s  (%s)" % (i, p["name"] or "(unnamed)", p["ip"] or "-"))
                    sel = input(" Enter peer number or name to revoke: ").strip()
                    target = None
                    if sel.isdigit() and 1 <= int(sel) <= len(peers):
                        target = peers[int(sel) - 1]
                    else:
                        for p in peers:
                            if sel and p["name"] == sel:
                                target = p
                                break
                    if target is None:
                        print("%s[X] No such peer.%s" % (C_RED, C_RESET))
                    else:
                        new_content = _remove_peer_block(config_content, target)
                        with open(WG_CONF_PATH, "w") as f:
                            f.write(new_content)
                        os.chmod(WG_CONF_PATH, 0o600)
                        _sync_live()
                        if target["name"]:
                            try:
                                os.remove(_client_conf_path(target["name"]))
                            except OSError:
                                pass
                        print("%s[OK] Peer '%s' revoked.%s" % (C_GREEN, target["name"] or target["pubkey"][:12], C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  CHANGE LISTEN PORT                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(WG_CONF_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new WireGuard port [Current: %s]: " % wg_port,
                                    default=int(wg_port) if str(wg_port).isdigit() else 51820)
            if str(new_port) != str(wg_port) and check_system_port_in_use(new_port, ("udp",)):
                print("%s[X] UDP port %s is already in use by another service.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            with open(WG_CONF_PATH, "r") as f:
                config_content = f.read()
            new_content = re.sub(r'^ListenPort\s*=\s*\d+', 'ListenPort = %s' % new_port, config_content, flags=re.MULTILINE)
            with open(WG_CONF_PATH, "w") as f:
                f.write(new_content)

            open_firewall_port(new_port, ("udp",))
            persist_firewall_rules()

            ok, msg = _apply_safely("Port change to %s" % new_port, new_port)
            if ok:
                old_port = wg_port
                ports_dict['WIREGUARD_PORT'] = str(new_port)
                if ports_dict.get('WG_BRIDGE_PORT'):
                    if check_system_port_in_use(new_port, ("tcp",)) and str(ports_dict['WG_BRIDGE_PORT']) != str(new_port):
                        print("%s[!] TCP %s is busy - the DNSTT bridge was NOT moved (reinstall it from option 9).%s" % (C_YELLOW, new_port, C_RESET))
                    else:
                        okb, _mb = _install_bridge(new_port, new_port)
                        if okb:
                            ports_dict['WG_BRIDGE_PORT'] = str(new_port)
                if str(old_port).isdigit() and str(old_port) != str(new_port):
                    close_firewall_port(int(old_port), ("udp",))
                    persist_firewall_rules()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("%s[!] Existing client profiles reference the old port - regenerate them" % C_YELLOW)
                print("    (revoke + re-add) if you want clients to reconnect on the new one.%s" % C_RESET)
            else:
                close_firewall_port(new_port, ("udp",))
                with open(WG_CONF_PATH, "w") as f:
                    f.write(config_content)
                _restart_wg()
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            _status_and_connections()

        elif choice == '5':
            if _restart_wg():
                print("%s[OK] WireGuard service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] WireGuard failed to restart - check 'wg-quick up wg0'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop wg-quick@wg0")
                print("%s[!] WireGuard service stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(WG_CONF_PATH):
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start wg-quick@wg0")
                if _service_active():
                    print("%s[OK] WireGuard service started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] WireGuard failed to start - check 'wg-quick up wg0'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            _view_copy_configs(wg_port)

        elif choice == '9':
            _bridge_menu(ports_dict)

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                UNINSTALL WIREGUARD                         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove WireGuard? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop wg-quick@wg0 && systemctl disable wg-quick@wg0")
                _remove_bridge()
                ports_dict.pop('WG_BRIDGE_PORT', None)
                _run("apt-get purge -y wireguard")
                if str(wg_port).isdigit():
                    close_firewall_port(int(wg_port), ("udp",))
                    persist_firewall_rules()
                _run("rm -f %s" % SYSCTL_DROPIN_PATH)
                _run("rm -rf %s" % WG_DIR)
                ports_dict.pop('WIREGUARD_PORT', None)
                ports_dict.pop('WIREGUARD_SUBNET', None)
                print("%s[OK] WireGuard purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
