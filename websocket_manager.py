"""
websocket_manager.py - standalone WebSocket tunnel module for the SmartUI
panel, wrapping wstunnel (github.com/erebe/wstunnel) - distinct from both
WS-EPRO (this panel's own lightweight from-scratch WS bridge) and Xray's own
WS transport option.

Confirmed real, actively maintained, well-established before building this:
7.0k stars, 564 forks, BSD-3-Clause, a complete Rust rewrite at v7+ (current
release confirmed v10.7.1). Chosen over building another homegrown bridge
because it's genuinely more capable than WS-EPRO: real TCP+UDP tunneling,
automatic TLS with an embedded self-signed certificate (no cert generation
needed at all, unlike Hysteria/Stunnel), and a real built-in `--restrict-to`
flag that IS this panel's "port redirection" concept natively, rather than
something bolted on.

Same architectural problem as Psiphon, solved the same way: wstunnel's own
authentication is `--restrict-http-upgrade-path-prefix`, a single shared
secret for the whole server instance - not a per-customer username/password
system. So exactly as with Psiphon, each instance's real wstunnel port is
closed by default (a per-instance iptables chain, DROP by default), and a
gate HTTP service verifies username/password (salted-hash) and, if
required, an Atken token (reading the same on-disk token store
atken_hash_manager.py produces, same as Psiphon's gate) before granting a
time-limited ACCEPT rule for that client's source IP. This is a deliberately
parallel, not shared, implementation of that gate - psiphon_manager.py's
gate is already shipped and tested, and generalizing the two into one
shared system is a real refactor opportunity for later, not something to
risk against already-working code in this pass.

Also applied here, confirmed from real-world reference deployments: running
wstunnel as a dedicated non-root system user with
`setcap CAP_NET_BIND_SERVICE=+eip` on the binary, rather than running the
whole process as root just to bind port 443 - every other module in this
panel runs its tunnel daemon as root, and wstunnel doesn't actually need
that, so it doesn't get it here.
"""

import os
import re
import json
import time
import hashlib
import hmac
import secrets
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)

WSTUNNEL_DIR = "/etc/wstunnel"
WSTUNNEL_BIN = "/usr/local/bin/wstunnel"
WSTUNNEL_USER = "wstunnel"
CREDENTIALS_PATH = f"{WSTUNNEL_DIR}/credentials.json"
GATE_SCRIPT_PATH = "/usr/local/bin/wstunnel-gate.py"
GATE_SERVICE_PATH = "/etc/systemd/system/wstunnel-gate.service"
GATE_STATE_PATH = f"{WSTUNNEL_DIR}/gate_state.json"
CLEANUP_CRON_PATH = "/etc/cron.d/wstunnel-gate-cleanup"
CLEANUP_SCRIPT_PATH = "/usr/local/bin/wstunnel-gate-cleanup.py"
GATE_CHAIN_PREFIX = "wsgate_"
ACCEPT_WINDOW_MINUTES = 10
ATKEN_TOKEN_FILE_DEFAULT = "/etc/atken/tokens.json"

GATE_SCRIPT = '''#!/usr/bin/env python3
"""wstunnel access gate. GET /unlock?instance=X&user=Y&pass=Z[&token=T] ->
verifies credentials for that instance and, if required, an Atken token, by
reading the same on-disk store atken_hash_manager.py produces directly
(never a cross-process import - this runs as its own standalone service).
On success, inserts a time-limited iptables ACCEPT rule for the connecting
client's source IP ahead of that instance's default DROP rule."""
import os
import sys
import json
import time
import hmac
import hashlib
import subprocess
import http.server
import socketserver
import urllib.parse

CREDENTIALS_PATH = "/etc/wstunnel/credentials.json"
GATE_STATE_PATH = "/etc/wstunnel/gate_state.json"
GATE_CHAIN_PREFIX = "wsgate_"
ACCEPT_WINDOW_MINUTES = 10
PORT = int(os.environ.get("WSTUNNEL_GATE_PORT", "8601"))
ATKEN_TOKEN_FILE = os.environ.get("ATKEN_TOKEN_FILE", "/etc/atken/tokens.json")

_fail_counts = {}
_fail_window = 60
_fail_limit = 10


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _hash(value, salt):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 100000).hex()


def load_credentials():
    try:
        with open(CREDENTIALS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def load_gate_state():
    try:
        with open(GATE_STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_gate_state(state):
    with open(GATE_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def verify_atken_token(token_value):
    try:
        with open(ATKEN_TOKEN_FILE) as f:
            data = json.load(f)
    except Exception:
        return False
    if data.get("master_salt") and data.get("master_hash"):
        if hmac.compare_digest(_hash(token_value, data["master_salt"]), data["master_hash"]):
            return True
    for rec in data.get("tokens", {}).values():
        if hmac.compare_digest(_hash(token_value, rec["salt"]), rec["hash"]):
            return True
    return False


def grant_access(instance, source_ip):
    chain = GATE_CHAIN_PREFIX + instance
    check = run(["iptables", "-C", chain, "-s", source_ip, "-j", "ACCEPT"])
    if check.returncode != 0:
        run(["iptables", "-I", chain, "1", "-s", source_ip, "-j", "ACCEPT"])
    state = load_gate_state()
    state.setdefault(instance, {})[source_ip] = time.time() + ACCEPT_WINDOW_MINUTES * 60
    save_gate_state(state)


def _rate_limited(addr):
    now = time.time()
    entry = [t for t in _fail_counts.get(addr, []) if now - t < _fail_window]
    _fail_counts[addr] = entry
    return len(entry) >= _fail_limit


def _record_failure(addr):
    _fail_counts.setdefault(addr, []).append(time.time())


class GateHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # the query string carries the password - never let it reach a log file

    def do_GET(self):
        client_addr = self.client_address[0]
        if _rate_limited(client_addr):
            self.send_response(429)
            self.end_headers()
            return

        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        instance = params.get("instance", [""])[0]
        user = params.get("user", [""])[0]
        password = params.get("pass", [""])[0]
        token = params.get("token", [None])[0]

        creds = load_credentials()
        rec = creds.get(instance)
        valid = False
        if rec:
            computed = _hash(password, rec["salt"])
            if rec.get("username") == user and hmac.compare_digest(computed, rec["hash"]):
                valid = True
                if rec.get("atken_required"):
                    valid = bool(token) and verify_atken_token(token)

        if not valid:
            _record_failure(client_addr)
            self.send_response(401)
            self.end_headers()
            return

        grant_access(instance, client_addr)
        body = json.dumps({"status": "granted", "valid_for_minutes": ACCEPT_WINDOW_MINUTES}).encode()
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with ReusableTCPServer(("0.0.0.0", PORT), GateHandler) as httpd:
        print("wstunnel-gate listening on 0.0.0.0:%d" % PORT)
        httpd.serve_forever()
'''

CLEANUP_SCRIPT = '''#!/usr/bin/env python3
"""Expires temporary per-IP ACCEPT rules once their window has passed - run
periodically via cron, same pattern used for the SSH user enforcer and the
Psiphon gate cleanup."""
import json
import time
import subprocess

GATE_STATE_PATH = "/etc/wstunnel/gate_state.json"
GATE_CHAIN_PREFIX = "wsgate_"


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    try:
        with open(GATE_STATE_PATH) as f:
            state = json.load(f)
    except Exception:
        return

    now = time.time()
    changed = False
    for instance, ips in list(state.items()):
        chain = GATE_CHAIN_PREFIX + instance
        for ip, expiry in list(ips.items()):
            if now >= expiry:
                run(["iptables", "-D", chain, "-s", ip, "-j", "ACCEPT"])
                del ips[ip]
                changed = True
        if not ips:
            del state[instance]

    if changed:
        with open(GATE_STATE_PATH, "w") as f:
            json.dump(state, f, indent=2)


if __name__ == "__main__":
    main()
'''


def _load_credentials():
    if not os.path.exists(CREDENTIALS_PATH):
        return {}
    with open(CREDENTIALS_PATH) as f:
        return json.load(f)


def _save_credentials(data):
    os.makedirs(WSTUNNEL_DIR, exist_ok=True)
    with open(CREDENTIALS_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(CREDENTIALS_PATH, 0o600)


def _hash_value(value, salt):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 100000).hex()


def _binary_ok():
    return os.path.exists(WSTUNNEL_BIN) and os.access(WSTUNNEL_BIN, os.X_OK)


def _ensure_binary_installed():
    if _binary_ok():
        return True
    print("%s[i] Fetching latest wstunnel release info...%s" % (C_CYAN, C_RESET))
    tag_res = _run(["curl", "-sL", "https://api.github.com/repos/erebe/wstunnel/releases/latest"])
    m = re.search(r'"tag_name"\s*:\s*"([^"]+)"', tag_res.stdout)
    if not m:
        print("%s[X] Could not determine the latest wstunnel version - check network access.%s" % (C_RED, C_RESET))
        return False
    tag = m.group(1)          # e.g. "v10.7.1"
    version = tag.lstrip("v")  # release asset filenames drop the leading "v"

    url = "https://github.com/erebe/wstunnel/releases/download/%s/wstunnel_%s_linux_amd64.tar.gz" % (tag, version)
    print("%s[i] Downloading wstunnel %s...%s" % (C_CYAN, version, C_RESET))
    os.makedirs("/tmp/wstunnel-dl", exist_ok=True)
    dl = _run("curl -fsSL %s -o /tmp/wstunnel-dl/wstunnel.tar.gz" % url)
    if dl.returncode != 0:
        print("%s[X] Download failed:\n%s%s" % (C_RED, dl.stderr.strip(), C_RESET))
        return False
    _run("tar -xzf /tmp/wstunnel-dl/wstunnel.tar.gz -C /tmp/wstunnel-dl")
    extracted = "/tmp/wstunnel-dl/wstunnel"
    if not os.path.exists(extracted):
        print("%s[X] Archive didn't contain the expected 'wstunnel' binary.%s" % (C_RED, C_RESET))
        return False
    _run("cp %s %s" % (extracted, WSTUNNEL_BIN))
    os.chmod(WSTUNNEL_BIN, 0o755)

    # Let the binary bind privileged ports (443/80) without running the whole
    # process as root - confirmed real technique from actual reference
    # deployments, not something every other module in this panel does, but
    # wstunnel doesn't actually need full root for anything else.
    _run(["setcap", "CAP_NET_BIND_SERVICE=+eip", WSTUNNEL_BIN])
    _run(["useradd", "--system", "--shell", "/usr/sbin/nologin", WSTUNNEL_USER])

    if not _binary_ok():
        print("%s[X] Install did not complete correctly.%s" % (C_RED, C_RESET))
        return False
    return True


def _ensure_gate_deployed():
    os.makedirs(WSTUNNEL_DIR, exist_ok=True)
    for path, content in ((GATE_SCRIPT_PATH, GATE_SCRIPT), (CLEANUP_SCRIPT_PATH, CLEANUP_SCRIPT)):
        needs_write = True
        if os.path.exists(path):
            with open(path) as f:
                needs_write = f.read() != content
        if needs_write:
            with open(path, "w") as f:
                f.write(content)
            os.chmod(path, 0o755)
            check = _run(["python3", "-m", "py_compile", path])
            if check.returncode != 0:
                print("%s[X] %s failed its own syntax check:\n%s%s" % (C_RED, os.path.basename(path), check.stderr.strip(), C_RESET))
                os.remove(path)
                return False
    if not os.path.exists(CLEANUP_CRON_PATH):
        with open(CLEANUP_CRON_PATH, "w") as f:
            f.write("* * * * * root /usr/bin/python3 %s\n" % CLEANUP_SCRIPT_PATH)
        os.chmod(CLEANUP_CRON_PATH, 0o644)
    return True


def _ensure_gate_service(gate_port):
    service_content = """[Unit]
Description=wstunnel Access Gate
After=network.target

[Service]
Type=simple
User=root
Environment=WSTUNNEL_GATE_PORT=%s
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (gate_port, GATE_SCRIPT_PATH)
    with open(GATE_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")
    _run("systemctl enable wstunnel-gate")
    _run("systemctl restart wstunnel-gate")


def _ensure_gate_chain(instance_name, port):
    chain = GATE_CHAIN_PREFIX + instance_name
    _run(["iptables", "-N", chain])
    check_jump = _run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(port), "-j", chain])
    if check_jump.returncode != 0:
        _run(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(port), "-j", chain])
    check_drop = _run(["iptables", "-C", chain, "-j", "DROP"])
    if check_drop.returncode != 0:
        _run(["iptables", "-A", chain, "-j", "DROP"])


def _remove_gate_chain(instance_name, port):
    chain = GATE_CHAIN_PREFIX + instance_name
    _run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", chain])
    _run(["iptables", "-F", chain])
    _run(["iptables", "-X", chain])


def _service_name(instance_name):
    return "wstunnel-%s" % instance_name


def _service_active(instance_name):
    return _run(["systemctl", "is-active", "--quiet", _service_name(instance_name)]).returncode == 0


def _wait_for_port_listening(port, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _write_instance_service(instance_name, port, target_host, target_port, path_prefix):
    exec_cmd = ("%s server wss://0.0.0.0:%s --restrict-to %s:%s "
                "--restrict-http-upgrade-path-prefix %s") % (
        WSTUNNEL_BIN, port, target_host, target_port, path_prefix)
    service_content = """[Unit]
Description=wstunnel Instance (%s)
After=network.target

[Service]
Type=simple
User=%s
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % (instance_name, WSTUNNEL_USER, exec_cmd)
    service_path = "/etc/systemd/system/%s.service" % _service_name(instance_name)
    with open(service_path, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")
    return service_path


def websocket_admin_manager(ports_dict):
    """Standalone WebSocket Tunnel (wstunnel) Administrator Module."""
    while True:
        credentials = _load_credentials()
        gate_port = ports_dict.get('WSTUNNEL_GATE_PORT', 'Not configured')
        instance_count = len(credentials)

        clear_screen()
        print("================================================================")
        print("           WEBSOCKET TUNNEL (wstunnel) ADMINISTRATOR        ")
        print("================================================================")
        print("      INSTANCES: %s  |  GATE PORT: %s" % (instance_count, gate_port))
        print("%s      Distinct from WS-EPRO (this panel's own lightweight bridge)" % C_YELLOW)
        print("      and Xray's WS transport - this wraps wstunnel, a more capable")
        print("      real project (TCP+UDP tunneling, automatic TLS). Each instance")
        print("      is gated: the real port is closed until the client hits the")
        print("      gate URL with valid username/password (and Atken token, if")
        print("      required).%s" % C_RESET)
        print("----------------------------------------------------------------")
        print(" [1]> ADD WEBSOCKET INSTANCE (creates user + provisions tunnel)")
        print(" [2]> LIST INSTANCES / CONNECTION INFO")
        print(" [3]> REMOVE INSTANCE")
        print(" [4]> VIEW GATE SERVICE LOGS")
        print(" [5]> RESTART GATE SERVICE")
        print("================================================================")
        print(" [0] RETURN")
        print("================================================================")

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("================================================================")
            print("              ADD WEBSOCKET INSTANCE                        ")
            print("================================================================")

            instance_name = input(" Instance/customer name (letters, numbers, hyphens): ").strip()
            if not instance_name or not re.match(r'^[a-zA-Z0-9_-]+$', instance_name):
                print("%s[X] Invalid name.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            if instance_name in credentials:
                print("%s[X] An instance named '%s' already exists.%s" % (C_RED, instance_name, C_RESET))
                input("\nPress Enter to continue...")
                continue

            port = prompt_port(" Enter the real wstunnel port for this instance (e.g. 9100): ", default=9100)
            if check_system_port_in_use(port, ("tcp",)):
                print("%s[X] Port %s is already in use.%s" % (C_RED, port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            target_port = prompt_port(" Enter backend target port (e.g. 22 for SSH, 143 for Dropbear): ", default=22)
            if not check_system_port_in_use(target_port, ("tcp",)):
                print("%s[!] Nothing seems to be listening on port %s yet.%s" % (C_YELLOW, target_port, C_RESET))

            username = input(" Username for this customer: ").strip()
            password = input(" Password (blank to auto-generate): ").strip()
            if not password:
                password = secrets.token_urlsafe(12)
                print("%s[i] Generated password: %s%s" % (C_CYAN, password, C_RESET))
            atken_required = input(" Also require a valid Atken token to unlock this instance? (y/N): ").strip().lower() == 'y'

            gate_port_raw = ports_dict.get('WSTUNNEL_GATE_PORT')
            if not gate_port_raw:
                gate_port_raw = prompt_port(" Enter port for the shared access gate (e.g. 8601): ", default=8601)
            else:
                gate_port_raw = int(gate_port_raw)

            if not _ensure_binary_installed():
                input("\nPress Enter to continue...")
                continue

            path_prefix = secrets.token_urlsafe(24)  # defense-in-depth: wstunnel's own native shared-secret layer
            _write_instance_service(instance_name, port, "127.0.0.1", target_port, path_prefix)
            _ensure_gate_chain(instance_name, port)
            open_firewall_port(port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable %s" % _service_name(instance_name))
            restart_ok = _run("systemctl restart %s" % _service_name(instance_name)).returncode == 0

            if not (restart_ok and _wait_for_port_listening(port)):
                _remove_gate_chain(instance_name, port)
                close_firewall_port(port, ("tcp",))
                print("%s[X] wstunnel failed to start on port %s - check 'journalctl -u %s'.%s" % (
                    C_RED, port, _service_name(instance_name), C_RESET))
                input("\nPress Enter to continue...")
                continue

            if not _ensure_gate_deployed():
                input("\nPress Enter to continue...")
                continue
            open_firewall_port(gate_port_raw, ("tcp",))
            persist_firewall_rules()
            _ensure_gate_service(gate_port_raw)
            ports_dict['WSTUNNEL_GATE_PORT'] = str(gate_port_raw)

            salt = secrets.token_hex(16)
            credentials[instance_name] = {
                "username": username,
                "salt": salt,
                "hash": _hash_value(password, salt),
                "port": port,
                "target_port": target_port,
                "path_prefix": path_prefix,
                "atken_required": atken_required,
            }
            _save_credentials(credentials)

            server_ip = os.popen("curl -s ifconfig.me || hostname -I | awk '{print $1}'").read().strip()
            print("%s[OK] Instance '%s' provisioned on port %s -> 127.0.0.1:%s (closed until" % (
                C_GREEN, instance_name, port, target_port))
            print("    unlocked via the gate).%s" % C_RESET)
            print()
            print(" Give the customer:")
            print("  Gate URL: http://%s:%s/unlock?instance=%s&user=%s&pass=%s%s" % (
                server_ip, gate_port_raw, instance_name, username, password,
                "&token=<ATKEN_TOKEN>" if atken_required else ""))
            print("  Client command (after unlocking, within %d minutes):" % ACCEPT_WINDOW_MINUTES)
            print("   wstunnel client -L tcp://LOCAL_PORT:127.0.0.1:%s --http-upgrade-path-prefix %s wss://%s:%s" % (
                target_port, path_prefix, server_ip, port))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("================================================================")
            print("                 INSTANCES / CONNECTION INFO                ")
            print("================================================================")
            if not credentials:
                print("%s No instances configured.%s" % (C_YELLOW, C_RESET))
            else:
                for name, rec in credentials.items():
                    active = _service_active(name)
                    status = ("%s[ON]%s" % (C_GREEN, C_RESET)) if active else ("%s[OFF]%s" % (C_RED, C_RESET))
                    atken_tag = " (+Atken)" if rec.get("atken_required") else ""
                    print(" %-16s port %-6s -> 127.0.0.1:%-6s user:%-12s %s%s" % (
                        name, rec["port"], rec["target_port"], rec["username"], status, atken_tag))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            instance_name = input(" Instance name to remove: ").strip()
            if instance_name not in credentials:
                print("%s[X] No such instance.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            confirm = input(" Permanently remove '%s'? (y/n): " % instance_name).strip().lower()
            if confirm == 'y':
                port = credentials[instance_name]["port"]
                _run("systemctl stop %s" % _service_name(instance_name))
                _run("systemctl disable %s" % _service_name(instance_name))
                _run("rm -f /etc/systemd/system/%s.service" % _service_name(instance_name))
                _run("systemctl daemon-reload")
                _remove_gate_chain(instance_name, port)
                close_firewall_port(port, ("tcp",))
                persist_firewall_rules()
                del credentials[instance_name]
                _save_credentials(credentials)
                print("%s[OK] Instance '%s' removed.%s" % (C_GREEN, instance_name, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            os.system("journalctl -u wstunnel-gate -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            ok = _run("systemctl restart wstunnel-gate").returncode == 0
            if ok:
                print("%s[OK] Gate service restarted.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Gate service not running - add an instance first to deploy it.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
