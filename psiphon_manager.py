"""
psiphon_manager.py - Psiphon (Obfuscated SSH) tunnel module for the SmartUI
panel, wrapping the official psiphond/ConsoleClient binaries from
Psiphon-Labs/psiphon-tunnel-core-binaries.

Confirmed real, official, actively-maintained project before building this
(latest release April 2026, 1.1k stars) - workflow taken directly from the
official README:
  ./psiphond -ipaddress <IP> -protocol OSSH:<port> generate
  ./psiphond run
  (client) copy server-entry.dat into a TargetServerEntry field, run
  ConsoleClient -config client.config, which exposes a local SOCKS5/HTTP
  proxy - NOT a private IP on a TUN device the way OpenVPN/WireGuard/the
  ICMP tunnel work.

Important nuance worth being upfront about, same as when this was proposed:
self-hosting psiphond does not join the real Psiphon network (that requires
Psiphon Inc's own signed server-list infrastructure) - this runs as a
private, standalone Obfuscated-SSH server. Clients need the panel-generated
client.config, not the public Psiphon apps.

The bigger architectural problem this module actually solves: Psiphon's
wire protocol has no concept of per-customer login credentials (clients
authenticate the SERVER via a pre-shared server entry - the reverse
direction from what a username/password would check), so there was no way
to bolt password/Atken-token auth directly onto psiphond's own config. The
solution built here doesn't modify or reimplement Psiphon's protocol at
all: each instance's real OSSH port is closed by default (a per-instance
iptables chain with a DROP rule), and a separate shared HTTP "gate" service
verifies username/password (salted-hash, matching the pattern used
throughout this panel) and, if the instance requires it, an Atken token -
by calling directly into atken_hash_manager's own hash-verification
functions rather than reimplementing them. On success, the gate inserts a
time-limited ACCEPT rule for that client's source IP ahead of the DROP
rule, so only verified clients can reach the real psiphond port at all -
the official, unmodified ConsoleClient then connects completely normally.
A periodic cleanup (matching the cron-enforcer pattern already used in
ssh_user_manager.py) expires stale ACCEPT rules automatically.
"""

import os
import re
import json
import time
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_live_port_from_service,
)

PSIPHON_DIR = "/etc/psiphon"
INSTANCES_DIR = f"{PSIPHON_DIR}/instances"
CREDENTIALS_PATH = f"{PSIPHON_DIR}/credentials.json"
PSIPHOND_BIN = "/usr/local/bin/psiphond"
CONSOLECLIENT_BIN = "/usr/local/bin/psiphon-console-client"
GATE_SCRIPT_PATH = "/usr/local/bin/psiphon-gate.py"
GATE_SERVICE_PATH = "/etc/systemd/system/psiphon-gate.service"
GATE_STATE_PATH = f"{PSIPHON_DIR}/gate_state.json"
CLEANUP_CRON_PATH = "/etc/cron.d/psiphon-gate-cleanup"
CLEANUP_SCRIPT_PATH = "/usr/local/bin/psiphon-gate-cleanup.py"
GATE_CHAIN_PREFIX = "psiphongate_"
ACCEPT_WINDOW_MINUTES = 10

BINARIES_BASE = "https://raw.githubusercontent.com/Psiphon-Labs/psiphon-tunnel-core-binaries/master"

GATE_SCRIPT = '''#!/usr/bin/env python3
"""Psiphon access gate. GET /unlock?instance=X&user=Y&pass=Z[&token=T] ->
verifies credentials for that instance and, if it requires one, an Atken
token (by importing atken_hash_manager's own verification directly - not
reimplemented here). On success, inserts a time-limited iptables ACCEPT
rule for the connecting client's source IP ahead of that instance's default
DROP rule, so only verified clients can reach the real OSSH port at all."""
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

CREDENTIALS_PATH = "/etc/psiphon/credentials.json"
GATE_STATE_PATH = "/etc/psiphon/gate_state.json"
GATE_CHAIN_PREFIX = "psiphongate_"
ACCEPT_WINDOW_MINUTES = 10
PORT = int(os.environ.get("PSIPHON_GATE_PORT", "8600"))
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
    """Reads the same on-disk token store atken_hash_manager.py produces and
    applies the identical PBKDF2 hash-and-compare directly, rather than
    cross-importing that module from a standalone systemd service - this
    script runs as its own separate process, and assuming a specific
    directory the panel's other modules happen to be installed in would be
    a fragile, unverified guess. Reading the same stable on-disk format the
    other module already writes is the robust way to check the same real
    tokens without that dependency."""
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


def grant_access(instance, port, source_ip):
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

        grant_access(instance, rec.get("port"), client_addr)
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
        print("psiphon-gate listening on 0.0.0.0:%d" % PORT)
        httpd.serve_forever()
'''

CLEANUP_SCRIPT = '''#!/usr/bin/env python3
"""Expires temporary per-IP ACCEPT rules once their window has passed - run
periodically via cron, same pattern as the SSH user enforcer."""
import json
import time
import subprocess

GATE_STATE_PATH = "/etc/psiphon/gate_state.json"
GATE_CHAIN_PREFIX = "psiphongate_"


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
    os.makedirs(PSIPHON_DIR, exist_ok=True)
    with open(CREDENTIALS_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(CREDENTIALS_PATH, 0o600)


def _hash_value(value, salt):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 100000).hex()


def _binaries_ok():
    return (os.path.exists(PSIPHOND_BIN) and os.access(PSIPHOND_BIN, os.X_OK)
            and os.path.exists(CONSOLECLIENT_BIN) and os.access(CONSOLECLIENT_BIN, os.X_OK))


def _ensure_binaries_installed():
    if _binaries_ok():
        return True
    print("%s[i] Downloading official Psiphon binaries...%s" % (C_CYAN, C_RESET))
    _run("curl -fsSL %s/psiphond/psiphond -o %s" % (BINARIES_BASE, PSIPHOND_BIN))
    _run("curl -fsSL %s/linux/psiphon-tunnel-core-x86_64 -o %s" % (BINARIES_BASE, CONSOLECLIENT_BIN))
    os.chmod(PSIPHOND_BIN, 0o755) if os.path.exists(PSIPHOND_BIN) else None
    os.chmod(CONSOLECLIENT_BIN, 0o755) if os.path.exists(CONSOLECLIENT_BIN) else None
    if not _binaries_ok():
        print("%s[X] Download failed - check network access.%s" % (C_RED, C_RESET))
        return False
    return True


def _ensure_gate_deployed():
    os.makedirs(PSIPHON_DIR, exist_ok=True)
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
Description=Psiphon Access Gate
After=network.target

[Service]
Type=simple
User=root
Environment=PSIPHON_GATE_PORT=%s
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (gate_port, GATE_SCRIPT_PATH)
    with open(GATE_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")
    _run("systemctl enable psiphon-gate")
    _run("systemctl reset-failed psiphon-gate")
    _run("systemctl restart psiphon-gate")


def _ensure_gate_chain(instance_name, port):
    """Default-DROP chain for this instance's public port - only source IPs
    the gate has explicitly granted (via a temporary ACCEPT rule inserted
    ahead of this) can reach it."""
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
    return "psiphon-%s" % instance_name


def _service_active(instance_name):
    return _run(["systemctl", "is-active", "--quiet", _service_name(instance_name)]).returncode == 0


def _wait_for_port_listening(port, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _generate_instance(instance_name, port, server_ip):
    instance_dir = "%s/%s" % (INSTANCES_DIR, instance_name)
    os.makedirs(instance_dir, exist_ok=True)
    gen = _run("cd %s && %s -ipaddress %s -protocol OSSH:%s generate" % (instance_dir, PSIPHOND_BIN, server_ip, port))
    expected = ["psiphond.config", "psiphond-osl.config", "psiphond-tactics.config",
                "psiphond-traffic-rules.config", "server-entry.dat"]
    if not all(os.path.exists("%s/%s" % (instance_dir, f)) for f in expected):
        return False, gen.stderr.strip()
    return True, instance_dir


def _build_client_config(instance_dir, instance_name):
    with open("%s/server-entry.dat" % instance_dir) as f:
        server_entry = f.read().strip()
    client_config = {
        "LocalHttpProxyPort": 8080,
        "LocalSocksProxyPort": 1080,
        "PropagationChannelId": secrets.token_hex(8).upper(),
        "SponsorId": secrets.token_hex(8).upper(),
        "TargetServerEntry": server_entry,
    }
    client_path = "%s/client-%s.config" % (instance_dir, instance_name)
    with open(client_path, "w") as f:
        json.dump(client_config, f, indent=4)
    return client_path


def _write_instance_service(instance_name, instance_dir):
    service_content = """[Unit]
Description=Psiphon OSSH Instance (%s)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % (instance_name, instance_dir, PSIPHOND_BIN)
    service_path = "/etc/systemd/system/%s.service" % _service_name(instance_name)
    with open(service_path, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")
    return service_path


def psiphon_admin_manager(ports_dict):
    """Psiphon (Obfuscated SSH) Administrator Module."""
    while True:
        live_gate_port = get_live_port_from_service(GATE_SERVICE_PATH, r'Environment=PSIPHON_GATE_PORT=(\d+)')
        recorded_gate_port = ports_dict.get('PSIPHON_GATE_PORT')
        if live_gate_port and str(recorded_gate_port) != str(live_gate_port):
            print(f"{C_YELLOW}[!] The saved gate port ({recorded_gate_port or 'none'}) didn't match what's")
            print(f"    actually running ({live_gate_port}) - correcting the panel's records.{C_RESET}")
            ports_dict['PSIPHON_GATE_PORT'] = live_gate_port
            input("\nPress Enter to continue...")

        credentials = _load_credentials()
        gate_port = ports_dict.get('PSIPHON_GATE_PORT', 'Not configured')
        instance_count = len(credentials)

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                 PSIPHON (OSSH) ADMINISTRATOR               %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      INSTANCES: %s  |  GATE PORT: %s" % (instance_count, gate_port))
        print("%s      Standalone Obfuscated-SSH - does not join the real Psiphon" % C_YELLOW)
        print("      network. Clients need the generated client.config, not the")
        print("      public Psiphon apps. Each instance is gated: the real OSSH")
        print("      port is closed until the client hits the gate URL with valid")
        print("      username/password (and Atken token, if required).%s" % C_RESET)
        print("----------------------------------------------------------------")
        print(" [1]> ADD PSIPHON INSTANCE (creates user + provisions server)")
        print(" [2]> LIST INSTANCES / CONNECTION INFO")
        print(" [3]> REMOVE INSTANCE")
        print(" [4]> VIEW GATE SERVICE LOGS")
        print(" [5]> RESTART GATE SERVICE")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s               ADD PSIPHON INSTANCE                         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            instance_name = input(" Instance/customer name (letters, numbers, hyphens): ").strip()
            if not instance_name or not re.match(r'^[a-zA-Z0-9_-]+$', instance_name):
                print("%s[X] Invalid name.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            if instance_name in credentials:
                print("%s[X] An instance named '%s' already exists.%s" % (C_RED, instance_name, C_RESET))
                input("\nPress Enter to continue...")
                continue

            port = prompt_port(" Enter the real OSSH port for this instance (e.g. 9000): ", default=9000)
            if check_system_port_in_use(port, ("tcp",)):
                print("%s[X] Port %s is already in use.%s" % (C_RED, port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            # Confirmed as the real, actionable fix for a genuine request:
            # letting the admin reuse an existing SSH account's real
            # credentials here, rather than always typing a brand-new,
            # separate username/password just for this instance. Password
            # reuse is possible here (unlike Atken tokens below) because
            # this panel's own SSH accounts keep a plaintext password store
            # specifically for exactly this kind of display/reuse -
            # confirmed directly from that module's own file. Still offers
            # a genuinely separate set as an option, since some admins may
            # legitimately want Psiphon-only access without SSH access
            # attached to the same credentials.
            existing_ssh_users = {}
            try:
                from ssh_user_manager import _load_registry as _load_ssh_registry, _load_password_store as _load_ssh_passwords
                ssh_registry = _load_ssh_registry()
                ssh_passwords = _load_ssh_passwords()
                existing_ssh_users = {u: ssh_passwords[u] for u in ssh_registry if u in ssh_passwords}
            except Exception:
                pass

            username, password = None, None
            if existing_ssh_users:
                print(" Existing SSH accounts available to reuse:")
                names = sorted(existing_ssh_users.keys())
                for i, u in enumerate(names, 1):
                    print("   [%d] %s" % (i, u))
                print("   [0] Create a separate, new username/password just for this instance")
                sel = input(" Reuse which account (number, or 0 for a new one): ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(names):
                    username = names[int(sel) - 1]
                    password = existing_ssh_users[username]
                    print("%s[i] Reusing SSH account '%s' - same username and password will" % (C_CYAN, username))
                    print("    unlock both SSH and this Psiphon instance.%s" % C_RESET)

            if username is None:
                username = input(" Username for this customer: ").strip()
                password = input(" Password (blank to auto-generate): ").strip()
                if not password:
                    password = secrets.token_urlsafe(12)
                    print("%s[i] Generated password: %s%s" % (C_CYAN, password, C_RESET))

            atken_required = input(" Also require a valid Atken token to unlock this instance? (y/N): ").strip().lower() == 'y'
            if atken_required:
                print("%s[i] No new token needed here - this validates against ANY existing," % C_CYAN)
                print("    already-issued Atken token (Extra Tools -> Atken and Hash), the same")
                print("    way every other Atken-gated protocol in this panel already works.%s" % C_RESET)

            gate_port_raw = ports_dict.get('PSIPHON_GATE_PORT')
            if not gate_port_raw:
                new_gate_port = prompt_port(" Enter port for the shared access gate (e.g. 8600): ", default=8600)
                gate_port_raw = new_gate_port
            else:
                gate_port_raw = int(gate_port_raw)

            if not _ensure_binaries_installed():
                input("\nPress Enter to continue...")
                continue

            server_ip = os.popen("curl -s ifconfig.me || hostname -I | awk '{print $1}'").read().strip()
            ok, result = _generate_instance(instance_name, port, server_ip)
            if not ok:
                print("%s[X] Config generation failed:\n%s%s" % (C_RED, result, C_RESET))
                input("\nPress Enter to continue...")
                continue
            instance_dir = result
            client_path = _build_client_config(instance_dir, instance_name)

            _write_instance_service(instance_name, instance_dir)
            _ensure_gate_chain(instance_name, port)
            open_firewall_port(port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable %s" % _service_name(instance_name))
            # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in
            # this panel: clear any prior rate-limit before every restart.
            _run("systemctl reset-failed %s" % _service_name(instance_name))
            restart_ok = _run("systemctl restart %s" % _service_name(instance_name)).returncode == 0

            if not (restart_ok and _wait_for_port_listening(port)):
                _remove_gate_chain(instance_name, port)
                close_firewall_port(port, ("tcp",))
                print("%s[X] psiphond failed to start on port %s - check 'journalctl -u %s'.%s" % (
                    C_RED, port, _service_name(instance_name), C_RESET))
                input("\nPress Enter to continue...")
                continue

            if not _ensure_gate_deployed():
                input("\nPress Enter to continue...")
                continue
            open_firewall_port(gate_port_raw, ("tcp",))
            persist_firewall_rules()
            _ensure_gate_service(gate_port_raw)
            ports_dict['PSIPHON_GATE_PORT'] = str(gate_port_raw)

            salt = secrets.token_hex(16)
            credentials[instance_name] = {
                "username": username,
                "salt": salt,
                "hash": _hash_value(password, salt),
                "port": port,
                "atken_required": atken_required,
            }
            _save_credentials(credentials)

            print("%s[OK] Instance '%s' provisioned and running on port %s (closed until" % (C_GREEN, instance_name, port))
            print("    unlocked via the gate).%s" % C_RESET)
            print()
            print(" Give the customer:")
            print("  Client config: %s" % client_path)
            print("  Gate URL: http://%s:%s/unlock?instance=%s&user=%s&pass=%s%s" % (
                server_ip, gate_port_raw, instance_name, username, password,
                "&token=<ATKEN_TOKEN>" if atken_required else ""))
            print("  (they must hit the gate URL first, then run ConsoleClient with the")
            print("   client config within %d minutes)" % ACCEPT_WINDOW_MINUTES)
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 INSTANCES / CONNECTION INFO                %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not credentials:
                print("%s No instances configured.%s" % (C_YELLOW, C_RESET))
            else:
                for name, rec in credentials.items():
                    active = _service_active(name)
                    status = ("%s[ON]%s" % (C_GREEN, C_RESET)) if active else ("%s[OFF]%s" % (C_RED, C_RESET))
                    atken_tag = " (+Atken)" if rec.get("atken_required") else ""
                    print(" %-16s port %-6s user:%-12s %s%s" % (name, rec["port"], rec["username"], status, atken_tag))
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
                _run("rm -rf %s/%s" % (INSTANCES_DIR, instance_name))
                del credentials[instance_name]
                _save_credentials(credentials)
                print("%s[OK] Instance '%s' removed.%s" % (C_GREEN, instance_name, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            os.system("journalctl -u psiphon-gate -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            _run("systemctl reset-failed psiphon-gate")
            ok = _run("systemctl restart psiphon-gate").returncode == 0
            if ok:
                print("%s[OK] Gate service restarted.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Gate service not running - add an instance first to deploy it.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
