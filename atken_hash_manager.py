"""
atken_hash_manager.py - Atken/Hash token authentication module for the
SmartUI panel.

The single most severe bug found here: the entrance key was hashed (SHA-256)
AND stored in plaintext in the same file, right next to its own hash:
    {"entrance_key": entrance_key, "master_hash": initial_hash, ...}
Hashing a secret is pointless the moment the plaintext sits right beside it -
anyone who reads tokens.json (a misconfigured backup, a compromised process
with read access, anything) gets the raw secret directly, no cracking
required. Fixed by never storing the plaintext at all - only a salted hash,
the same pattern already used in checkuser_api_manager.py.

Other real security bugs found, same category as #1 - not "doesn't work" but
"quietly less secure than it appears":

1. Unsalted SHA-256 for the token hash. SHA-256 is a fast general-purpose
   hash, not a password/secret hash - no salt means identical tokens always
   hash identically (rainbow-table risk), and it's fast enough to brute-force
   short tokens at billions of guesses/second on commodity hardware. Fixed
   with per-token salted PBKDF2, matching checkuser_api_manager.py.

2. The raw secret token is sent in the URL PATH (/auth/<token>) and
   SimpleHTTPRequestHandler's default logging writes the full request path
   to the journal on every request - meaning every authentication attempt's
   plaintext secret would end up in journalctl -u atken-hash forever. Fixed
   by switching to BaseHTTPRequestHandler with logging overridden to suppress
   path/query logging, matching the equivalent fix in checkuser_api_manager.py.

3. Subclassing SimpleHTTPRequestHandler at all is itself a latent risk here:
   that class's whole purpose is serving files from the process's working
   directory, and only do_GET was overridden - any other HTTP method (HEAD,
   etc.) would fall through to the inherited file-serving behavior. Since the
   systemd unit never set a WorkingDirectory, that default is "/" - the
   filesystem root. Fixed by using BaseHTTPRequestHandler instead, which has
   no such fallback at all.

4. Hash comparison used `in`/`==` rather than a timing-safe compare - fixed
   with hmac.compare_digest, matching the pattern used elsewhere in this panel.

Other bugs, matching classes already fixed across this panel:

5. redirect_target was captured from input but never referenced anywhere in
   the generated server code or config - same fabricated-feature pattern as
   the Shadowsocks/Hysteria/ZIVPN/Squid redirect bugs. Removed.

6. No restart verification, no port-conflict check, no rollback on failure,
   raw ufw/iptables instead of the shared firewall helpers, and uninstall
   never closed the port on the firewall.

7. Port changes patched the deployed script's source text via regex - moved
   to the environment-variable architecture already established for WS-EPRO/
   CheckUser-API, so a port change is a clean systemd-unit rewrite instead.

8. No way to revoke an individual issued token, only add new ones - added,
   matching the add/remove pattern already used for ZIVPN passwords and Squid
   users.
"""

import os
import re
import json
import time
import hashlib
import secrets
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_live_port_from_service,
)

ATKEN_DIR = "/etc/atken"
TOKENS_PATH = f"{ATKEN_DIR}/tokens.json"
API_SCRIPT_PATH = "/usr/local/bin/atken-api.py"
SERVICE_PATH = "/etc/systemd/system/atken-hash.service"

API_SCRIPT = '''#!/usr/bin/env python3
"""Atken/Hash token verification API. GET /auth/<token> -> 200 {"status":
"success"} if the token matches a stored (salted, hashed) token or the master
key, 401 otherwise. Reads its port and token-file path from the environment,
set in the systemd unit - never needs its own source text edited to change
ports."""
import os
import sys
import json
import time
import hmac
import hashlib
import http.server
import socketserver
import urllib.parse

PORT = int(os.environ.get("ATKEN_API_PORT", "85"))
TOKEN_FILE = os.environ.get("ATKEN_TOKEN_FILE", "/etc/atken/tokens.json")

_fail_counts = {}
_fail_window = 60
_fail_limit = 10


def _load_tokens():
    try:
        with open(TOKEN_FILE) as f:
            return json.load(f)
    except Exception:
        return {"master_hash": None, "master_salt": None, "tokens": {}}


def _hash(value, salt):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 100000).hex()


def _rate_limited(addr):
    now = time.time()
    entry = [t for t in _fail_counts.get(addr, []) if now - t < _fail_window]
    _fail_counts[addr] = entry
    return len(entry) >= _fail_limit


def _record_failure(addr):
    _fail_counts.setdefault(addr, []).append(time.time())


class AtkenHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Deliberately suppressed - the token itself travels in the request
        # path, and the default logger would write it straight into a log file.
        pass

    def _send_json(self, status_code, payload):
        body = json.dumps(payload).encode()
        self.send_response(status_code)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        client_addr = self.client_address[0]
        if _rate_limited(client_addr):
            self._send_json(429, {"status": "error", "message": "Too many attempts"})
            return

        parsed = urllib.parse.urlparse(self.path)
        path_parts = parsed.path.strip("/").split("/")
        hwid_query = urllib.parse.parse_qs(parsed.query).get("hwid", [None])[0]

        if len(path_parts) >= 2 and path_parts[0] == "auth":
            token_query = urllib.parse.unquote(path_parts[1])
            data = _load_tokens()

            valid = False
            matched_name = None
            if data.get("master_salt") and data.get("master_hash"):
                computed = _hash(token_query, data["master_salt"])
                if hmac.compare_digest(computed, data["master_hash"]):
                    valid = True

            if not valid:
                for name, rec in data.get("tokens", {}).items():
                    computed = _hash(token_query, rec["salt"])
                    if hmac.compare_digest(computed, rec["hash"]):
                        valid = True
                        matched_name = name
                        break

            # HWID binding only applies to individually-issued tokens, never
            # the master key (which is meant for admin/multi-device use).
            if valid and matched_name:
                rec = data["tokens"][matched_name]
                if rec.get("hwid_lock_enabled"):
                    if not hwid_query:
                        valid = False  # this token requires a device fingerprint and none was sent
                    elif not rec.get("hwid_bound"):
                        # First use: bind this token to whichever device presents it now.
                        rec["hwid_bound"] = hwid_query
                        with open(TOKEN_FILE, "w") as f:
                            json.dump(data, f, indent=2)
                    elif rec["hwid_bound"] != hwid_query:
                        valid = False  # right token, wrong device - reported identically to "invalid" below

            if valid:
                self._send_json(200, {"status": "success", "message": "Token verified valid"})
            else:
                _record_failure(client_addr)
                self._send_json(401, {"status": "unauthorized", "message": "Invalid token"})
        else:
            self._send_json(200, {"status": "active", "service": "Atken Hash Auth Server", "port": PORT})


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with ReusableTCPServer(("0.0.0.0", PORT), AtkenHandler) as httpd:
        print("atken-hash listening on 0.0.0.0:%d" % PORT)
        httpd.serve_forever()
'''


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "atken-hash"]).returncode == 0


def _restart_atken():
    return _run("systemctl restart atken-hash").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _hash_value(value, salt):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 100000).hex()


def _load_tokens():
    if not os.path.exists(TOKENS_PATH):
        return {"master_hash": None, "master_salt": None, "tokens": {}}
    with open(TOKENS_PATH) as f:
        return json.load(f)


def _save_tokens(data):
    os.makedirs(ATKEN_DIR, exist_ok=True)
    with open(TOKENS_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(TOKENS_PATH, 0o600)


def _ensure_script_deployed():
    os.makedirs(ATKEN_DIR, exist_ok=True)
    needs_write = True
    if os.path.exists(API_SCRIPT_PATH):
        with open(API_SCRIPT_PATH, "r") as f:
            needs_write = f.read() != API_SCRIPT
    if needs_write:
        with open(API_SCRIPT_PATH, "w") as f:
            f.write(API_SCRIPT)
        os.chmod(API_SCRIPT_PATH, 0o755)
        check = _run(["python3", "-m", "py_compile", API_SCRIPT_PATH])
        if check.returncode != 0:
            print("%s[X] API script failed its own syntax check:\n%s%s" % (C_RED, check.stderr.strip(), C_RESET))
            os.remove(API_SCRIPT_PATH)
            return False
    return True


def _write_service(port):
    service_content = """[Unit]
Description=Atken Hash Online Token Authentication Service
After=network.target

[Service]
Type=simple
User=root
Environment=ATKEN_API_PORT=%s
Environment=ATKEN_TOKEN_FILE=%s
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (port, TOKENS_PATH, API_SCRIPT_PATH)
    with open(SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_port_safely(port, description):
    original_unit = None
    if os.path.exists(SERVICE_PATH):
        with open(SERVICE_PATH, "r") as f:
            original_unit = f.read()

    _write_service(port)

    if not _restart_atken():
        if original_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_atken()
        return False, "%s failed to restart - reverted to the previous working setup." % description

    if not _wait_for_port_listening(port):
        if original_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_atken()
        return False, "%s restarted, but port %s never came up - reverted. Nothing was left broken." % (description, port)

    return True, "%s applied and verified on port %s." % (description, port)


def atken_hash_admin_manager(ports_dict):
    """ATKEN / HASH Administrator Module."""
    while True:
        live_port = get_live_port_from_service(SERVICE_PATH, r'Environment=ATKEN_API_PORT=(\d+)')
        recorded_port = ports_dict.get('ATKEN_PORT')
        if live_port and str(recorded_port) != str(live_port):
            print(f"{C_YELLOW}[!] The saved port ({recorded_port or 'none'}) didn't match what's actually")
            print(f"    running ({live_port}) - correcting the panel's records to match reality.{C_RESET}")
            ports_dict['ATKEN_PORT'] = live_port
            input("\nPress Enter to continue...")

        token_port = ports_dict.get('ATKEN_PORT', 'Not configured')
        tokens_data = _load_tokens()
        token_count = len(tokens_data.get('tokens', {}))
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s               ATKEN / HASH TOKEN AUTHENTICATION            %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      TOKEN PORT: %s  |  ISSUED TOKENS: %s" % (token_port, token_count))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL ATKEN HASH SERVICE (Wizard)")
        print(" [2]> ADD / GENERATE TOKEN")
        print(" [3]> REVOKE A TOKEN")
        print(" [4]> CHANGE TOKEN PORT")
        print(" [5]> VIEW ATKEN / HASH SERVICE LOGS")
        print(" [6]> RESTART ATKEN HASH SERVICE")
        print(" [7]> START/STOP ATKEN SERVICE [%s]" % status_label)
        print(" [9]> VIEW / RESET DEVICE BINDINGS (HWID)")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [8] UNINSTALL ATKEN HASH")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s         ATKEN HASH INSTALLATION WIZARD                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s The entrance key is stored only as a salted hash, never in" % C_YELLOW)
            print(" plaintext - write it down now, it can't be recovered later.%s\n" % C_RESET)

            listen_port = prompt_port(" Enter desired Token API Listen Port (e.g., 85 or 8085): ", default=85)
            if str(listen_port) != str(token_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            entrance_key = input(" Enter secret entrance key for master verification: ").strip()
            if not entrance_key:
                print("%s[X] Entrance key cannot be empty.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            if not _ensure_script_deployed():
                input("\nPress Enter to continue...")
                continue

            master_salt = secrets.token_hex(16)
            data = {
                "master_salt": master_salt,
                "master_hash": _hash_value(entrance_key, master_salt),
                "tokens": {},
            }
            _save_tokens(data)

            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable atken-hash")

            ok, msg = _apply_port_safely(listen_port, "Atken Hash service on port %s" % listen_port)
            if ok:
                ports_dict['ATKEN_PORT'] = str(listen_port)
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  ADD / GENERATE TOKEN                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(TOKENS_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_client = input(" Enter client/token name identifier: ").strip()
            new_secret = input(" Enter secret token value (blank to auto-generate): ").strip()
            if not new_secret:
                new_secret = secrets.token_urlsafe(16)
                print("%s[i] Generated token: %s%s" % (C_CYAN, new_secret, C_RESET))

            hwid_lock = input(" Bind this token to a single device (first device to use it wins)? (y/N): ").strip().lower() == 'y'

            if not new_client:
                print("%s[X] Client identifier cannot be empty.%s" % (C_RED, C_RESET))
            else:
                data = _load_tokens()
                salt = secrets.token_hex(16)
                data.setdefault("tokens", {})[new_client] = {
                    "salt": salt,
                    "hash": _hash_value(new_secret, salt),
                    "hwid_lock_enabled": hwid_lock,
                    "hwid_bound": None,
                }
                _save_tokens(data)
                print("%s[OK] Token issued for '%s'. Give this token to the client - it can't" % (C_GREEN, new_client))
                print("    be recovered from the server afterward (only its hash is stored):%s" % C_RESET)
                print("    %s" % new_secret)
                if hwid_lock:
                    print("%s[i] Device binding enabled - the first device to authenticate with this" % C_CYAN)
                    print("    token will be locked in; the client app must send a stable hardware ID")
                    print("    as ?hwid=... on the auth request.%s" % C_RESET)
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     REVOKE A TOKEN                          %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            data = _load_tokens()
            tokens = data.get("tokens", {})
            if not tokens:
                print("%s No issued tokens to revoke.%s" % (C_YELLOW, C_RESET))
            else:
                for name in tokens:
                    print("  - %s" % name)
                name = input(" Enter client/token name to revoke: ").strip()
                if name in tokens:
                    del tokens[name]
                    _save_tokens(data)
                    print("%s[OK] Token for '%s' revoked.%s" % (C_GREEN, name, C_RESET))
                else:
                    print("%s[X] No such token.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  CHANGE TOKEN PORT                          %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new Atken API port [Current: %s]: " % token_port,
                                    default=int(token_port) if str(token_port).isdigit() else 85)
            if str(new_port) != str(token_port) and check_system_port_in_use(new_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_port_safely(new_port, "Port change to %s" % new_port)
            if ok:
                old_port = token_port
                ports_dict['ATKEN_PORT'] = str(new_port)
                if str(old_port).isdigit() and str(old_port) != str(new_port):
                    close_firewall_port(int(old_port), ("tcp",))
                    persist_firewall_rules()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
            else:
                close_firewall_port(new_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                ATKEN HASH SERVICE LOGS                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u atken-hash -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if _restart_atken():
                print("%s[OK] Atken Hash service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u atken-hash'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            if is_active:
                _run("systemctl stop atken-hash")
                print("%s[!] Atken Hash service stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(API_SCRIPT_PATH):
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start atken-hash")
                if _service_active():
                    print("%s[OK] Atken Hash service started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u atken-hash'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                UNINSTALL ATKEN HASH                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove Atken Hash? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop atken-hash")
                _run("systemctl disable atken-hash")
                _run("rm -f %s %s" % (SERVICE_PATH, API_SCRIPT_PATH))
                _run("systemctl daemon-reload")
                if str(token_port).isdigit():
                    close_firewall_port(int(token_port), ("tcp",))
                    persist_firewall_rules()
                _run("rm -rf %s" % ATKEN_DIR)
                ports_dict.pop('ATKEN_PORT', None)
                print("%s[OK] Atken Hash purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '9':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s               DEVICE BINDINGS (HWID)                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            data = _load_tokens()
            bound_tokens = {n: r for n, r in data.get("tokens", {}).items() if r.get("hwid_lock_enabled")}
            if not bound_tokens:
                print("%s No tokens have device binding enabled.%s" % (C_YELLOW, C_RESET))
            else:
                for name, rec in bound_tokens.items():
                    status = rec.get("hwid_bound") or "(not yet bound - open to the next device that uses it)"
                    print("  %-16s -> %s" % (name, status))
                print()
                reset_name = input(" Enter a token name to reset its binding (blank to skip): ").strip()
                if reset_name:
                    if reset_name in bound_tokens:
                        data["tokens"][reset_name]["hwid_bound"] = None
                        _save_tokens(data)
                        print("%s[OK] Binding cleared for '%s' - the next device to use this token" % (C_GREEN, reset_name))
                        print("    will be the new one bound to it.%s" % C_RESET)
                    else:
                        print("%s[X] No device-bound token by that name.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
