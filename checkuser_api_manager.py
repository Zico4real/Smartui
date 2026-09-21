"""
checkuser_api_manager.py - Account Expiry / CheckUser API module for the
SmartUI panel.

Two real bugs found in the original draft, not just missing features:

1. The HTTP handler never parsed the request path or query string at all -
   do_GET always returned the same static HTML page regardless of what was
   requested. The "CheckUser Online" module's whole stated purpose - letting
   a client app look up its own account status - was never actually
   implemented. This module implements the real thing: a JSON API matching
   the exact contract client apps in this ecosystem use (GET /?user=X&pass=Y
   -> {"expiry": "N"}), with the expiry figure computed live from a stored
   expiry DATE per user rather than a static number that would silently go
   stale.

2. What it served instead (w -h output - who's logged in, from where, since
   when) had ZERO authentication and was reachable by anyone on the internet
   who found the port. That's a real information-disclosure bug: session
   data becomes reconnaissance material for an attacker, handed out to
   anyone who asks. Fixed by requiring valid credentials for anything this
   API returns, and moving the (legitimate, admin-only) session-listing
   feature to stay local-CLI-only rather than network-exposed. The
   "redirect_target" prompt from the original draft was also fabricated -
   asked for but never referenced anywhere in the generated server code -
   same pattern as several other modules in this panel; removed.

Because the wire protocol here is plain HTTP with credentials in a GET query
string (matching the client code this needs to serve, which explicitly uses
http:// and java.net.Proxy.NO_PROXY), a few things are handled carefully on
the server side to reduce what that inherently weak transport exposes:
  - Passwords are stored as salted hashes, never plaintext, and compared with
    a timing-safe function.
  - Query strings (which contain the password) are never written to logs -
    the request handler overrides logging to strip them.
  - Basic per-IP rate limiting on failed attempts, since an unauthenticated
    GET-based check is an easy brute-force target otherwise.
  - Invalid username and invalid password return the identical response
    (403, no body detail) so the endpoint can't be used to enumerate valid
    usernames.
"""

import os
import re
import json
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_live_port_from_service,
)

API_DIR = "/etc/checkuser-api"
USERS_DB_PATH = f"{API_DIR}/users.json"
API_SCRIPT_PATH = "/usr/local/bin/checkuser-api.py"
SERVICE_PATH = "/etc/systemd/system/checkuser-api.service"

API_SCRIPT = '''#!/usr/bin/env python3
"""Account expiry API. GET /?user=X&pass=Y -> 200 {"expiry": "N"} on valid
credentials (N = days remaining, negative if already expired), 403 otherwise.
Reads its listen ports (comma-separated - the client app tries several
fallback ports in sequence, so this can bind more than one at once) and DB
path from the environment, set in the systemd unit - never needs its own
source text edited to change ports."""
import os
import sys
import json
import time
import hmac
import hashlib
import threading
import http.server
import socketserver
import urllib.parse
from datetime import datetime

PORTS = [int(p) for p in os.environ.get("CHECKUSER_API_PORTS", "8082").split(",") if p.strip()]
DB_PATH = os.environ.get("CHECKUSER_API_DB", "/etc/checkuser-api/users.json")

_fail_counts = {}
_fail_window = 60
_fail_limit = 10


def _load_users():
    try:
        with open(DB_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()


def _rate_limited(addr):
    now = time.time()
    entry = _fail_counts.get(addr, [])
    entry = [t for t in entry if now - t < _fail_window]
    _fail_counts[addr] = entry
    return len(entry) >= _fail_limit


def _record_failure(addr):
    _fail_counts.setdefault(addr, []).append(time.time())


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Deliberately suppressed - the default logger would write the full
        # request line, which includes the password, straight into a log file.
        pass

    def do_GET(self):
        client_addr = self.client_address[0]
        if _rate_limited(client_addr):
            self.send_response(429)
            self.end_headers()
            return

        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        user = params.get("user", [""])[0]
        password = params.get("pass", [""])[0]

        users = _load_users()
        record = users.get(user)
        deny = False
        if not record:
            deny = True
            # Still hash something, so a missing-username response takes
            # roughly the same time as a wrong-password one.
            _hash_password(password, "no-such-user-salt")
        else:
            computed = _hash_password(password, record["salt"])
            if not hmac.compare_digest(computed, record["hash"]):
                deny = True

        if deny:
            _record_failure(client_addr)
            self.send_response(403)
            self.end_headers()
            return

        expiry_date = datetime.strptime(record["expiry"], "%Y-%m-%d")
        days_remaining = (expiry_date - datetime.now()).days

        body = json.dumps({"expiry": str(days_remaining)}).encode()
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_on(port):
    with ReusableTCPServer(("0.0.0.0", port), QuietHandler) as httpd:
        print("checkuser-api listening on 0.0.0.0:%d" % port)
        httpd.serve_forever()


if __name__ == "__main__":
    threads = []
    for p in PORTS:
        t = threading.Thread(target=serve_on, args=(p,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
'''


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "checkuser-api"]).returncode == 0


def _restart_api():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt.
    _run("systemctl reset-failed checkuser-api")
    return _run("systemctl restart checkuser-api").returncode == 0


def _wait_for_ports_listening(ports, tries=6, delay=1):
    """All explicitly requested ports must come up - if the admin asked for
    a specific set, silently succeeding on only some of them isn't success."""
    pending = set(ports)
    for _ in range(tries):
        pending = {p for p in pending if not check_system_port_in_use(p, ("tcp",))}
        if not pending:
            return True
        time.sleep(delay)
    return False


def _load_users():
    if not os.path.exists(USERS_DB_PATH):
        return {}
    with open(USERS_DB_PATH) as f:
        return json.load(f)


def _save_users(users):
    os.makedirs(API_DIR, exist_ok=True)
    with open(USERS_DB_PATH, "w") as f:
        json.dump(users, f, indent=2)
    os.chmod(USERS_DB_PATH, 0o600)


def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000).hex()


def _add_or_update_user(username, password, expiry_date_str):
    users = _load_users()
    salt = secrets.token_hex(16)
    users[username] = {
        "salt": salt,
        "hash": _hash_password(password, salt),
        "expiry": expiry_date_str,
    }
    _save_users(users)


def _ensure_script_deployed():
    os.makedirs(API_DIR, exist_ok=True)
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
            print("%s[X] API script failed its own syntax check:\\n%s%s" % (C_RED, check.stderr.strip(), C_RESET))
            os.remove(API_SCRIPT_PATH)
            return False
    return True


def _write_service(ports):
    ports_str = ",".join(str(p) for p in ports)
    service_content = """[Unit]
Description=CheckUser Account Expiry API
After=network.target

[Service]
Type=simple
User=root
Environment=CHECKUSER_API_PORTS=%s
Environment=CHECKUSER_API_DB=%s
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (ports_str, USERS_DB_PATH, API_SCRIPT_PATH)
    with open(SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_ports_safely(ports, description):
    original_unit = None
    if os.path.exists(SERVICE_PATH):
        with open(SERVICE_PATH, "r") as f:
            original_unit = f.read()

    _write_service(ports)

    if not _restart_api():
        if original_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_api()
        return False, "%s failed to restart - reverted to the previous working setup." % description

    if not _wait_for_ports_listening(ports):
        if original_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_api()
        ports_str = ", ".join(str(p) for p in ports)
        return False, "%s restarted, but port(s) %s never came up - reverted. Nothing was left broken." % (description, ports_str)

    ports_str = ", ".join(str(p) for p in ports)
    return True, "%s applied and verified on port(s) %s." % (description, ports_str)


KNOWN_CLIENT_FALLBACK_PORTS = [8880, 80, 143, 443]


def _pick_ports(current_ports=None):
    """Presents the ports a client app in this ecosystem is known to try as
    fallbacks (matching the exact list from the Android client this API
    needs to serve), plus custom entry - since the client tries several in
    sequence, binding more than one is supported and often desirable."""
    current_ports = current_ports or []
    clear_screen()
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("%s                    SELECT LISTEN PORT(S)                   %s" % (C_BOLD, C_RESET))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print(" The client app tries these in order until one responds - binding")
    print(" more than one increases the chance of a fast, first-try connect.")
    print()
    for i, p in enumerate(KNOWN_CLIENT_FALLBACK_PORTS, 1):
        tag = " (currently active)" if p in current_ports else ""
        print(" [%d] %s%s" % (i, p, tag))
    print(" [5] Custom port(s)")
    print(" [6] All of the above (%s)" % ", ".join(str(p) for p in KNOWN_CLIENT_FALLBACK_PORTS))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

    raw = input(" Enter your choice(s), comma-separated (e.g. 1,3 or 6): ").strip()
    if not raw:
        return None

    selected = set()
    custom_needed = False
    for token in raw.split(','):
        token = token.strip()
        if token == '6':
            selected.update(KNOWN_CLIENT_FALLBACK_PORTS)
        elif token == '5':
            custom_needed = True
        elif token.isdigit() and 1 <= int(token) <= 4:
            selected.add(KNOWN_CLIENT_FALLBACK_PORTS[int(token) - 1])
        else:
            print("%s[!] Ignoring unrecognized choice '%s'.%s" % (C_YELLOW, token, C_RESET))

    if custom_needed:
        custom_raw = input(" Enter custom port(s), comma-separated: ").strip()
        for p in custom_raw.split(','):
            p = p.strip()
            if p.isdigit() and 1 <= int(p) <= 65535:
                selected.add(int(p))
            elif p:
                print("%s[!] Ignoring invalid custom port '%s'.%s" % (C_YELLOW, p, C_RESET))

    if not selected:
        print("%s[X] No valid ports selected.%s" % (C_RED, C_RESET))
        return None

    # Report conflicts explicitly per port rather than silently dropping any -
    # 80/443 in particular are commonly already claimed by other modules in
    # this panel (Xray TLS, Stunnel, ACME challenges...).
    ports = sorted(selected)
    already_active = set(current_ports)
    conflicted = [p for p in ports if p not in already_active and check_system_port_in_use(p, ("tcp",))]
    if conflicted:
        print()
        print("%s[!] Already in use by something else: %s%s" % (
            C_YELLOW, ", ".join(str(p) for p in conflicted), C_RESET))
        free_ports = [p for p in ports if p not in conflicted]
        if not free_ports:
            print("%s[X] None of the selected ports are free - cancelled.%s" % (C_RED, C_RESET))
            return None
        proceed = input(" Proceed with just %s? (y/n): " % ", ".join(str(p) for p in free_ports)).strip().lower()
        if proceed != 'y':
            return None
        ports = free_ports

    return ports


def checkuser_api_manager(ports_dict):
    """CheckUser / Account Expiry API Administrator Module."""
    while True:
        # Same defensive re-enable as Stunnel/WS-EPRO/WebSocket/Atken/SSHGO
        # elsewhere in this panel - confirmed as a real, direct cause of a
        # genuine bug report, applied here proactively for the same class
        # of module before it's separately reported.
        if os.path.exists(SERVICE_PATH):
            _run("systemctl enable checkuser-api")
        live_ports = get_live_port_from_service(SERVICE_PATH, r'Environment=CHECKUSER_API_PORTS=([\d,]+)')
        recorded_ports_raw = ports_dict.get('CHECKUSER_API_PORTS', '')
        if live_ports and live_ports != recorded_ports_raw:
            print(f"{C_YELLOW}[!] The saved ports ({recorded_ports_raw or 'none'}) didn't match what's")
            print(f"    actually running ({live_ports}) - correcting the panel's records.{C_RESET}")
            ports_dict['CHECKUSER_API_PORTS'] = live_ports
            input("\nPress Enter to continue...")

        api_ports_raw = ports_dict.get('CHECKUSER_API_PORTS', '')
        api_ports = [int(p) for p in api_ports_raw.split(',') if p.isdigit()] if api_ports_raw else []
        api_ports_display = ", ".join(str(p) for p in api_ports) if api_ports else "Not configured"
        user_count = len(_load_users())
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s             CHECKUSER / ACCOUNT EXPIRY API                 %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      API PORT(S): %s  |  USERS: %s" % (api_ports_display, user_count))
        print("----------------------------------------------------------------")
        print(" [1]> VIEW ACTIVE SESSIONS (local, admin-only - not networked)")
        print(" [2]> CONFIGURE / INSTALL EXPIRY API")
        print(" [3]> MANAGE USERS (add / update / remove)")
        print(" [4]> CHANGE API PORT(S)")
        print(" [5]> VIEW SERVICE LOGS")
        print(" [6]> RESTART API SERVICE")
        print(" [7]> START/STOP API SERVICE [%s]" % status_label)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [8] UNINSTALL EXPIRY API")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                ACTIVE USER SESSIONS MONITOR                %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("\n--- Active SSH & Dropbear Sessions ---")
            os.system("w -h 2>/dev/null || who")
            print("\n--- Active Dropbear / SSH PIDs ---")
            os.system("ps aux | grep -E 'dropbear|sshd' | grep -v grep")
            print("\n--- Active OpenVPN Clients ---")
            if os.path.exists("/var/log/openvpn-status.log") or os.path.exists("/etc/openvpn/openvpn-status.log"):
                os.system("cat /var/log/openvpn-status.log 2>/dev/null || cat /etc/openvpn/openvpn-status.log 2>/dev/null")
            else:
                print(" [i] No OpenVPN status log found.")
            input("\nPress Enter to return to menu...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s           EXPIRY API INSTALLATION WIZARD                   %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s This serves plain HTTP (matching common client-app expectations) -" % C_YELLOW)
            print(" credentials travel in the query string. Passwords are stored hashed")
            print(" server-side and never logged, but the wire transport itself is not")
            print(" encrypted. Don't reuse a password here that matters elsewhere.%s\n" % C_RESET)

            selected_ports = _pick_ports(current_ports=api_ports)
            if not selected_ports:
                input("\nPress Enter to continue...")
                continue

            if not _ensure_script_deployed():
                input("\nPress Enter to continue...")
                continue

            for p in selected_ports:
                open_firewall_port(p, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable checkuser-api")

            ok, msg = _apply_ports_safely(selected_ports, "CheckUser API")
            if ok:
                ports_dict['CHECKUSER_API_PORTS'] = ",".join(str(p) for p in selected_ports)
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                if user_count == 0:
                    print("%s    No users yet - add some via option 3.%s" % (C_CYAN, C_RESET))
            else:
                for p in selected_ports:
                    if p not in api_ports:
                        close_firewall_port(p, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     MANAGE USERS                           %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" [1] Add / update a user")
            print(" [2] Remove a user")
            print(" [3] List users")
            print(" [0] Back")
            sub = input(" Select option: ").strip()

            if sub == '1':
                username = input(" Username: ").strip()
                password = input(" Password (blank to auto-generate): ").strip()
                if not password:
                    password = secrets.token_urlsafe(12)
                    print("%s[i] Generated password: %s%s" % (C_CYAN, password, C_RESET))
                days_raw = input(" Days until expiry from today (e.g., 30): ").strip()
                if not username or not days_raw.lstrip('-').isdigit():
                    print("%s[X] Username and a whole number of days are required.%s" % (C_RED, C_RESET))
                else:
                    expiry_date = (datetime.now() + timedelta(days=int(days_raw))).strftime("%Y-%m-%d")
                    _add_or_update_user(username, password, expiry_date)
                    print("%s[OK] User '%s' set to expire %s (%s days from now).%s" % (C_GREEN, username, expiry_date, days_raw, C_RESET))
            elif sub == '2':
                username = input(" Username to remove: ").strip()
                users = _load_users()
                if username in users:
                    del users[username]
                    _save_users(users)
                    print("%s[OK] User '%s' removed.%s" % (C_GREEN, username, C_RESET))
                else:
                    print("%s[X] No such user.%s" % (C_RED, C_RESET))
            elif sub == '3':
                users = _load_users()
                if not users:
                    print("%s No users configured.%s" % (C_YELLOW, C_RESET))
                else:
                    now = datetime.now()
                    for uname, rec in users.items():
                        expiry_date = datetime.strptime(rec["expiry"], "%Y-%m-%d")
                        days_left = (expiry_date - now).days
                        color = C_GREEN if days_left >= 0 else C_RED
                        print(" %-20s expires %s  (%s%s days%s)" % (uname, rec['expiry'], color, days_left, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  CHANGE API PORT(S)                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(SERVICE_PATH):
                print("%s[X] Not installed yet - run option 2 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            selected_ports = _pick_ports(current_ports=api_ports)
            if not selected_ports:
                input("\nPress Enter to continue...")
                continue

            for p in selected_ports:
                open_firewall_port(p, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_ports_safely(selected_ports, "Port change")
            if ok:
                old_ports = api_ports
                ports_dict['CHECKUSER_API_PORTS'] = ",".join(str(p) for p in selected_ports)
                dropped = [p for p in old_ports if p not in selected_ports]
                for p in dropped:
                    close_firewall_port(p, ("tcp",))
                if dropped:
                    persist_firewall_rules()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
            else:
                for p in selected_ports:
                    if p not in api_ports:
                        close_firewall_port(p, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                CHECKUSER API SERVICE LOGS                  %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u checkuser-api -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if _restart_api():
                print("%s[OK] CheckUser API service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u checkuser-api'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            if is_active:
                _run("systemctl stop checkuser-api")
                print("%s[!] CheckUser API service stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(API_SCRIPT_PATH):
                    print("%s[X] Not installed yet - run option 2 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start checkuser-api")
                if _service_active():
                    print("%s[OK] CheckUser API service started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u checkuser-api'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  UNINSTALL EXPIRY API                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove the CheckUser API? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop checkuser-api")
                _run("systemctl disable checkuser-api")
                _run("rm -f %s %s" % (SERVICE_PATH, API_SCRIPT_PATH))
                _run("systemctl daemon-reload")
                if api_ports:
                    for p in api_ports:
                        close_firewall_port(p, ("tcp",))
                    persist_firewall_rules()
                _run("rm -rf %s" % API_DIR)
                ports_dict.pop('CHECKUSER_API_PORTS', None)
                print("%s[OK] CheckUser API purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
