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
import re
import secrets
import threading
import subprocess
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


_SSH_REGISTRY_PATH = "/etc/ssh_users/registry.json"


def _ssh_registry_quota_bytes(username):
    """Fallback for a user whose quota was set via SSH Users > Add User instead of this module's
    own quota menu - read-only, best-effort, never raises."""
    try:
        with open(_SSH_REGISTRY_PATH) as f:
            reg = json.load(f)
        rec = reg.get(username) or {}
        if rec.get("quota_enabled") and rec.get("quota_bytes"):
            return rec["quota_bytes"]
    except Exception:
        pass
    return None


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


_dev_cache = {"t": 0.0, "counts": {}}
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
_db_lock = threading.Lock()
PASSWORD_STORE = "/etc/ssh_users/plaintext_passwords.json"


def _valid_new_password(pw):
    # chpasswd splits on ":" and reads one line, so those are not allowed;
    # printable ASCII only keeps it safe for every SSH/Dropbear client.
    if not (6 <= len(pw) <= 64):
        return False
    return all(33 <= ord(ch) <= 126 and ch != ":" for ch in pw)


def _set_system_password(user, new_password):
    """Sets the REAL login password. Returns True when it was changed, or when no Linux account
    of that name exists (API-only user). The password goes in as a ready-made hash (chpasswd -e),
    which skips PAM's password-history / quality rules, so going back to an old password works.
    Falls back to a plain chpasswd if openssl is not available."""
    if not _USER_RE.match(user):
        return True
    if subprocess.run(["id", "-u", user], capture_output=True, timeout=5).returncode != 0:
        return True
    try:
        h = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=new_password + "\\n",
                           capture_output=True, text=True, timeout=10)
        hashed = h.stdout.strip()
        if h.returncode == 0 and hashed.startswith("$"):
            r = subprocess.run(["chpasswd", "-e"], input="%s:%s\\n" % (user, hashed),
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                return True
    except Exception:
        pass
    r = subprocess.run(["chpasswd"], input="%s:%s\\n" % (user, new_password),
                       capture_output=True, text=True, timeout=10)
    return r.returncode == 0


def _update_password_store(user, new_password):
    """Keeps the panel's saved-passwords list (SSH users menu) in step; best effort."""
    try:
        if os.path.exists(PASSWORD_STORE):
            with open(PASSWORD_STORE) as f:
                data = json.load(f)
            if user in data:
                data[user] = new_password
                tmp = PASSWORD_STORE + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(data, f, indent=2)
                os.chmod(tmp, 0o600)
                os.replace(tmp, PASSWORD_STORE)
    except Exception:
        pass


def _change_password(user, new_password):
    """Real login first (so nothing is reported as changed when it was not), then the API record.
    Expiry, device limit and every other stored field are kept; there is no password history."""
    with _db_lock:
        users = _load_users()
        record = users.get(user)
        if not record:
            return False
        if not _set_system_password(user, new_password):
            return False
        salt = secrets.token_hex(16)
        record["salt"] = salt
        record["hash"] = _hash_password(new_password, salt)
        tmp = DB_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(users, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, DB_PATH)
        _update_password_store(user, new_password)
        return True


def _fmt_bytes(n):
    """1536000000 -> "1.43GB". Used for the data-quota fields the app shows on the account screen."""
    try:
        n = float(n)
    except Exception:
        return "0MB"
    gb = n / (1024.0 ** 3)
    if gb >= 1:
        return "%.2fGB" % gb
    mb = n / (1024.0 ** 2)
    return "%.0fMB" % mb


def _device_counts():
    """{username: number of live SSH/Dropbear sessions}. One ps call, cached
    for 3 seconds so a burst of app refreshes never spawns a burst of ps."""
    now = time.time()
    if now - _dev_cache["t"] < 3:
        return _dev_cache["counts"]
    counts = {}
    try:
        out = subprocess.run(["ps", "-eo", "user:32=,comm="], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[1].strip() in ("sshd", "dropbear") and parts[0] != "root":
                counts[parts[0]] = counts.get(parts[0], 0) + 1
    except Exception:
        pass
    _dev_cache["t"] = now
    _dev_cache["counts"] = counts
    return counts


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

        action = params.get("action", [""])[0]
        if action == "passwd":
            new_pw = params.get("new", [""])[0]
            if not _valid_new_password(new_pw):
                body = json.dumps({"ok": False, "error": "invalid_password"}).encode()
                code = 400
            elif _change_password(user, new_pw):
                body = json.dumps({"ok": True}).encode()
                code = 200
            else:
                body = json.dumps({"ok": False, "error": "failed"}).encode()
                code = 500
            self.send_response(code)
            self.send_header("Content-type", "application/json")
            self.send_header("Content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # "expiry" stays exactly as before (old client builds read only that).
        # The extra fields feed the app's My Account screen.
        info = {
            "expiry": str(days_remaining),
            "expiry_date": record["expiry"],
            "status": "active" if days_remaining >= 0 else "expired",
            "devices": _device_counts().get(user, 0),
        }
        if record.get("limit"):
            info["device_limit"] = record["limit"]

        # Data quota / usage. quota_bytes is set either by this module's own admin menu (option 3 > 5)
        # or, if absent here, inherited from ssh_user_manager.py's registry (a user set up with a
        # quota through SSH Users > Add User instead). The usage figures themselves are kept current
        # by a separate cron job (checkuser-usage-tracker.py), not computed here - this handler stays
        # a fast, read-only lookup. No quota_bytes from either source means unlimited, matching how
        # "limit" (device limit) already works above.
        quota_bytes = record.get("quota_bytes") or _ssh_registry_quota_bytes(user)
        used_today = record.get("usage_day_bytes", 0) or 0
        used_month = record.get("usage_month_bytes", 0) or 0
        info["data_used_today"] = _fmt_bytes(used_today)
        info["data_used_month"] = _fmt_bytes(used_month)
        if quota_bytes:
            info["data_limit"] = _fmt_bytes(quota_bytes)
            info["data_left"] = _fmt_bytes(max(0, quota_bytes - used_month))
        else:
            info["data_limit"] = "Unlimited"
            info["data_left"] = "Unlimited"
        body = json.dumps(info).encode()
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


def _fmt_bytes(n):
    """Module-level twin of the formatter embedded in API_SCRIPT - duplicated on purpose, since
    this one runs in the panel's own process (List Users) and that one runs inside the deployed,
    standalone API script subprocess; they can't share a Python import between them."""
    try:
        n = float(n)
    except Exception:
        return "0MB"
    gb = n / (1024.0 ** 3)
    if gb >= 1:
        return "%.2fGB" % gb
    return "%.0fMB" % (n / (1024.0 ** 2))


def _ssh_registry_quota_bytes(username):
    """Module-level twin of the one embedded in API_SCRIPT (separate process, can't share an
    import) - read-only lookup of a quota set via SSH Users > Add User instead of this menu."""
    try:
        with open(SSH_REGISTRY_PATH) as f:
            reg = json.load(f)
        rec = reg.get(username) or {}
        if rec.get("quota_enabled") and rec.get("quota_bytes"):
            return rec["quota_bytes"]
    except Exception:
        pass
    return None


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
    old = users.get(username) or {}
    users[username] = {
        "salt": salt,
        "hash": _hash_password(password, salt),
        "expiry": expiry_date_str,
    }
    if old.get("limit"):
        users[username]["limit"] = old["limit"]
    # Carry the data-quota plan and whatever the usage tracker has already counted across a
    # re-add/update - re-running this (e.g. on renewal) must not reset a user's quota or make
    # their usage-so-far disappear.
    for k in ("quota_bytes", "usage_day", "usage_day_bytes", "usage_month", "usage_month_bytes",
              "acct_last_total_bytes"):
        if k in old:
            users[username][k] = old[k]
    _save_users(users)


GB = 1024 ** 3
DATA_QUOTA_PRESETS = {"1": ("50GB", 50 * GB), "2": ("100GB", 100 * GB), "3": ("200GB", 200 * GB), "4": ("Unlimited", None)}
# Deliberately the SAME chain name ssh_user_manager.py uses (QUOTA_CHAIN_PREFIX there). A user added
# through SSH Users > Add User already gets an sshquota_<user> chain and an enforcer that locks the
# account on overage; this module reuses that exact chain instead of creating a second one next to
# it, so there is only ever one set of byte counters per user. This module only ever CREATES the
# chain (idempotent) or READS it - it never deletes it, because tearing the account down is
# ssh_user_manager's responsibility (it owns the "does this user still have an SSH account" lifecycle,
# and removing a user only from the CheckUser side should not rip out counters it still depends on).
ACCT_CHAIN_PREFIX = "sshquota_"
SSH_REGISTRY_PATH = "/etc/ssh_users/registry.json"
USAGE_TRACKER_SCRIPT_PATH = "/usr/local/bin/checkuser-usage-tracker.py"
USAGE_TRACKER_CRON_PATH = "/etc/cron.d/checkuser-usage-tracker"

USAGE_TRACKER_SCRIPT = '''#!/usr/bin/env python3
"""Run every 5 minutes via cron. Reads how many bytes each quota-having CheckUser API user has sent
since the last run, and rolls that into today's and this month's running totals in users.json.

Reads from sshquota_<user> - the SAME iptables accounting chain ssh_user_manager.py's own enforcer
already creates and meters - rather than a second chain of its own, so a user who already has a
quota from the SSH Users > Add User flow is not double-counted by two independent sets of counters.
This script only ever creates that chain if it is somehow missing (idempotent) or reads it; it never
deletes it, since tearing an account's accounting down belongs to ssh_user_manager, not here.

A user's quota_bytes can come from either place: set directly on this module's own users.json record
(via the panel's "Set / clear a user's data quota" option), or inherited from ssh_user_manager's own
registry.json when that user was set up there instead - checked here so a user created through EITHER
flow shows correct numbers on the app's account screen. The API script only reads what this tracker
already computed - it never talks to iptables itself, so a normal account lookup stays fast."""
import json
import os
import subprocess
from datetime import datetime

USERS_DB_PATH = "/etc/checkuser-api/users.json"
SSH_REGISTRY_PATH = "/etc/ssh_users/registry.json"
ACCT_CHAIN_PREFIX = "sshquota_"


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def ensure_chain(user, uid):
    chain = ACCT_CHAIN_PREFIX + user
    run(["iptables", "-N", chain])
    check = run(["iptables", "-C", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-j", chain])
    if check.returncode != 0:
        run(["iptables", "-I", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-j", chain])
    check2 = run(["iptables", "-C", chain, "-j", "RETURN"])
    if check2.returncode != 0:
        run(["iptables", "-A", chain, "-j", "RETURN"])


def read_total_bytes(user):
    chain = ACCT_CHAIN_PREFIX + user
    res = run(["iptables", "-L", chain, "-v", "-x", "-n"])
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            return int(parts[1])
    return 0


def load_ssh_registry():
    try:
        with open(SSH_REGISTRY_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def effective_quota_bytes(username, record, ssh_registry):
    """This module's own setting wins if present; otherwise fall back to what ssh_user_manager has
    for the same username, so a quota set there is still tracked and shown even if nobody ever
    opens this module's own quota menu for that user."""
    own = record.get("quota_bytes")
    if own:
        return own
    ssh_rec = ssh_registry.get(username) or {}
    if ssh_rec.get("quota_enabled") and ssh_rec.get("quota_bytes"):
        return ssh_rec["quota_bytes"]
    return None


def main():
    try:
        with open(USERS_DB_PATH) as f:
            users = json.load(f)
    except Exception:
        return

    ssh_registry = load_ssh_registry()
    today = datetime.now().strftime("%Y-%m-%d")
    this_month = datetime.now().strftime("%Y-%m")
    changed = False

    for username, record in users.items():
        quota_bytes = effective_quota_bytes(username, record, ssh_registry)
        if not quota_bytes:
            continue  # unlimited users are not tracked - nothing to show
        uid_res = run(["id", "-u", username])
        if uid_res.returncode != 0:
            continue  # API-only user, no system account to meter
        uid = uid_res.stdout.strip()

        ensure_chain(username, uid)
        total = read_total_bytes(username)
        last_total = record.get("acct_last_total_bytes", total)
        # A smaller total than last time means the counter was reset elsewhere (ssh_user_manager's
        # own "RESET DATA QUOTA COUNTER", a reboot, a manual iptables flush) - treat the new total
        # as the delta rather than going negative.
        delta = total - last_total if total >= last_total else total

        if record.get("usage_day") != today:
            record["usage_day"] = today
            record["usage_day_bytes"] = 0
        if record.get("usage_month") != this_month:
            record["usage_month"] = this_month
            record["usage_month_bytes"] = 0

        record["usage_day_bytes"] = record.get("usage_day_bytes", 0) + max(0, delta)
        record["usage_month_bytes"] = record.get("usage_month_bytes", 0) + max(0, delta)
        record["acct_last_total_bytes"] = total
        changed = True

    if changed:
        tmp = USERS_DB_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(users, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, USERS_DB_PATH)


if __name__ == "__main__":
    main()
'''


def _ensure_usage_tracker_deployed():
    """Prefers ssh_user_manager.py's own enforcer when that module is installed - it already polls
    the same sshquota_<user> chain every 5 minutes for connection-limit/quota-lock enforcement, and
    (as of this version) also rolls CheckUser users' day/month usage into this module's users.json
    in that same pass. Deploying this module's own separate tracker+cron on top of that would mean
    two cron jobs reading the same counter every 5 minutes for no benefit - so that only happens as
    a fallback, for a server that has CheckUser API installed without ssh_user_manager.py at all."""
    try:
        from ssh_user_manager import _ensure_enforcer_deployed as _ssh_ensure_enforcer_deployed
        return _ssh_ensure_enforcer_deployed()
    except ImportError:
        pass

    os.makedirs(API_DIR, exist_ok=True)
    needs_write = True
    if os.path.exists(USAGE_TRACKER_SCRIPT_PATH):
        with open(USAGE_TRACKER_SCRIPT_PATH) as f:
            needs_write = f.read() != USAGE_TRACKER_SCRIPT
    if needs_write:
        with open(USAGE_TRACKER_SCRIPT_PATH, "w") as f:
            f.write(USAGE_TRACKER_SCRIPT)
        os.chmod(USAGE_TRACKER_SCRIPT_PATH, 0o755)
        check = _run(["python3", "-m", "py_compile", USAGE_TRACKER_SCRIPT_PATH])
        if check.returncode != 0:
            os.remove(USAGE_TRACKER_SCRIPT_PATH)
            return False
    if not os.path.exists(USAGE_TRACKER_CRON_PATH):
        with open(USAGE_TRACKER_CRON_PATH, "w") as f:
            f.write("*/5 * * * * root /usr/bin/python3 %s\n" % USAGE_TRACKER_SCRIPT_PATH)
        os.chmod(USAGE_TRACKER_CRON_PATH, 0o644)
    return True


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
    # Keep the RUNNING script in step with this file. Before, the script on disk was only rewritten by
    # the install wizard (option 2) and the service was never restarted, so an old copy kept running
    # and ignored the password-change request. Runs every time this menu opens.
    if os.path.exists(SERVICE_PATH):
        before = None
        if os.path.exists(API_SCRIPT_PATH):
            with open(API_SCRIPT_PATH, "r") as f:
                before = f.read()
        if before != API_SCRIPT:
            if _ensure_script_deployed():
                _restart_api()
                print("%s[OK] CheckUser API script updated and restarted.%s" % (C_GREEN, C_RESET))
                time.sleep(1)
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
            print(" [4] Set / clear a user's device limit (shown in the app)")
            print(" [5] Set / clear a user's data quota (shown in the app)")
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
                        lim = rec.get("limit")
                        q = rec.get("quota_bytes")
                        if q:
                            quota_str = "  data %s/%s" % (_fmt_bytes(rec.get("usage_month_bytes", 0)), _fmt_bytes(q))
                        else:
                            quota_str = ""
                        print(" %-20s expires %s  (%s%s days%s)%s%s" % (uname, rec['expiry'], color, days_left, C_RESET,
                                                               ("  limit %s devices" % lim) if lim else "", quota_str))
            elif sub == '4':
                username = input(" Username: ").strip()
                users = _load_users()
                if username not in users:
                    print("%s[X] No such user.%s" % (C_RED, C_RESET))
                else:
                    lim_raw = input(" Max devices (blank or 0 to clear): ").strip()
                    if lim_raw.isdigit() and int(lim_raw) > 0:
                        users[username]["limit"] = int(lim_raw)
                        print("%s[OK] Limit for '%s' set to %s device(s) (display only).%s" % (C_GREEN, username, lim_raw, C_RESET))
                    else:
                        users[username].pop("limit", None)
                        print("%s[OK] Limit cleared for '%s'.%s" % (C_GREEN, username, C_RESET))
                    _save_users(users)
            elif sub == '5':
                username = input(" Username: ").strip()
                users = _load_users()
                if username not in users:
                    print("%s[X] No such user.%s" % (C_RED, C_RESET))
                else:
                    ssh_q = _ssh_registry_quota_bytes(username)
                    if ssh_q:
                        print("%s[i] '%s' already has a %s/month quota set from SSH Users > Add User." % (
                            C_CYAN, username, _fmt_bytes(ssh_q)))
                        print("    Setting one here as well adds a SEPARATE number shown on the app's" )
                        print("    account screen - it does not change or replace the SSH-side quota," )
                        print("    which is what actually locks the account on overage.%s" % C_RESET)
                    print("\n Select data quota:")
                    print("  [1] 50GB   [2] 100GB   [3] 200GB   [4] Unlimited   [5] Custom (GB)")
                    q_choice = input(" Choice [1-5]: ").strip()
                    quota_bytes = None
                    quota_label = "Unlimited"
                    if q_choice in DATA_QUOTA_PRESETS:
                        quota_label, quota_bytes = DATA_QUOTA_PRESETS[q_choice]
                    elif q_choice == '5':
                        custom_raw = input(" Custom quota in GB: ").strip()
                        if custom_raw.replace('.', '', 1).isdigit():
                            quota_bytes = int(float(custom_raw) * GB)
                            quota_label = "%sGB" % custom_raw
                        else:
                            print("%s[!] Invalid value - defaulting to unlimited.%s" % (C_YELLOW, C_RESET))
                    else:
                        print("%s[!] Invalid choice - defaulting to unlimited.%s" % (C_YELLOW, C_RESET))

                    if quota_bytes:
                        if _run(["id", "-u", username]).returncode != 0:
                            print("%s[X] '%s' has no system (SSH) login, so usage cannot be metered - " % (C_RED, username))
                            print("    a quota needs a real account to count traffic against.%s" % C_RESET)
                        else:
                            users[username]["quota_bytes"] = quota_bytes
                            _save_users(users)
                            if _ensure_usage_tracker_deployed():
                                print("%s[OK] '%s' set to %s/month. Usage tracker installed (updates every 5 min).%s" % (
                                    C_GREEN, username, quota_label, C_RESET))
                            else:
                                print("%s[!] Quota saved, but the usage tracker failed to deploy - check for a syntax error.%s" % (C_YELLOW, C_RESET))
                    else:
                        users[username].pop("quota_bytes", None)
                        _save_users(users)
                        if _ssh_registry_quota_bytes(username):
                            print("%s[OK] Cleared here. The app will now show the %s/month quota from" % (C_GREEN, _fmt_bytes(_ssh_registry_quota_bytes(username))))
                            print("    SSH Users > Add User instead (it was never removed).%s" % C_RESET)
                        else:
                            print("%s[OK] '%s' is now unlimited.%s" % (C_GREEN, username, C_RESET))
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