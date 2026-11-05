"""
ssh_user_manager.py - Unified SSH/master user management for the SmartUI
panel.

Three separate implementations of "manage SSH users" existed in the original
source:
  - ssh_user_admin_manager: a complete implementation, with real bugs (below).
  - master_user_and_auth_manager: an abandoned stub - only 4 of 15 menu
    options had actual code; the rest were literally a comment reading
    "Note: Implement remaining using patterns from previous module."
  - ssh_user_and_auth_manager: a near-line-for-line duplicate of
    ssh_user_admin_manager, plus an HWID/Token submenu that duplicates (and
    conflicts with - same files, different and less secure implementation)
    atken_hash_manager.py already built earlier in this panel.
Consolidated into this one module. The stub was discarded outright (nothing
salvageable), and HWID/Token management was NOT rebuilt a third time here -
that already exists correctly in atken_hash_manager.py.

Real bugs found in the surviving logic:

1. "ACCOUNT LIMITER" printed "[OK] Concurrent login limit set" but had no PAM
   hook, no limits.conf edit, nothing that would ever enforce it - a
   completely fabricated feature. Since real enforcement was explicitly
   requested for the new Add User flow, this is now a genuine mechanism: a
   deployed enforcer script (cron, every 5 minutes) that counts each user's
   active "sshd: user@pts/N" sessions and kills the newest ones beyond their
   configured limit.

2. "DELETE EXPIRED USERS" checked the wrong shadow field entirely:
   awk -F: '$2 ~ /^!/ {print $1}' /etc/shadow matches accounts whose
   password hash is LOCKED (starts with "!"), not accounts whose chage
   EXPIRE date has passed - a real, dangerous correctness bug that could
   delete locked-but-not-expired accounts while never touching genuinely
   expired ones. Fixed to check the actual expiration date via chage -l.

3. User-management commands were built via os.system(f"...") string
   interpolation with no username/password validation - a real command-
   injection risk. Moved to subprocess with argument lists throughout, plus
   an actual username validation pattern before any of it touches a shell.

New: real data-quota enforcement (not requested of the original, added here
per the new Add User design). Uses the standard per-UID iptables accounting
technique: a dedicated chain per quota-enabled user, jumped into from OUTPUT
by UID via the owner match module, with its packet/byte counters read
periodically by the same enforcer script. Worth being honest about a real
limitation: owner-match accounting only reliably attributes OUTBOUND traffic
to a process's UID (the standard, "good enough" approach broadly used in
this ecosystem) - it is not perfectly bidirectional byte-accurate the way a
dedicated traffic-shaping proxy would be.

New: linking a user to OpenVPN and/or the CheckUser API, by calling directly
into the create_client()/_add_or_update_user() functions already built in
openvpn_manager.py and checkuser_api_manager.py, rather than re-implementing
either.

UPDATED: the deployed enforcer script now ALSO rolls per-day/per-month data
usage into CheckUser API's users.json (when that module is installed), using
the SAME sshquota_<user> chain and counters it already reads here for
connection-limit/quota-lock enforcement - one read per user per tick, not
two. This replaced a second, independent cron job checkuser_api_manager.py
used to deploy on its own, which read the same chain a second time for the
same purpose (harmless, but a redundant poll every 5 minutes). CheckUser API
now defers to this module's enforcer when it is installed, and only falls
back to deploying its own standalone tracker if this module isn't present.
"""

import os
import re
import json
import time
import shlex
from datetime import datetime, timedelta
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, run_cmd as _run,
)

REGISTRY_DIR = "/etc/ssh_users"
REGISTRY_PATH = "%s/registry.json" % REGISTRY_DIR
PASSWORD_STORE_PATH = "%s/plaintext_passwords.json" % REGISTRY_DIR
ENFORCER_SCRIPT_PATH = "/usr/local/bin/ssh-user-enforcer.py"
CRON_PATH = "/etc/cron.d/ssh-user-enforcer"
QUOTA_CHAIN_PREFIX = "sshquota_"

GB = 1024 ** 3
QUOTA_PRESETS = {"1": ("50GB", 50 * GB), "2": ("100GB", 100 * GB), "3": ("Unlimited", None)}

USERNAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]{2,31}$')

ENFORCER_SCRIPT = '''#!/usr/bin/env python3
"""SSH user enforcer - run periodically via cron. Kills excess concurrent
sessions beyond each user's configured limit, locks any user who has
exceeded their data quota (tracked via per-UID iptables byte counters), and
rolls per-day/per-month usage into CheckUser API's own users.json (when that
module is installed) for the SAME users and the SAME iptables chain - so
there is only one poller reading this counter, not two."""
import json
import os
import subprocess
from datetime import datetime

REGISTRY_PATH = "/etc/ssh_users/registry.json"
QUOTA_CHAIN_PREFIX = "sshquota_"
CHECKUSER_DB_PATH = "/etc/checkuser-api/users.json"


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def load_registry():
    try:
        with open(REGISTRY_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_registry(data):
    with open(REGISTRY_PATH, "w") as f:
        json.dump(data, f, indent=2)


def active_session_pids(username):
    res = run(["ps", "-eo", "pid,cmd", "--sort=start_time"])
    pids = []
    markers = ("sshd: %s@" % username, "sshd-session: %s@" % username)
    for line in res.stdout.splitlines():
        if any(m in line for m in markers):
            pid = line.strip().split(None, 1)[0]
            if pid.isdigit():
                pids.append(pid)
    return pids


def enforce_connection_limit(username, max_connections):
    pids = active_session_pids(username)
    if len(pids) > max_connections:
        for pid in pids[max_connections:]:
            run(["kill", "-9", pid])


def ensure_quota_chain(username, uid):
    """Only needed for a user whose quota lives purely in CheckUser API's own users.json (set via
    its own "data quota" menu, with no entry in THIS module's registry.json) - such a user never
    went through add_user() here, so nothing has created their chain yet."""
    chain = QUOTA_CHAIN_PREFIX + username
    run(["iptables", "-N", chain])
    check = run(["iptables", "-C", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-j", chain])
    if check.returncode != 0:
        run(["iptables", "-I", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-j", chain])
    check2 = run(["iptables", "-C", chain, "-j", "RETURN"])
    if check2.returncode != 0:
        run(["iptables", "-A", chain, "-j", "RETURN"])


def read_quota_bytes_used(username):
    chain = QUOTA_CHAIN_PREFIX + username
    res = run(["iptables", "-L", chain, "-v", "-x", "-n"])
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
            return int(parts[1])
    return 0


def kill_all_sessions(username):
    for pid in active_session_pids(username):
        run(["kill", "-9", pid])


def sync_checkuser_usage(registry, already_read_totals):
    """Rolls per-day/per-month usage into CheckUser API's users.json, for every CheckUser user who
    has a quota (either set directly there, or inherited from THIS module's registry). Reuses the
    byte totals already read above for a user THIS module also tracks (already_read_totals), so a
    user with both an SSH registry entry and a CheckUser link is read from iptables once per tick,
    not twice. CheckUser API not being installed (no users.json yet) is normal and silently skipped."""
    try:
        with open(CHECKUSER_DB_PATH) as f:
            cu_users = json.load(f)
    except Exception:
        return  # CheckUser API module isn't installed on this server - nothing to do

    today = datetime.now().strftime("%Y-%m-%d")
    this_month = datetime.now().strftime("%Y-%m")
    changed = False

    for username, record in cu_users.items():
        quota_bytes = record.get("quota_bytes")
        if not quota_bytes:
            ssh_rec = registry.get(username) or {}
            if ssh_rec.get("quota_enabled") and ssh_rec.get("quota_bytes"):
                quota_bytes = ssh_rec["quota_bytes"]
        if not quota_bytes:
            continue  # unlimited - nothing to show

        if username in already_read_totals:
            total = already_read_totals[username]
        else:
            uid_res = run(["id", "-u", username])
            if uid_res.returncode != 0:
                continue  # API-only user, no system account to meter
            uid = uid_res.stdout.strip()
            ensure_quota_chain(username, uid)
            total = read_quota_bytes_used(username)

        last_total = record.get("acct_last_total_bytes", total)
        # A smaller total than last time means the counter was reset elsewhere (this module's own
        # "RESET DATA QUOTA COUNTER", a reboot, a manual iptables flush) - treat the new total as
        # the delta rather than going negative.
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
        tmp = CHECKUSER_DB_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cu_users, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CHECKUSER_DB_PATH)


def main():
    registry = load_registry()
    changed = False
    read_totals = {}  # username -> total bytes, shared with sync_checkuser_usage() below

    for username, record in registry.items():
        max_conn = record.get("max_connections")
        if max_conn:
            enforce_connection_limit(username, max_conn)

        if record.get("quota_enabled") and record.get("quota_bytes"):
            used = read_quota_bytes_used(username)
            read_totals[username] = used
            if used != record.get("quota_used_bytes"):
                record["quota_used_bytes"] = used
                changed = True
            if used >= record["quota_bytes"] and not record.get("locked"):
                run(["usermod", "-L", username])
                kill_all_sessions(username)
                record["locked"] = True
                record["locked_reason"] = "quota_exceeded"
                changed = True

        expiry = record.get("expiry")
        if expiry:
            try:
                from datetime import datetime
                if datetime.strptime(expiry, "%Y-%m-%d") < datetime.now() and not record.get("locked"):
                    kill_all_sessions(username)
            except ValueError:
                pass

    if changed:
        save_registry(registry)

    sync_checkuser_usage(registry, read_totals)


if __name__ == "__main__":
    main()
'''


def _load_registry():
    if not os.path.exists(REGISTRY_PATH):
        return {}
    with open(REGISTRY_PATH) as f:
        return json.load(f)


def _save_registry(data):
    os.makedirs(REGISTRY_DIR, exist_ok=True)
    with open(REGISTRY_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(REGISTRY_PATH, 0o600)


def _load_password_store():
    """Plaintext password storage, kept only because listing accounts with
    their passwords was explicitly requested after being told what it costs:
    real Linux account passwords are one-way hashed in /etc/shadow (nobody,
    not even root, can reverse that), and the panel's own registry never
    stored them either since login never needed to read them back. This is a
    genuine security tradeoff, not a neutral convenience - this file is a
    single point of failure containing every customer's password in
    cleartext, unlike individual system hashes which each require separately
    cracking. Kept permission-locked to 0600 and cleaned up automatically
    everywhere a user is removed, but the tradeoff itself doesn't go away."""
    if not os.path.exists(PASSWORD_STORE_PATH):
        return {}
    with open(PASSWORD_STORE_PATH) as f:
        return json.load(f)


def _save_password_store(data):
    os.makedirs(REGISTRY_DIR, exist_ok=True)
    with open(PASSWORD_STORE_PATH, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(PASSWORD_STORE_PATH, 0o600)


def _valid_username(username):
    return bool(USERNAME_PATTERN.match(username))


def _user_exists(username):
    return _run(["id", username]).returncode == 0


# ---------------------------------------------------------------------------
# ONLINE SESSION DETECTION
#
# Why "who" always said 0: `who` only lists logins that own a terminal (a pty
# recorded in utmp). Tunnel customers (HTTP Custom, HTTP Injector, SSH -N,
# anything on a nologin account) never get a terminal, so they never appear -
# only the admin's own shell does. Real sessions are found from the
# processes instead:
#   * OpenSSH: one process per connection titled "sshd: user@pts/0" or
#     "sshd: user@notty". OpenSSH 9.8+ (Ubuntu 25/26) renamed it to
#     "sshd-session: user@notty" - the old marker never matched there.
#   * Dropbear: one forked "dropbear" process per connection that does NOT
#     carry the username, so the username/source IP come from Dropbear's own
#     "auth succeeded for 'user' from ip:port" log line for that PID.
# ---------------------------------------------------------------------------

_SSHD_TITLE = re.compile(r'^(?:sshd|sshd-session): ([^\s@\[]+)@(\S+)')
_DB_AUTH = re.compile(r"auth succeeded for '([^']+)'")
_DB_FROM = re.compile(r"from (\S+?)(?::\d+)?\s*$")
_DB_EXIT = re.compile(r"\bExit\b")
_DB_LINE_SYSLOG = re.compile(r'dropbear\[(\d+)\]: (.*)$')
_DB_LINE_STDERR = re.compile(r'\[(\d+)\] [A-Za-z]{3} +\d+ [\d:]+ (.*)$')
_DROPBEAR_CACHE = {}  # pid -> (username, source_ip); a pid never changes owner


def _ps_table():
    """[(pid, etimes_seconds, user, args)] for every process."""
    res = _run(["ps", "-eo", "pid=,etimes=,user:32=,args="])
    rows = []
    for line in (res.stdout or "").splitlines():
        parts = line.strip().split(None, 3)
        if len(parts) == 4 and parts[0].isdigit() and parts[1].isdigit():
            rows.append((int(parts[0]), int(parts[1]), parts[2], parts[3]))
    return rows


def _ss_peers():
    """{pid: peer_ip} for established TCP connections, from `ss -tnp`."""
    res = _run(["ss", "-H", "-tnp", "state", "established"])
    peers = {}
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        peer = parts[3].rsplit(":", 1)[0].strip("[]")
        if peer.startswith("::ffff:"):
            peer = peer[7:]
        for pid in re.findall(r'pid=(\d+)', line):
            peers.setdefault(int(pid), peer)
    return peers


def _dropbear_log_lines(since):
    res = _run(["journalctl", "--no-pager", "-o", "short", "--since", since, "-u", "dropbear", "-u", "dropbear.service"])
    out = res.stdout or ""
    res2 = _run(["journalctl", "--no-pager", "-o", "short", "--since", since, "-t", "dropbear"])
    out += "\n" + (res2.stdout or "")
    if not out.strip():
        for path in ("/var/log/auth.log", "/var/log/syslog"):
            if os.path.exists(path):
                out += "\n" + (_run(["grep", "-a", "dropbear", path]).stdout or "")
    return out.splitlines()


def _resolve_dropbear(pids):
    """Fills _DROPBEAR_CACHE for the given live dropbear pids from its log.
    Looks back 1 day first (cheap), then 14 days for long-lived tunnels."""
    for since in ("-1 day", "-14 days"):
        wanted = [p for p in pids if p not in _DROPBEAR_CACHE]
        if not wanted:
            return
        state = {}
        for line in _dropbear_log_lines(since):
            m = _DB_LINE_SYSLOG.search(line)
            if m:
                pid, msg = int(m.group(1)), m.group(2)
                # "-E" (stderr) mode: the journal header carries the MAIN
                # dropbear pid, the real per-connection pid is inside the
                # message as "[pid] Mon dd hh:mm:ss text".
                inner = _DB_LINE_STDERR.match(msg)
                if inner:
                    pid, msg = int(inner.group(1)), inner.group(2)
            else:
                m = _DB_LINE_STDERR.search(line)
                if not m:
                    continue
                pid, msg = int(m.group(1)), m.group(2)
            if pid not in wanted:
                continue
            am = _DB_AUTH.search(msg)
            if am:
                fm = _DB_FROM.search(msg)
                state[pid] = (am.group(1), fm.group(1).strip("[]") if fm else "?")
            elif _DB_EXIT.search(msg) and pid in state:
                state.pop(pid, None)
        _DROPBEAR_CACHE.update(state)


def get_online_sessions():
    """Every authenticated SSH/Dropbear connection right now:
    [{"username","source","kind","pid","age"}], one entry per connection.
    Counts tunnel (no-terminal) logins, which `who` can never see."""
    rows = _ps_table()
    peers = _ss_peers()
    sessions = []
    for pid, age, user, args in rows:
        m = _SSHD_TITLE.match(args)
        if m:
            sessions.append({"username": m.group(1), "source": peers.get(pid),
                             "kind": "OpenSSH", "pid": pid, "age": age, "tty": m.group(2)})
    db_rows = [(pid, age, user) for pid, age, user, args in rows
               if args.split(None, 1)[0].rsplit("/", 1)[-1] == "dropbear"]
    live = {pid for pid, _, _ in db_rows}
    for stale in [p for p in _DROPBEAR_CACHE if p not in live]:
        _DROPBEAR_CACHE.pop(stale, None)
    if db_rows:
        _resolve_dropbear([pid for pid, _, _ in db_rows])
    for pid, age, user in db_rows:
        info = _DROPBEAR_CACHE.get(pid)
        if info:
            sessions.append({"username": info[0], "source": info[1], "kind": "Dropbear",
                             "pid": pid, "age": age, "tty": "-"})
        elif user not in ("root", "") and _user_exists(user):
            # this dropbear build runs the connection as the user itself
            sessions.append({"username": user, "source": peers.get(pid), "kind": "Dropbear",
                             "pid": pid, "age": age, "tty": "-"})
    return sessions


def count_online(registered_users=None):
    """(sessions, distinct_users) - optionally limited to panel customers."""
    sessions = get_online_sessions()
    if registered_users is not None:
        sessions = [s for s in sessions if s["username"] in registered_users]
    return len(sessions), len({s["username"] for s in sessions})


def _active_session_pids(username):
    """PIDs of this user's live connections (OpenSSH and Dropbear) - used to
    kill sessions on lock/remove/expire."""
    return [str(s["pid"]) for s in get_online_sessions() if s["username"] == username]


def _fmt_age(seconds):
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return "%dh %02dm" % (h, m) if h else "%dm %02ds" % (m, s)


def _parse_who_sessions():
    """Kept under its old name so the callers below keep working, but now
    backed by real process detection instead of `who` (see above)."""
    return [{"username": s["username"], "tty": s["tty"], "login_time": _fmt_age(s["age"]) + " ago",
             "source": s["source"], "kind": s["kind"]} for s in get_online_sessions()]


def _detect_shared_accounts(sessions, registered_users):
    """Flags a registered user as possibly sharing their login when their
    CURRENTLY ACTIVE sessions come from more than one distinct source IP at
    once - a strong signal the same credentials are in use on multiple
    devices/locations simultaneously."""
    ips_by_user = {}
    for s in sessions:
        if s["username"] in registered_users and s["source"]:
            ips_by_user.setdefault(s["username"], set()).add(s["source"])
    return {u: ips for u, ips in ips_by_user.items() if len(ips) > 1}


def _ensure_quota_chain(username):
    uid_res = _run(["id", "-u", username])
    if uid_res.returncode != 0:
        return False
    uid = uid_res.stdout.strip()
    chain = QUOTA_CHAIN_PREFIX + username

    _run(["iptables", "-N", chain])

    check = _run(["iptables", "-C", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-j", chain])
    if check.returncode != 0:
        _run(["iptables", "-I", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-j", chain])

    check2 = _run(["iptables", "-C", chain, "-j", "RETURN"])
    if check2.returncode != 0:
        _run(["iptables", "-A", chain, "-j", "RETURN"])
    return True


def _remove_quota_chain(username):
    uid_res = _run(["id", "-u", username])
    chain = QUOTA_CHAIN_PREFIX + username
    if uid_res.returncode == 0:
        uid = uid_res.stdout.strip()
        _run(["iptables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", uid, "-j", chain])
    _run(["iptables", "-F", chain])
    _run(["iptables", "-X", chain])


def _ensure_enforcer_deployed():
    os.makedirs(REGISTRY_DIR, exist_ok=True)
    needs_write = True
    if os.path.exists(ENFORCER_SCRIPT_PATH):
        with open(ENFORCER_SCRIPT_PATH) as f:
            needs_write = f.read() != ENFORCER_SCRIPT
    if needs_write:
        with open(ENFORCER_SCRIPT_PATH, "w") as f:
            f.write(ENFORCER_SCRIPT)
        os.chmod(ENFORCER_SCRIPT_PATH, 0o755)
        check = _run(["python3", "-m", "py_compile", ENFORCER_SCRIPT_PATH])
        if check.returncode != 0:
            os.remove(ENFORCER_SCRIPT_PATH)
            return False
    if not os.path.exists(CRON_PATH):
        with open(CRON_PATH, "w") as f:
            f.write("*/5 * * * * root /usr/bin/python3 %s\n" % ENFORCER_SCRIPT_PATH)
        os.chmod(CRON_PATH, 0o644)
    return True


def _real_expiry_check(username):
    """Real fix for the original's wrong-field bug: parses chage -l's actual
    "Account expires" line, rather than checking whether the password hash
    is locked (a completely different, unrelated condition)."""
    res = _run(["chage", "-l", username])
    for line in res.stdout.splitlines():
        if line.startswith("Account expires"):
            value = line.split(":", 1)[1].strip()
            if value == "never":
                return None
            try:
                return datetime.strptime(value, "%b %d, %Y")
            except ValueError:
                return None
    return None


def add_user(ports_dict):
    clear_screen()
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("%s                       ADD NEW USER                         %s" % (C_BOLD, C_RESET))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

    username = input(" Username: ").strip()
    if not _valid_username(username):
        print("%s[X] Invalid username - use 3-32 characters, letters/numbers/hyphens/" % C_RED)
        print("    underscores, starting with a letter.%s" % C_RESET)
        input("\nPress Enter to continue...")
        return
    if _user_exists(username):
        print("%s[X] A system user named '%s' already exists.%s" % (C_RED, username, C_RESET))
        input("\nPress Enter to continue...")
        return

    password = input(" Password (blank to auto-generate a strong one): ").strip()
    if not password:
        import secrets
        password = secrets.token_urlsafe(12)
        print("%s[i] Generated password: %s%s" % (C_CYAN, password, C_RESET))

    days_raw = input(" Expiry date (days from today, e.g. 30): ").strip()
    days = int(days_raw) if days_raw.isdigit() else 30
    expiry_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

    conn_raw = input(" Number of connections allowed (blank = unlimited): ").strip()
    max_connections = int(conn_raw) if conn_raw.isdigit() else None

    quota_enabled = input(" Data quota enabled? (Y/n): ").strip().lower() != 'n'
    used_openvpn = input(" Also create a linked OpenVPN client for this user? (y/N): ").strip().lower() == 'y'
    used_checkuser = input(" Also register this user with the CheckUser expiry API? (y/N): ").strip().lower() == 'y'

    quota_bytes = None
    quota_label = "Unlimited"
    if quota_enabled:
        print("\n Select Data quota:")
        print("  [1] 50GB")
        print("  [2] 100GB")
        print("  [3] Unlimited")
        print("  [4] Custom (enter a value in GB)")
        q_choice = input(" Choice [1-4]: ").strip()
        if q_choice in QUOTA_PRESETS:
            quota_label, quota_bytes = QUOTA_PRESETS[q_choice]
        elif q_choice == '4':
            custom_raw = input(" Enter custom quota in GB: ").strip()
            if custom_raw.replace('.', '', 1).isdigit():
                quota_bytes = int(float(custom_raw) * GB)
                quota_label = "%sGB" % custom_raw
            else:
                print("%s[!] Invalid value - defaulting to unlimited.%s" % (C_YELLOW, C_RESET))
        else:
            print("%s[!] Invalid choice - defaulting to unlimited.%s" % (C_YELLOW, C_RESET))

    create_res = _run(["useradd", "-m", "-s", "/usr/sbin/nologin", username])
    if create_res.returncode != 0:
        print("%s[X] Failed to create system user: %s%s" % (C_RED, create_res.stderr.strip(), C_RESET))
        input("\nPress Enter to continue...")
        return

    # Dropbear rejects password auth entirely for any account whose shell
    # isn't listed in /etc/shells, logging "User 'X' has invalid shell,
    # rejected" - confirmed against a real case where a correctly-created
    # account with the right password still got "Permission denied
    # (publickey,password)" purely because /usr/sbin/nologin wasn't in that
    # file (Ubuntu doesn't list it there by default). Nothing to do with the
    # password itself - fixing it here, at account creation, rather than
    # only where Dropbear happens to get touched, since the account can be
    # created before Dropbear is even installed.
    try:
        shells_path = "/etc/shells"
        if os.path.exists(shells_path):
            with open(shells_path) as f:
                existing_shells = [line.strip() for line in f.read().splitlines()]
        else:
            existing_shells = []
        if "/usr/sbin/nologin" not in existing_shells:
            with open(shells_path, "a") as f:
                f.write("/usr/sbin/nologin\n")
    except Exception:
        pass

    passwd_proc = _run("echo %s | chpasswd" % shlex.quote("%s:%s" % (username, password)))
    if passwd_proc.returncode != 0:
        _run(["userdel", "-r", username])
        print("%s[X] Failed to set password - user creation rolled back.%s" % (C_RED, C_RESET))
        input("\nPress Enter to continue...")
        return

    _run(["chage", "-E", expiry_date, username])

    if quota_enabled and quota_bytes:
        _ensure_quota_chain(username)
        _ensure_enforcer_deployed()
    if max_connections:
        _ensure_enforcer_deployed()

    registry = _load_registry()
    registry[username] = {
        "expiry": expiry_date,
        "max_connections": max_connections,
        "quota_enabled": quota_enabled,
        "quota_bytes": quota_bytes,
        "quota_used_bytes": 0,
        "linked_openvpn": used_openvpn,
        "linked_checkuser": used_checkuser,
        "locked": False,
    }
    _save_registry(registry)

    password_store = _load_password_store()
    password_store[username] = password
    _save_password_store(password_store)

    print("\n%s[OK] User '%s' created (expires %s, connections: %s, quota: %s).%s" % (
        C_GREEN, username, expiry_date, max_connections or 'unlimited',
        quota_label if quota_enabled else 'disabled', C_RESET))

    if used_openvpn:
        try:
            from openvpn_manager import create_client
            ovpn_port = ports_dict.get('OPENVPN_PORT')
            ovpn_proto = ports_dict.get('OPENVPN_PROTO', 'udp')
            if not ovpn_port:
                print("%s[!] OpenVPN isn't installed/configured yet - skipped linking.%s" % (C_YELLOW, C_RESET))
            else:
                ok, result = create_client(username, ovpn_port, ovpn_proto)
                if ok:
                    print("%s[OK] Linked OpenVPN client created: %s%s" % (C_GREEN, result, C_RESET))
                else:
                    print("%s[!] OpenVPN linking failed: %s%s" % (C_YELLOW, result, C_RESET))
        except ImportError:
            print("%s[!] OpenVPN module not available - skipped linking.%s" % (C_YELLOW, C_RESET))

    if used_checkuser:
        try:
            from checkuser_api_manager import _add_or_update_user as checkuser_add
            checkuser_add(username, password, expiry_date)
            print("%s[OK] Registered with the CheckUser expiry API.%s" % (C_GREEN, C_RESET))
        except ImportError:
            print("%s[!] CheckUser API module not available - skipped linking.%s" % (C_YELLOW, C_RESET))

    print("\n%sLogin: %s / %s%s" % (C_CYAN, username, password, C_RESET))
    input("\nPress Enter to continue...")


def ssh_user_admin_manager(ports_dict):
    """Unified SSH User Administrator Module."""
    if os.path.exists(CRON_PATH):
        _ensure_enforcer_deployed()  # picks up the sshd-session marker fix
    while True:
        registry = _load_registry()
        user_count = len(registry)

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                  SSH USER ADMINISTRATOR                    %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      REGISTERED USERS: %s" % user_count)
        print("----------------------------------------------------------------")
        print(" [1]> ADD NEW USER")
        print(" [2]> LIST USERS")
        print(" [3]> RENEW / EXTEND USER")
        print(" [4]> LOCK / UNLOCK USER")
        print(" [5]> REMOVE USER (kill sessions + delete)")
        print(" [6]> RESET DATA QUOTA COUNTER")
        print(" [7]> DELETE EXPIRED USERS")
        print(" [8]> DELETE ALL USERS")
        print(" [9]> VIEW ACTIVE ONLINE USERS")
        print(" [10]> VIEW USERS WITH SHARED ACCOUNT")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            add_user(ports_dict)

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                      USER LIST                             %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not registry:
                print("%s No users registered.%s" % (C_YELLOW, C_RESET))
            else:
                password_store = _load_password_store()
                now = datetime.now()
                for uname, rec in registry.items():
                    expiry = rec.get("expiry", "N/A")
                    try:
                        days_left = (datetime.strptime(expiry, "%Y-%m-%d") - now).days
                    except ValueError:
                        days_left = "?"
                    quota_str = "unlimited"
                    if rec.get("quota_enabled") and rec.get("quota_bytes"):
                        used_gb = rec.get("quota_used_bytes", 0) / GB
                        total_gb = rec["quota_bytes"] / GB
                        quota_str = "%.2f/%.0fGB" % (used_gb, total_gb)
                    lock_tag = ("%s[LOCKED]%s" % (C_RED, C_RESET)) if rec.get("locked") else ""
                    password_display = password_store.get(uname, "(not on file)")
                    print(" %-16s pass:%-16s expires in %4s days  conns:%-4s  quota:%-16s %s" % (
                        uname, password_display, days_left, rec.get('max_connections') or '∞', quota_str, lock_tag))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            username = input(" Username to renew: ").strip()
            if username not in registry:
                print("%s[X] Not a registered user.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            days_raw = input(" Extend by how many days: ").strip()
            if not days_raw.isdigit():
                print("%s[X] Invalid number of days.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            new_expiry = (datetime.now() + timedelta(days=int(days_raw))).strftime("%Y-%m-%d")
            _run(["chage", "-E", new_expiry, username])
            registry[username]["expiry"] = new_expiry
            registry[username]["locked"] = False
            _run(["usermod", "-U", username])
            _save_registry(registry)
            if registry[username].get("linked_checkuser"):
                try:
                    from checkuser_api_manager import _load_users, _save_users
                    cu = _load_users()
                    if username in cu:
                        cu[username]["expiry"] = new_expiry
                        _save_users(cu)
                except ImportError:
                    pass
            print("%s[OK] '%s' renewed to %s and unlocked.%s" % (C_GREEN, username, new_expiry, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            username = input(" Username to lock/unlock: ").strip()
            if not _user_exists(username):
                print("%s[X] No such system user.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            status_out = _run(["passwd", "-S", username]).stdout.split()
            is_locked = len(status_out) > 1 and status_out[1] == 'L'
            if is_locked:
                _run(["usermod", "-U", username])
                if username in registry:
                    registry[username]["locked"] = False
                    _save_registry(registry)
                print("%s[OK] '%s' unlocked.%s" % (C_GREEN, username, C_RESET))
            else:
                _run(["usermod", "-L", username])
                for pid in _active_session_pids(username):
                    _run(["kill", "-9", pid])
                if username in registry:
                    registry[username]["locked"] = True
                    registry[username]["locked_reason"] = "manual"
                    _save_registry(registry)
                print("%s[!] '%s' locked and active sessions terminated.%s" % (C_YELLOW, username, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            username = input(" Username to remove: ").strip()
            if not _user_exists(username):
                print("%s[X] No such system user.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            confirm = input(" Permanently remove '%s'? (y/n): " % username).strip().lower()
            if confirm == 'y':
                for pid in _active_session_pids(username):
                    _run(["kill", "-9", pid])
                _remove_quota_chain(username)
                _run(["userdel", "-r", username])
                registry.pop(username, None)
                _save_registry(registry)
                password_store = _load_password_store()
                if password_store.pop(username, None) is not None:
                    _save_password_store(password_store)
                print("%s[OK] '%s' removed.%s" % (C_GREEN, username, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            username = input(" Username to reset quota for: ").strip()
            if username not in registry:
                print("%s[X] Not a registered user.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            _run(["iptables", "-Z", QUOTA_CHAIN_PREFIX + username])
            registry[username]["quota_used_bytes"] = 0
            if registry[username].get("locked_reason") == "quota_exceeded":
                registry[username]["locked"] = False
                _run(["usermod", "-U", username])
            _save_registry(registry)
            print("%s[OK] Quota counter reset for '%s'.%s" % (C_GREEN, username, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s               DELETE EXPIRED USERS                         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            removed = []
            for uname in list(registry.keys()):
                expiry_dt = _real_expiry_check(uname)
                if expiry_dt and expiry_dt < datetime.now():
                    for pid in _active_session_pids(uname):
                        _run(["kill", "-9", pid])
                    _remove_quota_chain(uname)
                    _run(["userdel", "-r", uname])
                    registry.pop(uname, None)
                    removed.append(uname)
            _save_registry(registry)
            if removed:
                password_store = _load_password_store()
                for uname in removed:
                    password_store.pop(uname, None)
                _save_password_store(password_store)
                print("%s[OK] Removed expired users: %s%s" % (C_GREEN, ", ".join(removed), C_RESET))
            else:
                print("%s[i] No expired users found.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            confirm = input(" Remove ALL registered users? This cannot be undone. (y/n): ").strip().lower()
            if confirm == 'y':
                for uname in list(registry.keys()):
                    for pid in _active_session_pids(uname):
                        _run(["kill", "-9", pid])
                    _remove_quota_chain(uname)
                    _run(["userdel", "-r", uname])
                registry.clear()
                _save_registry(registry)
                _save_password_store({})
                print("%s[OK] All registered users removed.%s" % (C_GREEN, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '9':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 ACTIVE ONLINE USERS                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            sessions = _parse_who_sessions()
            registered_users = set(registry.keys())
            online = [s for s in sessions if s["username"] in registered_users]
            others = len(sessions) - len(online)
            if not online:
                print("%s No registered users are currently online.%s" % (C_YELLOW, C_RESET))
            else:
                print(" %-16s %-9s %-10s %-9s %s" % ("USER", "TYPE", "ONLINE FOR", "TTY", "FROM"))
                for s in sorted(online, key=lambda x: x["username"]):
                    print(" %-16s %-9s %-10s %-9s %s" % (
                        s["username"], s["kind"], s["login_time"].replace(" ago", ""), s["tty"], s["source"] or "?"))
                users = len({s["username"] for s in online})
                print("\n Total online: %d session(s) from %d user(s)" % (len(online), users))
            if others:
                print(" (plus %d non-panel session(s), e.g. your own admin login)" % others)
            input("\nPress Enter to continue...")

        elif choice == '10':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s               USERS WITH SHARED ACCOUNT                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" Flags registered users whose currently active sessions come from")
            print(" more than one distinct source IP at the same time - a strong signal")
            print(" the same login is being used on multiple devices/locations.")
            print("----------------------------------------------------------------")
            sessions = _parse_who_sessions()
            registered_users = set(registry.keys())
            shared = _detect_shared_accounts(sessions, registered_users)
            if not shared:
                print("%s No signs of account sharing detected right now.%s" % (C_YELLOW, C_RESET))
            else:
                for uname, ips in shared.items():
                    print(" %s%-16s%s connected from %d different IPs at once:" % (C_RED, uname, C_RESET, len(ips)))
                    for ip in sorted(ips):
                        print("      - %s" % ip)
                print("\n%s[i] This is a point-in-time snapshot - re-run to catch sharing that" % C_CYAN)
                print("    only overlaps briefly. Consider setting a connection limit (option 1")
                print("    or the RENEW screen) if this keeps happening for the same user.%s" % C_RESET)
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
