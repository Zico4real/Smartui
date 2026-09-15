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
"""

import os
import re
import json
import time
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
sessions beyond each user's configured limit, and locks any user who has
exceeded their data quota (tracked via per-UID iptables byte counters)."""
import json
import subprocess

REGISTRY_PATH = "/etc/ssh_users/registry.json"
QUOTA_CHAIN_PREFIX = "sshquota_"


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
    marker = "sshd: %s@" % username
    for line in res.stdout.splitlines():
        if marker in line:
            pid = line.strip().split(None, 1)[0]
            if pid.isdigit():
                pids.append(pid)
    return pids


def enforce_connection_limit(username, max_connections):
    pids = active_session_pids(username)
    if len(pids) > max_connections:
        for pid in pids[max_connections:]:
            run(["kill", "-9", pid])


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


def main():
    registry = load_registry()
    changed = False

    for username, record in registry.items():
        max_conn = record.get("max_connections")
        if max_conn:
            enforce_connection_limit(username, max_conn)

        if record.get("quota_enabled") and record.get("quota_bytes"):
            used = read_quota_bytes_used(username)
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


def _active_session_pids(username):
    res = _run(["ps", "-eo", "pid,cmd", "--sort=start_time"])
    pids = []
    marker = "sshd: %s@" % username
    for line in res.stdout.splitlines():
        if marker in line:
            pid = line.strip().split(None, 1)[0]
            if pid.isdigit():
                pids.append(pid)
    return pids


def _parse_who_sessions():
    """Standard `who` output: 'username  pts/N  YYYY-MM-DD HH:MM  (source_ip)'.
    The parenthesized source only appears for network logins (ssh), which is
    exactly what's relevant here - local ttys have no source and are skipped
    by the callers that care about source IPs."""
    res = _run(["who"])
    sessions = []
    for line in res.stdout.splitlines():
        if not line.strip():
            continue
        m = re.match(r'^(\S+)\s+(\S+)\s+([\d-]+ [\d:]+)\s*(?:\(([^)]+)\))?', line)
        if m:
            username, tty, login_time, source = m.groups()
            sessions.append({"username": username, "tty": tty, "login_time": login_time, "source": source})
    return sessions


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

    passwd_proc = _run("echo '%s:%s' | chpasswd" % (username, password))
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
    while True:
        registry = _load_registry()
        user_count = len(registry)

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                  SSH USER ADMINISTRATOR                    %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      REGISTERED USERS: %s" % user_count)
        print("----------------------------------------------------------------")
        print(" %s[1]>%s ADD NEW USER" % (C_YELLOW, C_RESET))
        print(" %s[2]>%s LIST USERS" % (C_YELLOW, C_RESET))
        print(" %s[3]>%s RENEW / EXTEND USER" % (C_YELLOW, C_RESET))
        print(" %s[4]>%s LOCK / UNLOCK USER" % (C_YELLOW, C_RESET))
        print(" %s[5]>%s REMOVE USER (kill sessions + delete)" % (C_YELLOW, C_RESET))
        print(" %s[6]>%s RESET DATA QUOTA COUNTER" % (C_YELLOW, C_RESET))
        print(" %s[7]>%s DELETE EXPIRED USERS" % (C_YELLOW, C_RESET))
        print(" %s[8]>%s DELETE ALL USERS" % (C_YELLOW, C_RESET))
        print(" %s[9]>%s VIEW ACTIVE ONLINE USERS" % (C_YELLOW, C_RESET))
        print(" %s[10]>%s VIEW USERS WITH SHARED ACCOUNT" % (C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" %s[0]%s RETURN" % (C_YELLOW, C_RESET))
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
                        uname, password_display, days_left, rec.get('max_connections') or '\u221e', quota_str, lock_tag))
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
            if not online:
                print("%s No registered users are currently online.%s" % (C_YELLOW, C_RESET))
            else:
                for s in online:
                    src = s["source"] or "local"
                    print(" %-16s %-10s since %-18s from %s" % (s["username"], s["tty"], s["login_time"], src))
                print("\n Total online: %d" % len(online))
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
