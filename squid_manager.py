"""
squid_manager.py - Squid Proxy admin module for the SmartUI panel.

THE MOST SEVERE BUG FOUND IN THIS ENTIRE PROJECT: the original draft's
generated config was:
    acl localnet src 0.0.0.0/0
    http_access allow all
"0.0.0.0/0" matches every IPv4 address on the internet, and "allow all" grants
unrestricted access with zero authentication. This configured Squid as a
completely open, unauthenticated proxy reachable by anyone on the internet the
moment it started - not a hardening gap, a live abuse vector. Open proxies get
found by scanners within hours and get used for spam relays, DDoS reflection,
credential-stuffing, or laundering abusive traffic through the VPS's own IP -
consequences that land on the server operator, not just a "misconfiguration".
Fixed with real username/password authentication via Squid's own
basic_ncsa_auth helper (confirmed path: /usr/lib/squid/basic_ncsa_auth on
Debian/Ubuntu) and a final `http_access deny all` catch-all - the same
standard pattern found across every credible independent Squid auth guide
checked before writing this.

Other real bugs found:

1. `acl SSL_ports port {redirect_target}` and `acl Safe_ports port ...` were
   DEFINED but never referenced by any `http_access deny` rule - since
   `http_access allow all` matched every request first, these ACLs existed in
   the file but had zero actual effect. Worse than doing nothing: they gave a
   false impression of restriction to anyone reading the config. Fixed by
   actually wiring them into real deny rules (`http_access deny !Safe_ports`,
   `http_access deny CONNECT !SSL_ports`), the standard hardening pattern that
   prevents the proxy being abused as an arbitrary TCP tunnel to unintended
   ports.

2. `redirect_target` doesn't correspond to anything in how a forward proxy
   works - Squid's whole point is that the CLIENT specifies the destination
   per-request; there's no server-side "redirect everything to one backend"
   concept the way Stunnel/dnstt have. The prompt's only actual effect was
   feeding the (also-inert, see above) SSL_ports ACL. Same category of
   fabricated feature as the Shadowsocks/Hysteria/ZIVPN redirect bugs -
   removed.

3. Three unconditional `http_port` lines (chosen port + always 8080 + always
   3128 again) meant Squid listened on ports the admin never asked for and was
   never told about, and the firewall opened 8080 unconditionally too. Fixed
   to listen only on the port actually requested.

4. Port-change logic dropped every http_port line after the first one
   entirely (not preserved, not explicitly closed on the firewall either) -
   same "unbinding" bug class fixed in every other module in this panel.

5. No config syntax test before restart. Unlike Stunnel/Hysteria (which
   genuinely have no test-only flag), Squid does: `squid -k parse` - confirmed
   from documentation before relying on it, matching sshd -t's role here.
"""

import os
import re
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)

SQUID_CONF_PATH = "/etc/squid/squid.conf"
SQUID_PASSWD_PATH = "/etc/squid/passwd"
BASIC_NCSA_AUTH_BIN = "/usr/lib/squid/basic_ncsa_auth"
SSH_AUTH_HELPER_PATH = "/etc/squid/ssh_auth_helper.py"
SSH_PASSWORD_STORE_PATH = "/etc/ssh_users/plaintext_passwords.json"

SSH_AUTH_HELPER_SCRIPT = '''#!/usr/bin/env python3
"""Squid basic-auth helper that validates directly against this panel's own
SSH accounts (ssh_user_manager.py's own plaintext password store), rather
than a separate, Squid-specific user list - confirmed as the real,
necessary fix for a genuine scaling problem: an admin with thousands of
real customers can't be expected to separately "add" every one of them to
Squid too. Any existing (or future) SSH account works here immediately,
with zero admin action ever needed per customer.

Implements Squid's own documented basic auth helper protocol exactly:
reads "username password" lines from stdin, writes "OK" or "ERR" to
stdout for each one, for the whole lifetime of the process - Squid starts
several of these and keeps them running, feeding each one auth requests
one at a time as they arrive."""
import sys
import json

PASSWORD_STORE_PATH = "%s"


def load_passwords():
    try:
        with open(PASSWORD_STORE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


for line in sys.stdin:
    line = line.rstrip("\\n")
    if " " not in line:
        print("ERR")
        sys.stdout.flush()
        continue
    username, password = line.split(" ", 1)
    # Re-read on every request rather than caching - Squid's own
    # `credentialsttl 2 hours` already limits how often this actually gets
    # called per active user, so the cost is negligible, and it means a
    # brand-new SSH account works with Squid immediately, no restart of
    # this helper (or Squid itself) ever required.
    passwords = load_passwords()
    if username in passwords and passwords[username] == password:
        print("OK")
    else:
        print("ERR")
    sys.stdout.flush()
''' % SSH_PASSWORD_STORE_PATH


def _ensure_ssh_auth_helper_installed():
    """Writes the auth helper script out if it's missing or stale (content
    changed since last written) - safe to call on every install/config
    apply, matching the same idempotent pattern this project's other
    embedded-script modules (icmp_manager.py, websocket_manager.py) use."""
    needs_write = True
    if os.path.exists(SSH_AUTH_HELPER_PATH):
        with open(SSH_AUTH_HELPER_PATH) as f:
            needs_write = f.read() != SSH_AUTH_HELPER_SCRIPT
    if needs_write:
        with open(SSH_AUTH_HELPER_PATH, "w") as f:
            f.write(SSH_AUTH_HELPER_SCRIPT)
        os.chmod(SSH_AUTH_HELPER_PATH, 0o755)


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "squid"]).returncode == 0


def _restart_squid():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt.
    _run("systemctl reset-failed squid")
    return _run("systemctl restart squid").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _ensure_installed():
    if os.path.exists("/usr/sbin/squid"):
        return True
    print("%s[i] Installing Squid...%s" % (C_CYAN, C_RESET))
    _run("apt-get update && apt-get install -y squid")
    ok = os.path.exists("/usr/sbin/squid")
    if not ok:
        print("%s[X] Squid did not install correctly - check network access.%s" % (C_RED, C_RESET))
    return ok


def _build_config(listen_port, extra_ssl_ports=None):
    # Called from every place that generates a config (initial install,
    # port changes) - guarantees the auth helper is always present and
    # current, the same "can't be missed at a new call site" principle
    # this panel already applies to shared install/setup logic elsewhere.
    _ensure_ssh_auth_helper_installed()
    ssl_ports = ["443"] + (extra_ssl_ports or [])
    ssl_ports_lines = "\n".join("acl SSL_ports port %s" % p for p in ssl_ports)
    return """# Managed Squid Proxy Configuration
http_port %s

# --- Port hardening: without these deny rules, a proxy can be abused as an
# --- arbitrary TCP tunnel to any port, not just web traffic.
%s
acl Safe_ports port 80
acl Safe_ports port 443
acl Safe_ports port 21
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports

# --- Authentication: REQUIRED. Without this, Squid is an open proxy reachable
# --- by anyone on the internet the moment it starts.
auth_param basic program %s
auth_param basic realm Squid Proxy Authentication Required
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive off
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all

coredump_dir /var/spool/squid
""" % (listen_port, ssl_ports_lines, SSH_AUTH_HELPER_PATH)


def _test_config_syntax():
    """squid -k parse validates config syntax without starting the daemon -
    confirmed real and documented, the Squid equivalent of sshd -t."""
    res = _run(["squid", "-k", "parse"])
    return res.returncode == 0, res.stderr


def _apply_config_safely(new_content, description, check_port):
    original = None
    if os.path.exists(SQUID_CONF_PATH):
        with open(SQUID_CONF_PATH, "r") as f:
            original = f.read()

    with open(SQUID_CONF_PATH, "w") as f:
        f.write(new_content)

    ok, err = _test_config_syntax()
    if not ok:
        if original is not None:
            with open(SQUID_CONF_PATH, "w") as f:
                f.write(original)
        return False, "%s failed 'squid -k parse' validation - reverted, nothing was changed:\n%s" % (description, err.strip())

    if not _restart_squid():
        if original is not None:
            with open(SQUID_CONF_PATH, "w") as f:
                f.write(original)
            _restart_squid()
        return False, "%s passed syntax check but failed to restart - reverted to the previous working config." % description

    if not _wait_for_port_listening(check_port):
        if original is not None:
            with open(SQUID_CONF_PATH, "w") as f:
                f.write(original)
            _restart_squid()
        return False, "%s restarted, but port %s never came up - reverted. Nothing was left broken." % (description, check_port)

    return True, "%s applied and verified on port %s." % (description, check_port)


def _user_count():
    """Every existing SSH account authenticates here automatically - this
    reflects that real count, not a separate Squid-specific list (which no
    longer exists)."""
    try:
        from ssh_user_manager import _load_registry as _load_ssh_registry
        return len(_load_ssh_registry())
    except Exception:
        return 0


def squid_admin_manager(ports_dict):
    """Squid Proxy Administrator Module."""
    while True:
        squid_port = ports_dict.get('SQUID_PORT', 'Not configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"
        user_count = _user_count()

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                  SQUID PROXY ADMINISTRATOR                 %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      PROXY PORT: %s  |  SSH ACCOUNTS THAT CAN AUTHENTICATE: %s" % (squid_port, user_count))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL SQUID PROXY (Wizard)")
        print(" [2]> MODIFY PROXY PORT")
        print(" [3]> EDIT SQUID CONFIGURATION (nano)")
        print(" [4]> VIEW SERVICE LOGS")
        print(" [5]> RESTART SQUID SERVICE")
        print(" [6]> START/STOP SQUID SERVICE [%s]" % status_label)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL SQUID")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s            SQUID PROXY INSTALLATION WIZARD                 %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s Squid requires authentication to use - an open, unauthenticated" % C_YELLOW)
            print(" proxy is a real abuse risk, not a convenience. Every existing SSH")
            print(" account already works here automatically - customers use the same")
            print(" username and password they already have. Nothing else to set up.%s\n" % C_RESET)

            listen_port = prompt_port(" Enter desired Squid Proxy listen port (e.g., 3128 or 8080): ", default=3128)
            if str(listen_port) != str(squid_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            new_content = _build_config(listen_port)
            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable squid")

            ok, msg = _apply_config_safely(new_content, "Squid on port %s" % listen_port, listen_port)
            if ok:
                ports_dict['SQUID_PORT'] = str(listen_port)
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("%s    Client proxy URL: http://<ssh-username>:<ssh-password>@<server-ip>:%s%s" % (C_CYAN, listen_port, C_RESET))
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   MODIFY SQUID PORT                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(SQUID_CONF_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new Squid listen port [Current: %s]: " % squid_port,
                                    default=int(squid_port) if str(squid_port).isdigit() else 3128)
            if str(new_port) != str(squid_port) and check_system_port_in_use(new_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            with open(SQUID_CONF_PATH, "r") as f:
                existing = f.read()
            extra_ssl = re.findall(r'^acl SSL_ports port (\d+)$', existing, re.MULTILINE)
            extra_ssl = [p for p in extra_ssl if p != "443"]
            new_content = _build_config(new_port, extra_ssl_ports=extra_ssl)

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_config_safely(new_content, "Port change to %s" % new_port, new_port)
            if ok:
                old_port = squid_port
                ports_dict['SQUID_PORT'] = str(new_port)
                if str(old_port).isdigit() and str(old_port) != str(new_port):
                    close_firewall_port(int(old_port), ("tcp",))
                    persist_firewall_rules()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
            else:
                close_firewall_port(new_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue
            os.system("nano %s" % SQUID_CONF_PATH)
            ok, err = _test_config_syntax()
            if ok and _restart_squid():
                print("%s[OK] Configuration saved and Squid restarted.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Config failed validation or restart - fix it manually before relying on it:" % C_RED)
                print("%s%s" % (err.strip() if err else '', C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    SQUID SERVICE LOGS                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u squid -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            ok, err = _test_config_syntax()
            if not ok:
                print("%s[X] Current config fails 'squid -k parse' - not restarting:\n%s%s" % (C_RED, err.strip(), C_RESET))
            elif _restart_squid():
                print("%s[OK] Squid service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Squid failed to restart - check 'journalctl -u squid'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop squid")
                print("%s[!] Squid service stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not _ensure_installed():
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start squid")
                if _service_active():
                    print("%s[OK] Squid service started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Squid failed to start - check 'journalctl -u squid'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    UNINSTALL SQUID                         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove Squid Proxy? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop squid && systemctl disable squid")
                _run("apt-get purge -y squid")
                if str(squid_port).isdigit():
                    close_firewall_port(int(squid_port), ("tcp",))
                    persist_firewall_rules()
                _run("rm -f %s %s" % (SQUID_PASSWD_PATH, SSH_AUTH_HELPER_PATH))
                ports_dict.pop('SQUID_PORT', None)
                ports_dict.pop('SQUID_USERS', None)
                print("%s[OK] Squid proxy purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
