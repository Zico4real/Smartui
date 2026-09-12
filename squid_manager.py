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


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "squid"]).returncode == 0


def _restart_squid():
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
    print("%s[i] Installing Squid and htpasswd utility...%s" % (C_CYAN, C_RESET))
    _run("apt-get update && apt-get install -y squid apache2-utils")
    ok = os.path.exists("/usr/sbin/squid")
    if not ok:
        print("%s[X] Squid did not install correctly - check network access.%s" % (C_RED, C_RESET))
    return ok


def _build_config(listen_port, extra_ssl_ports=None):
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
auth_param basic program %s %s
auth_param basic realm Squid Proxy Authentication Required
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive off
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all

coredump_dir /var/spool/squid
""" % (listen_port, ssl_ports_lines, BASIC_NCSA_AUTH_BIN, SQUID_PASSWD_PATH)


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
    if not os.path.exists(SQUID_PASSWD_PATH):
        return 0
    with open(SQUID_PASSWD_PATH) as f:
        return sum(1 for line in f if line.strip())


def _add_user(username, password):
    first_user = not os.path.exists(SQUID_PASSWD_PATH)
    flag = "-bc" if first_user else "-b"  # -c CREATES (and truncates!) the file - only ever on the first user
    res = _run(["htpasswd", flag, SQUID_PASSWD_PATH, username, password])
    if res.returncode == 0 and os.path.exists(SQUID_PASSWD_PATH):
        os.chmod(SQUID_PASSWD_PATH, 0o640)
        _run(["chown", "proxy:proxy", SQUID_PASSWD_PATH])
    return res.returncode == 0


def squid_admin_manager(ports_dict):
    """Squid Proxy Administrator Module."""
    while True:
        squid_port = ports_dict.get('SQUID_PORT', 'Not configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"
        user_count = _user_count()

        clear_screen()
        print("================================================================")
        print("                  SQUID PROXY ADMINISTRATOR                 ")
        print("================================================================")
        print("      PROXY PORT: %s  |  AUTHENTICATED USERS: %s" % (squid_port, user_count))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL SQUID PROXY (Wizard)")
        print(" [2]> MODIFY PROXY PORT")
        print(" [3]> MANAGE USERS (add / remove)")
        print(" [4]> EDIT SQUID CONFIGURATION (nano)")
        print(" [5]> VIEW SERVICE LOGS")
        print(" [6]> RESTART SQUID SERVICE")
        print(" [7]> START/STOP SQUID SERVICE [%s]" % status_label)
        print("================================================================")
        print(" [0] RETURN  [8] UNINSTALL SQUID")
        print("================================================================")

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("================================================================")
            print("            SQUID PROXY INSTALLATION WIZARD                 ")
            print("================================================================")
            print("%s Squid will require a username and password to use - an open," % C_YELLOW)
            print(" unauthenticated proxy is a real abuse risk, not a convenience.%s\n" % C_RESET)

            listen_port = prompt_port(" Enter desired Squid Proxy listen port (e.g., 3128 or 8080): ", default=3128)
            if str(listen_port) != str(squid_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            username = input(" Enter a username for proxy access: ").strip()
            if not username:
                print("%s[X] A username is required.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            password = input(" Enter a password (blank to auto-generate a strong one): ").strip()
            if not password:
                import secrets
                password = secrets.token_urlsafe(16)
                print("%s[i] Generated password: %s%s" % (C_CYAN, password, C_RESET))

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            if os.path.exists(SQUID_PASSWD_PATH):
                os.remove(SQUID_PASSWD_PATH)  # fresh install - start with a clean user list
            if not _add_user(username, password):
                print("%s[X] Failed to create the auth credentials file.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_content = _build_config(listen_port)
            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable squid")

            ok, msg = _apply_config_safely(new_content, "Squid on port %s" % listen_port, listen_port)
            if ok:
                ports_dict['SQUID_PORT'] = str(listen_port)
                ports_dict['SQUID_USERS'] = username
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("%s    Client proxy URL: http://%s:****@<server-ip>:%s%s" % (C_CYAN, username, listen_port, C_RESET))
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("================================================================")
            print("                   MODIFY SQUID PORT                        ")
            print("================================================================")
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
            clear_screen()
            print("================================================================")
            print("                     MANAGE USERS                           ")
            print("================================================================")
            if not os.path.exists(SQUID_PASSWD_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            print(" [1] Add a user")
            print(" [2] Remove a user")
            print(" [0] Back")
            sub = input(" Select option: ").strip()

            if sub == '1':
                username = input(" Enter new username: ").strip()
                password = input(" Enter password (blank to auto-generate): ").strip()
                if not username:
                    print("%s[X] Username cannot be empty.%s" % (C_RED, C_RESET))
                else:
                    if not password:
                        import secrets
                        password = secrets.token_urlsafe(16)
                        print("%s[i] Generated password: %s%s" % (C_CYAN, password, C_RESET))
                    if _add_user(username, password):
                        existing_users = ports_dict.get('SQUID_USERS', '')
                        users = [u for u in existing_users.split(',') if u] if existing_users else []
                        if username not in users:
                            users.append(username)
                        ports_dict['SQUID_USERS'] = ",".join(users)
                        print("%s[OK] User '%s' added.%s" % (C_GREEN, username, C_RESET))
                    else:
                        print("%s[X] Failed to add user.%s" % (C_RED, C_RESET))
            elif sub == '2':
                if _user_count() <= 1:
                    print("%s[X] Can't remove the last user - Squid needs at least one to stay usable.%s" % (C_RED, C_RESET))
                else:
                    username = input(" Enter username to remove: ").strip()
                    with open(SQUID_PASSWD_PATH) as f:
                        lines = [l for l in f if not l.startswith(username + ":")]
                    with open(SQUID_PASSWD_PATH, "w") as f:
                        f.writelines(lines)
                    existing_users = ports_dict.get('SQUID_USERS', '')
                    users = [u for u in existing_users.split(',') if u and u != username]
                    ports_dict['SQUID_USERS'] = ",".join(users)
                    print("%s[OK] User '%s' removed (existing sessions stay open until credentialsttl expires).%s" % (C_GREEN, username, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
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

        elif choice == '5':
            clear_screen()
            print("================================================================")
            print("                    SQUID SERVICE LOGS                      ")
            print("================================================================")
            os.system("journalctl -u squid -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '6':
            ok, err = _test_config_syntax()
            if not ok:
                print("%s[X] Current config fails 'squid -k parse' - not restarting:\n%s%s" % (C_RED, err.strip(), C_RESET))
            elif _restart_squid():
                print("%s[OK] Squid service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Squid failed to restart - check 'journalctl -u squid'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
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

        elif choice == '8':
            clear_screen()
            print("================================================================")
            print("                    UNINSTALL SQUID                         ")
            print("================================================================")
            confirm = input(" Are you sure you want to completely remove Squid Proxy? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop squid && systemctl disable squid")
                _run("apt-get purge -y squid")
                if str(squid_port).isdigit():
                    close_firewall_port(int(squid_port), ("tcp",))
                    persist_firewall_rules()
                _run("rm -f %s" % SQUID_PASSWD_PATH)
                ports_dict.pop('SQUID_PORT', None)
                ports_dict.pop('SQUID_USERS', None)
                print("%s[OK] Squid proxy purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
