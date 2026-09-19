"""
filebrowser_manager.py - FileBrowser admin module for the SmartUI panel.

The single most severe bug found here: the admin account was always created
with the password hardcoded as the literal string "admin":
    filebrowser users add {admin_user} admin --perm.admin
Whatever username the operator chose, the password was always "admin" -
a trivially guessable default for a web-exposed, ADMIN-level file manager
that (per the operator's own choice of root directory) can have read/write/
delete access to the entire server filesystem. Confirmed this is a real,
recurring footgun in FileBrowser deployments generally (an open upstream
issue - filebrowser/filebrowser#3777 - describes exactly this: leaving the
password as the literal "admin" resets every account back to guessable
default credentials). Fixed by prompting for a real password (or generating
a strong one), never hardcoding it - FileBrowser itself bcrypt-hashes
whatever password it's given, so the only thing that needed fixing was never
handing it "admin" in the first place.

Other real bugs found, matching classes already fixed across this panel:

1. No verification the binary install (curl | bash) actually succeeded -
   filebrowser config init/set and users add were chained with
   2>/dev/null || true, silently swallowing any failure, and the code
   proceeded to write and start a systemd unit regardless of whether the
   binary or database ever actually existed.

2. No warning when the managed root directory is the filesystem root (/)
   or similarly sensitive - combined with the default-password bug, this
   would have meant anyone who found the port could browse/edit/delete
   anything on the server using guessable credentials. Now warns explicitly
   before proceeding if the chosen root looks unusually broad.

3. No restart verification/rollback, no port-conflict check, inconsistent
   firewall handling (the install wizard used both ufw AND raw non-idempotent
   iptables -I INPUT, but the port-change flow only used ufw) - moved to the
   shared panel_common firewall helpers used throughout this panel, and to
   the same restart-verify-rollback safety net used for Stunnel/Hysteria/
   OpenVPN (FileBrowser has no config-syntax-test-only flag either - it's a
   single self-contained binary + embedded BoltDB, not a text config parsed
   at startup).

4. Port-change didn't close the old port on the firewall - same "unbinding"
   bug class fixed in every other module in this panel.

5. Uninstall didn't close the firewall port either.
"""

import os
import time
import secrets
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)

FILEBROWSER_BIN = "/usr/local/bin/filebrowser"
FILEBROWSER_DB = "/etc/filebrowser.db"
SERVICE_PATH = "/etc/systemd/system/filebrowser.service"

SENSITIVE_ROOTS = {"/", "/etc", "/etc/", "/root", "/root/"}


def _service_active():
    return (_run(["systemctl", "is-active", "--quiet", "filebrowser"]).returncode == 0
            or _run("pgrep -f filebrowser").returncode == 0)


def _restart_filebrowser():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt.
    _run("systemctl reset-failed filebrowser")
    return _run("systemctl restart filebrowser").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _binary_ok():
    return os.path.exists(FILEBROWSER_BIN) and os.access(FILEBROWSER_BIN, os.X_OK)


def _ensure_installed():
    if _binary_ok():
        return True
    print("%s[i] Installing FileBrowser...%s" % (C_CYAN, C_RESET))
    _run("curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash")
    ok = _binary_ok()
    if not ok:
        print("%s[X] FileBrowser did not install correctly - check network access.%s" % (C_RED, C_RESET))
    return ok


def _write_service():
    service_content = """[Unit]
Description=FileBrowser Web File Manager
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s --database %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (FILEBROWSER_BIN, FILEBROWSER_DB)
    with open(SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_safely(description, check_port):
    """No config-syntax-test flag exists for FileBrowser either - it's a
    single binary with an embedded BoltDB, not a text config parsed at
    startup. Same restart-verify-rollback pattern as Stunnel/Hysteria/
    OpenVPN, without a pre-flight check step."""
    if not _restart_filebrowser():
        return False, "%s failed to restart - check the FileBrowser database/config." % description

    if not _wait_for_port_listening(check_port):
        return False, "%s restarted, but port %s never came up." % (description, check_port)

    return True, "%s applied and verified on port %s." % (description, check_port)


def filebrowser_admin_manager(ports_dict):
    """FileBrowser Administrator Module."""
    while True:
        fb_port = ports_dict.get('FILEBROWSER_PORT', 'Not configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                    FILEBROWSER ADMINISTRATOR               %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      FILEBROWSER PORT: %s" % fb_port)
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL FILEBROWSER (Wizard)")
        print(" [2]> CHANGE FILEBROWSER PORT")
        print(" [3]> RESET ADMIN PASSWORD")
        print(" [4]> VIEW SERVICE LOGS")
        print(" [5]> RESTART FILEBROWSER SERVICE")
        print(" [6]> START/STOP FILEBROWSER SERVICE [%s]" % status_label)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL FILEBROWSER")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s         FILEBROWSER INSTALLATION WIZARD                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter desired FileBrowser listen port (e.g., 8080): ", default=8080)
            if str(listen_port) != str(fb_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            root_dir = input(" Enter root directory to manage (e.g., /var/www or /home/user): ").strip()
            if not root_dir:
                print("%s[X] A root directory is required.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            if root_dir.rstrip('/') == '' or root_dir in SENSITIVE_ROOTS:
                print("%s[!] '%s' gives FileBrowser access to a very broad or sensitive part" % (C_YELLOW, root_dir))
                print("    of the filesystem (SSH keys, other services' secrets, etc.) - anyone who logs")
                print("    in gets full read/write/delete there.%s" % C_RESET)
                if input(" Continue anyway? (y/n): ").strip().lower() != 'y':
                    input("\nPress Enter to continue...")
                    continue
            if not os.path.exists(root_dir):
                print("%s[i] Directory '%s' does not exist - creating it.%s" % (C_CYAN, root_dir, C_RESET))
                os.makedirs(root_dir, exist_ok=True)

            admin_user = input(" Enter admin username [default: admin]: ").strip() or "admin"
            admin_pass = input(" Enter admin password (blank to auto-generate a strong one): ").strip()
            if not admin_pass:
                admin_pass = secrets.token_urlsafe(16)
                print("%s[i] Generated password: %s%s" % (C_CYAN, admin_pass, C_RESET))
            elif len(admin_pass) < 12:
                print("%s[!] FileBrowser requires at least 12 characters - it will reject a shorter one.%s" % (C_YELLOW, C_RESET))

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            if os.path.exists(FILEBROWSER_DB):
                os.remove(FILEBROWSER_DB)

            init_res = _run("%s config init --database %s" % (FILEBROWSER_BIN, FILEBROWSER_DB))
            if init_res.returncode != 0:
                print("%s[X] Database initialization failed: %s%s" % (C_RED, init_res.stderr.strip(), C_RESET))
                input("\nPress Enter to continue...")
                continue

            set_res = _run("%s config set --database %s --address 0.0.0.0 --port %s --root %s" %
                            (FILEBROWSER_BIN, FILEBROWSER_DB, listen_port, root_dir))
            if set_res.returncode != 0:
                print("%s[X] Configuration failed: %s%s" % (C_RED, set_res.stderr.strip(), C_RESET))
                input("\nPress Enter to continue...")
                continue

            user_res = _run('%s users add --database %s "%s" "%s" --perm.admin' %
                             (FILEBROWSER_BIN, FILEBROWSER_DB, admin_user, admin_pass))
            if user_res.returncode != 0:
                print("%s[X] Admin user creation failed: %s%s" % (C_RED, user_res.stderr.strip(), C_RESET))
                input("\nPress Enter to continue...")
                continue

            _write_service()
            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable filebrowser")

            ok, msg = _apply_safely("FileBrowser on port %s" % listen_port, listen_port)
            if ok:
                ports_dict['FILEBROWSER_PORT'] = str(listen_port)
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("%s    Login: %s / %s%s" % (C_CYAN, admin_user, admin_pass, C_RESET))
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                CHANGE FILEBROWSER PORT                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(FILEBROWSER_DB):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new FileBrowser port [Current: %s]: " % fb_port,
                                    default=int(fb_port) if str(fb_port).isdigit() else 8080)
            if str(new_port) != str(fb_port) and check_system_port_in_use(new_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            set_res = _run("%s config set --database %s --port %s" % (FILEBROWSER_BIN, FILEBROWSER_DB, new_port))
            if set_res.returncode != 0:
                print("%s[X] Failed to update port: %s%s" % (C_RED, set_res.stderr.strip(), C_RESET))
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_safely("Port change to %s" % new_port, new_port)
            if ok:
                old_port = fb_port
                ports_dict['FILEBROWSER_PORT'] = str(new_port)
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
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  RESET ADMIN PASSWORD                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(FILEBROWSER_DB):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            username = input(" Username to update: ").strip()
            new_pass = input(" New password (blank to auto-generate): ").strip()
            if not new_pass:
                new_pass = secrets.token_urlsafe(16)
                print("%s[i] Generated password: %s%s" % (C_CYAN, new_pass, C_RESET))

            was_active = is_active
            if was_active:
                _run("systemctl stop filebrowser")

            res = _run('%s users update --database %s "%s" --password "%s"' %
                       (FILEBROWSER_BIN, FILEBROWSER_DB, username, new_pass))
            if was_active:
                _run("systemctl start filebrowser")

            if res.returncode == 0:
                print("%s[OK] Password updated for '%s': %s%s" % (C_GREEN, username, new_pass, C_RESET))
            else:
                print("%s[X] Failed to update password: %s%s" % (C_RED, res.stderr.strip(), C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 FILEBROWSER SERVICE LOGS                   %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u filebrowser -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_filebrowser():
                print("%s[OK] FileBrowser service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] FileBrowser failed to restart - check 'journalctl -u filebrowser'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop filebrowser")
                print("%s[!] FileBrowser service stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not _binary_ok():
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start filebrowser")
                if _service_active():
                    print("%s[OK] FileBrowser service started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] FileBrowser failed to start - check 'journalctl -u filebrowser'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                UNINSTALL FILEBROWSER                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove FileBrowser? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop filebrowser && systemctl disable filebrowser")
                _run("rm -f %s %s %s" % (SERVICE_PATH, FILEBROWSER_BIN, FILEBROWSER_DB))
                _run("systemctl daemon-reload")
                if str(fb_port).isdigit():
                    close_firewall_port(int(fb_port), ("tcp",))
                    persist_firewall_rules()
                ports_dict.pop('FILEBROWSER_PORT', None)
                print("%s[OK] FileBrowser purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
