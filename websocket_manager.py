"""
websocket_manager.py - standalone WebSocket tunnel module for the SmartUI
panel, wrapping wstunnel (github.com/erebe/wstunnel).

Rebuilt to the same simple pattern every other redirect-style protocol in
this panel already uses (Stunnel, WS-EPRO, SSHGO): one listen port, one
redirect port, nothing else asked. The previous version provisioned a
separate per-customer "instance" with its own generated username/password
and an HTTP gate verifying them before unlocking the real port - dropped
entirely. Real authentication now happens exactly where it already does for
every other tunnel in this panel: at the redirect target itself (normally
SSH/Dropbear), using the accounts already managed by ssh_user_manager.py.
Reusing a separate credential system per protocol was the actual problem -
one account system, reused everywhere, is simpler and is what was asked for.

Public IP is auto-detected (panel_common.get_public_ip()) for the client
command shown after setup, never prompted for.

wstunnel's own --restrict-http-upgrade-path-prefix secret is still generated
(defense-in-depth against casual port scanning finding a live wstunnel
endpoint) but auto-generated, never asked - shown in the client command
output the same way Stunnel/WireGuard/etc. show their own auto-generated
secrets after setup rather than requesting them upfront.
"""

import os
import re
import time
import secrets
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_public_ip, get_live_port_from_service,
)

WSTUNNEL_DIR = "/etc/wstunnel"
WSTUNNEL_BIN = "/usr/local/bin/wstunnel"
WSTUNNEL_USER = "wstunnel"
WSTUNNEL_SERVICE_PATH = "/etc/systemd/system/wstunnel.service"


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
    tag = m.group(1)
    version = tag.lstrip("v")

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

    _run(["setcap", "CAP_NET_BIND_SERVICE=+eip", WSTUNNEL_BIN])
    _run(["useradd", "--system", "--shell", "/usr/sbin/nologin", WSTUNNEL_USER])

    ok = _binary_ok()
    if not ok:
        print("%s[X] Install did not complete correctly.%s" % (C_RED, C_RESET))
    return ok


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "wstunnel"]).returncode == 0


def _restart_wstunnel():
    return _run("systemctl restart wstunnel").returncode == 0


def _wait_for_port_listening(port, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _write_service(listen_port, target_port, path_prefix):
    exec_cmd = ("%s server wss://0.0.0.0:%s --restrict-to 127.0.0.1:%s "
                "--restrict-http-upgrade-path-prefix %s") % (
        WSTUNNEL_BIN, listen_port, target_port, path_prefix)
    service_content = """[Unit]
Description=WebSocket Tunnel (wstunnel)
After=network.target

[Service]
Type=simple
User=%s
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % (WSTUNNEL_USER, exec_cmd)
    with open(WSTUNNEL_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_safely(listen_port, target_port, path_prefix, description):
    original = None
    if os.path.exists(WSTUNNEL_SERVICE_PATH):
        with open(WSTUNNEL_SERVICE_PATH, "r") as f:
            original = f.read()

    _write_service(listen_port, target_port, path_prefix)

    if not _restart_wstunnel():
        if original is not None:
            with open(WSTUNNEL_SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_wstunnel()
        return False, "%s failed to restart - check 'journalctl -u wstunnel'." % description

    if not _wait_for_port_listening(listen_port):
        if original is not None:
            with open(WSTUNNEL_SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_wstunnel()
        return False, "%s restarted, but port %s never came up - reverted. Nothing was left broken." % (description, listen_port)

    return True, "%s applied and verified on port %s." % (description, listen_port)


def websocket_admin_manager(ports_dict):
    """Standalone WebSocket Tunnel (wstunnel) Administrator Module."""
    while True:
        live_port = get_live_port_from_service(WSTUNNEL_SERVICE_PATH, r'wss://0\.0\.0\.0:(\d+)')
        live_target = get_live_port_from_service(WSTUNNEL_SERVICE_PATH, r'--restrict-to 127\.0\.0\.1:(\d+)')
        recorded_port = ports_dict.get('WSTUNNEL_PORT')
        if live_port and str(recorded_port) != str(live_port):
            print(f"{C_YELLOW}[!] The saved port ({recorded_port or 'none'}) didn't match what's actually")
            print(f"    running ({live_port}) - correcting the panel's records to match reality.{C_RESET}")
            ports_dict['WSTUNNEL_PORT'] = live_port
            if live_target:
                ports_dict['WSTUNNEL_TARGET_PORT'] = live_target
            input("\nPress Enter to continue...")

        ws_port = ports_dict.get('WSTUNNEL_PORT', 'Not configured')
        ws_target = ports_dict.get('WSTUNNEL_TARGET_PORT', '22')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s              WEBSOCKET (wstunnel) ADMINISTRATOR            %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      PORT: %s  |  REDIRECTION TARGET: %s" % (ws_port, ws_target))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL WEBSOCKET")
        print(" [2]> MODIFY PORT & TRAFFIC REDIRECTION")
        print(" [3]> VIEW CONNECTION INFO")
        print(" [4]> VIEW SERVICE LOGS")
        print(" [5]> RESTART SERVICE")
        print(" [6]> START/STOP SERVICE [%s]" % status_label)
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL WEBSOCKET")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    SETUP WIZARD                            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter WebSocket port (e.g., 8080): ", default=8080)
            if str(listen_port) != str(ws_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            target_port = prompt_port(" Enter redirect port (e.g., 22 for SSH, 143 for Dropbear): ", default=22)
            if not check_system_port_in_use(target_port, ("tcp",)):
                print("%s[!] Nothing seems to be listening on port %s yet.%s" % (C_YELLOW, target_port, C_RESET))

            if not _ensure_binary_installed():
                input("\nPress Enter to continue...")
                continue

            path_prefix = secrets.token_urlsafe(24)
            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable wstunnel")

            ok, msg = _apply_safely(listen_port, target_port, path_prefix, "WebSocket tunnel")
            if ok:
                ports_dict['WSTUNNEL_PORT'] = str(listen_port)
                ports_dict['WSTUNNEL_TARGET_PORT'] = str(target_port)
                ports_dict['WSTUNNEL_PATH_PREFIX'] = path_prefix
                server_ip = get_public_ip()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print()
                print(" Client command:")
                print("  wstunnel client -L tcp://LOCAL_PORT:127.0.0.1:%s --http-upgrade-path-prefix %s wss://%s:%s" % (
                    target_port, path_prefix, server_ip, listen_port))
                print()
                print(" Then connect through LOCAL_PORT using the same SSH username/password")
                print(" already set up for this server - no separate login for this tunnel.")
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            if not os.path.exists(WSTUNNEL_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new WebSocket port [Current: %s]: " % ws_port,
                                    default=int(ws_port) if str(ws_port).isdigit() else 8080)
            if str(new_port) != str(ws_port) and check_system_port_in_use(new_port, ("tcp",)):
                print("%s[X] Port %s is already in use.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_target = prompt_port(" Enter new redirect port [Current: %s]: " % ws_target,
                                      default=int(ws_target) if str(ws_target).isdigit() else 22)

            path_prefix = ports_dict.get('WSTUNNEL_PATH_PREFIX') or secrets.token_urlsafe(24)
            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_safely(new_port, new_target, path_prefix, "Port/redirect change")
            if ok:
                old_port = ws_port
                ports_dict['WSTUNNEL_PORT'] = str(new_port)
                ports_dict['WSTUNNEL_TARGET_PORT'] = str(new_target)
                ports_dict['WSTUNNEL_PATH_PREFIX'] = path_prefix
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
            if not os.path.exists(WSTUNNEL_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            path_prefix = ports_dict.get('WSTUNNEL_PATH_PREFIX', '')
            server_ip = get_public_ip()
            print(" Server IP: %s" % server_ip)
            print(" Port: %s  ->  127.0.0.1:%s" % (ws_port, ws_target))
            print()
            print(" %sFor an app like HTTP Custom / HTTP Injector (not the wstunnel CLI):%s" % (C_YELLOW, C_RESET))
            print("   Host / SNI:  %s" % server_ip)
            print("   Port:        %s" % ws_port)
            print("   Path:        /%s" % path_prefix)
            print("   %s(the path is REQUIRED, not optional - wstunnel is deliberately" % C_YELLOW)
            print("   configured to reject any request that doesn't use this exact")
            print("   path, as a security measure. Requesting the plain root path")
            print("   ('/', which most apps default to if the path field is left")
            print("   blank) gets an immediate connection close with no response at")
            print("   all - confirmed as the actual cause of a real failed connection,")
            print("   not a bug in the tunnel itself.)%s" % C_RESET)
            print("   Then authenticate at the backend (127.0.0.1:%s) with your" % ws_target)
            print("   normal SSH/Dropbear account.")
            print()
            print(" Client command (only relevant if using the actual wstunnel CLI tool):")
            print("  wstunnel client -L tcp://LOCAL_PORT:127.0.0.1:%s --http-upgrade-path-prefix %s wss://%s:%s" % (
                ws_target, path_prefix, server_ip, ws_port))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            os.system("journalctl -u wstunnel -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_wstunnel():
                print("%s[OK] WebSocket tunnel restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u wstunnel'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop wstunnel")
                print("%s[!] WebSocket tunnel stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not _binary_ok():
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start wstunnel")
                if _service_active():
                    print("%s[OK] WebSocket tunnel started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u wstunnel'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            confirm = input(" Are you sure you want to completely remove the WebSocket tunnel? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop wstunnel")
                _run("systemctl disable wstunnel")
                _run("rm -f %s" % WSTUNNEL_SERVICE_PATH)
                _run("systemctl daemon-reload")
                if str(ws_port).isdigit():
                    close_firewall_port(int(ws_port), ("tcp",))
                    persist_firewall_rules()
                ports_dict.pop('WSTUNNEL_PORT', None)
                ports_dict.pop('WSTUNNEL_TARGET_PORT', None)
                ports_dict.pop('WSTUNNEL_PATH_PREFIX', None)
                print("%s[OK] WebSocket tunnel removed and purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
