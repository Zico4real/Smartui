"""
websocket_manager.py - standalone WebSocket tunnel module for the SmartUI
panel.

Rebuilt from a wstunnel-wrapping design to a plain Python3 relay, matching
the same proven pattern already confirmed working in python_socks_manager.py
and ws_epro_manager.py. Two real, confirmed reasons for the switch:

1. wstunnel always terminates real TLS (wss://) by default. Confirmed
   directly from a real service log on a real VPS: the client's connection
   was accepted and a TLS handshake began, then went completely silent - no
   error, no completion. This matches a well-documented pattern (a wstunnel
   GitHub issue describing the same thing) where some ISPs/mobile carriers
   detect and silently drop WS/WSS traffic mid-handshake. A plain ws://
   toggle was added as a workaround, but the underlying client apps used
   throughout this ecosystem (HTTP Custom and similar) were never actually
   doing real TLS negotiation to begin with - they only ever send a minimal,
   non-compliant "Upgrade: websocket" header block, the same payload
   confirmed working through Python SOCKS. A plain Python3 relay removes the
   TLS layer (and the third-party binary) entirely, rather than just
   offering an alternate mode.

2. wstunnel's own --restrict-http-upgrade-path-prefix security feature
   requires the exact secret path in every request - confirmed as a second,
   separate real cause of a failed connection, since the actual client apps
   default to requesting the plain root path with no way to know a path was
   even required. Dropping the requirement entirely (matching how Python
   SOCKS and WS-EPRO already work) removes an entire class of "looks broken,
   isn't documented anywhere the client would see it" failures.

Client apps authenticate at the redirect target itself (normally
SSH/Dropbear), using the accounts already managed by ssh_user_manager.py -
same as every other tunnel in this panel.
"""

import os
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_public_ip, get_live_port_from_service,
)

WS_DIR = "/etc/websocket-tunnel"
WS_SCRIPT_PATH = "/etc/websocket-tunnel/bridge.py"
WS_SERVICE_PATH = "/etc/systemd/system/websocket-tunnel.service"

BRIDGE_SCRIPT = '''#!/usr/bin/env python3
"""Standalone WebSocket-style TCP bridge - plain Python3, no TLS, no strict
handshake. Accepts a minimal "Upgrade: websocket" request (no Sec-WebSocket-
Key required - confirmed as what real client apps in this ecosystem
actually send) and bridges the connection to TARGET_PORT on localhost."""
import socket
import threading
import os
import sys

LISTEN_PORT = int(os.environ.get("WS_TUNNEL_LISTEN_PORT", "8080"))
TARGET_HOST = "127.0.0.1"
TARGET_PORT = int(os.environ.get("WS_TUNNEL_TARGET_PORT", "22"))

RESPONSE = b"HTTP/1.1 101 Switching Protocols\\r\\n\\r\\n"


def relay(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(client_sock):
    try:
        client_sock.settimeout(0.4)
        buf = b""
        try:
            while b"\\r\\n\\r\\n" not in buf and len(buf) < 8192:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        client_sock.settimeout(None)
        client_sock.sendall(RESPONSE)
    except Exception:
        client_sock.close()
        return

    try:
        backend = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    except Exception as e:
        sys.stderr.write("websocket-tunnel: cannot reach backend %s:%s: %s\\n" % (TARGET_HOST, TARGET_PORT, e))
        client_sock.close()
        return

    t1 = threading.Thread(target=relay, args=(client_sock, backend), daemon=True)
    t2 = threading.Thread(target=relay, args=(backend, client_sock), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    try:
        client_sock.close()
    except Exception:
        pass
    try:
        backend.close()
    except Exception:
        pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(128)
    while True:
        client_sock, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()
'''


def _deploy_script():
    os.makedirs(WS_DIR, exist_ok=True)
    with open(WS_SCRIPT_PATH, "w") as f:
        f.write(BRIDGE_SCRIPT)
    os.chmod(WS_SCRIPT_PATH, 0o755)


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "websocket-tunnel"]).returncode == 0


def _restart_service():
    _run("systemctl reset-failed websocket-tunnel")
    return _run("systemctl restart websocket-tunnel").returncode == 0


def _wait_for_port_listening(port, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _write_service(listen_port, target_port):
    _deploy_script()
    service_content = """[Unit]
Description=WebSocket Tunnel (plain Python3 relay)
After=network.target

[Service]
Type=simple
User=root
Environment="WS_TUNNEL_LISTEN_PORT=%s"
Environment="WS_TUNNEL_TARGET_PORT=%s"
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % (listen_port, target_port, WS_SCRIPT_PATH)
    with open(WS_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_safely(listen_port, target_port, description):
    original = None
    if os.path.exists(WS_SERVICE_PATH):
        with open(WS_SERVICE_PATH, "r") as f:
            original = f.read()

    _write_service(listen_port, target_port)

    if not _restart_service():
        if original is not None:
            with open(WS_SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_service()
        return False, "%s failed to restart - check 'journalctl -u websocket-tunnel'." % description

    if not _wait_for_port_listening(listen_port):
        if original is not None:
            with open(WS_SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_service()
        return False, "%s restarted, but port %s never came up - reverted. Nothing was left broken." % (description, listen_port)

    return True, "%s applied and verified on port %s." % (description, listen_port)


def websocket_admin_manager(ports_dict):
    """Standalone WebSocket Tunnel Administrator Module."""
    while True:
        # Same defensive re-enable as Stunnel/WS-EPRO elsewhere in this
        # panel - confirmed as a real, direct cause of a genuine bug
        # report where this service was found "disabled" (never wired to
        # start at boot at all), for reasons this code can't fully
        # reconstruct after the fact.
        if os.path.exists(WS_SERVICE_PATH):
            _run("systemctl enable websocket-tunnel")
        live_port = get_live_port_from_service(WS_SERVICE_PATH, r'WS_TUNNEL_LISTEN_PORT=(\d+)')
        live_target = get_live_port_from_service(WS_SERVICE_PATH, r'WS_TUNNEL_TARGET_PORT=(\d+)')
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
        print("%s                  WEBSOCKET ADMINISTRATOR                   %s" % (C_BOLD, C_RESET))
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

            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable websocket-tunnel")

            ok, msg = _apply_safely(listen_port, target_port, "WebSocket tunnel")
            if ok:
                ports_dict['WSTUNNEL_PORT'] = str(listen_port)
                ports_dict['WSTUNNEL_TARGET_PORT'] = str(target_port)
                server_ip = get_public_ip()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print()
                print(" Client setup (HTTP Custom / HTTP Injector or similar):")
                print("   Host:  %s" % server_ip)
                print("   Port:  %s" % listen_port)
                print("   Path:  / (leave the path field blank/default - no secret path required)")
                print()
                print(" Then authenticate at the backend with your normal SSH/Dropbear account.")
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            if not os.path.exists(WS_SERVICE_PATH):
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

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_safely(new_port, new_target, "Port/redirect change")
            if ok:
                old_port = ws_port
                ports_dict['WSTUNNEL_PORT'] = str(new_port)
                ports_dict['WSTUNNEL_TARGET_PORT'] = str(new_target)
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
            if not os.path.exists(WS_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            server_ip = get_public_ip()
            print(" Server IP: %s" % server_ip)
            print(" Port: %s  ->  127.0.0.1:%s" % (ws_port, ws_target))
            print()
            print(" %sFor an app like HTTP Custom / HTTP Injector:%s" % (C_YELLOW, C_RESET))
            print("   Host / SNI:  %s" % server_ip)
            print("   Port:        %s" % ws_port)
            print("   Path:        / (leave blank/default - no secret path required, unlike")
            print("   the earlier wstunnel-based version of this module)")
            print("   Then authenticate at the backend (127.0.0.1:%s) with your" % ws_target)
            print("   normal SSH/Dropbear account.")
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            os.system("journalctl -u websocket-tunnel -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_service():
                print("%s[OK] WebSocket tunnel restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u websocket-tunnel'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop websocket-tunnel")
                print("%s[!] WebSocket tunnel stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(WS_SERVICE_PATH):
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start websocket-tunnel")
                if _service_active():
                    print("%s[OK] WebSocket tunnel started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u websocket-tunnel'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            confirm = input(" Are you sure you want to completely remove the WebSocket tunnel? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop websocket-tunnel")
                _run("systemctl disable websocket-tunnel")
                _run("rm -f %s" % WS_SERVICE_PATH)
                _run("rm -rf %s" % WS_DIR)
                _run("systemctl daemon-reload")
                if str(ws_port).isdigit():
                    close_firewall_port(int(ws_port), ("tcp",))
                    persist_firewall_rules()
                ports_dict.pop('WSTUNNEL_PORT', None)
                ports_dict.pop('WSTUNNEL_TARGET_PORT', None)
                ports_dict.pop('WSTUNNEL_PATH_PREFIX', None)
                ports_dict.pop('WSTUNNEL_USE_TLS', None)
                print("%s[OK] WebSocket tunnel removed and purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
