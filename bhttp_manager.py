"""
bhttp_manager.py - "BHTTP Tunnel" admin module for the SmartUI panel.

Design notes (read before changing the protocol):

Seen only as a name ("BHTTP TUNNEL") next to "HCR Custom" in the same
third-party screenshot, with no fields of its own shown and no source
available anywhere - so, same as hcr_manager.py, this is an independent
design built to integrate with this panel rather than a byte-compatible
clone of an unknown wire format.

Unlike HCR (a long-polling tunnel, chosen because the screenshot exposed
polling-specific parameters), BHTTP is modeled as the simpler sibling: a
single persistent bidirectional TCP connection, the same proven shape as
websocket_manager.py and ws_epro_manager.py, but fronted by a plain HTTP/1.1
200 response instead of a 101 WebSocket upgrade. That is the actual
distinction the "B" (bidirectional/bug) HTTP tunnels in this app ecosystem
are known for: some client apps and some network paths handle a plain
"HTTP response, then raw bytes" framing more reliably than a WebSocket
upgrade, without needing a long-poll request/response cycle for every chunk
- so this gives the panel a second, differently-shaped plain-HTTP option
alongside WEBSOCKET and HCR CUSTOM, rather than a third copy of the same
thing. Same optional self-signed-TLS toggle as HCR, same reasoning as there
for terminating it directly in Python rather than via a separate daemon.
"""

import os
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_public_ip, get_live_port_from_service,
)

BHTTP_DIR = "/etc/bhttp-tunnel"
BHTTP_SCRIPT_PATH = "/etc/bhttp-tunnel/bridge.py"
BHTTP_SERVICE_PATH = "/etc/systemd/system/bhttp-tunnel.service"
BHTTP_PEM_PATH = "/etc/bhttp-tunnel/bhttp.pem"

BRIDGE_SCRIPT = '''#!/usr/bin/env python3
"""Standalone BHTTP bidirectional tunnel - plain Python3, no third-party
daemon. Reads and discards one plain HTTP request, replies with a plain
HTTP/1.1 200 (not a WebSocket 101 upgrade - see bhttp_manager.py's module
docstring for why), then relays raw bytes both ways to TARGET_PORT on
localhost, same relay pattern as websocket-tunnel's own bridge script."""
import os
import socket
import ssl
import sys
import threading

LISTEN_PORT = int(os.environ.get("BHTTP_LISTEN_PORT", "8080"))
TARGET_HOST = "127.0.0.1"
TARGET_PORT = int(os.environ.get("BHTTP_TARGET_PORT", "22"))
USE_TLS = os.environ.get("BHTTP_USE_TLS", "0") == "1"
PEM_PATH = os.environ.get("BHTTP_PEM_PATH", "/etc/bhttp-tunnel/bhttp.pem")

RESPONSE = (
    b"HTTP/1.1 200 Connection Established\\r\\n"
    b"Connection: keep-alive\\r\\n"
    b"\\r\\n"
)


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
        sys.stderr.write("bhttp-tunnel: cannot reach backend %s:%s: %s\\n" % (TARGET_HOST, TARGET_PORT, e))
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

    if USE_TLS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=PEM_PATH, keyfile=PEM_PATH)

    while True:
        client_sock, _ = server.accept()
        if USE_TLS:
            try:
                client_sock = ctx.wrap_socket(client_sock, server_side=True)
            except Exception as e:
                sys.stderr.write("bhttp-tunnel: TLS handshake failed: %s\\n" % e)
                try:
                    client_sock.close()
                except Exception:
                    pass
                continue
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()
'''


def _deploy_script():
    os.makedirs(BHTTP_DIR, exist_ok=True)
    with open(BHTTP_SCRIPT_PATH, "w") as f:
        f.write(BRIDGE_SCRIPT)
    os.chmod(BHTTP_SCRIPT_PATH, 0o755)


def _generate_self_signed_cert():
    os.makedirs(BHTTP_DIR, exist_ok=True)
    result = _run(
        "openssl req -new -x509 -days 3650 -nodes -out %s -keyout %s "
        "-subj '/CN=bhttp-tunnel' 2>/dev/null" % (BHTTP_PEM_PATH, BHTTP_PEM_PATH)
    )
    return result.returncode == 0 and os.path.exists(BHTTP_PEM_PATH)


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "bhttp-tunnel"]).returncode == 0


def _restart_service():
    _run("systemctl reset-failed bhttp-tunnel")
    return _run("systemctl restart bhttp-tunnel").returncode == 0


def _wait_for_port_listening(port, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _write_service(listen_port, target_port, use_tls):
    _deploy_script()
    if use_tls and not os.path.exists(BHTTP_PEM_PATH):
        _generate_self_signed_cert()
    service_content = """[Unit]
Description=BHTTP Tunnel (plain Python3 relay)
After=network.target

[Service]
Type=simple
User=root
Environment="BHTTP_LISTEN_PORT=%s"
Environment="BHTTP_TARGET_PORT=%s"
Environment="BHTTP_USE_TLS=%s"
Environment="BHTTP_PEM_PATH=%s"
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % (listen_port, target_port, "1" if use_tls else "0", BHTTP_PEM_PATH, BHTTP_SCRIPT_PATH)
    with open(BHTTP_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_safely(listen_port, target_port, use_tls, description):
    original = None
    if os.path.exists(BHTTP_SERVICE_PATH):
        with open(BHTTP_SERVICE_PATH, "r") as f:
            original = f.read()

    _write_service(listen_port, target_port, use_tls)

    if not _restart_service():
        if original is not None:
            with open(BHTTP_SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_service()
        return False, "%s failed to restart - check 'journalctl -u bhttp-tunnel'." % description

    if not _wait_for_port_listening(listen_port):
        if original is not None:
            with open(BHTTP_SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_service()
        return False, "%s restarted, but port %s never came up - reverted. Nothing was left broken." % (description, listen_port)

    return True, "%s applied and verified on port %s." % (description, listen_port)


def bhttp_admin_manager(ports_dict):
    """Standalone BHTTP Tunnel Administrator Module."""
    while True:
        if os.path.exists(BHTTP_SERVICE_PATH):
            _run("systemctl enable bhttp-tunnel")
        live_port = get_live_port_from_service(BHTTP_SERVICE_PATH, r'BHTTP_LISTEN_PORT=(\d+)')
        if live_port and str(ports_dict.get('BHTTP_PORT')) != str(live_port):
            print(f"{C_YELLOW}[!] The saved port didn't match what's actually running ({live_port}) -")
            print(f"    correcting the panel's records to match reality.{C_RESET}")
            ports_dict['BHTTP_PORT'] = live_port
            input("\nPress Enter to continue...")

        bhttp_port = ports_dict.get('BHTTP_PORT', 'Not configured')
        bhttp_target = ports_dict.get('BHTTP_TARGET_PORT', '22')
        use_tls = ports_dict.get('BHTTP_USE_TLS', '0') == '1'
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                  BHTTP TUNNEL ADMINISTRATOR                %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      PORT: %s  |  REDIRECTION TARGET: %s" % (bhttp_port, bhttp_target))
        print("      SSL/TLS MODE: %s" % ("ON" if use_tls else "OFF"))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL BHTTP TUNNEL")
        print(" [2]> MODIFY PORT & REDIRECTION")
        print(" [3]> TOGGLE SSL/TLS MODE")
        print(" [4]> VIEW CONNECTION INFO")
        print(" [5]> VIEW SERVICE LOGS")
        print(" [6]> RESTART SERVICE")
        print(" [7]> START/STOP SERVICE [%s]" % status_label)
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [8] UNINSTALL BHTTP TUNNEL")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    SETUP WIZARD                            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter BHTTP port (e.g., 8080): ", default=8080)
            if str(listen_port) != str(bhttp_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            target_port = prompt_port(" Enter redirect port (e.g., 22 for SSH, 143 for Dropbear): ", default=22)
            if not check_system_port_in_use(target_port, ("tcp",)):
                print("%s[!] Nothing seems to be listening on port %s yet.%s" % (C_YELLOW, target_port, C_RESET))

            tls_choice = input(" Enable SSL/TLS mode? (y/n) [n]: ").strip().lower()
            new_use_tls = tls_choice == 'y'

            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable bhttp-tunnel")

            ok, msg = _apply_safely(listen_port, target_port, new_use_tls, "BHTTP tunnel")
            if ok:
                ports_dict['BHTTP_PORT'] = str(listen_port)
                ports_dict['BHTTP_TARGET_PORT'] = str(target_port)
                ports_dict['BHTTP_USE_TLS'] = '1' if new_use_tls else '0'
                server_ip = get_public_ip()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print()
                print(" Client setup (HTTP Custom / HTTP Injector or similar):")
                print("   Host:  %s" % server_ip)
                print("   Port:  %s" % listen_port)
                print("   Scheme: %s" % ("https" if new_use_tls else "http"))
                print("   Path:  / (any request line is accepted - no Upgrade header required)")
                print()
                print(" Then authenticate at the backend with your normal SSH/Dropbear account.")
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            if not os.path.exists(BHTTP_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new BHTTP port [Current: %s]: " % bhttp_port,
                                    default=int(bhttp_port) if str(bhttp_port).isdigit() else 8080)
            if str(new_port) != str(bhttp_port) and check_system_port_in_use(new_port, ("tcp",)):
                print("%s[X] Port %s is already in use.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_target = prompt_port(" Enter new redirect port [Current: %s]: " % bhttp_target,
                                      default=int(bhttp_target) if str(bhttp_target).isdigit() else 22)

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_safely(new_port, new_target, use_tls, "Port/redirect change")
            if ok:
                old_port = bhttp_port
                ports_dict['BHTTP_PORT'] = str(new_port)
                ports_dict['BHTTP_TARGET_PORT'] = str(new_target)
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
            if not os.path.exists(BHTTP_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            new_use_tls = not use_tls
            if new_use_tls and not os.path.exists(BHTTP_PEM_PATH):
                print("%s[i] No certificate found - generating a self-signed one so this actually works.%s" % (C_CYAN, C_RESET))
                if not _generate_self_signed_cert():
                    print("%s[X] Certificate generation failed - leaving SSL/TLS mode off.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
            ok, msg = _apply_safely(bhttp_port, bhttp_target, new_use_tls, "SSL/TLS mode change")
            if ok:
                ports_dict['BHTTP_USE_TLS'] = '1' if new_use_tls else '0'
                print("%s[OK] SSL/TLS mode is now %s. %s%s" % (C_GREEN, "ON" if new_use_tls else "OFF", msg, C_RESET))
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            if not os.path.exists(BHTTP_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            server_ip = get_public_ip()
            print(" Server IP: %s" % server_ip)
            print(" Port: %s  ->  127.0.0.1:%s" % (bhttp_port, bhttp_target))
            print(" Scheme: %s" % ("https" if use_tls else "http"))
            print()
            print(" %sFor an app like HTTP Custom / HTTP Injector:%s" % (C_YELLOW, C_RESET))
            print("   Host / SNI:  %s" % server_ip)
            print("   Port:        %s" % bhttp_port)
            print("   Path:        / (any request line is accepted)")
            print("   Then authenticate at the backend (127.0.0.1:%s) with your" % bhttp_target)
            print("   normal SSH/Dropbear account.")
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            os.system("journalctl -u bhttp-tunnel -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if _restart_service():
                print("%s[OK] BHTTP tunnel restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u bhttp-tunnel'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            if is_active:
                _run("systemctl stop bhttp-tunnel")
                print("%s[!] BHTTP tunnel stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(BHTTP_SERVICE_PATH):
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start bhttp-tunnel")
                if _service_active():
                    print("%s[OK] BHTTP tunnel started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u bhttp-tunnel'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            confirm = input(" Are you sure you want to completely remove the BHTTP tunnel? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop bhttp-tunnel")
                _run("systemctl disable bhttp-tunnel")
                _run("rm -f %s" % BHTTP_SERVICE_PATH)
                _run("rm -rf %s" % BHTTP_DIR)
                _run("systemctl daemon-reload")
                if str(bhttp_port).isdigit():
                    close_firewall_port(int(bhttp_port), ("tcp",))
                    persist_firewall_rules()
                ports_dict.pop('BHTTP_PORT', None)
                ports_dict.pop('BHTTP_TARGET_PORT', None)
                ports_dict.pop('BHTTP_USE_TLS', None)
                print("%s[OK] BHTTP tunnel removed and purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
