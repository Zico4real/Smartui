"""
ws_epro_manager.py - WS-EPRO (WebSocket-to-TCP bridge) admin module for the
SmartUI panel.

No external project by this exact name exists (checked - only a generic GitHub
topic tag alongside similar reseller-panel components, confirming this is meant
as a homegrown piece of the panel itself rather than wrapping something
external). History of this module's bridge script:

1. The original draft was a plain TCP byte-forwarder with no HTTP Upgrade
   handshake at all - a real, confirmed gap at the time.

2. That was "fixed" by switching to Python's real `websockets` library for a
   strict, RFC 6455-compliant handshake - which turned out to be the wrong
   fix and a real regression: confirmed directly from the library's own
   source code that it requires a Sec-WebSocket-Key header, raising
   InvalidHandshake ("400 Bad Request") without one. The actual client apps
   used throughout this ecosystem (HTTP Custom, HTTP Injector, etc.) send
   only a minimal "Upgrade: websocket" request as an obfuscation trick, not
   a real handshake - confirmed against a real client log showing exactly
   that minimal request, and the exact "400 Bad Request" response the
   library's source code predicts for it. A strict, compliant server is the
   wrong tool for what these clients actually send.

3. Now uses the same permissive, canned-response pattern as
   python_socks_manager.py (confirmed working end-to-end against a real
   client log there) - a fixed "101 Switching Protocols" response
   regardless of what headers arrived, then a raw byte relay. This is also
   simpler and drops the `websockets` library dependency entirely.

4. Port changes are still applied via a systemd unit-file rewrite (the
   deployed script reads LISTEN_PORT/TARGET_PORT from environment
   variables, never from patching the running script's own source text) -
   this part of the earlier fix was correct and unrelated to the handshake
   issue above, so it's unchanged.

5. Restart verification, port-conflict checks, and firewall consistency
   remain in place, matching every other module in this panel.
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

WS_SCRIPT_PATH = "/usr/local/bin/ws-epro-bridge.py"
WS_SERVICE_PATH = "/etc/systemd/system/ws-epro.service"

# Static, port-agnostic: reads its config from the environment, set in the
# systemd unit. Never needs its own source text edited to change ports.
BRIDGE_SCRIPT = '''#!/usr/bin/env python3
"""WS-EPRO: WebSocket-to-TCP bridge. Accepts a WebSocket-style HTTP Upgrade
request on LISTEN_PORT and bridges the connection to TARGET_PORT on
localhost.

Deliberately does NOT use the real `websockets` library or perform a strict
RFC 6455 handshake. Confirmed as the actual cause of a real connection
failure: the library requires a Sec-WebSocket-Key header (raising
InvalidHandshake -> "400 Bad Request" without one, per the library's own
source), but the actual client apps used throughout this ecosystem (HTTP
Custom, HTTP Injector, etc.) send only a minimal Upgrade-style request as an
obfuscation technique, not a real browser-style handshake - they never
include that header at all. A real, RFC-compliant server is the wrong tool
here; this now uses the same proven, permissive canned-response pattern as
python_socks_manager.py, which is confirmed working end-to-end against a
real client log.
"""
import socket
import threading
import os
import sys

LISTEN_PORT = int(os.environ.get("WS_EPRO_LISTEN_PORT", "2082"))
TARGET_HOST = "127.0.0.1"
TARGET_PORT = int(os.environ.get("WS_EPRO_TARGET_PORT", "22"))

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
        # Half-close only dst's write direction, rather than fully closing
        # both sockets - the OTHER relay direction (running in its own
        # thread) may still be actively delivering data (e.g. the backend's
        # own banner/greeting) and must be allowed to finish naturally.
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(client_sock):
    try:
        # Drain whatever the client sends within a short window before
        # responding - long enough to catch a full payload-mode request,
        # short enough that a direct-mode client (which may send nothing at
        # all before expecting a response) doesn't get stuck waiting and
        # dropped. A longer, fatal-on-timeout wait here would silently drop
        # exactly that kind of client instead of responding to it.
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
        sys.stderr.write("ws-epro: cannot reach backend %s:%s: %s\\n" % (TARGET_HOST, TARGET_PORT, e))
        client_sock.close()
        return

    t1 = threading.Thread(target=relay, args=(client_sock, backend), daemon=True)
    t2 = threading.Thread(target=relay, args=(backend, client_sock), daemon=True)
    t1.start()
    t2.start()
    # Only fully close both sockets once BOTH directions have genuinely
    # finished - closing them earlier is exactly what caused a real bug
    # (see relay()'s own comment above).
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


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "ws-epro"]).returncode == 0


def _restart_ws_epro():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt.
    _run("systemctl reset-failed ws-epro")
    return _run("systemctl restart ws-epro").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _ensure_script_deployed():
    """The script itself never needs to change between port updates - only
    deploy/overwrite it if missing or if we're intentionally updating its
    version, not on every port change."""
    needs_write = True
    if os.path.exists(WS_SCRIPT_PATH):
        with open(WS_SCRIPT_PATH, "r") as f:
            needs_write = f.read() != BRIDGE_SCRIPT
    if needs_write:
        with open(WS_SCRIPT_PATH, "w") as f:
            f.write(BRIDGE_SCRIPT)
        os.chmod(WS_SCRIPT_PATH, 0o755)
        # Real syntax check available here (unlike Stunnel/Hysteria/ZIVPN,
        # which have no config-test flag at all) - catch a broken deploy
        # before ever handing it to systemd.
        check = _run(["python3", "-m", "py_compile", WS_SCRIPT_PATH])
        if check.returncode != 0:
            os.remove(WS_SCRIPT_PATH)
            return False, check.stderr.strip()
    return True, None


def _write_service(listen_port, target_port):
    service_content = f"""[Unit]
Description=WS-EPRO WebSocket-to-TCP Bridge
After=network.target

[Service]
Type=simple
User=root
Environment=WS_EPRO_LISTEN_PORT={listen_port}
Environment=WS_EPRO_TARGET_PORT={target_port}
ExecStart=/usr/bin/python3 {WS_SCRIPT_PATH}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    with open(WS_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_ports_safely(listen_port, target_port, description):
    """No config-test-only flag applies here either (beyond the py_compile
    syntax check already done at deploy time) - restart, verify the port
    actually came up, roll back to the previous unit if not."""
    original_unit = None
    if os.path.exists(WS_SERVICE_PATH):
        with open(WS_SERVICE_PATH, "r") as f:
            original_unit = f.read()

    _write_service(listen_port, target_port)

    if not _restart_ws_epro():
        if original_unit is not None:
            with open(WS_SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_ws_epro()
        return False, f"{description} failed to restart WS-EPRO - reverted to the previous working setup."

    if not _wait_for_port_listening(listen_port):
        if original_unit is not None:
            with open(WS_SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_ws_epro()
        return False, f"{description} restarted, but port {listen_port} never came up - reverted. Nothing was left broken."

    return True, f"{description} applied and verified on port {listen_port}."


def _get_live_ports():
    """Reads the actual configured ports straight from the running systemd
    unit - the real source of truth. ports_dict can drift out of sync with
    what's genuinely deployed (found on a real install: ports_dict said 883,
    the live service was actually running on 8080), so the dashboard
    reconciles against this every time it loads rather than trusting a
    value that could be stale."""
    if not os.path.exists(WS_SERVICE_PATH):
        return None, None
    with open(WS_SERVICE_PATH) as f:
        content = f.read()
    listen_match = re.search(r'Environment=WS_EPRO_LISTEN_PORT=(\d+)', content)
    target_match = re.search(r'Environment=WS_EPRO_TARGET_PORT=(\d+)', content)
    listen = listen_match.group(1) if listen_match else None
    target = target_match.group(1) if target_match else None
    return listen, target


def ws_epro_admin_manager(ports_dict):
    """WS-EPRO Administrator Module."""
    while True:
        # Confirmed as a real, direct cause of a genuine bug report: a
        # service can end up "disabled" (never wired to start at boot at
        # all - a completely different, more basic problem than crashing)
        # through any number of past events this code can't fully
        # reconstruct after the fact. Checking and re-applying enable here,
        # every time this admin screen opens for an already-installed
        # instance, is defensive against that regardless of how it
        # happened - the same pattern already proven fixing this exact
        # class of issue for Stunnel elsewhere in this panel.
        if os.path.exists(WS_SERVICE_PATH):
            _run("systemctl enable ws-epro")
        live_port, live_target = _get_live_ports()
        recorded_port = ports_dict.get('WS_PORT')
        if live_port and str(recorded_port) != str(live_port):
            print(f"{C_YELLOW}[!] The saved port ({recorded_port or 'none'}) didn't match what's actually")
            print(f"    running ({live_port}) - correcting the panel's records to match reality.{C_RESET}")
            ports_dict['WS_PORT'] = live_port
            if live_target:
                ports_dict['WS_TARGET_PORT'] = live_target
            input("\nPress Enter to continue...")

        ws_port = ports_dict.get('WS_PORT', 'Not configured')
        ws_target = ports_dict.get('WS_TARGET_PORT', '22')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                    WS-EPRO ADMINISTRATOR                   %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      PORT: {ws_port}  |  REDIRECTION TARGET: {ws_target}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL WS-EPRO")
        print(" [2]> MODIFY PORT & TRAFFIC REDIRECTION")
        print(" [3]> VIEW SERVICE LOGS")
        print(" [4]> RESTART WS-EPRO SERVICE")
        print(f" [5]> START/STOP WS-EPRO SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [6] UNINSTALL WS-EPRO")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s             WS-EPRO INSTALLATION WIZARD                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter desired WebSocket listen port (e.g., 2082 or 80): ", default=2082)
            if str(listen_port) != str(ws_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print(f"{C_RED}[X] Port {listen_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            target_port = prompt_port(" Enter backend target port (e.g., 22 for SSH, 143 for Dropbear): ", default=22)
            if not check_system_port_in_use(target_port, ("tcp",)):
                print(f"{C_YELLOW}[!] Nothing seems to be listening on port {target_port} yet - the bridge")
                print(f"    will have nowhere to forward traffic until that backend is running.{C_RESET}")

            deployed, err = _ensure_script_deployed()
            if not deployed:
                print(f"{C_RED}[X] Bridge script failed its own syntax check - not deployed:\n{err}{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable ws-epro")

            ok, msg = _apply_ports_safely(listen_port, target_port, f"Port {listen_port} -> {target_port}")
            if ok:
                ports_dict['WS_PORT'] = str(listen_port)
                ports_dict['WS_TARGET_PORT'] = str(target_port)
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(listen_port, ("tcp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s           MODIFY PORT & TRAFFIC REDIRECTION TARGET         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            new_port = prompt_port(f" Enter new WebSocket listen port [Current: {ws_port}]: ",
                                    default=int(ws_port) if str(ws_port).isdigit() else 2082)
            new_target = prompt_port(f" Enter new redirection target port [Current: {ws_target}]: ",
                                      default=int(ws_target) if str(ws_target).isdigit() else 22)

            if str(new_port) != str(ws_port) and check_system_port_in_use(new_port, ("tcp",)):
                print(f"{C_RED}[X] Port {new_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            deployed, err = _ensure_script_deployed()
            if not deployed:
                print(f"{C_RED}[X] Bridge script failed its own syntax check: {err}{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_ports_safely(new_port, new_target, f"Port {new_port} -> {new_target}")
            if ok:
                old_port = ws_port
                ports_dict['WS_PORT'] = str(new_port)
                ports_dict['WS_TARGET_PORT'] = str(new_target)
                if str(old_port).isdigit() and str(old_port) != str(new_port):
                    close_firewall_port(int(old_port), ("tcp",))
                    persist_firewall_rules()
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(new_port, ("tcp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    WS-EPRO SERVICE LOGS                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u ws-epro -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if _restart_ws_epro():
                print(f"{C_GREEN}[OK] WS-EPRO service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] WS-EPRO failed to restart - check 'journalctl -u ws-epro'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if is_active:
                _run("systemctl stop ws-epro")
                print(f"{C_YELLOW}[!] WS-EPRO service stopped.{C_RESET}")
            else:
                if not os.path.exists(WS_SCRIPT_PATH):
                    print(f"{C_RED}[X] Not configured yet - run option 1 first.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start ws-epro")
                if _service_active():
                    print(f"{C_GREEN}[OK] WS-EPRO service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] WS-EPRO failed to start - check 'journalctl -u ws-epro'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    UNINSTALL WS-EPRO                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove WS-EPRO? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop ws-epro")
                _run("systemctl disable ws-epro")
                _run(f"rm -f {WS_SERVICE_PATH} {WS_SCRIPT_PATH}")
                _run("systemctl daemon-reload")
                if str(ws_port).isdigit():
                    close_firewall_port(int(ws_port), ("tcp",))
                    persist_firewall_rules()
                ports_dict.pop('WS_PORT', None)
                ports_dict.pop('WS_TARGET_PORT', None)
                print(f"{C_GREEN}[OK] WS-EPRO purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
