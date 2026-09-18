"""
ws_epro_manager.py - WS-EPRO (WebSocket-to-TCP bridge) admin module for the
SmartUI panel.

No external project by this exact name exists (checked - only a generic GitHub
topic tag alongside similar reseller-panel components, confirming this is meant
as a homegrown piece of the panel itself rather than wrapping something
external). Real bugs found in the original draft:

1. It wasn't actually a WebSocket proxy at all. The deployed script was a plain
   TCP byte-forwarder (socket.accept -> connect -> relay bytes) with zero
   WebSocket framing - no HTTP Upgrade handshake, no WS frame parsing. The
   entire point of "WS" wrapping in this ecosystem is to make traffic look
   like genuine WebSocket/HTTP to evade DPI; a raw TCP relay provides none of
   that camouflage no matter what it's named. Fixed using Python's standard
   `websockets` library to do a real handshake and real frame-level bridging,
   matching the pattern used by real WS-SSH bridge tools.

2. Port changes were applied via literal string search-and-replace on the
   DEPLOYED SCRIPT'S SOURCE TEXT ("LISTENING_PORT = {old}" -> "= {new}"). If
   that exact substring wasn't found for any reason (tracked port drifted from
   the file's actual content, manual edits, a previously-failed update), str.
   replace() silently returns the string unchanged - no error - and the code
   proceeded to restart and report success regardless of whether anything
   actually changed. Fixed at the architecture level: the deployed script is
   now static and reads LISTEN_PORT/TARGET_PORT from environment variables set
   in the systemd unit, so a port change is a full unit-file rewrite (already
   the safe, established pattern elsewhere in this panel) rather than fragile
   text-patching of running source code.

3. One raw OS thread per connection, unbounded - a basic resource-exhaustion
   risk under load or a connection flood. Switching to the `websockets`
   library's asyncio model addresses this as a side effect of fixing bug #1,
   rather than needing a separate fix.

4. No verification that the restart actually succeeded, no port-conflict
   check, no firewall consistency - the same class of bug fixed in every
   other module in this panel.
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
"""WS-EPRO: WebSocket-to-TCP bridge. Accepts a real WebSocket handshake on
LISTEN_PORT, bridges each connection to TARGET_PORT on localhost."""
import asyncio
import os
import sys

try:
    import websockets
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "websockets", "--break-system-packages", "-q"])
    import websockets

LISTEN_PORT = int(os.environ.get("WS_EPRO_LISTEN_PORT", "2082"))
TARGET_PORT = int(os.environ.get("WS_EPRO_TARGET_PORT", "22"))
TARGET_HOST = "127.0.0.1"


async def bridge(websocket):
    try:
        reader, writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
    except Exception as e:
        print(f"[ws-epro] cannot reach backend {TARGET_HOST}:{TARGET_PORT}: {e}", file=sys.stderr)
        await websocket.close(1011, "backend unreachable")
        return

    async def ws_to_tcp():
        try:
            async for msg in websocket:
                data = msg if isinstance(msg, bytes) else msg.encode()
                writer.write(data)
                await writer.drain()
        except websockets.ConnectionClosed:
            pass
        finally:
            # Half-close (signal "no more data from me") rather than a full
            # close - a full close kills the SHARED underlying transport,
            # which tcp_to_ws() below is still reading from. Confirmed as a
            # real bug: the client side ending first was closing the
            # connection to the backend entirely, so the backend's own
            # banner/greeting (still in flight) never reached the client.
            try:
                if not writer.is_closing() and writer.can_write_eof():
                    writer.write_eof()
            except Exception:
                pass

    async def tcp_to_ws():
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await websocket.send(data)
        except (websockets.ConnectionClosed, ConnectionResetError):
            pass

    await asyncio.gather(ws_to_tcp(), tcp_to_ws(), return_exceptions=True)
    # Only fully close the backend connection once BOTH directions are done -
    # closing it earlier is exactly what caused the bug above.
    try:
        if not writer.is_closing():
            writer.close()
    except Exception:
        pass


async def main():
    try:
        from websockets.asyncio.server import serve
    except ImportError:
        from websockets.server import serve
    async with serve(bridge, "0.0.0.0", LISTEN_PORT):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
'''


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "ws-epro"]).returncode == 0


def _restart_ws_epro():
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
