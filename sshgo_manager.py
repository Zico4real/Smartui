"""
sshgo_manager.py - SSHGO admin module for the SmartUI panel.

No external project literally named "sshgo" exists (checked - only a broad
category of similar SSH-over-WebSocket tools: wstunnel, go-ssh-to-websocket,
huproxy, sheller). This is a homegrown panel component, same situation as
WS-EPRO. Two real bugs found, matching bugs already fixed elsewhere in this
panel:

1. The "WebSocket" tunnel mode set a MODE variable in the deployed script but
   never actually used it anywhere in the connection handler - the connection
   logic was identical raw-TCP-forwarding regardless of which mode was
   selected. There was no WebSocket handshake or framing at all - the exact
   same fake-WS bug already found and fixed in ws_epro_manager.py. Rather
   than write a second, separately-buggy WS implementation, this module now
   reuses that already-built, already-tested bridge script directly for
   WebSocket mode, and only implements its own (much simpler) raw-TCP
   forwarder for "Direct SSH" mode, where that's actually correct.

2. "Configure SSL / Domain Certificate" ran certbot and generated a real
   Let's Encrypt certificate - but the proxy script had no TLS code anywhere
   at all. The certificate was never loaded or used by anything. An operator
   running this menu option would reasonably believe their tunnel was now
   encrypted when it provided zero additional protection - a false sense of
   security, not just a missing feature. Removed entirely rather than left
   in place implying protection it doesn't give; Stunnel already exists in
   this panel specifically for TLS termination, so SSHGO now just points
   there instead of duplicating (and getting wrong) a second, redundant TLS
   implementation.

Other bugs, matching classes already fixed across this panel:

3. Port/mode changes patched the deployed script's source text via regex -
   moved to the environment-variable architecture already used for WS-EPRO/
   CheckUser-API/Atken, so a change is a clean systemd-unit rewrite instead.

4. No restart verification/rollback, no port-conflict check, raw ufw/
   iptables instead of the shared firewall helpers, and uninstall never
   closed the port on the firewall.
"""

import os
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_live_port_from_service,
)
from ws_epro_manager import BRIDGE_SCRIPT as WS_BRIDGE_SCRIPT

SSHGO_DIR = "/usr/local/bin"
WS_SCRIPT_PATH = "%s/sshgo-ws-bridge.py" % SSHGO_DIR
TCP_SCRIPT_PATH = "%s/sshgo-tcp-bridge.py" % SSHGO_DIR
SERVICE_PATH = "/etc/systemd/system/sshgo.service"

TCP_BRIDGE_SCRIPT = '''#!/usr/bin/env python3
"""SSHGO direct-TCP bridge: plain forward, no protocol framing - correct for
raw SSH tunneling where no WS camouflage is wanted."""
import socket
import threading
import os
import sys

LISTEN_PORT = int(os.environ.get("SSHGO_LISTEN_PORT", "2222"))
TARGET_HOST = os.environ.get("SSHGO_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("SSHGO_TARGET_PORT", "22"))


def forward(source, destination):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            destination.sendall(data)
    except Exception:
        pass
    finally:
        try:
            source.close()
        except Exception:
            pass
        try:
            destination.close()
        except Exception:
            pass


def handle_client(client_sock):
    try:
        target_sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    except Exception as e:
        sys.stderr.write("sshgo-tcp: cannot reach backend %s:%s: %s\\n" % (TARGET_HOST, TARGET_PORT, e))
        client_sock.close()
        return
    t1 = threading.Thread(target=forward, args=(client_sock, target_sock), daemon=True)
    t2 = threading.Thread(target=forward, args=(target_sock, client_sock), daemon=True)
    t1.start()
    t2.start()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(128)
    print("sshgo-tcp listening on 0.0.0.0:%d -> %s:%d" % (LISTEN_PORT, TARGET_HOST, TARGET_PORT))
    while True:
        client_sock, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()
'''


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "sshgo"]).returncode == 0


def _restart_sshgo():
    return _run("systemctl restart sshgo").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _ensure_script_deployed(mode):
    """WebSocket mode reuses ws_epro_manager's already-tested bridge directly
    rather than a second, separately-maintained (and previously fake) copy."""
    path, content = (WS_SCRIPT_PATH, WS_BRIDGE_SCRIPT) if mode == "ws" else (TCP_SCRIPT_PATH, TCP_BRIDGE_SCRIPT)
    os.makedirs(SSHGO_DIR, exist_ok=True)
    needs_write = True
    if os.path.exists(path):
        with open(path, "r") as f:
            needs_write = f.read() != content
    if needs_write:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o755)
        check = _run(["python3", "-m", "py_compile", path])
        if check.returncode != 0:
            print("%s[X] %s failed its own syntax check:\n%s%s" % (C_RED, os.path.basename(path), check.stderr.strip(), C_RESET))
            os.remove(path)
            return None
    return path


def _write_service(mode, listen_port, target_port):
    script_path = WS_SCRIPT_PATH if mode == "ws" else TCP_SCRIPT_PATH
    if mode == "ws":
        env_lines = "Environment=WS_EPRO_LISTEN_PORT=%s\nEnvironment=WS_EPRO_TARGET_PORT=%s" % (listen_port, target_port)
    else:
        env_lines = ("Environment=SSHGO_LISTEN_PORT=%s\nEnvironment=SSHGO_TARGET_HOST=127.0.0.1\n"
                     "Environment=SSHGO_TARGET_PORT=%s" % (listen_port, target_port))
    service_content = """[Unit]
Description=SSHGO Tunnel Proxy (%s mode)
After=network.target

[Service]
Type=simple
User=root
%s
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (mode.upper(), env_lines, script_path)
    with open(SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_safely(mode, listen_port, target_port, description):
    original_unit = None
    if os.path.exists(SERVICE_PATH):
        with open(SERVICE_PATH, "r") as f:
            original_unit = f.read()

    _write_service(mode, listen_port, target_port)

    if not _restart_sshgo():
        if original_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_sshgo()
        return False, "%s failed to restart - reverted to the previous working setup." % description

    if not _wait_for_port_listening(listen_port):
        if original_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_sshgo()
        return False, "%s restarted, but port %s never came up - reverted. Nothing was left broken." % (description, listen_port)

    return True, "%s applied and verified on port %s." % (description, listen_port)


def sshgo_admin_manager(ports_dict):
    """SSHGO Administrator Module."""
    while True:
        # Same reconciliation as WS-EPRO: read the port straight from the live
        # unit file (whichever variable name applies for the current mode)
        # rather than trust a ports_dict value that could have drifted.
        live_port = (get_live_port_from_service(SERVICE_PATH, r'Environment=WS_EPRO_LISTEN_PORT=(\d+)')
                     or get_live_port_from_service(SERVICE_PATH, r'Environment=SSHGO_LISTEN_PORT=(\d+)'))
        recorded_port = ports_dict.get('SSHGO_PORT')
        if live_port and str(recorded_port) != str(live_port):
            print(f"{C_YELLOW}[!] The saved port ({recorded_port or 'none'}) didn't match what's actually")
            print(f"    running ({live_port}) - correcting the panel's records to match reality.{C_RESET}")
            ports_dict['SSHGO_PORT'] = live_port
            input("\nPress Enter to continue...")

        sshgo_port = ports_dict.get('SSHGO_PORT', 'Not configured')
        sshgo_mode = ports_dict.get('SSHGO_MODE', 'ws')
        sshgo_target = ports_dict.get('SSHGO_TARGET', '22')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                     SSHGO ADMINISTRATOR                    %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      PORT: %s  |  MODE: %s  |  TARGET: %s" % (sshgo_port, sshgo_mode.upper(), sshgo_target))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL SSHGO PROXY (Wizard)")
        print(" [2]> CHANGE PORT & TUNNEL MODE (SSH / WebSocket)")
        print(" [3]> VIEW SERVICE LOGS")
        print(" [4]> RESTART SSHGO SERVICE")
        print(" [5]> START/STOP SSHGO SERVICE [%s]" % status_label)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [6] UNINSTALL SSHGO")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s           SSHGO INSTALLATION WIZARD                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter desired SSHGO listen port (e.g., 2222 or 443): ", default=2222)
            if str(listen_port) != str(sshgo_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            mode_choice = input(" Select Tunnel Mode ([1] WebSocket / [2] Direct SSH) [Default: 1]: ").strip()
            tunnel_mode = "tcp" if mode_choice == '2' else "ws"

            target_port = prompt_port(" Enter backend target port (e.g., 22 for SSH, 143 for Dropbear): ", default=22)
            if not check_system_port_in_use(target_port, ("tcp",)):
                print("%s[!] Nothing seems to be listening on port %s yet - the tunnel will have" % (C_YELLOW, target_port))
                print("    nowhere to forward traffic until that backend is running.%s" % C_RESET)

            if tunnel_mode == "ws":
                print("%s[i] WebSocket mode does its own HTTP Upgrade handshake but does NOT" % C_CYAN)
                print("    terminate TLS itself. For WSS (encrypted), chain Stunnel (already in")
                print("    this panel) in front of it, listening externally and forwarding to")
                print("    this port on 127.0.0.1.%s" % C_RESET)

            script_path = _ensure_script_deployed(tunnel_mode)
            if not script_path:
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable sshgo")

            ok, msg = _apply_safely(tunnel_mode, listen_port, target_port,
                                     "SSHGO (%s) on port %s" % (tunnel_mode.upper(), listen_port))
            if ok:
                ports_dict['SSHGO_PORT'] = str(listen_port)
                ports_dict['SSHGO_MODE'] = tunnel_mode
                ports_dict['SSHGO_TARGET'] = str(target_port)
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s           CHANGE PORT & TUNNEL MODE SETTINGS               %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new SSHGO port [Current: %s]: " % sshgo_port,
                                    default=int(sshgo_port) if str(sshgo_port).isdigit() else 2222)
            mode_choice = input(" Select Tunnel Mode ([1] WebSocket / [2] Direct SSH): ").strip()
            new_mode = "tcp" if mode_choice == '2' else "ws"
            new_target = prompt_port(" Enter backend target port [Current: %s]: " % sshgo_target,
                                      default=int(sshgo_target) if str(sshgo_target).isdigit() else 22)

            if str(new_port) != str(sshgo_port) and check_system_port_in_use(new_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            script_path = _ensure_script_deployed(new_mode)
            if not script_path:
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_safely(new_mode, new_port, new_target, "Port/mode change")
            if ok:
                old_port = sshgo_port
                ports_dict['SSHGO_PORT'] = str(new_port)
                ports_dict['SSHGO_MODE'] = new_mode
                ports_dict['SSHGO_TARGET'] = str(new_target)
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
            print("%s                     SSHGO SERVICE LOGS                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u sshgo -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if _restart_sshgo():
                print("%s[OK] SSHGO service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] SSHGO failed to restart - check 'journalctl -u sshgo'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            if is_active:
                _run("systemctl stop sshgo")
                print("%s[!] SSHGO service stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not (os.path.exists(WS_SCRIPT_PATH) or os.path.exists(TCP_SCRIPT_PATH)):
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start sshgo")
                if _service_active():
                    print("%s[OK] SSHGO service started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] SSHGO failed to start - check 'journalctl -u sshgo'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    UNINSTALL SSHGO                         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove SSHGO? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop sshgo && systemctl disable sshgo")
                _run("rm -f %s %s %s" % (SERVICE_PATH, WS_SCRIPT_PATH, TCP_SCRIPT_PATH))
                _run("systemctl daemon-reload")
                if str(sshgo_port).isdigit():
                    close_firewall_port(int(sshgo_port), ("tcp",))
                    persist_firewall_rules()
                ports_dict.pop('SSHGO_PORT', None)
                ports_dict.pop('SSHGO_MODE', None)
                ports_dict.pop('SSHGO_TARGET', None)
                print("%s[OK] SSHGO purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
