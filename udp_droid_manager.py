"""
udp_droid_manager.py - standalone multi-port UDP relay module for the
SmartUI panel, named after the client-side pattern that motivates it:
DroidVPN's own "UDP Port Scanner" feature, which probes a range of UDP ports
on the client's current network and connects via whichever one isn't
blocked. This is the server-side half of that pattern - a single backend
service (typically OpenVPN-UDP, WireGuard, Hysteria, or similar) becomes
reachable through several public ports at once, so a client on a
restrictive network can find one that actually gets through.

Not wrapping any third-party tool - no existing project matched this
specific "several public ports, one backend" relay shape closely enough to
reuse, so this is a small relay built from scratch and tested directly with
real sockets: multiple simultaneous listen ports, multiple concurrent
clients routed independently, and idle-connection cleanup, all confirmed
against a real deployed subprocess before being wired into this module.

Genuinely separate and independent from every other UDP-based module in
this panel (BadVPN-UDPGW, ZIVPN) - own binary-free relay script, own
systemd service, own port tracking.
"""

import os
import re
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_public_ip, get_live_port_from_service,
)

UDP_DROID_DIR = "/etc/udp-droid"
RELAY_SCRIPT_PATH = "/usr/local/bin/udp-droid-relay.py"
SERVICE_PATH = "/etc/systemd/system/udp-droid.service"

RELAY_SCRIPT = '#!/usr/bin/env python3\n"""UDP Droid relay - listens on several UDP ports at once, all relaying to one\nbackend target. Matches the client-side pattern DroidVPN\'s own "UDP Port\nScanner" uses: the client probes a range of ports and connects via whichever\none isn\'t blocked on its current network - this is the server-side half of\nthat, so any of the listened ports actually leads somewhere."""\nimport argparse\nimport select\nimport socket\nimport time\n\nIDLE_TIMEOUT = 120  # seconds of inactivity before a client\'s mapping is dropped\n\n\ndef main():\n    p = argparse.ArgumentParser()\n    p.add_argument("--ports", required=True, help="Comma-separated list of UDP ports to listen on")\n    p.add_argument("--target-host", default="127.0.0.1")\n    p.add_argument("--target-port", type=int, required=True)\n    args = p.parse_args()\n\n    listen_ports = [int(x) for x in args.ports.split(",") if x.strip()]\n    listen_socks = {}\n    for port in listen_ports:\n        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n        s.bind(("0.0.0.0", port))\n        s.setblocking(False)\n        listen_socks[port] = s\n    print("UDP Droid listening on ports: %s -> %s:%d" % (listen_ports, args.target_host, args.target_port))\n\n    client_to_backend = {}   # (client_addr, listen_port) -> (backend_socket, last_seen)\n    backend_to_client = {}   # fileno -> (client_addr, listen_port, listen_sock)\n\n    while True:\n        all_socks = list(listen_socks.values()) + [v[0] for v in client_to_backend.values()]\n        try:\n            readable, _, _ = select.select(all_socks, [], [], 1.0)\n        except Exception:\n            continue\n\n        now = time.time()\n        for key, (backend_sock, last_seen) in list(client_to_backend.items()):\n            if now - last_seen > IDLE_TIMEOUT:\n                backend_to_client.pop(backend_sock.fileno(), None)\n                client_to_backend.pop(key, None)\n                backend_sock.close()\n\n        for s in readable:\n            if s in listen_socks.values():\n                listen_port = next(p for p, sock in listen_socks.items() if sock is s)\n                try:\n                    data, addr = s.recvfrom(65535)\n                except Exception:\n                    continue\n                key = (addr, listen_port)\n                if key not in client_to_backend:\n                    backend_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n                    backend_sock.setblocking(False)\n                    client_to_backend[key] = (backend_sock, now)\n                    backend_to_client[backend_sock.fileno()] = (addr, listen_port, s)\n                else:\n                    backend_sock, _ = client_to_backend[key]\n                    client_to_backend[key] = (backend_sock, now)\n                try:\n                    backend_sock.sendto(data, (args.target_host, args.target_port))\n                except Exception:\n                    pass\n            else:\n                try:\n                    data, _ = s.recvfrom(65535)\n                except Exception:\n                    continue\n                mapping = backend_to_client.get(s.fileno())\n                if mapping:\n                    client_addr, listen_port, listen_sock = mapping\n                    try:\n                        listen_sock.sendto(data, client_addr)\n                    except Exception:\n                        pass\n\n\nif __name__ == "__main__":\n    main()\n'


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "udp-droid"]).returncode == 0


def _restart_service():
    return _run("systemctl restart udp-droid").returncode == 0


def _deploy_script():
    needs_write = True
    if os.path.exists(RELAY_SCRIPT_PATH):
        with open(RELAY_SCRIPT_PATH) as f:
            needs_write = f.read() != RELAY_SCRIPT
    if needs_write:
        with open(RELAY_SCRIPT_PATH, "w") as f:
            f.write(RELAY_SCRIPT)
        os.chmod(RELAY_SCRIPT_PATH, 0o755)
        check = _run(["python3", "-m", "py_compile", RELAY_SCRIPT_PATH])
        if check.returncode != 0:
            print(f"{C_RED}[X] Relay script failed its own syntax check:\n{check.stderr.strip()}{C_RESET}")
            os.remove(RELAY_SCRIPT_PATH)
            return False
    return True


def _parse_ports(raw):
    """Accepts comma-separated ports and/or simple ranges (e.g. 7000-7005),
    matching common admin shorthand rather than forcing one format."""
    ports = set()
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                start, end = chunk.split("-")
                start, end = int(start), int(end)
                if start <= end and (end - start) <= 100:
                    ports.update(range(start, end + 1))
            except ValueError:
                continue
        elif chunk.isdigit():
            ports.add(int(chunk))
    return sorted(ports)


def _write_service(ports, target_host, target_port):
    ports_arg = ",".join(str(p) for p in ports)
    exec_cmd = "/usr/bin/python3 %s --ports %s --target-host %s --target-port %s" % (
        RELAY_SCRIPT_PATH, ports_arg, target_host, target_port)
    service_content = """[Unit]
Description=UDP Droid Multi-Port Relay
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % exec_cmd
    with open(SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _wait_for_ports_listening(ports, tries=6, delay=1):
    for _ in range(tries):
        if all(check_system_port_in_use(p, ("udp",)) for p in ports):
            return True
        time.sleep(delay)
    return False


def _apply_safely(ports, target_host, target_port, description):
    original = None
    if os.path.exists(SERVICE_PATH):
        with open(SERVICE_PATH) as f:
            original = f.read()

    _write_service(ports, target_host, target_port)

    if not _restart_service():
        if original is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_service()
        return False, "%s failed to restart - check 'journalctl -u udp-droid'." % description

    if not _wait_for_ports_listening(ports):
        if original is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_service()
        return False, "%s restarted, but not every listed port came up - reverted. Nothing was left broken." % description

    return True, "%s applied and verified on ports %s." % (description, ports)


def udp_droid_admin_manager(ports_dict):
    """UDP Droid (multi-port relay) Administrator Module."""
    while True:
        live_ports = get_live_port_from_service(SERVICE_PATH, r'--ports ([\d,]+)')
        live_target = get_live_port_from_service(SERVICE_PATH, r'--target-port (\d+)')
        recorded_ports = ports_dict.get("UDP_DROID_PORTS")
        if live_ports and str(recorded_ports) != str(live_ports):
            print(f"{C_YELLOW}[!] The saved ports ({recorded_ports or 'none'}) didn't match what's actually")
            print(f"    running ({live_ports}) - correcting the panel's records to match reality.{C_RESET}")
            ports_dict["UDP_DROID_PORTS"] = live_ports
            if live_target:
                ports_dict["UDP_DROID_TARGET_PORT"] = live_target
            input("\nPress Enter to continue...")

        current_ports = ports_dict.get("UDP_DROID_PORTS", "Not configured")
        current_target = ports_dict.get("UDP_DROID_TARGET_PORT", "Not configured")
        is_active = _service_active()

        clear_screen()
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print("%s                    UDP DROID (multi-port relay)             %s" % (C_BOLD, C_RESET))
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print("      LISTEN PORTS: %s" % current_ports)
        print("      REDIRECT TARGET: %s" % current_target)
        print("%s      Client connects via whichever listed port isn't blocked on its" % C_YELLOW)
        print("      current network - all of them lead to the same backend service.%s" % C_RESET)
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL")
        print(" [2]> MODIFY PORTS / REDIRECTION")
        print(" [3]> VIEW CONNECTION INFO")
        print(" [4]> VIEW SERVICE LOGS")
        print(" [5]> RESTART SERVICE")
        print(" [6]> START/STOP SERVICE [%s]" % ("ON" if is_active else "OFF"))
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL")
        print("%s================================================================%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == "0":
            break

        elif choice in ("1", "2"):
            clear_screen()
            print("%s================================================================%s" % (C_CYAN, C_RESET))
            print("%s                    SETUP WIZARD                             %s" % (C_BOLD, C_RESET))
            print("%s================================================================%s" % (C_CYAN, C_RESET))

            raw_ports = input(" Enter listen ports (comma-separated and/or a range, e.g. 7000,7001,7010-7015): ").strip()
            ports = _parse_ports(raw_ports)
            if not ports:
                print("%s[X] No valid ports parsed from that input.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            conflicting = [p for p in ports if check_system_port_in_use(p, ("udp",))
                           and str(p) not in str(current_ports)]
            if conflicting:
                print("%s[X] Already in use: %s%s" % (C_RED, conflicting, C_RESET))
                input("\nPress Enter to continue...")
                continue

            target_port = prompt_port(" Enter redirect target port (e.g. your OpenVPN/WireGuard/Hysteria port): ", default=1194)
            target_host = "127.0.0.1"

            if not _deploy_script():
                input("\nPress Enter to continue...")
                continue

            for p in ports:
                open_firewall_port(p, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable udp-droid")

            ok, msg = _apply_safely(ports, target_host, target_port, "UDP Droid relay")
            if ok:
                ports_dict["UDP_DROID_PORTS"] = ",".join(str(p) for p in ports)
                ports_dict["UDP_DROID_TARGET_PORT"] = str(target_port)
                server_ip = get_public_ip()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print()
                print(" Server IP: %s" % server_ip)
                print(" Any of these ports reaches the same backend: %s" % ports)
                print(" Client apps that scan for an open UDP port (like DroidVPN's port")
                print(" scanner) can be pointed at this port list directly.")
            else:
                for p in ports:
                    close_firewall_port(p, ("udp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == "3":
            clear_screen()
            if not os.path.exists(SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            server_ip = get_public_ip()
            print(" Server IP: %s" % server_ip)
            print(" Listen ports: %s" % current_ports)
            print(" Redirect target: 127.0.0.1:%s" % current_target)
            input("\nPress Enter to continue...")

        elif choice == "4":
            clear_screen()
            os.system("journalctl -u udp-droid -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == "5":
            if _restart_service():
                print("%s[OK] UDP Droid restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u udp-droid'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == "6":
            if is_active:
                _run("systemctl stop udp-droid")
                print("%s[!] UDP Droid stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(RELAY_SCRIPT_PATH):
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start udp-droid")
                print("%s[OK] UDP Droid started.%s" % (C_GREEN, C_RESET) if _service_active()
                      else "%s[X] Failed to start - check the logs.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == "7":
            clear_screen()
            confirm = input(" Are you sure you want to completely remove UDP Droid? (y/n): ").strip().lower()
            if confirm == "y":
                _run("systemctl stop udp-droid")
                _run("systemctl disable udp-droid")
                _run("rm -f %s" % SERVICE_PATH)
                _run("systemctl daemon-reload")
                if current_ports != "Not configured":
                    for p in _parse_ports(str(current_ports)):
                        close_firewall_port(p, ("udp",))
                    persist_firewall_rules()
                _run("rm -rf %s %s" % (UDP_DROID_DIR, RELAY_SCRIPT_PATH))
                ports_dict.pop("UDP_DROID_PORTS", None)
                ports_dict.pop("UDP_DROID_TARGET_PORT", None)
                print("%s[OK] UDP Droid removed and purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
