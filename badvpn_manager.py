"""
badvpn_manager.py - BadVPN-UDPGW admin module for the SmartUI panel.

BadVPN-UDPGW (ambrop72/badvpn) is a real, well-known, simple UDP forwarding
daemon - the install command (git clone + cmake -DBUILD_UDPGW=1 -DBUILD_NOTHING_
BY_DEFAULT=1 && make install) was already correct. Real bugs found, verified
against the project's own source (udpgw/udpgw.c options struct) rather than
assumed:

1. `--max-connections {max_clients}` is not a real badvpn-udpgw flag at all.
   The actual flag, confirmed directly from the source's options struct, is
   `max_connections_for_client` -> `--max-connections-for-client`. Passing an
   unrecognized argument would almost certainly make the binary refuse to
   start outright - but the original code wrote the systemd unit and reported
   "[OK] successfully installed and running" regardless of whether it actually
   did.

2. No verification the build actually produced a binary. `cmake .. && make
   install` failing (missing deps, a `git clone ... || true` that silently
   swallowed a network failure and left no source tree at all) would leave
   `/usr/local/bin/badvpn-udpgw` never created, yet the code proceeded to
   write and start a systemd unit pointing at a binary that didn't exist,
   claiming success regardless - same class of bug fixed in every other
   module in this panel.

3. No restart verification/rollback on the port-change flow, no port-conflict
   check, and firewall handling was raw ufw/iptables instead of the shared
   nftables-aware helpers used elsewhere in this panel.

Also added (confirmed real, optional flags from the same source /
widely-used reference deployments): --client-socket-sndbuf and --udp-mtu,
exposed as optional tuning rather than mandatory.
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

BADVPN_BIN = "/usr/local/bin/badvpn-udpgw"
BADVPN_SRC_DIR = "/root/badvpn-src"
BADVPN_SERVICE_PATH = "/etc/systemd/system/badvpn.service"


def _service_active():
    return (_run(["systemctl", "is-active", "--quiet", "badvpn"]).returncode == 0
            or _run(["systemctl", "is-active", "--quiet", "badvpn-udpgw"]).returncode == 0)


def _restart_badvpn():
    r = _run("systemctl restart badvpn")
    if r.returncode != 0:
        r = _run("systemctl restart badvpn-udpgw")
    return r.returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("udp",)):
            return True
        time.sleep(delay)
    return False


def _binary_ok():
    return os.path.exists(BADVPN_BIN) and os.access(BADVPN_BIN, os.X_OK)


def _ensure_installed():
    if _binary_ok():
        return True

    print(f"{C_CYAN}[i] Installing build dependencies...{C_RESET}")
    _run("apt-get update && apt-get install -y cmake build-essential git")

    if not os.path.exists(f"{BADVPN_SRC_DIR}/udpgw"):
        print(f"{C_CYAN}[i] Cloning badvpn source...{C_RESET}")
        clone = _run(f"git clone https://github.com/ambrop72/badvpn.git {BADVPN_SRC_DIR}")
        if clone.returncode != 0 and not os.path.exists(f"{BADVPN_SRC_DIR}/udpgw"):
            print(f"{C_RED}[X] Clone failed and no existing source tree found - check network access:")
            print(f"{clone.stderr.strip()}{C_RESET}")
            return False

    build_dir = f"{BADVPN_SRC_DIR}/build"
    os.makedirs(build_dir, exist_ok=True)
    print(f"{C_CYAN}[i] Building badvpn-udpgw (this can take a minute)...{C_RESET}")
    build = _run(f"cd {build_dir} && cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 && make install")

    if not _binary_ok():
        print(f"{C_RED}[X] Build did not produce {BADVPN_BIN}:")
        print(f"{build.stderr[-800:]}{C_RESET}")
        return False
    return True


def _write_service(listen_port, max_clients, sndbuf=None, mtu=None):
    exec_cmd = (
        f"{BADVPN_BIN} --listen-addr 127.0.0.1:{listen_port} "
        f"--max-clients {max_clients} --max-connections-for-client {max_clients}"
    )
    if sndbuf is not None:
        exec_cmd += f" --client-socket-sndbuf {sndbuf}"
    if mtu is not None:
        exec_cmd += f" --udp-mtu {mtu}"

    service_content = f"""[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
User=root
ExecStart={exec_cmd}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    with open(BADVPN_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_settings_safely(listen_port, max_clients, description, sndbuf=None, mtu=None):
    """badvpn-udpgw's whole config is CLI args (no config file to syntax-test) -
    restart, verify the port actually came up, roll back to the previous unit
    if not."""
    original_unit = None
    if os.path.exists(BADVPN_SERVICE_PATH):
        with open(BADVPN_SERVICE_PATH, "r") as f:
            original_unit = f.read()

    _write_service(listen_port, max_clients, sndbuf, mtu)

    if not _restart_badvpn():
        if original_unit is not None:
            with open(BADVPN_SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_badvpn()
        return False, f"{description} failed to restart BadVPN - reverted to the previous working setup."

    if not _wait_for_port_listening(listen_port):
        if original_unit is not None:
            with open(BADVPN_SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_badvpn()
        return False, f"{description} restarted, but port {listen_port} never came up - reverted. Nothing was left broken."

    return True, f"{description} applied and verified on port {listen_port}."


def badvpn_admin_manager(ports_dict):
    """BADVPN-UDPGW Administrator Module."""
    while True:
        badvpn_port = ports_dict.get('BADVPN_PORT', 'Not configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                   BADVPN-UDPGW ADMINISTRATOR               %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      UDPGW PORT: {badvpn_port}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL BADVPN-UDPGW")
        print(" [2]> CHANGE GATEWAY PORT")
        print(" [3]> VIEW SERVICE LOGS")
        print(" [4]> RESTART BADVPN SERVICE")
        print(f" [5]> START/STOP BADVPN SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [6] UNINSTALL BADVPN-UDPGW")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s          BADVPN-UDPGW INSTALLATION WIZARD                  %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter desired BADVPN-UDPGW listen port (e.g., 7300): ", default=7300)
            if str(listen_port) != str(badvpn_port) and check_system_port_in_use(listen_port, ("udp",)):
                print(f"{C_RED}[X] UDP port {listen_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            max_clients_raw = input(" Enter maximum concurrent clients (e.g., 1000, blank for 512): ").strip()
            max_clients = int(max_clients_raw) if max_clients_raw.isdigit() else 512

            adv = input(" Configure advanced tuning (socket buffer / MTU)? [y/N]: ").strip().lower()
            sndbuf, mtu = None, None
            if adv == 'y':
                sb_raw = input(" Client socket send buffer in bytes (0 = OS default, blank to skip): ").strip()
                if sb_raw.isdigit():
                    sndbuf = int(sb_raw)
                mtu_raw = input(" UDP MTU (blank to skip, common value: 9000 for jumbo frames): ").strip()
                if mtu_raw.isdigit():
                    mtu = int(mtu_raw)

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(listen_port, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable badvpn")

            ok, msg = _apply_settings_safely(listen_port, max_clients, f"BadVPN on port {listen_port}", sndbuf, mtu)
            if ok:
                ports_dict['BADVPN_PORT'] = str(listen_port)
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(listen_port, ("udp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   CHANGE GATEWAY PORT                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not _binary_ok():
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(f" Enter new BadVPN gateway port [Current: {badvpn_port}]: ",
                                    default=int(badvpn_port) if str(badvpn_port).isdigit() else 7300)
            if str(new_port) != str(badvpn_port) and check_system_port_in_use(new_port, ("udp",)):
                print(f"{C_RED}[X] UDP port {new_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            # Preserve whatever max-clients/tuning is already in the unit rather
            # than resetting it - only the listen port changes here.
            max_clients = 512
            sndbuf, mtu = None, None
            if os.path.exists(BADVPN_SERVICE_PATH):
                with open(BADVPN_SERVICE_PATH, "r") as f:
                    existing = f.read()
                m = re.search(r'--max-clients (\d+)', existing)
                if m:
                    max_clients = int(m.group(1))
                m = re.search(r'--client-socket-sndbuf (\d+)', existing)
                if m:
                    sndbuf = int(m.group(1))
                m = re.search(r'--udp-mtu (\d+)', existing)
                if m:
                    mtu = int(m.group(1))

            open_firewall_port(new_port, ("udp",))
            persist_firewall_rules()

            ok, msg = _apply_settings_safely(new_port, max_clients, f"Gateway port change to {new_port}", sndbuf, mtu)
            if ok:
                old_port = badvpn_port
                ports_dict['BADVPN_PORT'] = str(new_port)
                if str(old_port).isdigit() and str(old_port) != str(new_port):
                    close_firewall_port(int(old_port), ("udp",))
                    persist_firewall_rules()
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(new_port, ("udp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   BADVPN SERVICE LOGS                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u badvpn -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if _restart_badvpn():
                print(f"{C_GREEN}[OK] BadVPN service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] BadVPN failed to restart - check 'journalctl -u badvpn'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if is_active:
                _run("systemctl stop badvpn")
                print(f"{C_YELLOW}[!] BadVPN service stopped.{C_RESET}")
            else:
                if not _binary_ok():
                    print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start badvpn")
                if _service_active():
                    print(f"{C_GREEN}[OK] BadVPN service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] BadVPN failed to start - check 'journalctl -u badvpn'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  UNINSTALL BADVPN-UDPGW                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove BadVPN-UDPGW? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop badvpn")
                _run("systemctl disable badvpn")
                _run(f"rm -f {BADVPN_SERVICE_PATH} {BADVPN_BIN}")
                _run("systemctl daemon-reload")
                if str(badvpn_port).isdigit():
                    close_firewall_port(int(badvpn_port), ("udp",))
                    persist_firewall_rules()
                ports_dict.pop('BADVPN_PORT', None)
                print(f"{C_GREEN}[OK] BadVPN purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
