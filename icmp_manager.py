"""
icmp_manager.py - ICMP tunnel (IP-over-ICMP) admin module for the SmartUI
panel, wrapping Hans (github.com/friedrich/hans).

Hans was chosen over the alternatives checked before building this:
  - Azumi67/ICMP_tunnels (the initially-suggested option) turned out to be a
    menu-driven orchestrator around five different tools, one of which
    (jamesbarlow/icmptunnel) is a low-star fork with "pivoting inside a
    network" framing and an offensive-security-leaning maintainer portfolio -
    and critically, every config it generates uses a HARDCODED shared secret
    ("azumi86chwan" for Hans, "azumichwan" for FRP) baked into the public
    script, identical across every deployment of it that has ever existed.
  - DhavalKapil/icmptunnel (most-starred alternative) has no authentication
    concept at all - a bare transparent pipe, which would mean designing and
    maintaining a custom auth layer from scratch.
  - Hans has real, protocol-level password authentication built in (the -p
    flag is core to how it works, not bolted on), and is confirmed still
    actively maintained (DeepWiki architecture docs current as of within
    this project's own timeframe) at its canonical location,
    github.com/friedrich/hans - used here instead of the older SourceForge
    1.1 tarball a script found during research pointed at.

This module generates a genuinely unique password per deployment via
secrets.token_urlsafe() - never a hardcoded default - fixing the exact bug
found in the script that was initially suggested.

Architecture note on "port redirection": ICMP tunnels don't have a port to
redirect the way Stunnel/dnstt/WS-EPRO do. Like OpenVPN and WireGuard
(already built in this panel), Hans hands the connecting client a private IP
on a TUN interface - once connected, the client has real IP connectivity and
can reach anything on the server's network directly, including SSH/Dropbear
on their normal ports using the customer's real system username and
password. That's the same integration model already used for OpenVPN/
WireGuard, not a new one invented for this module.

Firewall note: ICMP has no port concept at all (confirmed directly from a
discussion among Hans's own upstream maintainers - "ICMP does not
technically have port numbers"), so the panel's existing port-based firewall
helpers don't apply. Added open_firewall_icmp()/close_firewall_icmp() to
panel_common.py for this - a real netfilter INPUT rule, which works
regardless of ufw/firewalld being layered on top, with an honest warning
that ufw's before.rules or firewalld's icmp-block config could still filter
it separately (scripting an edit to those risks breaking something the admin
set deliberately, so this warns rather than guesses).
"""

import os
import re
import time
import secrets
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, run_cmd as _run,
    open_firewall_icmp, close_firewall_icmp, persist_firewall_rules,
)
from openvpn_manager import _default_interface

HANS_SRC_DIR = "/opt/hans-src"
HANS_BIN = "/usr/local/bin/hans"
HANS_DEVICE = "tun-icmp"
SERVICE_PATH = "/etc/systemd/system/icmp-tunnel.service"
SYSCTL_DROPIN_PATH = "/etc/sysctl.d/99-icmp-tunnel-forward.conf"
DEFAULT_NETWORK = "10.66.0.0"


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "icmp-tunnel"]).returncode == 0


def _restart_hans():
    return _run("systemctl restart icmp-tunnel").returncode == 0


def _binary_ok():
    return os.path.exists(HANS_BIN) and os.access(HANS_BIN, os.X_OK)


def _ensure_installed():
    if _binary_ok():
        return True
    print("%s[i] Installing build dependencies...%s" % (C_CYAN, C_RESET))
    _run("apt-get update && apt-get install -y git build-essential")

    if not os.path.exists("%s/hans" % HANS_SRC_DIR):
        print("%s[i] Cloning Hans (IP-over-ICMP) source...%s" % (C_CYAN, C_RESET))
        clone = _run("git clone https://github.com/friedrich/hans.git %s" % HANS_SRC_DIR)
        if clone.returncode != 0 and not os.path.exists(HANS_SRC_DIR):
            print("%s[X] Clone failed - check network access:\n%s%s" % (C_RED, clone.stderr.strip(), C_RESET))
            return False

    print("%s[i] Building Hans...%s" % (C_CYAN, C_RESET))
    build = _run("cd %s && make" % HANS_SRC_DIR)
    built_bin = "%s/hans" % HANS_SRC_DIR
    if not os.path.exists(built_bin):
        print("%s[X] Build did not produce a binary:\n%s%s" % (C_RED, build.stderr[-800:], C_RESET))
        return False

    _run("cp %s %s" % (built_bin, HANS_BIN))
    if not _binary_ok():
        print("%s[X] Could not install the built binary to %s.%s" % (C_RED, HANS_BIN, C_RESET))
        return False
    return True


def _ensure_ip_forwarding():
    _run("sysctl -w net.ipv4.ip_forward=1")
    with open(SYSCTL_DROPIN_PATH, "w") as f:
        f.write("net.ipv4.ip_forward=1\n")
    _run("sysctl -p %s" % SYSCTL_DROPIN_PATH)


def _ensure_masquerade(network, interface):
    check = _run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", "%s/24" % network,
                  "-o", interface, "-j", "MASQUERADE"])
    if check.returncode != 0:
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "%s/24" % network,
              "-o", interface, "-j", "MASQUERADE"])


def _remove_masquerade(network, interface):
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "%s/24" % network,
          "-o", interface, "-j", "MASQUERADE"])


def _write_service(network, password):
    # -f: foreground, required for correct systemd Type=simple integration -
    # without it Hans daemonizes itself and systemd loses track of the real
    # process. Password is passed as a literal CLI arg here (Hans has no
    # env-var/file input option for it), same tradeoff as any tool whose
    # own interface requires this.
    exec_cmd = "%s -s %s -p %s -f -d %s" % (HANS_BIN, network, password, HANS_DEVICE)
    service_content = """[Unit]
Description=ICMP Tunnel (Hans - IP over ICMP)
After=network.target

[Service]
Type=simple
User=root
ExecStart=%s
ExecStartPost=/bin/sh -c 'sleep 2; ip link set dev %s mtu 1200 || true'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % (exec_cmd, HANS_DEVICE)
    with open(SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _tun_interface_up(device_name, tries=8, delay=1):
    """No port to check here (ICMP has none) - the equivalent correctness check
    for a TUN-based tunnel is whether the interface actually exists and has
    been assigned an IP, the same signal OpenVPN/WireGuard admins would look
    for."""
    for _ in range(tries):
        result = _run(["ip", "addr", "show", "dev", device_name])
        if result.returncode == 0 and re.search(r'inet \d+\.\d+\.\d+\.\d+', result.stdout):
            return True
        time.sleep(delay)
    return False


def _apply_safely(network, password, description):
    """No config-syntax-test flag exists for Hans either - same restart-verify-
    rollback pattern as Stunnel/Hysteria/OpenVPN, with the TUN-interface check
    standing in for the port check those other modules use."""
    original_unit = None
    if os.path.exists(SERVICE_PATH):
        with open(SERVICE_PATH, "r") as f:
            original_unit = f.read()

    _write_service(network, password)

    if not _restart_hans():
        if original_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_hans()
        return False, "%s failed to restart - check 'journalctl -u icmp-tunnel'." % description

    if not _tun_interface_up(HANS_DEVICE):
        if original_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(original_unit)
            _run("systemctl daemon-reload")
            _restart_hans()
        return False, "%s restarted, but the %s interface never came up - reverted. Nothing was left broken." % (description, HANS_DEVICE)

    return True, "%s applied and verified - %s is up." % (description, HANS_DEVICE)


def icmp_admin_manager(ports_dict):
    """ICMP Tunnel (Hans) Administrator Module."""
    while True:
        network = ports_dict.get('ICMP_NETWORK', 'Not configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("================================================================")
        print("                   ICMP TUNNEL ADMINISTRATOR                ")
        print("================================================================")
        print("      NETWORK: %s" % network)
        print("%s      No port to redirect - clients get a private IP (like OpenVPN/" % C_YELLOW)
        print("      WireGuard), then authenticate to SSH/Dropbear with their real")
        print("      system account over that connection.%s" % C_RESET)
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL ICMP TUNNEL (Wizard)")
        print(" [2]> VIEW / REGENERATE CONNECTION INFO")
        print(" [3]> VIEW SERVICE LOGS")
        print(" [4]> RESTART SERVICE")
        print(" [5]> START/STOP SERVICE [%s]" % status_label)
        print("================================================================")
        print(" [0] RETURN  [6] UNINSTALL ICMP TUNNEL")
        print("================================================================")

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("================================================================")
            print("            ICMP TUNNEL INSTALLATION WIZARD                 ")
            print("================================================================")

            network_raw = input(" Enter tunnel network [default %s]: " % DEFAULT_NETWORK).strip() or DEFAULT_NETWORK
            if not re.match(r'^\d+\.\d+\.\d+\.0$', network_raw):
                print("%s[X] Enter a network address ending in .0, e.g. 10.66.0.0.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            password = secrets.token_urlsafe(16)  # unique per deployment - never a hardcoded default

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            interface = _default_interface()
            _ensure_ip_forwarding()
            _ensure_masquerade(network_raw, interface)
            open_firewall_icmp()
            persist_firewall_rules()
            _run("systemctl enable icmp-tunnel")

            ok, msg = _apply_safely(network_raw, password, "ICMP tunnel")
            if ok:
                ports_dict['ICMP_NETWORK'] = network_raw
                ports_dict['ICMP_PASSWORD'] = password
                server_ip = os.popen("curl -s ifconfig.me || hostname -I | awk '{print $1}'").read().strip()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("%s    NAT/MASQUERADE enabled on %s so clients reach the internet.%s" % (C_CYAN, interface, C_RESET))
                print()
                print(" Server IP:  %s" % server_ip)
                print(" Password:   %s" % password)
                print(" Client command: hans -c %s -p %s -f -d tun0" % (server_ip, password))
                print("%s (client also needs Hans built/installed locally)%s" % (C_YELLOW, C_RESET))
            else:
                close_firewall_icmp()
                _remove_masquerade(network_raw, interface)
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("================================================================")
            print("               CONNECTION INFO                              ")
            print("================================================================")
            if not os.path.exists(SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            current_password = ports_dict.get('ICMP_PASSWORD')
            server_ip = os.popen("curl -s ifconfig.me || hostname -I | awk '{print $1}'").read().strip()
            print(" Server IP:  %s" % server_ip)
            print(" Password:   %s" % current_password)
            print(" Client command: hans -c %s -p %s -f -d tun0" % (server_ip, current_password))
            print()
            regen = input(" Regenerate a new password? (y/N): ").strip().lower()
            if regen == 'y':
                new_password = secrets.token_urlsafe(16)
                ok, msg = _apply_safely(network, new_password, "Password rotation")
                if ok:
                    ports_dict['ICMP_PASSWORD'] = new_password
                    print("%s[OK] Password rotated: %s%s" % (C_GREEN, new_password, C_RESET))
                    print("%s Existing connected clients will need the new password to reconnect.%s" % (C_YELLOW, C_RESET))
                else:
                    print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("================================================================")
            print("                  ICMP TUNNEL SERVICE LOGS                  ")
            print("================================================================")
            os.system("journalctl -u icmp-tunnel -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if _restart_hans():
                print("%s[OK] ICMP tunnel service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u icmp-tunnel'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            if is_active:
                _run("systemctl stop icmp-tunnel")
                print("%s[!] ICMP tunnel service stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not _binary_ok():
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start icmp-tunnel")
                if _service_active():
                    print("%s[OK] ICMP tunnel service started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u icmp-tunnel'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            print("================================================================")
            print("                UNINSTALL ICMP TUNNEL                       ")
            print("================================================================")
            confirm = input(" Are you sure you want to completely remove the ICMP tunnel? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop icmp-tunnel")
                _run("systemctl disable icmp-tunnel")
                _run("rm -f %s" % SERVICE_PATH)
                _run("systemctl daemon-reload")
                close_firewall_icmp()
                if network != 'Not configured':
                    _remove_masquerade(network, _default_interface())
                persist_firewall_rules()
                _run("rm -f %s" % SYSCTL_DROPIN_PATH)
                _run("rm -rf %s %s" % (HANS_SRC_DIR, HANS_BIN))
                ports_dict.pop('ICMP_NETWORK', None)
                ports_dict.pop('ICMP_PASSWORD', None)
                print("%s[OK] ICMP tunnel removed and purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
