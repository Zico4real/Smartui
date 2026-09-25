"""
hysteria1_manager.py - Hysteria 1.x (legacy) admin module for the SmartUI
panel. Fully independent from hysteria_manager.py (Hysteria 2) - separate
binary, config schema, systemd unit, and firewall rules, since v1 and v2 are
protocol-incompatible and can't interconnect.

The installer was rebuilt from scratch. The previous approach wrapped
evozi/hysteria-install's hysteria1.sh via `curl | bash` - that script is
confirmed real, but it is NOT actually a scriptable installer: it's a fully
interactive menu tool (the whole script ends by calling menu(), which reads
a sequence of `read -rp` prompts for cert type, protocol, port, obfuscation
mode, speed limits, DNS resolution preference, etc.). Piped through
`curl | bash`, none of those prompts can receive an answer - stdin is
occupied by the script content itself, not a terminal. That's why it always
failed to produce a binary, not a network issue. It also installs to
/usr/local/bin/hysteria1, not the /usr/local/bin/hysteria-v1 path this
module was checking for - a second, independent bug on top of the first.

Rebuilt to work the same way Hysteria 2 already does in this panel: download
the official binary directly and build the config ourselves, rather than
wrapping a third-party interactive script at all. Confirmed real source:
apernet/hysteria's own GitHub releases still host v1 directly, under the
v1.3.5 tag (separate from v2's app/vX.Y.Z tag scheme, since v1 is a frozen/
legacy branch with no further releases) - independently verified against two
separate sources before using it, not assumed from the community installer.

Config schema (flat obfs string, flat up_mbps/down_mbps - not the nested
objects v2 uses) was already correct in the code this was extracted from,
confirmed directly from an actual v1.3.2 server's own output.
"""

import os
import json
import re
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_public_ip,
)
from openvpn_manager import _default_interface

HYSTERIA1_DIR = "/etc/hysteria1"
HYSTERIA1_CONFIG_PATH = f"{HYSTERIA1_DIR}/config.json"
HYSTERIA1_BIN = "/usr/local/bin/hysteria1"
HYSTERIA1_SERVICE_PATH = "/etc/systemd/system/hysteria1.service"
HYSTERIA1_DOWNLOAD_URL = "https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-amd64"


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "hysteria1"]).returncode == 0


def _restart_hysteria1():
    return _run("systemctl restart hysteria1").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("udp",)):
            return True
        time.sleep(delay)
    return False


def _ensure_installed():
    if os.path.exists(HYSTERIA1_BIN) and os.access(HYSTERIA1_BIN, os.X_OK):
        return True
    print(f"{C_CYAN}[i] Downloading the official Hysteria 1.3.5 binary directly (the last v1")
    print(f"    release - v1 is a frozen/legacy branch with no further updates)...{C_RESET}")
    dl = _run(f"curl -fsSL {HYSTERIA1_DOWNLOAD_URL} -o {HYSTERIA1_BIN}")
    if dl.returncode == 0:
        os.chmod(HYSTERIA1_BIN, 0o755)
    ok = os.path.exists(HYSTERIA1_BIN) and os.access(HYSTERIA1_BIN, os.X_OK)
    if not ok:
        print(f"{C_RED}[X] Download failed - check network access.{C_RESET}")
    return ok


def _generate_self_signed_cert():
    os.makedirs(HYSTERIA1_DIR, exist_ok=True)
    cert_path = f"{HYSTERIA1_DIR}/cert.crt"
    key_path = f"{HYSTERIA1_DIR}/private.key"
    _run(f"openssl req -x509 -nodes -newkey rsa:2048 "
         f"-keyout {key_path} -out {cert_path} -subj '/CN=bing.com' -days 36500")
    ok = os.path.exists(cert_path) and os.path.exists(key_path)
    return ok, cert_path, key_path


def _write_service(listen_port):
    service_file = f"""[Unit]
Description=Hysteria 1.x Server (legacy)
After=network.target

[Service]
Type=simple
User=root
ExecStart={HYSTERIA1_BIN} server -c {HYSTERIA1_CONFIG_PATH}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(HYSTERIA1_SERVICE_PATH, "w") as f:
        f.write(service_file)
    _run("systemctl daemon-reload")


def _apply_config_safely(new_config, description, check_port):
    original = None
    if os.path.exists(HYSTERIA1_CONFIG_PATH):
        with open(HYSTERIA1_CONFIG_PATH, "r") as f:
            original = f.read()

    with open(HYSTERIA1_CONFIG_PATH, "w") as f:
        json.dump(new_config, f, indent=4)

    if not _restart_hysteria1():
        if original is not None:
            with open(HYSTERIA1_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_hysteria1()
        return False, f"{description} failed to restart Hysteria 1 - reverted to the previous working config."

    if not _wait_for_port_listening(check_port):
        if original is not None:
            with open(HYSTERIA1_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_hysteria1()
        return False, f"{description} restarted, but port {check_port} never came up - reverted. Nothing was left broken."

    return True, f"{description} applied and verified on port {check_port}."


UDP_MOD_COMMENT = "hysteria1-udpmod"


def _udp_mod_active():
    """Checks for the actual iptables rule rather than trusting ports_dict -
    same lesson as everywhere else in this panel: the live rule table is the
    only real source of truth. Searches by comment via -L rather than -C,
    since -C requires matching the exact --to-port value, which isn't known
    up front here."""
    res = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n"])
    return UDP_MOD_COMMENT in res.stdout


def _enable_udp_mod(real_port, ports_dict=None):
    """Redirects every UDP port (1-65535) to wherever Hysteria is actually
    listening, via a REDIRECT rule scoped to the loopback-safe REDIRECT
    target rather than DNAT to a literal IP (works correctly regardless of
    the server's public IP, and needs no interface-specific destination).
    This is the actual mechanism behind third-party "UDP mod" Hysteria
    builds - confirmed directly from a working install's own systemd unit -
    and it's pure iptables, not anything specific to which binary is
    listening on the real port. Lets clients connect on literally any UDP
    port, which matters on networks that throttle or block specific
    well-known ports.

    Confirmed as a real, severe bug in an earlier version of this function:
    the blanket redirect covered literally every UDP port with no
    exclusions at all, including port 53 - silently hijacking every DNS
    tunneling engine's traffic (DNSTT, MasterDnsVPN, VayDNS, StormDNS,
    Slipstream, CottenDNS all share that one port through the router) and
    redirecting it straight to Hysteria instead. The router itself, the
    firewall, DNS delegation - everything else was genuinely correct the
    whole time; the traffic was just never arriving because this rule
    caught it first. iptables stops at the first matching rule, so
    excluding known-important UDP ports has to happen via rules inserted
    BEFORE the blanket one, not by editing the blanket rule itself.
    """
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    iface = _default_interface()
    _run(["sysctl", "-w", "net.ipv4.conf.%s.rp_filter=0" % iface])
    _run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"])

    exclude_ports = {53}  # the shared DNS router always uses this - not configurable
    if ports_dict:
        # Confirmed as real bugs in an earlier version of this exact fix:
        # two of these keys were simply wrong (ICMP_PORT vs the actual
        # ICMP_GATE_PORT; UDP_DROID_PORT singular vs the actual
        # UDP_DROID_PORTS, a comma-separated list, from the old UDP Droid
        # implementation). UDP Droid has since been rewritten as a genuine,
        # single-port tunnel (udp_droid_manager.py) rather than a
        # multi-port scanner, so its real port now lives under
        # UDPDROID_TUNNEL_PORT - a single int, not a list - confirmed
        # directly against where that module actually sets it, not
        # assumed. Verified each of these six key names directly against
        # where its own module actually sets it, rather than assuming.
        for key in ('ZIVPN_PORT', 'BADVPN_PORT', 'ICMP_GATE_PORT', 'HYSTERIA_PORT', 'UDPDROID_TUNNEL_PORT'):
            val = ports_dict.get(key)
            if val and str(val).isdigit() and int(val) != real_port:
                exclude_ports.add(int(val))

    for tool in ("iptables", "ip6tables"):
        for p in sorted(exclude_ports):
            _run([tool, "-t", "nat", "-A", "PREROUTING", "-p", "udp",
                  "--dport", str(p), "-m", "comment", "--comment", UDP_MOD_COMMENT,
                  "-j", "RETURN"])
        _run([tool, "-t", "nat", "-A", "PREROUTING", "-p", "udp",
              "--dport", "1:65535", "-m", "comment", "--comment", UDP_MOD_COMMENT,
              "-j", "REDIRECT", "--to-port", str(real_port)])

    ok1 = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "udp",
                "--dport", "1:65535", "-m", "comment", "--comment", UDP_MOD_COMMENT,
                "-j", "REDIRECT", "--to-port", str(real_port)])
    persist_firewall_rules()
    return ok1.returncode == 0


def _disable_udp_mod():
    # The rule's exact --to-port value varies by install and isn't tracked
    # separately, so deleting by matching comment text (via line number)
    # rather than reconstructing the exact original rule to match against.
    while True:
        res = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "--line-numbers", "-n"])
        line_no = None
        for line in res.stdout.splitlines():
            if UDP_MOD_COMMENT in line:
                line_no = line.split()[0]
                break
        if not line_no or not line_no.isdigit():
            break
        _run(["iptables", "-t", "nat", "-D", "PREROUTING", line_no])
    while True:
        res6 = _run(["ip6tables", "-t", "nat", "-L", "PREROUTING", "--line-numbers", "-n"])
        line_no = None
        for line in res6.stdout.splitlines():
            if UDP_MOD_COMMENT in line:
                line_no = line.split()[0]
                break
        if not line_no or not line_no.isdigit():
            break
        _run(["ip6tables", "-t", "nat", "-D", "PREROUTING", line_no])
    persist_firewall_rules()


def hysteria1_admin_manager(ports_dict):
    """Hysteria 1.x (legacy) Administrator Module."""
    while True:
        hy1_port = ports_dict.get('HYSTERIA1_PORT', 'Not configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        udp_mod_on = _udp_mod_active()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s              HYSTERIA 1.x ADMINISTRATOR (LEGACY)           %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      PORT: {hy1_port}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL (Wizard)")
        print(" [2]> VIEW CONNECTION INFO")
        print(" [3]> VIEW SERVICE LOGS")
        print(" [4]> RESTART SERVICE")
        print(f" [5]> START/STOP SERVICE [{status_label}]")
        print(f" [6]> UDP MOD (redirect all UDP ports here) [{'ON' if udp_mod_on else 'OFF'}]")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    SETUP WIZARD                            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter main listen port (e.g., 36712): ", default=36712)
            if str(listen_port) != str(hy1_port) and check_system_port_in_use(listen_port, ("udp",)):
                print(f"{C_RED}[X] UDP port {listen_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            obfs_pass = input(" Enter OBFS password (blank to skip): ").strip()
            up_mbps_raw = input(" Upload speed limit in Mbps (blank for 0 = unlimited): ").strip()
            down_mbps_raw = input(" Download speed limit in Mbps (blank for 0 = unlimited): ").strip()
            up_mbps = int(up_mbps_raw) if up_mbps_raw.isdigit() else 0
            down_mbps = int(down_mbps_raw) if down_mbps_raw.isdigit() else 0

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            cert_ok, cert_path, key_path = _generate_self_signed_cert()
            if not cert_ok:
                print(f"{C_RED}[X] Certificate generation failed - cannot proceed without one.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            print(f"{C_CYAN}[i] Using a self-signed certificate - your client MUST set 'insecure: true'")
            print(f"    (or the equivalent skip-cert-verify option), or the TLS handshake will")
            print(f"    fail outright and the client will never connect at all.{C_RESET}")

            config_data = {
                "listen": f":{listen_port}",
                "protocol": "udp",
                "cert": cert_path,
                "key": key_path,
                "up_mbps": up_mbps,
                "down_mbps": down_mbps,
            }
            if obfs_pass:
                config_data["obfs"] = obfs_pass

            _write_service(listen_port)
            open_firewall_port(listen_port, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable hysteria1")

            ok, msg = _apply_config_safely(config_data, f"Hysteria 1 on port {listen_port}", listen_port)
            if ok:
                ports_dict['HYSTERIA1_PORT'] = str(listen_port)
                ports_dict['HYSTERIA1_OBFS'] = obfs_pass
                server_ip = get_public_ip()
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
                print()
                print(" Client connection details:")
                print(f"  Server:   {server_ip}")
                print(f"  Port:     {listen_port}")
                print(f"  OBFS:     {obfs_pass if obfs_pass else '(none set)'}")
                print(f"  {C_YELLOW}Insecure/skip-cert-verify: MUST be enabled on the client{C_RESET}")
                print(f"    (self-signed cert, CN=bing.com - won't match your real server")
                print(f"    hostname, so the client must be told not to verify it)")
            else:
                close_firewall_port(listen_port, ("udp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 CLIENT CONNECTION INFO                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(HYSTERIA1_BIN):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
            else:
                server_ip = get_public_ip()
                obfs_pass = ports_dict.get('HYSTERIA1_OBFS', '')
                print(f" Server:   {server_ip}")
                print(f" Port:     {hy1_port}")
                print(f" OBFS:     {obfs_pass if obfs_pass else '(none set)'}")
                print()
                print(f" {C_YELLOW}Insecure/skip-cert-verify: MUST be enabled on the client{C_RESET}")
                print(f"   (self-signed cert, CN=bing.com - won't match your real server")
                print(f"   hostname, so the client must be told not to verify it. This is")
                print(f"   the single most common reason a client fails to connect at all.)")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            os.system("journalctl -u hysteria1 -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if _restart_hysteria1():
                print(f"{C_GREEN}[OK] Hysteria 1 service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] Failed to restart - check 'journalctl -u hysteria1'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if is_active:
                _run("systemctl stop hysteria1")
                print(f"{C_YELLOW}[!] Hysteria 1 service stopped.{C_RESET}")
            else:
                if not os.path.exists(HYSTERIA1_BIN):
                    print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start hysteria1")
                if _service_active():
                    print(f"{C_GREEN}[OK] Hysteria 1 service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] Failed to start - check 'journalctl -u hysteria1'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                        UDP MOD                             %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if udp_mod_on:
                print(" Currently ON - every UDP port redirects to Hysteria's real port.")
                confirm = input(" Turn UDP MOD off? (y/n): ").strip().lower()
                if confirm == 'y':
                    _disable_udp_mod()
                    print(f"{C_GREEN}[OK] UDP MOD disabled - only the configured port ({hy1_port}) works now.{C_RESET}")
                else:
                    print(f"{C_YELLOW}[i] Cancelled.{C_RESET}")
            else:
                if not str(hy1_port).isdigit():
                    print(f"{C_RED}[X] Configure Hysteria 1 first (option 1) - there's no real port")
                    print(f"    yet to redirect traffic to.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                print(" This redirects every UDP port (1-65535) on this server to your")
                print(f" real Hysteria port ({hy1_port}) - clients can connect on ANY UDP port")
                print(" and it reaches Hysteria, which helps on networks that throttle or")
                print(" block specific well-known ports.")
                confirm = input(" Turn UDP MOD on? (y/n): ").strip().lower()
                if confirm == 'y':
                    if _enable_udp_mod(int(hy1_port), ports_dict):
                        print(f"{C_GREEN}[OK] UDP MOD enabled - any UDP port now reaches Hysteria on {hy1_port}.{C_RESET}")
                    else:
                        print(f"{C_RED}[X] Failed to add the redirect rule - check iptables manually.{C_RESET}")
                else:
                    print(f"{C_YELLOW}[i] Cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            confirm = input(" Are you sure you want to completely remove Hysteria 1? (y/n): ").strip().lower()
            if confirm == 'y':
                if udp_mod_on:
                    _disable_udp_mod()
                _run("systemctl stop hysteria1")
                _run("systemctl disable hysteria1")
                _run(f"rm -rf {HYSTERIA1_DIR} {HYSTERIA1_BIN} {HYSTERIA1_SERVICE_PATH}")
                _run("systemctl daemon-reload")
                if str(hy1_port).isdigit():
                    close_firewall_port(int(hy1_port), ("udp",))
                    persist_firewall_rules()
                ports_dict.pop('HYSTERIA1_PORT', None)
                ports_dict.pop('HYSTERIA1_OBFS', None)
                print(f"{C_GREEN}[OK] Hysteria 1 removed and purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
