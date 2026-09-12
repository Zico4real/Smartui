"""
wireguard_manager.py - WireGuard admin module for the SmartUI panel.

The single most severe bug found here: every new peer was assigned the exact
same hardcoded address:
    AllowedIPs = 10.7.0.2/32
Adding a second client peer would give it the IDENTICAL IP address as the
first one - a fundamental, immediately-breaking correctness bug for the core
"add multiple clients" use case of a VPN server, not an edge case. Fixed by
scanning the existing config for already-allocated addresses and assigning
each new peer the next genuinely free one.

Other real bugs found:

1. The server's own interface address was computed via a naive string
   replace: server_subnet.replace('0/24', '1/24'). This "worked" by luck
   only for the exact suggested default (a /24 subnet ending in ".0/24") -
   for any other prefix length (/16, /22, /28...), str.replace() finds no
   match and silently returns the input UNCHANGED, meaning the server's own
   "Address" line would end up being the network address itself (e.g.
   10.7.0.0/16) - not a valid host address, and wg-quick would either refuse
   to bring the interface up or behave incorrectly. Fixed using the
   ipaddress module for real subnet arithmetic, correct for any prefix.

2. "MANAGE CLIENT PEERS (Add/Revoke)" only implemented Add - there was no way
   to actually revoke a peer despite the menu's own label promising it. Also,
   what "Add" produced wasn't usable on its own: it printed the client's raw
   keys to the terminal without ever assembling a real, importable client
   .conf file (which needs the SERVER's public key and endpoint too - neither
   of which were shown anywhere in that flow). Fixed with real revocation
   (removes the matching [Peer] block and re-syncs live via wg syncconf) and
   a complete, ready-to-import client .conf, matching the pattern already
   used for OpenVPN's client profiles.

3. A peer's private key was piped through a shell command as a literal
   argument (echo '{key}' | wg pubkey) - briefly visible to any other local
   user on the box via ps aux during that command's execution window. Fixed
   by piping the key directly via stdin instead of as a command argument.

4. Same IP-forwarding persistence bug as OpenVPN: sed-patching the exact
   commented line in /etc/sysctl.conf silently no-ops if that line isn't
   present. Fixed with a dedicated /etc/sysctl.d/ drop-in file instead.

5. No install verification, no restart-verify-rollback, no port-conflict
   check, raw ufw/iptables instead of the shared firewall helpers, and
   uninstall never closed the port on the firewall - same classes of bug
   fixed in every other module in this panel.
"""

import os
import re
import time
import ipaddress
import subprocess
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)
from openvpn_manager import _default_interface

WG_DIR = "/etc/wireguard"
WG_CONF_PATH = "%s/wg0.conf" % WG_DIR
SYSCTL_DROPIN_PATH = "/etc/sysctl.d/99-wireguard-forward.conf"


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "wg-quick@wg0"]).returncode == 0


def _restart_wg():
    return _run("systemctl restart wg-quick@wg0").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("udp",)):
            return True
        time.sleep(delay)
    return False


def _genkey():
    return _run("wg genkey").stdout.strip()


def _pubkey_from(private_key):
    """Pipes the private key via stdin, never as a command-line argument -
    a key passed as an argument is briefly visible to other local users via
    ps aux during the command's execution window."""
    result = subprocess.run(["wg", "pubkey"], input=private_key, capture_output=True, text=True)
    return result.stdout.strip()


def _ensure_ip_forwarding():
    _run("sysctl -w net.ipv4.ip_forward=1")
    with open(SYSCTL_DROPIN_PATH, "w") as f:
        f.write("net.ipv4.ip_forward=1\n")
    _run("sysctl -p %s" % SYSCTL_DROPIN_PATH)


def _server_address_for_subnet(subnet_str):
    """Real subnet arithmetic instead of a string-replace hack that only
    happened to work for the one suggested default value."""
    network = ipaddress.ip_network(subnet_str, strict=False)
    server_ip = network.network_address + 1
    return "%s/%s" % (server_ip, network.prefixlen)


def _allocated_addresses(config_content):
    """Every address already in use - the server's own Address line, plus
    every peer's AllowedIPs - so a new peer never collides with one that
    already exists."""
    used = set()
    for m in re.finditer(r'^Address\s*=\s*([\d.]+)', config_content, re.MULTILINE):
        used.add(m.group(1))
    for m in re.finditer(r'^AllowedIPs\s*=\s*([\d.]+)', config_content, re.MULTILINE):
        used.add(m.group(1))
    return used


def _next_free_address(config_content, subnet_str):
    network = ipaddress.ip_network(subnet_str, strict=False)
    used = _allocated_addresses(config_content)
    for host in network.hosts():
        if str(host) not in used:
            return str(host)
    return None


def _write_server_config(listen_port, subnet_str, private_key, interface):
    server_address = _server_address_for_subnet(subnet_str)
    config = """[Interface]
Address = %s
ListenPort = %s
PrivateKey = %s
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o %s -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o %s -j MASQUERADE
""" % (server_address, listen_port, private_key, interface, interface)
    with open(WG_CONF_PATH, "w") as f:
        f.write(config)
    os.chmod(WG_CONF_PATH, 0o600)


def _apply_safely(description, check_port):
    """No standalone config-syntax-test exists for wg-quick either - same
    restart-verify-rollback pattern as Stunnel/Hysteria/OpenVPN/FileBrowser."""
    if not _restart_wg():
        return False, "%s failed to restart - check 'wg-quick up wg0' manually for the error." % description

    if not _wait_for_port_listening(check_port):
        return False, "%s restarted, but port %s never came up." % (description, check_port)

    return True, "%s applied and verified on port %s." % (description, check_port)


def wireguard_admin_manager(ports_dict):
    """WireGuard Administrator Module."""
    while True:
        wg_port = ports_dict.get('WIREGUARD_PORT', 'Not configured')
        wg_subnet = ports_dict.get('WIREGUARD_SUBNET', '10.7.0.0/24')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"
        peer_count = 0
        if os.path.exists(WG_CONF_PATH):
            with open(WG_CONF_PATH) as f:
                peer_count = f.read().count('[Peer]')

        clear_screen()
        print("================================================================")
        print("                  WIREGUARD ADMINISTRATOR                   ")
        print("================================================================")
        print("      PORT: %s  |  SUBNET: %s  |  PEERS: %s" % (wg_port, wg_subnet, peer_count))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL WIREGUARD (Wizard)")
        print(" [2]> MANAGE CLIENT PEERS (Add/Revoke)")
        print(" [3]> CHANGE LISTEN PORT")
        print(" [4]> VIEW SERVICE STATUS / PEERS")
        print(" [5]> RESTART WIREGUARD SERVICE")
        print(" [6]> START/STOP WIREGUARD SERVICE [%s]" % status_label)
        print("================================================================")
        print(" [0] RETURN  [7] UNINSTALL WIREGUARD")
        print("================================================================")

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("================================================================")
            print("           WIREGUARD INSTALLATION WIZARD                    ")
            print("================================================================")

            listen_port = prompt_port(" Enter desired WireGuard listen port (e.g., 51820): ", default=51820)
            if str(listen_port) != str(wg_port) and check_system_port_in_use(listen_port, ("udp",)):
                print("%s[X] UDP port %s is already in use by another service.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            subnet_raw = input(" Enter VPN subnet [default 10.7.0.0/24]: ").strip() or "10.7.0.0/24"
            try:
                ipaddress.ip_network(subnet_raw, strict=False)
            except ValueError:
                print("%s[X] '%s' isn't a valid subnet (e.g. 10.7.0.0/24).%s" % (C_RED, subnet_raw, C_RESET))
                input("\nPress Enter to continue...")
                continue

            print("\n[i] Installing WireGuard...")
            _run("apt-get update && apt-get install -y wireguard iptables")
            if _run("which wg-quick").returncode != 0:
                print("%s[X] WireGuard did not install correctly - check network access.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            os.makedirs(WG_DIR, exist_ok=True)
            server_private_key = _genkey()
            if not server_private_key:
                print("%s[X] Key generation failed.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            interface = _default_interface()
            _write_server_config(listen_port, subnet_raw, server_private_key, interface)
            _ensure_ip_forwarding()

            open_firewall_port(listen_port, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable wg-quick@wg0")

            ok, msg = _apply_safely("WireGuard on port %s" % listen_port, listen_port)
            if ok:
                ports_dict['WIREGUARD_PORT'] = str(listen_port)
                ports_dict['WIREGUARD_SUBNET'] = subnet_raw
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("%s    NAT/MASQUERADE enabled on %s so peers reach the internet.%s" % (C_CYAN, interface, C_RESET))
            else:
                close_firewall_port(listen_port, ("udp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("================================================================")
            print("                MANAGE WIREGUARD CLIENT PEERS               ")
            print("================================================================")
            if not os.path.exists(WG_CONF_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            print(" [1] Add a peer")
            print(" [2] Revoke a peer")
            print(" [0] Back")
            sub = input(" Select option: ").strip()

            if sub == '1':
                peer_name = input(" Enter a name for this peer (for your own reference): ").strip() or "peer"
                with open(WG_CONF_PATH, "r") as f:
                    config_content = f.read()

                peer_address = _next_free_address(config_content, wg_subnet)
                if not peer_address:
                    print("%s[X] No free addresses left in subnet %s.%s" % (C_RED, wg_subnet, C_RESET))
                    input("\nPress Enter to continue...")
                    continue

                m = re.search(r'^PrivateKey\s*=\s*(\S+)', config_content, re.MULTILINE)
                server_private_key = m.group(1) if m else None
                server_public_key = _pubkey_from(server_private_key) if server_private_key else None
                m = re.search(r'^ListenPort\s*=\s*(\d+)', config_content, re.MULTILINE)
                server_port = m.group(1) if m else wg_port

                if not server_public_key:
                    print("%s[X] Could not read the server's key from wg0.conf.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue

                client_private_key = _genkey()
                client_public_key = _pubkey_from(client_private_key)

                peer_block = "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n" % (peer_name, client_public_key, peer_address)
                with open(WG_CONF_PATH, "a") as f:
                    f.write(peer_block)

                sync = _run("wg syncconf wg0 <(wg-quick strip wg0)")
                if sync.returncode != 0:
                    _restart_wg()

                server_ip = os.popen("curl -s ifconfig.me || hostname -I | awk '{print $1}'").read().strip()
                client_conf = """[Interface]
PrivateKey = %s
Address = %s/24
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = %s:%s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
""" % (client_private_key, peer_address, server_public_key, server_ip, server_port)
                os.makedirs("%s/clients" % WG_DIR, exist_ok=True)
                client_path = "%s/clients/%s.conf" % (WG_DIR, peer_name)
                with open(client_path, "w") as f:
                    f.write(client_conf)

                print("%s[OK] Peer '%s' added with address %s. Profile ready at:%s" % (C_GREEN, peer_name, peer_address, C_RESET))
                print("     %s" % client_path)
            elif sub == '2':
                with open(WG_CONF_PATH, "r") as f:
                    config_content = f.read()
                peer_blocks = re.findall(r'\[Peer\]\n# (\S+)\n', config_content)
                if not peer_blocks:
                    print("%s No named peers to revoke.%s" % (C_YELLOW, C_RESET))
                else:
                    for name in peer_blocks:
                        print("  - %s" % name)
                    name = input(" Enter peer name to revoke: ").strip()
                    pattern = re.compile(r'\n\[Peer\]\n# ' + re.escape(name) + r'\nPublicKey = .+\nAllowedIPs = .+\n')
                    new_content, count = pattern.subn('', config_content)
                    if count == 0:
                        print("%s[X] No such peer.%s" % (C_RED, C_RESET))
                    else:
                        with open(WG_CONF_PATH, "w") as f:
                            f.write(new_content)
                        sync = _run("wg syncconf wg0 <(wg-quick strip wg0)")
                        if sync.returncode != 0:
                            _restart_wg()
                        _run("rm -f %s/clients/%s.conf" % (WG_DIR, name))
                        print("%s[OK] Peer '%s' revoked.%s" % (C_GREEN, name, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("================================================================")
            print("                  CHANGE LISTEN PORT                        ")
            print("================================================================")
            if not os.path.exists(WG_CONF_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new WireGuard port [Current: %s]: " % wg_port,
                                    default=int(wg_port) if str(wg_port).isdigit() else 51820)
            if str(new_port) != str(wg_port) and check_system_port_in_use(new_port, ("udp",)):
                print("%s[X] UDP port %s is already in use by another service.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            with open(WG_CONF_PATH, "r") as f:
                config_content = f.read()
            new_content = re.sub(r'^ListenPort\s*=\s*\d+', 'ListenPort = %s' % new_port, config_content, flags=re.MULTILINE)
            with open(WG_CONF_PATH, "w") as f:
                f.write(new_content)

            open_firewall_port(new_port, ("udp",))
            persist_firewall_rules()

            ok, msg = _apply_safely("Port change to %s" % new_port, new_port)
            if ok:
                old_port = wg_port
                ports_dict['WIREGUARD_PORT'] = str(new_port)
                if str(old_port).isdigit() and str(old_port) != str(new_port):
                    close_firewall_port(int(old_port), ("udp",))
                    persist_firewall_rules()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("%s[!] Existing client profiles reference the old port - regenerate them" % C_YELLOW)
                print("    (revoke + re-add) if you want clients to reconnect on the new one.%s" % C_RESET)
            else:
                close_firewall_port(new_port, ("udp",))
                with open(WG_CONF_PATH, "w") as f:
                    f.write(config_content)
                _restart_wg()
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("================================================================")
            print("               WIREGUARD STATUS / PEERS                     ")
            print("================================================================")
            os.system("wg show wg0")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_wg():
                print("%s[OK] WireGuard service restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] WireGuard failed to restart - check 'wg-quick up wg0'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop wg-quick@wg0")
                print("%s[!] WireGuard service stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(WG_CONF_PATH):
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start wg-quick@wg0")
                if _service_active():
                    print("%s[OK] WireGuard service started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] WireGuard failed to start - check 'wg-quick up wg0'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("================================================================")
            print("                UNINSTALL WIREGUARD                         ")
            print("================================================================")
            confirm = input(" Are you sure you want to completely remove WireGuard? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop wg-quick@wg0 && systemctl disable wg-quick@wg0")
                _run("apt-get purge -y wireguard")
                if str(wg_port).isdigit():
                    close_firewall_port(int(wg_port), ("udp",))
                    persist_firewall_rules()
                _run("rm -f %s" % SYSCTL_DROPIN_PATH)
                _run("rm -rf %s" % WG_DIR)
                ports_dict.pop('WIREGUARD_PORT', None)
                ports_dict.pop('WIREGUARD_SUBNET', None)
                print("%s[OK] WireGuard purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
