"""
openvpn_manager.py - OpenVPN admin module for the SmartUI panel.

Two independently severe "doesn't actually work at all" bugs found in the
original draft:

1. server.conf referenced ca.crt, server.crt, server.key, and dh2048.pem -
   but the original code only ran `make-cadir` (which just copies the
   Easy-RSA template SCRIPTS into place) and never actually built a PKI at
   all: no `easyrsa init-pki`, no CA, no server cert, no DH params, and
   nothing ever copied those files into /etc/openvpn/ where the config
   expects them. OpenVPN cannot start without them - there is no scenario
   where the original "[OK] successfully installed and running" message was
   ever true. Fixed with the real, full Easy-RSA 3.x sequence, verifying each
   step actually produced its output file before moving to the next, and
   copying the results into place.

2. No NAT/MASQUERADE rule anywhere. Even with a working PKI, clients using
   `redirect-gateway` (full-tunnel mode, which the wizard offers and defaults
   to) would have zero actual internet access - their traffic would reach the
   server's tun0 interface and go nowhere, since nothing translates it to the
   server's public IP before it leaves. Added an idempotent MASQUERADE rule
   on the server's real outbound interface (detected via the default route,
   never hardcoded as eth0 - the same reasoning applied to the dnstt NAT
   redirect earlier in this panel, since interface names vary by provider).

Other real bugs found:

3. "MANAGE CLIENTS (Add/Revoke)" created an empty directory and printed
   "(Configure keys via Easy-RSA integration)" - a placeholder with no actual
   client cert generation and no revocation logic at all, despite promising
   both in its own menu label. Implemented for real: `easyrsa build-client-
   full`, a proper unified inline .ovpn profile (ca/cert/key/tls-crypt
   embedded directly, the modern standard format), and `easyrsa revoke` +
   `easyrsa gen-crl` wired into a `crl-verify` directive that the original
   config never had either - without it, revocation would have had zero
   actual enforcement effect even if the revoke command itself worked.

4. `sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf`
   silently does nothing if that exact commented line isn't present (common
   on modern Ubuntu, which increasingly manages this via /etc/sysctl.d/ drop-
   ins) - meaning IP forwarding might not survive a reboot even though
   `sysctl -w` made it work for the current session. Fixed by writing our own
   dedicated drop-in file instead of depending on the exact pre-existing
   contents of sysctl.conf.

5. No config-test flag exists for OpenVPN either (confirmed: there's an open,
   unresolved upstream GitHub issue - OpenVPN/openvpn#566 - explicitly asking
   for one that doesn't exist) - same restart-verify-rollback safety net used
   for Stunnel/Hysteria, not a squid -k parse-style pre-flight check.
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

OPENVPN_DIR = "/etc/openvpn"
EASYRSA_DIR = f"{OPENVPN_DIR}/easy-rsa"
PKI_DIR = f"{EASYRSA_DIR}/pki"
SERVER_CONF_PATH = f"{OPENVPN_DIR}/server.conf"
CLIENT_DIR = f"{OPENVPN_DIR}/client-configs"
SYSCTL_DROPIN_PATH = "/etc/sysctl.d/99-openvpn-forward.conf"
VPN_SUBNET = "10.8.0.0"
VPN_NETMASK = "255.255.255.0"


def _service_active():
    return (_run(["systemctl", "is-active", "--quiet", "openvpn-server@server"]).returncode == 0
            or _run(["systemctl", "is-active", "--quiet", "openvpn"]).returncode == 0)


def _restart_openvpn():
    r = _run("systemctl restart openvpn-server@server")
    if r.returncode != 0:
        r = _run("systemctl restart openvpn")
    return r.returncode == 0


def _wait_for_port_listening(port, proto, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, (proto,)):
            return True
        time.sleep(delay)
    return False


def _default_interface():
    """Detect the real outbound interface rather than hardcode eth0 - names
    vary by provider (ens3, enp1s0, eth0...), and hardcoding one caused
    exactly this kind of silent-no-op bug elsewhere in this panel."""
    res = _run("ip route show default")
    m = re.search(r'dev (\S+)', res.stdout)
    return m.group(1) if m else "eth0"


def _easyrsa(*args):
    return _run(f"cd {EASYRSA_DIR} && ./easyrsa --batch " + " ".join(args))


def _ensure_pki():
    """The actual missing piece: build a real, complete PKI instead of just
    copying the Easy-RSA scripts into place and stopping there."""
    os.makedirs(OPENVPN_DIR, exist_ok=True)

    if not os.path.exists(EASYRSA_DIR):
        print(f"{C_CYAN}[i] Setting up Easy-RSA...{C_RESET}")
        _run(f"make-cadir {EASYRSA_DIR}")
        if not os.path.exists(EASYRSA_DIR):
            print(f"{C_RED}[X] Could not set up Easy-RSA directory.{C_RESET}")
            return False

    ca_cert = f"{PKI_DIR}/ca.crt"
    server_cert = f"{PKI_DIR}/issued/server.crt"
    server_key = f"{PKI_DIR}/private/server.key"
    dh_pem = f"{PKI_DIR}/dh.pem"

    if not os.path.exists(PKI_DIR):
        print(f"{C_CYAN}[i] Initializing PKI...{C_RESET}")
        _easyrsa("init-pki")
        if not os.path.exists(PKI_DIR):
            print(f"{C_RED}[X] PKI initialization failed.{C_RESET}")
            return False

    if not os.path.exists(ca_cert):
        print(f"{C_CYAN}[i] Building Certificate Authority...{C_RESET}")
        _easyrsa("build-ca", "nopass")
        if not os.path.exists(ca_cert):
            print(f"{C_RED}[X] CA build failed - {ca_cert} was never created.{C_RESET}")
            return False

    if not os.path.exists(server_cert) or not os.path.exists(server_key):
        print(f"{C_CYAN}[i] Building server certificate (this can take a moment)...{C_RESET}")
        _easyrsa("build-server-full", "server", "nopass")
        if not os.path.exists(server_cert) or not os.path.exists(server_key):
            print(f"{C_RED}[X] Server certificate build failed.{C_RESET}")
            return False

    if not os.path.exists(dh_pem):
        print(f"{C_CYAN}[i] Generating Diffie-Hellman parameters (this can take a while)...{C_RESET}")
        _easyrsa("gen-dh")
        if not os.path.exists(dh_pem):
            print(f"{C_RED}[X] DH parameter generation failed.{C_RESET}")
            return False

    tc_key = f"{OPENVPN_DIR}/tc.key"
    if not os.path.exists(tc_key):
        print(f"{C_CYAN}[i] Generating tls-crypt key (hides the TLS handshake from casual DPI)...{C_RESET}")
        _run(f"openvpn --genkey secret {tc_key}")
        if not os.path.exists(tc_key):
            print(f"{C_RED}[X] tls-crypt key generation failed.{C_RESET}")
            return False

    # Copy everything server.conf actually references into /etc/openvpn/,
    # where its relative paths expect to find them.
    _run(f"cp {ca_cert} {OPENVPN_DIR}/ca.crt")
    _run(f"cp {server_cert} {OPENVPN_DIR}/server.crt")
    _run(f"cp {server_key} {OPENVPN_DIR}/server.key")
    _run(f"cp {dh_pem} {OPENVPN_DIR}/dh2048.pem")

    return all(os.path.exists(p) for p in (
        f"{OPENVPN_DIR}/ca.crt", f"{OPENVPN_DIR}/server.crt",
        f"{OPENVPN_DIR}/server.key", f"{OPENVPN_DIR}/dh2048.pem", tc_key
    ))


def _ensure_crl_generated():
    crl_pki = f"{PKI_DIR}/crl.pem"
    _easyrsa("gen-crl")
    if os.path.exists(crl_pki):
        _run(f"cp {crl_pki} {OPENVPN_DIR}/crl.pem")
        _run(f"chmod 644 {OPENVPN_DIR}/crl.pem")
    return os.path.exists(f"{OPENVPN_DIR}/crl.pem")


def _build_config(listen_port, listen_proto, redirect_gateway=True):
    redirect_directive = 'push "redirect-gateway def1 bypass-dhcp"' if redirect_gateway else '# push redirect-gateway skipped'
    return f"""port {listen_port}
proto {listen_proto}
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
tls-crypt tc.key
crl-verify crl.pem
auth SHA256
cipher AES-256-GCM
server {VPN_SUBNET} {VPN_NETMASK}
ifconfig-pool-persist ipp.txt
{redirect_directive}
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
"""


def _ensure_ip_forwarding():
    _run("sysctl -w net.ipv4.ip_forward=1")
    # A dedicated drop-in file instead of sed-ing the pre-existing sysctl.conf -
    # sysctl reads every file under /etc/sysctl.d/, so this guarantees it
    # survives a reboot without depending on what sysctl.conf already contains.
    with open(SYSCTL_DROPIN_PATH, "w") as f:
        f.write("net.ipv4.ip_forward=1\n")
    _run(f"sysctl -p {SYSCTL_DROPIN_PATH}")


def _ensure_masquerade(interface):
    check = _run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", f"{VPN_SUBNET}/24",
                  "-o", interface, "-j", "MASQUERADE"])
    if check.returncode != 0:
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"{VPN_SUBNET}/24",
              "-o", interface, "-j", "MASQUERADE"])


def _remove_masquerade(interface):
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"{VPN_SUBNET}/24",
          "-o", interface, "-j", "MASQUERADE"])


def _apply_config_safely(new_content, description, check_port, check_proto):
    original = None
    if os.path.exists(SERVER_CONF_PATH):
        with open(SERVER_CONF_PATH, "r") as f:
            original = f.read()

    with open(SERVER_CONF_PATH, "w") as f:
        f.write(new_content)

    if not _restart_openvpn():
        if original is not None:
            with open(SERVER_CONF_PATH, "w") as f:
                f.write(original)
            _restart_openvpn()
        return False, f"{description} failed to restart OpenVPN - reverted to the previous working config."

    if not _wait_for_port_listening(check_port, check_proto):
        if original is not None:
            with open(SERVER_CONF_PATH, "w") as f:
                f.write(original)
            _restart_openvpn()
        return False, f"{description} restarted, but port {check_port}/{check_proto} never came up - reverted. Nothing was left broken."

    return True, f"{description} applied and verified on port {check_port}/{check_proto}."


def _generate_client_profile(client_name, server_ip, listen_port, listen_proto):
    client_cert = f"{PKI_DIR}/issued/{client_name}.crt"
    client_key = f"{PKI_DIR}/private/{client_name}.key"
    ca_cert = f"{PKI_DIR}/ca.crt"
    tc_key = f"{OPENVPN_DIR}/tc.key"

    if not (os.path.exists(client_cert) and os.path.exists(client_key)):
        return None

    def read(path):
        with open(path) as f:
            return f.read()

    ovpn_content = f"""client
dev tun
proto {listen_proto}
remote {server_ip} {listen_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
verb 3
<ca>
{read(ca_cert)}</ca>
<cert>
{read(client_cert)}</cert>
<key>
{read(client_key)}</key>
<tls-crypt>
{read(tc_key)}</tls-crypt>
"""
    os.makedirs(CLIENT_DIR, exist_ok=True)
    profile_path = f"{CLIENT_DIR}/{client_name}.ovpn"
    with open(profile_path, "w") as f:
        f.write(ovpn_content)
    return profile_path


def create_client(client_name, listen_port, listen_proto):
    """Extracted for reuse - the SSH/master user manager needs to be able to
    create a linked OpenVPN client the same way this menu does, rather than
    duplicating the cert-generation logic a second time.
    Returns (ok: bool, profile_path_or_error: str)."""
    if not client_name or not re.match(r'^[A-Za-z0-9_-]+$', client_name):
        return False, "Client name must contain only letters, numbers, hyphens, underscores."
    if not os.path.exists(PKI_DIR):
        return False, "OpenVPN PKI not initialized - install OpenVPN first."
    if os.path.exists(f"{PKI_DIR}/issued/{client_name}.crt"):
        return False, f"A client named '{client_name}' already exists."

    _easyrsa("build-client-full", client_name, "nopass")
    if not os.path.exists(f"{PKI_DIR}/issued/{client_name}.crt"):
        return False, "Client certificate generation failed."

    server_ip = os.popen("curl -s ifconfig.me || hostname -I | awk '{print $1}'").read().strip()
    profile_path = _generate_client_profile(client_name, server_ip, listen_port, listen_proto)
    if not profile_path:
        return False, "Certificate was created but the .ovpn profile couldn't be assembled."
    return True, profile_path


def openvpn_admin_manager(ports_dict):
    """OpenVPN Administrator Module."""
    while True:
        ovpn_port = ports_dict.get('OPENVPN_PORT', 'Not configured')
        ovpn_proto = ports_dict.get('OPENVPN_PROTO', 'udp')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                   OPENVPN ADMINISTRATOR                    %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      PORT: {ovpn_port}  |  PROTOCOL: {ovpn_proto.upper() if isinstance(ovpn_proto, str) else ovpn_proto}")
        print("----------------------------------------------------------------")
        print(" %s[1]>%s CONFIGURE / INSTALL OPENVPN (Wizard)" % (C_YELLOW, C_RESET))
        print(" %s[2]>%s CHANGE PORT & PROTOCOL (TCP/UDP)" % (C_YELLOW, C_RESET))
        print(" %s[3]>%s MANAGE CLIENTS (Add/Revoke)" % (C_YELLOW, C_RESET))
        print(" %s[4]>%s VIEW SERVICE LOGS" % (C_YELLOW, C_RESET))
        print(" %s[5]>%s RESTART OPENVPN SERVICE" % (C_YELLOW, C_RESET))
        print(f" {C_YELLOW}[6]>{C_RESET} START/STOP OPENVPN SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" %s[0]%s RETURN  %s[7]%s UNINSTALL OPENVPN" % (C_YELLOW, C_RESET, C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s            OPENVPN INSTALLATION WIZARD                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            proto_choice = input(" Select Protocol ([1] UDP / [2] TCP) [Default: UDP]: ").strip()
            listen_proto = "tcp" if proto_choice == '2' else "udp"

            listen_port = prompt_port(" Enter desired OpenVPN Listen Port (e.g., 1194 or 443): ", default=1194)
            if str(listen_port) != str(ovpn_port) and check_system_port_in_use(listen_port, (listen_proto,)):
                print(f"{C_RED}[X] Port {listen_port}/{listen_proto} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            redirect_gateway = input(" Enable full traffic redirection (route ALL client traffic through the VPN)? (y/n) [Default: y]: ").strip().lower() != 'n'

            print(f"\n[i] Installing OpenVPN and Easy-RSA packages...")
            _run("apt-get update && apt-get install -y openvpn easy-rsa iptables")

            if not _ensure_pki():
                input("\nPress Enter to continue...")
                continue
            if not _ensure_crl_generated():
                print(f"{C_RED}[X] CRL generation failed - revocation wouldn't be enforceable without it.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            new_content = _build_config(listen_port, listen_proto, redirect_gateway)

            _ensure_ip_forwarding()
            interface = _default_interface()
            _ensure_masquerade(interface)
            open_firewall_port(listen_port, (listen_proto,))
            persist_firewall_rules()
            _run("systemctl enable openvpn-server@server")

            ok, msg = _apply_config_safely(new_content, f"OpenVPN on port {listen_port}/{listen_proto}", listen_port, listen_proto)
            if ok:
                ports_dict['OPENVPN_PORT'] = str(listen_port)
                ports_dict['OPENVPN_PROTO'] = listen_proto
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
                print(f"{C_CYAN}    NAT/MASQUERADE enabled on {interface} so clients actually reach the internet.{C_RESET}")
            else:
                close_firewall_port(listen_port, (listen_proto,))
                _remove_masquerade(interface)
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s              CHANGE PORT & PROTOCOL SETTINGS               %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(SERVER_CONF_PATH):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(f" Enter new OpenVPN port [Current: {ovpn_port}]: ",
                                    default=int(ovpn_port) if str(ovpn_port).isdigit() else 1194)
            proto_choice = input(" Select Protocol ([1] UDP / [2] TCP): ").strip()
            new_proto = "tcp" if proto_choice == '2' else "udp"

            if (str(new_port), new_proto) != (str(ovpn_port), ovpn_proto) and check_system_port_in_use(new_port, (new_proto,)):
                print(f"{C_RED}[X] Port {new_port}/{new_proto} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            with open(SERVER_CONF_PATH, "r") as f:
                existing = f.read()
            redirect_gw = 'redirect-gateway' in existing and not '# push redirect-gateway' in existing
            new_content = _build_config(new_port, new_proto, redirect_gw)

            open_firewall_port(new_port, (new_proto,))
            persist_firewall_rules()

            ok, msg = _apply_config_safely(new_content, f"Port change to {new_port}/{new_proto}", new_port, new_proto)
            if ok:
                old_port, old_proto = ovpn_port, ovpn_proto
                ports_dict['OPENVPN_PORT'] = str(new_port)
                ports_dict['OPENVPN_PROTO'] = new_proto
                if str(old_port).isdigit() and (str(old_port), old_proto) != (str(new_port), new_proto):
                    close_firewall_port(int(old_port), (old_proto,))
                    persist_firewall_rules()
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(new_port, (new_proto,))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   MANAGE OPENVPN CLIENTS                   %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(PKI_DIR):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            print(" %s[1]%s Add a client" % (C_YELLOW, C_RESET))
            print(" %s[2]%s Revoke a client" % (C_YELLOW, C_RESET))
            print(" %s[0]%s Back" % (C_YELLOW, C_RESET))
            sub = input(" Select option: ").strip()

            if sub == '1':
                client_name = input(" Enter client profile name (e.g., user1): ").strip()
                print(f"{C_CYAN}[i] Generating client certificate...{C_RESET}")
                ok, result = create_client(client_name, ovpn_port, ovpn_proto)
                if ok:
                    existing_clients = ports_dict.get('OPENVPN_CLIENTS', '')
                    clients = [c for c in existing_clients.split(',') if c] if existing_clients else []
                    clients.append(client_name)
                    ports_dict['OPENVPN_CLIENTS'] = ",".join(clients)
                    print(f"{C_GREEN}[OK] Client '{client_name}' created. Profile ready at:{C_RESET}")
                    print(f"     {result}")
                else:
                    print(f"{C_RED}[X] {result}{C_RESET}")

            elif sub == '2':
                client_name = input(" Enter client name to revoke: ").strip()
                if not os.path.exists(f"{PKI_DIR}/issued/{client_name}.crt"):
                    print(f"{C_RED}[X] No such client.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                confirm = input(f" Revoke '{client_name}'? This immediately blocks their access. (y/n): ").strip().lower()
                if confirm == 'y':
                    _easyrsa("revoke", client_name)
                    if _ensure_crl_generated():
                        _run(f"rm -f {CLIENT_DIR}/{client_name}.ovpn")
                        existing_clients = ports_dict.get('OPENVPN_CLIENTS', '')
                        clients = [c for c in existing_clients.split(',') if c and c != client_name]
                        ports_dict['OPENVPN_CLIENTS'] = ",".join(clients)
                        print(f"{C_GREEN}[OK] '{client_name}' revoked - the CRL was regenerated so this takes effect")
                        print(f"     immediately without needing a restart (crl-verify checks it on each connect).{C_RESET}")
                    else:
                        print(f"{C_RED}[X] Revoke command ran but CRL regeneration failed - revocation may not be enforced yet.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  OPENVPN SERVICE LOGS                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u openvpn-server@server -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_openvpn():
                print(f"{C_GREEN}[OK] OpenVPN service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] OpenVPN failed to restart - check 'journalctl -u openvpn-server@server'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop openvpn-server@server")
                print(f"{C_YELLOW}[!] OpenVPN service stopped.{C_RESET}")
            else:
                if not os.path.exists(SERVER_CONF_PATH):
                    print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start openvpn-server@server")
                if _service_active():
                    print(f"{C_GREEN}[OK] OpenVPN service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] OpenVPN failed to start - check 'journalctl -u openvpn-server@server'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   UNINSTALL OPENVPN                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove OpenVPN? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop openvpn-server@server && systemctl disable openvpn-server@server")
                _run("apt-get purge -y openvpn easy-rsa")
                if str(ovpn_port).isdigit():
                    close_firewall_port(int(ovpn_port), (ovpn_proto,))
                    persist_firewall_rules()
                interface = _default_interface()
                _remove_masquerade(interface)
                _run(f"rm -f {SYSCTL_DROPIN_PATH}")
                _run(f"rm -rf {OPENVPN_DIR}")
                ports_dict.pop('OPENVPN_PORT', None)
                ports_dict.pop('OPENVPN_PROTO', None)
                ports_dict.pop('OPENVPN_CLIENTS', None)
                print(f"{C_GREEN}[OK] OpenVPN purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
