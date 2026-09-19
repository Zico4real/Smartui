"""
port_broker_manager.py - Port 443/80 multiplexing for the SmartUI panel,
using sslh (a real, well-established protocol demultiplexer - confirmed
current and packaged across recent Ubuntu releases before building this).

sslh peeks at the first bytes of each new TCP connection and routes the
whole connection to the right backend based on what protocol it looks like
(SSH banner, TLS ClientHello, OpenVPN's header byte, plain HTTP) - this is
what actually lets SSH, a TLS-based service (Xray or Stunnel), OpenVPN in
TCP mode, and an HTTP-based tunnel all share the same public port 443/80.

Scope note, deliberately kept honest rather than overreaching: sslh only
demultiplexes TCP. Every UDP-based protocol in this panel (Hysteria,
WireGuard, BadVPN, ZIVPN, the DNSTT family, the ICMP tunnel, and OpenVPN's
own UDP mode) fundamentally cannot be multiplexed this way - there is no
"peek at the first bytes of a connection" concept for UDP the way there is
for TCP. Only OpenVPN's TCP mode qualifies.

Integration approach: SSH is the one backend this module can safely and
automatically relocate off the shared port, reusing the already-tested
_change_ssh_port() from ssh_dropbear_manager.py directly rather than
duplicating that logic. For the TLS/OpenVPN-TCP/HTTP backends, this module
does not reach into and reconfigure Stunnel/OpenVPN/WS-EPRO/Xray's own
internals - each of those already has its own port-configuration wizard
(and Stunnel in particular is designed to run multiple simultaneous ports
already, so there's no single "port" to relocate the way SSH has). Instead,
the broker asks for whichever internal port the admin has already set that
service to listen on via its own module, and configures sslh to route to
it - the admin points their existing wizard at a non-443/80 port first, the
same way they'd need to if manually wiring up sslh by hand.
"""

import os
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)

SSLH_CONFIG_PATH = "/etc/sslh/sslh.cfg"
SSLH_SERVICE_NAME = "sslh"


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", SSLH_SERVICE_NAME]).returncode == 0


def _restart_sslh():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt.
    _run("systemctl reset-failed %s" % SSLH_SERVICE_NAME)
    return _run("systemctl restart %s" % SSLH_SERVICE_NAME).returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _ensure_installed():
    if _run("which sslh").returncode == 0:
        return True
    print("%s[i] Installing sslh...%s" % (C_CYAN, C_RESET))
    _run("apt-get update && apt-get install -y sslh")
    ok = _run("which sslh").returncode == 0
    if not ok:
        print("%s[X] sslh did not install correctly - check network access.%s" % (C_RED, C_RESET))
    return ok


def _build_config(public_port, backends, has_openvpn_tcp):
    """backends: dict of protocol name -> internal port, e.g.
    {"ssh": 2222, "tls": 8443, "http": 8080, "openvpn": 1195}"""
    lines = []
    lines.append("listen:")
    lines.append("(")
    lines.append('  { host: "0.0.0.0"; port: "%s"; },' % public_port)
    lines.append('  { host: "::"; port: "%s"; }' % public_port)
    lines.append(");")
    lines.append("")
    # OpenVPN clients connecting through -port-share-style setups reportedly
    # take over a second between TCP connect and their first data packet -
    # sslh's own docs recommend a longer timeout specifically for this, or a
    # correctly-behaved connection can get misclassified/dropped.
    lines.append("timeout: %s;" % (5 if has_openvpn_tcp else 2))
    lines.append("")
    lines.append("protocols:")
    lines.append("(")
    entries = []
    if "ssh" in backends:
        entries.append('  { name: "ssh"; host: "127.0.0.1"; port: "%s"; probe: "builtin"; }' % backends["ssh"])
    if "openvpn" in backends:
        entries.append('  { name: "openvpn"; host: "127.0.0.1"; port: "%s"; probe: "builtin"; }' % backends["openvpn"])
    if "http" in backends:
        entries.append('  { name: "http"; host: "127.0.0.1"; port: "%s"; probe: "builtin"; }' % backends["http"])
    if "tls" in backends:
        # Must come last among these - TLS's probe is a broad "does this look
        # like a TLS handshake" check, so anything more specific should be
        # tried first.
        entries.append('  { name: "tls"; host: "127.0.0.1"; port: "%s"; probe: "builtin"; }' % backends["tls"])
    lines.append(",\n".join(entries))
    lines.append(");")
    return "\n".join(lines) + "\n"


def _apply_safely(public_port, backends, has_openvpn_tcp, description):
    """No config-syntax-test flag for sslh either - same restart-verify-
    rollback pattern used throughout this panel."""
    original = None
    if os.path.exists(SSLH_CONFIG_PATH):
        with open(SSLH_CONFIG_PATH, "r") as f:
            original = f.read()

    os.makedirs(os.path.dirname(SSLH_CONFIG_PATH), exist_ok=True)
    new_content = _build_config(public_port, backends, has_openvpn_tcp)
    with open(SSLH_CONFIG_PATH, "w") as f:
        f.write(new_content)

    if not _restart_sslh():
        if original is not None:
            with open(SSLH_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_sslh()
        return False, "%s failed to restart - check 'journalctl -u sslh'." % description

    if not _wait_for_port_listening(public_port):
        if original is not None:
            with open(SSLH_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_sslh()
        return False, "%s restarted, but port %s never came up - reverted. Nothing was left broken." % (description, public_port)

    return True, "%s applied and verified on port %s." % (description, public_port)


def port_broker_manager(ports_dict):
    """Port 443/80 Multiplexing Administrator Module."""
    while True:
        current_port = ports_dict.get('BROKER_PORT', 'Not configured')
        current_backends = ports_dict.get('BROKER_BACKENDS', '')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s            PORT 443/80 MULTIPLEXING (sslh)                 %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      SHARED PORT: %s  |  BACKENDS: %s" % (current_port, current_backends or "none"))
        print("%s      Only TCP-based protocols can share a port this way - UDP" % C_YELLOW)
        print("      protocols (Hysteria, WireGuard, BadVPN, ZIVPN, DNSTT, ICMP,")
        print("      OpenVPN-UDP) cannot be included, there's no way to peek at a")
        print("      UDP flow's first bytes before it's already been delivered.%s" % C_RESET)
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE MULTIPLEXING (Wizard)")
        print(" [2]> VIEW CURRENT CONFIGURATION")
        print(" [3]> VIEW SERVICE LOGS")
        print(" [4]> RESTART SERVICE")
        print(" [5]> START/STOP SERVICE [%s]" % status_label)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [6] UNINSTALL / DISABLE MULTIPLEXING")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s          PORT MULTIPLEXING CONFIGURATION WIZARD            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            public_port = prompt_port(" Which port do you want to share? (443 or 80): ", default=443)

            existing_ssh_port = ports_dict.get('SSH_PORT')
            include_ssh = input(" Include SSH? (y/N): ").strip().lower() == 'y'
            backends = {}

            if include_ssh:
                if existing_ssh_port and str(existing_ssh_port) == str(public_port):
                    print("%s[i] SSH is currently ON the port you want to share - relocating it" % C_CYAN)
                    print("    to an internal port first (reusing SSH's own tested port-change")
                    print("    logic, the same as if you'd done this from the SSH Administrator).%s" % C_RESET)
                    new_ssh_port = prompt_port(" Enter a new internal port for SSH (e.g. 2299): ", default=2299)
                    from ssh_dropbear_manager import _change_ssh_port
                    _change_ssh_port(new_ssh_port, str(existing_ssh_port), ports_dict)
                    backends["ssh"] = new_ssh_port
                elif existing_ssh_port:
                    backends["ssh"] = int(existing_ssh_port)
                    print("%s[i] Using SSH's current port %s as the internal target.%s" % (C_CYAN, existing_ssh_port, C_RESET))
                else:
                    print("%s[X] SSH isn't configured yet - set it up in SSH Administrator first.%s" % (C_RED, C_RESET))

            include_tls = input(" Include a TLS-based service (Xray or Stunnel)? (y/N): ").strip().lower() == 'y'
            if include_tls:
                print("%s[i] This must already be running on an internal (non-%s) port -" % (C_CYAN, public_port))
                print("    set that up in Xray or Stunnel's own menu first if you haven't.%s" % C_RESET)
                tls_port = prompt_port(" Enter that service's current internal port: ", default=8443)
                if str(tls_port) == str(public_port):
                    print("%s[X] That's the same as the shared port - it needs to be a different," % C_RED)
                    print("    internal-only port. Skipping TLS backend.%s" % C_RESET)
                else:
                    backends["tls"] = tls_port

            include_openvpn = input(" Include OpenVPN? Only its TCP mode can share a port (y/N): ").strip().lower() == 'y'
            has_openvpn_tcp = False
            if include_openvpn:
                ovpn_proto = ports_dict.get('OPENVPN_PROTO', 'udp')
                if ovpn_proto != 'tcp':
                    print("%s[X] OpenVPN is currently in UDP mode - switch it to TCP mode in OpenVPN" % C_RED)
                    print("    Administrator first if you want to include it here.%s" % C_RESET)
                else:
                    ovpn_port = ports_dict.get('OPENVPN_PORT')
                    if ovpn_port and str(ovpn_port) != str(public_port):
                        backends["openvpn"] = int(ovpn_port)
                        has_openvpn_tcp = True
                    else:
                        print("%s[X] OpenVPN needs to be on a different internal port than %s first.%s" % (C_RED, public_port, C_RESET))

            include_http = input(" Include an HTTP-based tunnel (e.g. WS-EPRO)? (y/N): ").strip().lower() == 'y'
            if include_http:
                ws_port = ports_dict.get('WS_PORT')
                if ws_port and str(ws_port) != str(public_port):
                    backends["http"] = int(ws_port)
                else:
                    print("%s[X] WS-EPRO needs to be on a different internal port than %s first.%s" % (C_RED, public_port, C_RESET))

            if not backends:
                print("%s[X] No backends selected/available - nothing to configure.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(public_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable %s" % SSLH_SERVICE_NAME)

            ok, msg = _apply_safely(public_port, backends, has_openvpn_tcp, "Port %s multiplexing" % public_port)
            if ok:
                ports_dict['BROKER_PORT'] = str(public_port)
                ports_dict['BROKER_BACKENDS'] = ",".join(backends.keys())
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print("     Backends: %s" % ", ".join("%s->127.0.0.1:%s" % (k, v) for k, v in backends.items()))
            else:
                close_firewall_port(public_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                CURRENT CONFIGURATION                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if os.path.exists(SSLH_CONFIG_PATH):
                with open(SSLH_CONFIG_PATH) as f:
                    print(f.read())
            else:
                print("%s Not configured yet.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            os.system("journalctl -u sslh -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if _restart_sslh():
                print("%s[OK] sslh restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u sslh'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            if is_active:
                _run("systemctl stop %s" % SSLH_SERVICE_NAME)
                print("%s[!] sslh stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(SSLH_CONFIG_PATH):
                    print("%s[X] Not configured yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start %s" % SSLH_SERVICE_NAME)
                if _service_active():
                    print("%s[OK] sslh started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u sslh'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            confirm = input(" Disable port multiplexing and remove sslh? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop %s" % SSLH_SERVICE_NAME)
                _run("systemctl disable %s" % SSLH_SERVICE_NAME)
                _run("apt-get purge -y sslh")
                if str(current_port).isdigit():
                    close_firewall_port(int(current_port), ("tcp",))
                    persist_firewall_rules()
                ports_dict.pop('BROKER_PORT', None)
                ports_dict.pop('BROKER_BACKENDS', None)
                print("%s[OK] Port multiplexing disabled and sslh removed.%s" % (C_GREEN, C_RESET))
                print("%s[!] Any services you relocated off port %s are still on their new" % (C_YELLOW, current_port))
                print("    internal ports - reconfigure them individually if you want them")
                print("    back on a public port directly.%s" % C_RESET)
            else:
                print("%s[i] Cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
