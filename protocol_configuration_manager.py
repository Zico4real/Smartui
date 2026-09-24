"""
protocol_configuration_manager.py - the Protocol Manager dashboard for the
SmartUI panel. This is the master navigation hub the rest of the dashboard
calls into - every protocol module built throughout this project is reached
through here.

The single most important finding in this whole file: as originally written,
16 of its 17 menu options were complete stubs -
    else: print(f"[i] Protocol option {choice} selected.")
- doing nothing at all. Only option 15 (V2Ray/Xray) even attempted to
dispatch anywhere, and it pointed at a script (/usr/local/bin/xmenu.py) with
no connection to anything actually in this codebase - selecting it would
silently do nothing, no error, no feedback. Every module built and fixed
throughout this entire project (SSH, Dropbear, Stunnel, DNSTT family,
WS-EPRO, ZIVPN, Hysteria, BadVPN, Squid, OpenVPN, CheckUser API, Atken,
FileBrowser, Xray, SSHGO, WireGuard) was unreachable from the real dashboard
without this fix - this is the glue that makes the rest of the project
actually usable, not just correct in isolation.

The status-detection helper (get_service_status_and_port) also had two real
bugs of its own:

1. It only checked TCP listening sockets (`ss -tlnp`), never UDP
   (`ss -ulnp`). Hysteria, WireGuard, BadVPN-UDPGW, the DNSTT family, and
   ZIVPN are all UDP-based - every one of them would have shown [OFF] even
   while genuinely running, since their actual listening sockets are
   invisible to a TCP-only scan.

2. Several of the hardcoded service-name/port guesses in services_map didn't
   match what was actually built: "wsproxy" vs the real "ws-epro" service,
   "udp-custom" vs the real "zivpn" service, "hysteria" vs the real
   "hysteria-server"/"hysteria-v1" services, "checkuser" vs the real
   "checkuser-api" service (and port 81 vs the real default 8082),
   "atken" vs the real "atken-hash" service (and port 8888 vs the real
   default 85). These would have shown [OFF] for running services simply
   because the name being checked wasn't the name actually in use.

Fixed by reading each module's own ports_dict entries as the source of
truth for what's configured (each module already maintains this - matching
this dashboard's job to the rest of the panel's own state rather than
re-guessing it), then confirming the recorded port is genuinely listening as
a live correctness check, rather than blindly trusting either the static
guess list alone or the ports_dict record alone.
"""

import os
import re
import json
from panel_common import C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN, clear_screen, check_system_port_in_use, get_live_port_from_service


# (ports_dict key, systemd unit path, regex pattern) for every module that
# bakes its port into a systemd unit - keeps Protocol Manager's own display
# in sync with reality even if the admin never opens that module's own
# screen (which is where the per-module reconciliation used to live
# exclusively - meaning a stale value could sit here indefinitely until the
# admin happened to visit that specific module).
_RECONCILE_TARGETS = [
    ("ATKEN_PORT", "/etc/systemd/system/atken-hash.service", r'Environment=ATKEN_API_PORT=(\d+)'),
    ("ICMP_GATE_PORT", "/etc/systemd/system/icmp-vpn-gate.service", r'Environment=ICMP_GATE_PORT=(\d+)'),
    ("PSIPHON_GATE_PORT", "/etc/systemd/system/psiphon-gate.service", r'Environment=PSIPHON_GATE_PORT=(\d+)'),
    ("WSTUNNEL_PORT", "/etc/systemd/system/websocket-tunnel.service", r'WS_TUNNEL_LISTEN_PORT=(\d+)'),
    ("CHECKUSER_API_PORTS", "/etc/systemd/system/checkuser-api.service", r'Environment=CHECKUSER_API_PORTS=([\d,]+)'),
    ("UDP_DROID_PORTS", "/etc/systemd/system/udp-droid.service", r'--ports ([\d,]+)'),
    ("WS_PORT", "/etc/systemd/system/ws-epro.service", r'Environment=WS_EPRO_LISTEN_PORT=(\d+)'),
    ("HYSTERIA1_PORT", "/etc/hysteria1/config.json", r'"listen":\s*":(\d+)"'),
    ("BROKER_PORT", "/etc/sslh/sslh.cfg", r'port: "(\d+)"'),
]


def _reconcile_live_ports(ports_dict):
    """Runs once per Protocol Manager screen load - silently corrects any
    ports_dict entry that has drifted from what its systemd unit actually
    shows, without waiting for the admin to happen to open that specific
    module's own screen first."""
    for key, service_path, pattern in _RECONCILE_TARGETS:
        live = get_live_port_from_service(service_path, pattern)
        if live and str(ports_dict.get(key)) != str(live):
            ports_dict[key] = live

    # SSHGO uses one of two possible variable names depending on its mode
    sshgo_live = (get_live_port_from_service("/etc/systemd/system/sshgo.service", r'Environment=WS_EPRO_LISTEN_PORT=(\d+)')
                  or get_live_port_from_service("/etc/systemd/system/sshgo.service", r'Environment=SSHGO_LISTEN_PORT=(\d+)'))
    if sshgo_live and str(ports_dict.get('SSHGO_PORT')) != str(sshgo_live):
        ports_dict['SSHGO_PORT'] = sshgo_live


def _service_active(service_name):
    return os.system("systemctl is-active --quiet %s 2>/dev/null" % service_name) == 0


def _ssh_status(ports_dict):
    """SSH's systemd unit is named 'ssh' on most Debian/Ubuntu installs but
    'sshd' on some - ssh_dropbear_manager.py's own detection already checks
    both for this exact reason, so this matches that here rather than only
    checking one name and risking a mismatch between the two screens.

    Port comes from the live sshd_config, not ports_dict - on a fresh
    install, ports_dict['SSH_PORT'] is only ever set by explicitly going
    through the "Modify SSH Port" wizard. If SSH is just running on the OS
    default (22) without that wizard ever being used, ports_dict has
    nothing recorded at all - confirmed on a real fresh install where SSH
    showed [ON] but the port and summary line were both blank. Reading the
    real config directly (falling back to 22 when the Port directive is
    commented out or absent, which is the standard sshd_config default)
    fixes this the same way the other modules' live-port reconciliation
    does."""
    active = _service_active("ssh") or _service_active("sshd")
    if not active:
        return "%s[OFF]%s" % (C_RED, C_RESET), None

    port = ports_dict.get('SSH_PORT')
    if not port:
        try:
            with open("/etc/ssh/sshd_config") as f:
                content = f.read()
            m = re.search(r'^\s*Port\s+(\d+)', content, re.MULTILINE)
            port = m.group(1) if m else "22"
        except Exception:
            port = "22"

    if port and str(port).isdigit():
        listening = check_system_port_in_use(int(port), ("tcp",))
        if not listening:
            return "%s[ON?]%s" % (C_YELLOW, C_RESET), port
    return "%s[ON]%s" % (C_GREEN, C_RESET), port


def _status_tag(service_name, port=None, proto="tcp"):
    """Two-layer check: is the service genuinely active, AND (if we have a
    specific port to confirm) is it actually listening there. A service that
    reports 'active' but isn't bound to anything is still worth flagging."""
    active = _service_active(service_name)
    if not active:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    if port and str(port).isdigit():
        listening = check_system_port_in_use(int(port), (proto,))
        if not listening:
            return "%s[ON?]%s" % (C_YELLOW, C_RESET), port  # active per systemd, but port not confirmed live
    return "%s[ON]%s" % (C_GREEN, C_RESET), port


def _dnstt_status(ports_dict):
    # Single-instance path (old, still supported): ports_dict tracks it
    # directly.
    mode = ports_dict.get('DNSTT_MODE')
    port = ports_dict.get('DNSTT_PORT')
    if mode:
        service_name = "masterdnsvpn" if mode == "masterdns" else "slowdns"
        # dnstt and vaydns NAT-redirect from the externally-advertised port
        # (DNSTT_PORT, e.g. 53) to a fixed internal port (5300) where the
        # binary actually binds - confirmed directly from the install
        # flow's own comment. Checking DNSTT_PORT here was checking a port
        # nothing ever directly binds to at all, which is exactly why this
        # always showed the ambiguous "[ON?]" rather than a clean "[ON]"
        # even on a perfectly healthy install - the redirect target was
        # never going to show up as "listening" on its own. Slipstream (and
        # every other mode reaching this branch) binds its own port
        # directly and needs no such correction.
        if mode in ('dnstt', 'vaydns'):
            from dnstt_manager import DNSTT_INTERNAL_PORT
            tag, _ = _status_tag(service_name, DNSTT_INTERNAL_PORT, "udp")
            # Display the port the admin's own customers actually connect
            # to, not the internal redirect target used only for the
            # liveness check above.
            return tag, port
        return _status_tag(service_name, port, "udp")

    # Multi-Engine path: confirmed as a real gap - these instances are
    # tracked in their own registry file, never in ports_dict at all, so
    # this status always showed OFF regardless of how many multi-engine
    # instances were genuinely running. dns-router itself being active,
    # with at least one instance in its registry, is what "on" actually
    # means here - the live registry is the real source of truth, not
    # ports_dict, which this architecture never touches.
    try:
        from dnstt_manager import _load_instance_registry
        registry = _load_instance_registry()
    except Exception:
        registry = {}
    if registry and _service_active("dns-router"):
        count = len(registry)
        label = "1 instance" if count == 1 else "%d instances" % count
        return "%s[ON]%s" % (C_GREEN, C_RESET), label

    return "%s[OFF]%s" % (C_RED, C_RESET), None


def _pysocks_status(ports_dict):
    raw = ports_dict.get('PYSOCKS_INSTANCES', '')
    instances = [e for e in raw.split(',') if e]
    if not instances:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    running_ports = []
    for entry in instances:
        parts = entry.split(':')
        if len(parts) == 3 and _service_active("python.%s" % parts[1]):
            running_ports.append(parts[1])
    if not running_ports:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    return "%s[ON]%s" % (C_GREEN, C_RESET), ", ".join(running_ports)


def _icmp_status(ports_dict):
    """Confirmed as a direct, real bug: this checked a service literally
    named 'icmp-tunnel', which has never existed - the actual units are
    'icmp-vpn' (the tunnel itself) and 'icmp-vpn-gate' (the authentication
    gate clients must unlock through first, per this module's own admin
    screen). Checking a nonexistent service name meant this always read
    OFF regardless of whether the real services were healthy. Both need to
    be active for the tunnel to be genuinely usable, matching the same
    "both together" check the module's own admin screen already uses."""
    tunnel_active = _service_active("icmp-vpn")
    gate_active = _service_active("icmp-vpn-gate")
    if tunnel_active and gate_active:
        gate_port = ports_dict.get('ICMP_GATE_PORT')
        return "%s[ON]%s" % (C_GREEN, C_RESET), gate_port
    return "%s[OFF]%s" % (C_RED, C_RESET), None


def _nginx_status():
    """Shows how many path routes are configured, same pattern as HAProxy's
    own route count."""
    tag, _ = _status_tag("nginx")
    if "91m" in tag:  # red/OFF
        return tag, None
    try:
        import nginx_manager as ngm
        registry = ngm._load_registry()
    except Exception:
        registry = {}
    if not registry:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    count = len(registry)
    label = "1 route" if count == 1 else "%d routes" % count
    return tag, label


def _haproxy_status():
    """Shows how many SNI routes are configured, same pattern as SLOWDNS's
    instance count and Xray's real-profile check - a bare process-active
    check alone wouldn't tell an admin whether any route actually exists."""
    tag, _ = _status_tag("haproxy")
    if "91m" in tag:  # red/OFF - service itself isn't running
        return tag, None
    try:
        import haproxy_manager as hpm
        registry = hpm._load_registry()
    except Exception:
        registry = {}
    if not registry:
        # Matches the same convention requested for Xray: a running
        # process with nothing actually configured isn't useful to an
        # admin the way any other "ON" protocol is, so it reads as OFF
        # rather than a distinct in-between state.
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    count = len(registry)
    label = "1 route" if count == 1 else "%d routes" % count
    return tag, label


def _xray_status():
    # Xray's own module manages its own state independently of the shared
    # ports_dict (it predates that convention) - check its actual service.
    # Confirmed as a real gap: checking only "is the process active" shows
    # ON even with a config that has zero real inbounds - Xray-core itself
    # stays running fine on an empty or minimal config, so the process
    # being active tells an admin nothing about whether any actual profile
    # exists. Reading the live config directly and counting real inbounds
    # gives a genuinely useful signal instead.
    tag, _ = _status_tag("xray")
    if "91m" in tag:  # red/OFF - service itself isn't even running
        return tag, None
    try:
        with open("/usr/local/etc/xray/config.json") as f:
            config = json.load(f)
        inbounds = config.get("inbounds", [])
        ports = sorted(set(str(ib.get("port")) for ib in inbounds if ib.get("port")))
        if not ports:
            # A running process with zero real profiles isn't useful to an
            # admin the way any other "ON" protocol is - nothing is actually
            # reachable by any user, so this should read the same as OFF
            # rather than a distinct in-between state.
            return "%s[OFF]%s" % (C_RED, C_RESET), None
        detail = ", ".join(ports) if len(ports) <= 3 else "%s, +%d more" % (", ".join(ports[:3]), len(ports) - 3)
        return tag, detail
    except Exception:
        return tag, None


def _psiphon_status(ports_dict):
    """Multiple customer instances can exist under one gate service - report
    how many are actually running, same pattern as the Python SOCKS multi-
    instance status, rather than a single misleading ON/OFF for the gate
    alone."""
    try:
        import psiphon_manager as psm
        credentials = psm._load_credentials()
    except Exception:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    if not credentials:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    running = sum(1 for name in credentials if _service_active("psiphon-%s" % name))
    if running == 0:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    return "%s[ON]%s" % (C_GREEN, C_RESET), "%d/%d running" % (running, len(credentials))


def _visible_len(text):
    return len(re.sub(r'\033\[[0-9;]*m', '', text))


def _pad_visible(text, width):
    """Pads a string that may contain ANSI color codes to a fixed VISIBLE
    width - naive %-Ns padding counts the invisible escape sequences as part
    of the string length, which is what caused the second column to drift
    depending on whether the first column's status was ON/OFF/ON? (each a
    different visible length)."""
    current = _visible_len(text)
    if current >= width:
        return text
    return text + " " * (width - current)


def protocol_configuration_manager(ports_dict):
    while True:
        clear_screen()
        _reconcile_live_ports(ports_dict)

        entries = [
            ("1", "SSH", None, None, None),  # handled specially below (checks both ssh/sshd service names)
            ("2", "DROPBEAR", "dropbear", ports_dict.get('DROPBEAR_PORTS'), "tcp"),
            ("3", "SOCKS PYTHON", None, None, None),  # handled specially below
            ("4", "STUNNEL (SSL)", "stunnel4", ports_dict.get('STUNNEL_PORTS'), "tcp"),
            ("5", "SLOWDNS", None, None, None),  # handled specially below
            ("6", "WS-EPRO", "ws-epro", ports_dict.get('WS_PORT'), "tcp"),
            ("7", "UDP-CUSTOM (ZIVPN)", "zivpn", ports_dict.get('ZIVPN_PORT'), "udp"),
            ("8", "HYSTERIA 2", "hysteria-server", ports_dict.get('HYSTERIA_PORT'), "udp"),
            ("9", "BADVPN-UDPGW", "badvpn", ports_dict.get('BADVPN_PORT'), "tcp"),
            ("10", "SQUID", "squid", ports_dict.get('SQUID_PORT'), "tcp"),
            ("11", "OPENVPN", "openvpn-server@server", ports_dict.get('OPENVPN_PORT'), ports_dict.get('OPENVPN_PROTO', 'udp')),
            ("12", "CHECKUSER ONLINE", "checkuser-api", (ports_dict.get('CHECKUSER_API_PORTS') or '').split(',')[0] or None, "tcp"),
            ("13", "ATKEN and HASH", "atken-hash", ports_dict.get('ATKEN_PORT'), "tcp"),
            ("14", "FILEBROWSER", "filebrowser", ports_dict.get('FILEBROWSER_PORT'), "tcp"),
            ("15", "V2RAY/XRAY", None, None, None),  # handled specially below
            ("16", "SSHGO", "sshgo", ports_dict.get('SSHGO_PORT'), "tcp"),
            ("17", "WIREGUARD", "wg-quick@wg0", ports_dict.get('WIREGUARD_PORT'), "udp"),
            ("18", "ICMP TUNNEL", None, None, None),  # handled specially below - no port, TUN-based
            ("19", "PSIPHON (OSSH)", "psiphon-gate", ports_dict.get('PSIPHON_GATE_PORT'), "tcp"),
            ("20", "MULTIPLEX", "sslh", ports_dict.get('BROKER_PORT'), "tcp"),
            ("21", "WEBSOCKET", "websocket-tunnel", ports_dict.get('WSTUNNEL_PORT'), "tcp"),
            ("22", "HYSTERIA 1", "hysteria1", ports_dict.get('HYSTERIA1_PORT'), "udp"),
            ("23", "UDP DROID", "udp-droid", ports_dict.get('UDP_DROID_PORTS'), "udp"),
            ("24", "HAPROXY (SNI)", None, None, None),  # handled specially below
            ("25", "NGINX (PROXY)", None, None, None),  # handled specially below
        ]

        status_by_num = {}
        detail_by_num = {}
        active_display_list = []
        for num, label, svc, port, proto in entries:
            if num == "1":
                tag, detail = _ssh_status(ports_dict)
            elif num == "3":
                tag, detail = _pysocks_status(ports_dict)
            elif num == "5":
                tag, detail = _dnstt_status(ports_dict)
            elif num == "15":
                tag, detail = _xray_status()
            elif num == "18":
                tag, detail = _icmp_status(ports_dict)
            elif num == "19":
                tag, detail = _psiphon_status(ports_dict)
            elif num == "24":
                tag, detail = _haproxy_status()
            elif num == "25":
                tag, detail = _nginx_status()
            else:
                tag, detail = _status_tag(svc, port, proto)
            status_by_num[num] = tag
            detail_by_num[num] = detail
            if "[ON]" in tag and detail:
                active_display_list.append("%s: %s" % (label, detail))

        print("%s============================================================%s" % (C_CYAN, C_RESET))
        print("%s%s                     PROTOCOL MANAGER                       %s" % (C_BOLD, "", C_RESET))
        print("%s============================================================%s" % (C_CYAN, C_RESET))

        if not active_display_list:
            print(" %sNo active protocols running.%s" % (C_YELLOW, C_RESET))
        else:
            for i in range(0, len(active_display_list), 2):
                col1 = active_display_list[i]
                col2 = active_display_list[i + 1] if i + 1 < len(active_display_list) else ""
                print(" %s%s" % (_pad_visible(col1, 30), col2))

        print("%s============================================================%s" % (C_CYAN, C_RESET))

        def _format_cell(num, label, tag, label_width=18, cell_width=31):
            """Matches the compact reference layout: the whole "[N]>" token
            right-justified in a 5-char field (so [1]> and [10]> occupy the
            same width, with the padding going before the bracket rather
            than inside it), label left-padded to a fixed width, and the
            entire cell padded to one fixed total width - which is what
            keeps the gap before the next column consistent regardless of
            whether the status is [ON] (4 chars) or [OFF] (5 chars)."""
            token = "[%s]>" % num
            token_field = token.rjust(5)
            colored_prefix = " " + token_field.replace(token, "%s%s%s" % (C_YELLOW, token, C_RESET))
            label_padded = label.ljust(label_width)
            if len(label) >= label_width:
                label_padded = label + "  "  # guarantee a minimum gap even when the label itself is long
            cell = colored_prefix + " " + label_padded + tag
            return _pad_visible(cell, cell_width)

        def print_row(n1, label1, n2, label2):
            cell1 = _format_cell(n1, label1, status_by_num[n1])
            cell2 = _format_cell(n2, label2, status_by_num[n2])
            # cell2's own leading space (meant for standalone/single-column use)
            # is redundant here - cell1's own padding to a fixed width already
            # provides the correct gap before column 2 begins.
            print("%s%s" % (cell1, cell2[1:]))

        print_row("1", "SSH", "10", "SQUID")
        print_row("2", "DROPBEAR", "11", "OPENVPN")
        print_row("3", "SOCKS PYTHON", "12", "CHECKUSER ONLINE")
        print_row("4", "STUNNEL (SSL)", "13", "ATKEN and HASH")
        print_row("5", "SLOWDNS", "14", "FILEBROWSER")
        print_row("6", "WS-EPRO", "15", "V2RAY/XRAY")
        print_row("7", "UDP-CUSTOM", "16", "SSHGO")
        print_row("8", "HYSTERIA 2", "17", "WIREGUARD")
        print_row("9", "BADVPN-UDPGW", "18", "ICMP TUNNEL")
        print(_format_cell("19", "PSIPHON (OSSH)", status_by_num["19"]))
        print(_format_cell("20", "MULTIPLEX", status_by_num["20"]))
        print(_format_cell("21", "WEBSOCKET", status_by_num["21"]))
        print(_format_cell("22", "HYSTERIA 1", status_by_num["22"]))
        print(_format_cell("23", "UDP DROID", status_by_num["23"]))
        print(_format_cell("24", "HAPROXY (SNI)", status_by_num["24"]))
        print(_format_cell("25", "NGINX (PROXY)", status_by_num["25"]))

        print("%s============================================================%s" % (C_CYAN, C_RESET))
        print(" %s[0] Back%s" % (C_GREEN, C_RESET))
        print("%s============================================================%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            from ssh_dropbear_manager import ssh_admin_manager
            ssh_admin_manager(ports_dict)
        elif choice == '2':
            from ssh_dropbear_manager import dropbear_admin_manager
            dropbear_admin_manager(ports_dict)
        elif choice == '3':
            from python_socks_manager import python_socks_admin_manager
            python_socks_admin_manager(ports_dict)
        elif choice == '4':
            from stunnel_manager import stunnel_admin_manager
            stunnel_admin_manager(ports_dict)
        elif choice == '5':
            from dnstt_manager import dnstt_admin_manager
            dnstt_admin_manager(ports_dict)
        elif choice == '6':
            from ws_epro_manager import ws_epro_admin_manager
            ws_epro_admin_manager(ports_dict)
        elif choice == '7':
            from zivpn_manager import zivpn_admin_manager
            zivpn_admin_manager(ports_dict)
        elif choice == '8':
            from hysteria_manager import hysteria_admin_manager
            hysteria_admin_manager(ports_dict)
        elif choice == '9':
            from badvpn_manager import badvpn_admin_manager
            badvpn_admin_manager(ports_dict)
        elif choice == '10':
            from squid_manager import squid_admin_manager
            squid_admin_manager(ports_dict)
        elif choice == '11':
            from openvpn_manager import openvpn_admin_manager
            openvpn_admin_manager(ports_dict)
        elif choice == '12':
            from checkuser_api_manager import checkuser_api_manager
            checkuser_api_manager(ports_dict)
        elif choice == '13':
            from atken_hash_manager import atken_hash_admin_manager
            atken_hash_admin_manager(ports_dict)
        elif choice == '14':
            from filebrowser_manager import filebrowser_admin_manager
            filebrowser_admin_manager(ports_dict)
        elif choice == '15':
            from xray_manager import main_menu as xray_main_menu
            xray_main_menu()
        elif choice == '16':
            from sshgo_manager import sshgo_admin_manager
            sshgo_admin_manager(ports_dict)
        elif choice == '17':
            from wireguard_manager import wireguard_admin_manager
            wireguard_admin_manager(ports_dict)
        elif choice == '18':
            from icmp_manager import icmp_admin_manager
            icmp_admin_manager(ports_dict)
        elif choice == '19':
            from psiphon_manager import psiphon_admin_manager
            psiphon_admin_manager(ports_dict)
        elif choice == '20':
            from port_broker_manager import port_broker_manager
            port_broker_manager(ports_dict)
        elif choice == '21':
            from websocket_manager import websocket_admin_manager
            websocket_admin_manager(ports_dict)
        elif choice == '22':
            from hysteria1_manager import hysteria1_admin_manager
            hysteria1_admin_manager(ports_dict)
        elif choice == '23':
            from udp_droid_manager import udp_droid_admin_manager
            udp_droid_admin_manager(ports_dict)
        elif choice == '24':
            from haproxy_manager import haproxy_admin_manager
            haproxy_admin_manager(ports_dict)
        elif choice == '25':
            from nginx_manager import nginx_admin_manager
            nginx_admin_manager(ports_dict)
        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("Press Enter to continue...")
