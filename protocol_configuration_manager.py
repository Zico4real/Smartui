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
from panel_common import C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN, clear_screen, check_system_port_in_use


def _service_active(service_name):
    return os.system("systemctl is-active --quiet %s 2>/dev/null" % service_name) == 0


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
    mode = ports_dict.get('DNSTT_MODE')
    port = ports_dict.get('DNSTT_PORT')
    if not mode:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    service_name = "masterdnsvpn" if mode == "masterdns" else "slowdns"
    proto = "udp" if mode in ("dnstt", "vaydns", "masterdns") else "udp"  # all 4 DNSTT-family backends are UDP-facing
    return _status_tag(service_name, port, proto)


def _pysocks_status(ports_dict):
    raw = ports_dict.get('PYSOCKS_INSTANCES', '')
    instances = [e for e in raw.split(',') if e]
    if not instances:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    running = 0
    for entry in instances:
        parts = entry.split(':')
        if len(parts) == 3 and _service_active("python.%s" % parts[1]):
            running += 1
    if running == 0:
        return "%s[OFF]%s" % (C_RED, C_RESET), None
    return "%s[ON]%s" % (C_GREEN, C_RESET), "%d/%d running" % (running, len(instances))


def _xray_status():
    # Xray's own module manages its own state independently of the shared
    # ports_dict (it predates that convention) - check its actual service.
    return _status_tag("xray")


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

        entries = [
            ("1", "SSH", "ssh_dropbear_manager", "ssh_admin_manager", (ports_dict.get('SSH_PORT'), "tcp")),
            ("2", "DROPBEAR", "dropbear", ports_dict.get('DROPBEAR_PORTS'), "tcp"),
            ("3", "SOCKS PYTHON", None, None, None),  # handled specially below
            ("4", "STUNNEL (SSL)", "stunnel4", ports_dict.get('STUNNEL_PORTS'), "tcp"),
            ("5", "SLOWDNS", None, None, None),  # handled specially below
            ("6", "WS-EPRO", "ws-epro", ports_dict.get('WS_PORT'), "tcp"),
            ("7", "UDP-CUSTOM (ZIVPN)", "zivpn", ports_dict.get('ZIVPN_PORT'), "udp"),
            ("8", "HYSTERIA 2", "hysteria-server", ports_dict.get('HYSTERIA_PORT'), "udp"),
            ("9", "BADVPN-UDPGW", "badvpn", ports_dict.get('BADVPN_PORT'), "udp"),
            ("10", "SQUID", "squid", ports_dict.get('SQUID_PORT'), "tcp"),
            ("11", "OPENVPN", "openvpn-server@server", ports_dict.get('OPENVPN_PORT'), ports_dict.get('OPENVPN_PROTO', 'udp')),
            ("12", "CHECKUSER ONLINE", "checkuser-api", (ports_dict.get('CHECKUSER_API_PORTS') or '').split(',')[0] or None, "tcp"),
            ("13", "ATKEN and HASH", "atken-hash", ports_dict.get('ATKEN_PORT'), "tcp"),
            ("14", "FILEBROWSER", "filebrowser", ports_dict.get('FILEBROWSER_PORT'), "tcp"),
            ("15", "V2RAY/XRAY", None, None, None),  # handled specially below
            ("16", "SSHGO", "sshgo", ports_dict.get('SSHGO_PORT'), "tcp"),
            ("17", "WIREGUARD", "wg-quick@wg0", ports_dict.get('WIREGUARD_PORT'), "udp"),
            ("18", "ICMP TUNNEL", "icmp-tunnel", None, None),  # handled specially below - no port, TUN-based
            ("19", "PSIPHON (OSSH)", "psiphon-gate", ports_dict.get('PSIPHON_GATE_PORT'), "tcp"),
            ("20", "PORT 443/80 MULTIPLEX", "sslh", ports_dict.get('BROKER_PORT'), "tcp"),
            ("21", "WEBSOCKET (wstunnel)", "wstunnel", ports_dict.get('WSTUNNEL_PORT'), "tcp"),
            ("22", "HYSTERIA 1 (LEGACY)", "hysteria1", ports_dict.get('HYSTERIA1_PORT'), "udp"),
            ("23", "UDP DROID (multi-port)", "udp-droid", ports_dict.get('UDP_DROID_PORTS'), "udp"),
        ]

        status_by_num = {}
        detail_by_num = {}
        active_display_list = []
        for num, label, svc, port, proto in entries:
            if num == "3":
                tag, detail = _pysocks_status(ports_dict)
            elif num == "5":
                tag, detail = _dnstt_status(ports_dict)
            elif num == "15":
                tag, detail = _xray_status()
            elif num == "18":
                tag, detail = _status_tag("icmp-tunnel", None, None)
            elif num == "19":
                tag, detail = _psiphon_status(ports_dict)
            else:
                tag, detail = _status_tag(svc, port, proto)
            status_by_num[num] = tag
            detail_by_num[num] = detail
            if "[ON]" in tag:
                shown = "%s %s" % (label, detail) if detail else label
                active_display_list.append(shown)

        print("%s============================================================%s" % (C_CYAN, C_RESET))
        print("%s%s                     PROTOCOL MANAGER                       %s" % (C_BOLD, "", C_RESET))
        print("%s============================================================%s" % (C_CYAN, C_RESET))

        if not active_display_list:
            print(" %sNo active protocols running.%s" % (C_YELLOW, C_RESET))
        else:
            for i in range(0, len(active_display_list), 2):
                col1 = active_display_list[i]
                col2 = active_display_list[i + 1] if i + 1 < len(active_display_list) else ""
                print(" %s%-28s%s %s" % (C_GREEN, col1, C_RESET, col2))

        print("%s============================================================%s" % (C_CYAN, C_RESET))

        def _format_cell(num, label, tag, detail, label_width=18, status_width=6, detail_max=14):
            label_part = " %s[%s]>%s %s" % (C_YELLOW, num, C_RESET, label)
            target_width = len(num) + 5 + label_width
            if _visible_len(label_part) >= target_width:
                label_part = label_part + "  "  # guarantee a minimum gap even when the label itself is long
            else:
                label_part = _pad_visible(label_part, target_width)
            status_part = _pad_visible(tag, status_width)
            if detail and "[ON]" in tag:
                detail_str = str(detail)
                if len(detail_str) > detail_max:
                    detail_str = detail_str[:detail_max - 3] + "..."
                return "%s%s(%s)" % (label_part, status_part, detail_str)
            return "%s%s" % (label_part, status_part)

        def print_row(n1, label1, n2, label2):
            cell1 = _format_cell(n1, label1, status_by_num[n1], detail_by_num[n1])
            cell1 = _pad_visible(cell1, 44)
            cell2 = _format_cell(n2, label2, status_by_num[n2], detail_by_num[n2])
            print("%s%s" % (cell1, cell2))

        print_row("1", "SSH", "10", "SQUID")
        print_row("2", "DROPBEAR", "11", "OPENVPN")
        print_row("3", "SOCKS PYTHON", "12", "CHECKUSER ONLINE")
        print_row("4", "STUNNEL (SSL)", "13", "ATKEN and HASH")
        print_row("5", "SLOWDNS", "14", "FILEBROWSER")
        print_row("6", "WS-EPRO", "15", "V2RAY/XRAY")
        print_row("7", "UDP-CUSTOM", "16", "SSHGO")
        print_row("8", "HYSTERIA 2", "17", "WIREGUARD")
        print_row("9", "BADVPN-UDPGW", "18", "ICMP TUNNEL")
        print(_format_cell("19", "PSIPHON (OSSH)", status_by_num["19"], detail_by_num["19"]))
        print(_format_cell("20", "PORT 443/80 MULTIPLEX", status_by_num["20"], detail_by_num["20"]))
        print(_format_cell("21", "WEBSOCKET (wstunnel)", status_by_num["21"], detail_by_num["21"]))
        print(_format_cell("22", "HYSTERIA 1 (LEGACY)", status_by_num["22"], detail_by_num["22"]))
        print(_format_cell("23", "UDP DROID (multi-port)", status_by_num["23"], detail_by_num["23"]))

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
        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("Press Enter to continue...")
