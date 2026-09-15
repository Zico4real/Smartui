"""
shadowsocks_manager.py — Shadowsocks (shadowsocks-libev) admin module for the
SmartUI panel.

Real bugs found, verified against the actual SIP002 spec and shadowsocks-libev's
config model rather than assumed:

1. The generated ss:// link used the LEGACY pre-SIP002 format — base64-encoding
   the entire "method:password@host:port" string. The current spec (SIP002,
   confirmed at shadowsocks.org/doc/sip002.html) only base64-encodes
   "method:password"; host:port stay in plain text after the "@". Encoding the
   whole thing produces a link most modern clients (Shadowrocket, NekoBox,
   sing-box, Outline...) won't parse correctly. Also fixed: the original used
   standard base64 (can emit '+' and '/', which aren't URL-safe) instead of the
   URL-safe variant SIP002 actually specifies.

2. The menu advertised "VIEW CONNECTION INFO / QR CODES" but the implementation
   never generated a QR code at all — just printed the link as text. Actually
   implemented via `qrencode` now, matching what the menu already promised.

3. "Traffic Redirection Settings" let the admin set local_address/local_port in
   server config.json. These are shadowsocks-libev CLIENT (ss-local) config
   fields, not something ss-server acts on — Shadowsocks is a general SOCKS5-
   style proxy where the CLIENT chooses the destination per-connection, not a
   fixed-destination tunnel like Stunnel/dnstt. Setting these on the server
   config did nothing. Removed rather than left in place doing nothing while
   looking like a working feature — same category of issue as the fake
   "DNSTT over QUIC/TCP" modes fixed earlier in this panel.

4. No verification that `apt-get install` or the subsequent restart actually
   succeeded — matches the "blind restart, claims success regardless" bug
   fixed in every other module in this panel so far.

5. Re-running "SETUP" silently overwrote the existing config.json (this only
   supports one instance at a time — the config.json schema used here has a
   single "server_port"/"password", not shadowsocks-libev's separate
   multi-user "port_password" schema) with no warning that it would disconnect
   whoever was using the previous password.
"""

import os
import re
import json
import base64
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)

SS_DIR = "/etc/shadowsocks-libev"
SS_CONFIG_PATH = f"{SS_DIR}/config.json"
CIPHERS = {"1": "aes-256-gcm", "2": "chacha20-ietf-poly1305", "3": "aes-128-gcm"}


def _service_active():
    return (_run(["systemctl", "is-active", "--quiet", "shadowsocks-libev"]).returncode == 0
            or _run(["systemctl", "is-active", "--quiet", "shadowsocks"]).returncode == 0)


def _restart_shadowsocks():
    r = _run("systemctl restart shadowsocks-libev")
    if r.returncode != 0:
        r = _run("systemctl restart shadowsocks")
    return r.returncode == 0


def _wait_for_port_listening(port, protocols=("tcp",), tries=6, delay=1):
    for _ in range(tries):
        if all(check_system_port_in_use(port, (p,)) for p in protocols):
            return True
        time.sleep(delay)
    return False


def _ensure_installed():
    if os.path.exists(SS_DIR) and _run("which ss-server").returncode == 0:
        return True
    print(f"{C_CYAN}[i] Installing shadowsocks-libev...{C_RESET}")
    _run("apt-get update && apt-get install -y shadowsocks-libev")
    ok = _run("which ss-server").returncode == 0
    if not ok:
        print(f"{C_RED}[✖] shadowsocks-libev did not install correctly — check apt output/network access.{C_RESET}")
    return ok


def _sip002_uri(method, password, server_ip, port, tag=""):
    """websafe-base64-encode-utf8(method ":" password) "@" hostname ":" port —
    per SIP002, only userinfo is encoded, host:port stay in plain text."""
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    uri = f"ss://{userinfo}@{server_ip}:{port}"
    if tag:
        uri += f"#{tag}"
    return uri


def _print_qr(text):
    if _run("which qrencode").returncode != 0:
        print(f"{C_CYAN}[i] Installing qrencode for QR code display...{C_RESET}")
        _run("apt-get update && apt-get install -y qrencode")
    if _run("which qrencode").returncode == 0:
        os.system(f"qrencode -t ANSIUTF8 '{text}'")
    else:
        print(f"{C_YELLOW}[!] Could not install qrencode — showing link as text only.{C_RESET}")


def shadowsocks_admin_manager(ports_dict):
    """Shadowsocks (shadowsocks-libev) Administrator Module."""
    while True:
        ss_port = ports_dict.get('SS_PORT', 'Not configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                SHADOWSOCKS (SS) ADMINISTRATOR              %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      PORT: {ss_port}")
        print("────────────────────────────────────────────────────────────")
        print(" %s[1]>%s SETUP / ADD SHADOWSOCKS INSTANCE" % (C_YELLOW, C_RESET))
        print(" %s[2]>%s MANUAL CONFIGURATION (nano)" % (C_YELLOW, C_RESET))
        print(" %s[3]>%s VIEW CONNECTION INFO / QR CODE" % (C_YELLOW, C_RESET))
        print(" %s[4]>%s VIEW SERVICE LOGS" % (C_YELLOW, C_RESET))
        print(" %s[5]>%s RESTART SHADOWSOCKS SERVICE" % (C_YELLOW, C_RESET))
        print(f" {C_YELLOW}[6]>{C_RESET} START/STOP SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" %s[0]%s RETURN  %s[7]%s UNINSTALL SHADOWSOCKS" % (C_YELLOW, C_RESET, C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s            MANUAL SHADOWSOCKS CONFIGURATION SETUP          %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            if os.path.exists(SS_CONFIG_PATH):
                print(f"{C_YELLOW}[!] A Shadowsocks instance is already configured on port {ss_port}.")
                print(f"    Continuing will REPLACE it — anyone using the current password will be")
                print(f"    disconnected (this schema only supports one instance at a time).{C_RESET}")
                if input(" Continue anyway? (y/n): ").strip().lower() != 'y':
                    input("\nPress Enter to continue...")
                    continue

            listen_port = prompt_port(" Enter desired Shadowsocks Listen Port (e.g., 8388): ", default=8388)
            if str(listen_port) != str(ss_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print(f"{C_RED}[✖] Port {listen_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            password = input(" Enter desired Password (blank to auto-generate a strong one): ").strip()
            if not password:
                import secrets
                password = secrets.token_urlsafe(16)
                print(f"{C_CYAN}[i] Generated password: {password}{C_RESET}")

            print("\nAvailable Common Encryption Ciphers:")
            print(" 1. aes-256-gcm (Recommended)")
            print(" 2. chacha20-ietf-poly1305")
            print(" 3. aes-128-gcm")
            cipher_choice = input(" Select cipher option [1-3] or type custom string: ").strip()
            cipher = CIPHERS.get(cipher_choice, cipher_choice) if cipher_choice else CIPHERS["1"]

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            os.makedirs(SS_DIR, exist_ok=True)
            config_data = {
                "server": "0.0.0.0",
                "server_port": listen_port,
                "password": password,
                "timeout": 300,
                "method": cipher,
                "fast_open": True,
            }

            backup = None
            if os.path.exists(SS_CONFIG_PATH):
                with open(SS_CONFIG_PATH, "r") as f:
                    backup = f.read()

            with open(SS_CONFIG_PATH, "w") as f:
                json.dump(config_data, f, indent=4)

            open_firewall_port(listen_port, ("tcp", "udp"))
            persist_firewall_rules()
            _run("systemctl enable shadowsocks-libev")

            if _restart_shadowsocks() and _wait_for_port_listening(listen_port, ("tcp",)):
                ports_dict['SS_PORT'] = str(listen_port)
                print(f"{C_GREEN}[✔] Shadowsocks configured successfully on port {listen_port} using {cipher}!{C_RESET}")
            else:
                if backup is not None:
                    with open(SS_CONFIG_PATH, "w") as f:
                        f.write(backup)
                else:
                    os.remove(SS_CONFIG_PATH)
                _restart_shadowsocks()
                close_firewall_port(listen_port, ("tcp", "udp"))
                print(f"{C_RED}[✖] New config didn't come up — reverted to the previous working setup.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            if not os.path.exists(SS_CONFIG_PATH):
                _ensure_installed()
            os.system(f"nano {SS_CONFIG_PATH}")
            if _restart_shadowsocks():
                print(f"{C_GREEN}[✔] Configuration saved and Shadowsocks restarted.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Shadowsocks failed to restart with the edited config — check it manually")
                print(f"    (systemctl status shadowsocks-libev / journalctl -u shadowsocks-libev).{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                SHADOWSOCKS CONNECTION DETAILS              %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if os.path.exists(SS_CONFIG_PATH):
                with open(SS_CONFIG_PATH, "r") as f:
                    cfg = json.load(f)

                s_port = cfg.get("server_port")
                s_pass = cfg.get("password")
                s_method = cfg.get("method")

                pub_ip = os.popen("curl -s ifconfig.me || hostname -I | awk '{print $1}'").read().strip()
                ss_uri = _sip002_uri(s_method, s_pass, pub_ip, s_port, tag=pub_ip)

                print(f" Server IP:     {pub_ip}")
                print(f" Port:          {s_port}")
                print(f" Password:      {s_pass}")
                print(f" Cipher:        {s_method}")
                print("\n Shadowsocks Link (SIP002):")
                print(f" {ss_uri}")
                print()
                _print_qr(ss_uri)
            else:
                print(f"{C_RED}[✖] No configuration file found. Please set up an instance first.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                SHADOWSOCKS SERVICE LOGS                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u shadowsocks-libev -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_shadowsocks():
                print(f"{C_GREEN}[✔] Shadowsocks service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Shadowsocks failed to restart — check 'journalctl -u shadowsocks-libev'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop shadowsocks-libev")
                _run("systemctl stop shadowsocks")
                print(f"{C_YELLOW}[!] Shadowsocks service stopped.{C_RESET}")
            else:
                if not _ensure_installed():
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl enable shadowsocks-libev")
                if _run("systemctl start shadowsocks-libev").returncode == 0:
                    print(f"{C_GREEN}[✔] Shadowsocks service started.{C_RESET}")
                else:
                    print(f"{C_RED}[✖] Shadowsocks failed to start — check 'journalctl -u shadowsocks-libev'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                UNINSTALL SHADOWSOCKS                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove Shadowsocks? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop shadowsocks-libev && systemctl disable shadowsocks-libev")
                _run("apt-get purge -y shadowsocks-libev")
                if str(ss_port).isdigit():
                    close_firewall_port(int(ss_port), ("tcp", "udp"))
                    persist_firewall_rules()
                ports_dict.pop('SS_PORT', None)
                print(f"{C_GREEN}[✔] Shadowsocks purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
