"""
zivpn_manager.py - ZIVPN (UDP Custom) admin module for the SmartUI panel.

The original draft of this module ("UDP Custom / ZIVPN Administrator") never
actually installed anything at all. Verified against the real upstream project
(zahidbd2/udp-zivpn) before writing this rather than guessing:

1. NO INSTALL STEP EXISTED. The "setup wizard" wrote a config.json and printed
   success, but never downloaded the zivpn binary, never created a systemd
   unit, and never started anything. Every other menu action (restart, logs,
   start/stop, status) assumed a "zivpn"/"udp-custom" service that had never
   been created by this code - nothing in this module could ever have worked,
   even by accident. Fixed with a real install: download the matching prebuilt
   binary from the project's GitHub releases, generate the self-signed cert it
   needs, and write the real systemd unit (confirmed from the project's own
   install scripts, including its capability/security hardening lines).

2. The config schema was entirely fabricated. Fetched the real template
   directly from the upstream repo - it's:
     {"listen": ":PORT", "cert": "...", "key": "...", "obfs": "...",
      "auth": {"mode": "passwords", "config": ["pass1", "pass2", ...]}}
   The original code instead wrote "stream_buffer"/"receive_buffer"/
   "target_port" (none of which exist in the real schema) and put a single
   password string under "auth.password" instead of a LIST under
   "auth.config" - multi-user support was silently broken by the wrong key
   name and wrong structure. Also missing entirely: "cert"/"key" (required -
   the server can't start without them) and "obfs" (real, documented, and
   provides genuine DPI-resistance value).

3. "Traffic redirection target" doesn't correspond to anything in ZIVPN's
   actual config model - it's a complete standalone UDP VPN protocol/app, not
   a raw port-forwarder like Stunnel/dnstt. Same category of fabricated
   feature as the Shadowsocks local_address/local_port bug and Hysteria's
   traffic_redir bug - removed rather than left in place doing nothing.

4. The reference install scripts also apply `sysctl -w net.core.rmem_max=...`
   for the larger UDP receive buffer - a real, recommended tuning step for a
   UDP-heavy protocol, applied at the kernel level rather than as a (fake)
   JSON config key the way the original code attempted it.
"""

import os
import re
import json
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)

ZIVPN_DIR = "/etc/zivpn"
ZIVPN_BIN = "/usr/local/bin/zivpn"
ZIVPN_CONFIG_PATH = f"{ZIVPN_DIR}/config.json"
ZIVPN_SERVICE_PATH = "/etc/systemd/system/zivpn.service"
ZIVPN_RELEASES_BASE = "https://github.com/zahidbd2/udp-zivpn/releases/latest/download"


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "zivpn"]).returncode == 0


def _restart_zivpn():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt.
    _run("systemctl reset-failed zivpn")
    return _run("systemctl restart zivpn").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("udp",)):
            return True
        time.sleep(delay)
    return False


def _detect_arch():
    machine = _run("uname -m").stdout.strip()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "armv8", "arm64"):
        return "arm64"
    if machine.startswith("arm"):
        return "arm"
    return None


def _binary_ok():
    return os.path.exists(ZIVPN_BIN) and os.access(ZIVPN_BIN, os.X_OK)


def _install_binary():
    if _binary_ok():
        return True
    arch = _detect_arch()
    if not arch:
        print(f"{C_RED}[X] Unrecognized CPU architecture - can't pick a matching binary.{C_RESET}")
        return False
    url = f"{ZIVPN_RELEASES_BASE}/udp-zivpn-linux-{arch}"
    print(f"{C_CYAN}[i] Downloading zivpn ({arch})...{C_RESET}")
    _run(f"wget -q {url} -O {ZIVPN_BIN}")
    _run(f"chmod +x {ZIVPN_BIN}")
    if not _binary_ok():
        print(f"{C_RED}[X] Download failed or produced a non-executable file - check network access.{C_RESET}")
        return False
    return True


def _generate_cert():
    os.makedirs(ZIVPN_DIR, exist_ok=True)
    cert_path = f"{ZIVPN_DIR}/zivpn.crt"
    key_path = f"{ZIVPN_DIR}/zivpn.key"
    _run(f'openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 '
         f'-subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" '
         f'-keyout "{key_path}" -out "{cert_path}"')
    return (os.path.exists(cert_path) and os.path.exists(key_path)), cert_path, key_path


def _write_service():
    service_file = f"""[Unit]
Description=ZIVPN UDP Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={ZIVPN_DIR}
ExecStart={ZIVPN_BIN} server -c {ZIVPN_CONFIG_PATH}
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    with open(ZIVPN_SERVICE_PATH, "w") as f:
        f.write(service_file)
    _run("systemctl daemon-reload")


def _apply_config_safely(new_config, description, check_port):
    """No config-test-only flag exists for zivpn either - restart, verify the
    port actually came up, roll back if not."""
    original = None
    if os.path.exists(ZIVPN_CONFIG_PATH):
        with open(ZIVPN_CONFIG_PATH, "r") as f:
            original = f.read()

    with open(ZIVPN_CONFIG_PATH, "w") as f:
        json.dump(new_config, f, indent=2)

    if not _restart_zivpn():
        if original is not None:
            with open(ZIVPN_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_zivpn()
        return False, f"{description} failed to restart ZIVPN - reverted to the previous working config."

    if not _wait_for_port_listening(check_port):
        if original is not None:
            with open(ZIVPN_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_zivpn()
        return False, f"{description} restarted, but port {check_port} never came up - reverted. Nothing was left broken."

    return True, f"{description} applied and verified on port {check_port}."


def zivpn_admin_manager(ports_dict):
    """ZIVPN (UDP Custom) Administrator Module."""
    while True:
        zivpn_port = ports_dict.get('ZIVPN_PORT', 'Not configured')
        password_count = len(ports_dict.get('ZIVPN_PASSWORDS', '').split(',')) if ports_dict.get('ZIVPN_PASSWORDS') else 0
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                 ZIVPN (UDP CUSTOM) ADMINISTRATOR           %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      PORT: {zivpn_port}  |  PASSWORDS CONFIGURED: {password_count}")
        print("----------------------------------------------------------------")
        print(" [1]> INSTALL / RECONFIGURE ZIVPN")
        print(" [2]> MANAGE PASSWORDS (add / remove / list)")
        print(" [3]> MANUAL CONFIGURATION (nano)")
        print(" [4]> VIEW SERVICE LOGS")
        print(" [5]> RESTART SERVICE")
        print(f" [6]> START/STOP SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL ZIVPN")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s               ZIVPN INSTALL / SETUP WIZARD                 %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter desired UDP Listen Port (e.g., 5667): ", default=5667)
            if str(listen_port) != str(zivpn_port) and check_system_port_in_use(listen_port, ("udp",)):
                print(f"{C_RED}[X] UDP port {listen_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            pw_input = input(" Enter passwords, comma-separated (blank for default 'zi'): ").strip()
            passwords = [p.strip() for p in pw_input.split(",") if p.strip()] if pw_input else ["zi"]

            obfs = input(" Enter OBFS obfuscation string [default: zivpn]: ").strip() or "zivpn"

            if not _install_binary():
                input("\nPress Enter to continue...")
                continue

            cert_ok, cert_path, key_path = _generate_cert()
            if not cert_ok:
                print(f"{C_RED}[X] Certificate generation failed - cannot proceed without one.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            config_data = {
                "listen": f":{listen_port}",
                "cert": cert_path,
                "key": key_path,
                "obfs": obfs,
                "auth": {
                    "mode": "passwords",
                    "config": passwords,
                },
            }

            _write_service()
            _run("sysctl -w net.core.rmem_max=16777216")  # real recommended tuning, not a fake JSON field
            open_firewall_port(listen_port, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable zivpn")

            ok, msg = _apply_config_safely(config_data, f"ZIVPN on port {listen_port}", listen_port)
            if ok:
                ports_dict['ZIVPN_PORT'] = str(listen_port)
                ports_dict['ZIVPN_PASSWORDS'] = ",".join(passwords)
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(listen_port, ("udp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     MANAGE PASSWORDS                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(ZIVPN_CONFIG_PATH):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            with open(ZIVPN_CONFIG_PATH, "r") as f:
                cfg = json.load(f)
            current = cfg.get("auth", {}).get("config", [])
            print(f" Current passwords: {', '.join(current) if current else '(none)'}")
            print(" [1] Add a password")
            print(" [2] Remove a password")
            print(" [0] Back")
            sub = input(" Select option: ").strip()

            if sub == '1':
                new_pw = input(" Enter new password to add: ").strip()
                if new_pw and new_pw not in current:
                    current.append(new_pw)
                elif not new_pw:
                    print(f"{C_RED}[X] Password cannot be empty.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
            elif sub == '2':
                if not current:
                    print(f"{C_YELLOW}[i] No passwords to remove.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                for i, pw in enumerate(current, 1):
                    print(f"  {i}. {pw}")
                idx = input(" Enter number to remove: ").strip()
                if idx.isdigit() and 1 <= int(idx) <= len(current):
                    if len(current) == 1:
                        print(f"{C_RED}[X] Can't remove the last password - ZIVPN needs at least one.{C_RESET}")
                        input("\nPress Enter to continue...")
                        continue
                    current.pop(int(idx) - 1)
                else:
                    print(f"{C_RED}[X] Invalid selection.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
            else:
                continue

            cfg.setdefault("auth", {"mode": "passwords"})["config"] = current
            listen_port = int((cfg.get("listen", ":5667") or ":5667").lstrip(":") or 5667)
            ok, msg = _apply_config_safely(cfg, "Password list update", listen_port)
            if ok:
                ports_dict['ZIVPN_PASSWORDS'] = ",".join(current)
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            if not os.path.exists(ZIVPN_CONFIG_PATH):
                os.makedirs(ZIVPN_DIR, exist_ok=True)
                with open(ZIVPN_CONFIG_PATH, "w") as f:
                    json.dump({"listen": ":5667", "cert": "", "key": "", "obfs": "zivpn",
                               "auth": {"mode": "passwords", "config": ["zi"]}}, f, indent=2)
            os.system(f"nano {ZIVPN_CONFIG_PATH}")
            if _restart_zivpn():
                print(f"{C_GREEN}[OK] Configuration saved and ZIVPN restarted.{C_RESET}")
            else:
                print(f"{C_RED}[X] ZIVPN failed to restart with the edited config - check it manually")
                print(f"    (systemctl status zivpn / journalctl -u zivpn).{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     ZIVPN SERVICE LOGS                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u zivpn -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_zivpn():
                print(f"{C_GREEN}[OK] ZIVPN service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] ZIVPN failed to restart - check 'journalctl -u zivpn'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop zivpn")
                print(f"{C_YELLOW}[!] ZIVPN service stopped.{C_RESET}")
            else:
                if not _binary_ok():
                    print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start zivpn")
                if _service_active():
                    print(f"{C_GREEN}[OK] ZIVPN service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] ZIVPN failed to start - check 'journalctl -u zivpn'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    UNINSTALL ZIVPN                         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove ZIVPN? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop zivpn")
                _run("systemctl disable zivpn")
                _run(f"rm -f {ZIVPN_SERVICE_PATH}")
                _run("systemctl daemon-reload")
                if str(zivpn_port).isdigit():
                    close_firewall_port(int(zivpn_port), ("udp",))
                    persist_firewall_rules()
                _run(f"rm -rf {ZIVPN_DIR} {ZIVPN_BIN}")
                ports_dict.pop('ZIVPN_PORT', None)
                ports_dict.pop('ZIVPN_PASSWORDS', None)
                print(f"{C_GREEN}[OK] ZIVPN uninstalled and purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
