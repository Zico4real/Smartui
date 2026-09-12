"""
hysteria_manager.py - Hysteria2 admin module for the SmartUI panel.

Real bugs found, verified against Hysteria's own official docs (v1.hysteria.network,
v2.hysteria.network) rather than assumed:

1. The generated config.json had NO TLS/certificate configuration at all - for
   either Hysteria v1 or v2. Both real schemas absolutely require one (cert+key
   files, or ACME auto-cert). Hysteria is QUIC-based, and QUIC mandates TLS 1.3
   at the transport layer - there is no way to start hysteria-server without it.
   This means the original wizard's "[OK] successfully configured" message would
   have been false on every single install; the service would never actually
   start. Fixed by auto-generating a self-signed cert if the admin doesn't
   provide a real domain for ACME (same pattern used for Stunnel/Slipstream
   elsewhere in this panel).

2. "auth": {"mode": "password", ...} - the real key is "type", not "mode".
   Confirmed against the official v2 server config docs.

3. "transport": {"type": "udp"} and "traffic_redir": {"target_port": N} are
   both fabricated fields that don't exist in any real Hysteria2 schema (official
   docs, sing-box, mihomo all checked). The underlying premise was also wrong:
   Hysteria2, like Shadowsocks, is a general SOCKS5/HTTP-style proxy where the
   CLIENT picks the destination per-connection - there's no "redirect everything
   hitting the server to one fixed backend port" concept in the base protocol.
   Removed, same as the equivalent fake feature in the Shadowsocks module.

4. The "select Hysteria v1 or v2" prompt was captured into a variable and then
   never actually used - the exact same config got written regardless of the
   choice made. v1 is also legacy/deprecated (protocol-incompatible with v2 per
   Hysteria's own docs) - dropped entirely rather than kept as a fake choice,
   same principle as removing the fake "DNSTT over QUIC/TCP" modes earlier in
   this panel.

5. Port hopping (a real, documented Hysteria2 feature) used --dport 20000-45000
   - iptables port RANGES require a colon (20000:45000), not a dash. The error
   was silently swallowed by 2>/dev/null || true, so this had never actually
   worked while claiming success every time.

This converges onto the same verified-correct schema already used by the bonus
Hysteria2 feature bolted onto xray_manager.py earlier in this project. Worth
flagging: if that Xray-bonus feature is still enabled, it and this module would
both try to own the same hysteria-server systemd unit and config file - once
this standalone module exists, the Xray one should probably be removed to avoid
two installers fighting over the same service.
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

HYSTERIA_DIR = "/etc/hysteria"
HYSTERIA_CONFIG_PATH = f"{HYSTERIA_DIR}/config.json"
HYSTERIA_INSTALL_URL = "https://get.hy2.sh/"  # the same URL already verified earlier in this project

# Hysteria 1.x and 2.x are protocol-incompatible (confirmed straight from apernet's
# own install script: "Hysteria 2 uses a completely redesigned protocol & config,
# which is NOT compatible with the version 1.x.x in any way") and apernet's OFFICIAL
# installer now auto-upgrades any v1 install to v2 rather than supporting staying on
# v1. Since v1 is still wanted here, this uses evozi/hysteria-install's still-current
# separate v1 installer, and every path/service name below is kept fully distinct
# from the v2 ones above so both can coexist on the same box without colliding.
HYSTERIA1_DIR = "/etc/hysteria/v1"
HYSTERIA1_CONFIG_PATH = f"{HYSTERIA1_DIR}/config.json"
HYSTERIA1_BIN = "/usr/local/bin/hysteria-v1"
HYSTERIA1_SERVICE_PATH = "/etc/systemd/system/hysteria-v1.service"
HYSTERIA1_INSTALL_URL = "https://raw.githubusercontent.com/evozi/hysteria-install/main/hy1/hysteria1.sh"


def _service_active():
    return (_run(["systemctl", "is-active", "--quiet", "hysteria-server"]).returncode == 0
            or _run(["systemctl", "is-active", "--quiet", "hysteria"]).returncode == 0)


def _restart_hysteria():
    r = _run("systemctl restart hysteria-server")
    if r.returncode != 0:
        r = _run("systemctl restart hysteria")
    return r.returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("udp",)):
            return True
        time.sleep(delay)
    return False


def _ensure_installed():
    if _run("which hysteria").returncode == 0:
        return True
    print(f"{C_CYAN}[i] Installing Hysteria2...{C_RESET}")
    _run(f"bash <(curl -fsSL {HYSTERIA_INSTALL_URL})")
    ok = _run("which hysteria").returncode == 0
    if not ok:
        print(f"{C_RED}[X] Hysteria2 did not install correctly - check network access.{C_RESET}")
    return ok


def _generate_self_signed_cert():
    os.makedirs(HYSTERIA_DIR, exist_ok=True)
    cert_path = f"{HYSTERIA_DIR}/cert.crt"
    key_path = f"{HYSTERIA_DIR}/private.key"
    _run(f"openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) "
         f"-keyout {key_path} -out {cert_path} -subj '/CN=bing.com' -days 36500")
    ok = os.path.exists(cert_path) and os.path.exists(key_path)
    return ok, cert_path, key_path


def _apply_config_safely(new_config, description, check_port):
    """Hysteria has no config-test-only flag either (same situation as Stunnel) -
    the only real safety net is restart, verify the port actually came up, and
    roll back automatically if not."""
    original = None
    if os.path.exists(HYSTERIA_CONFIG_PATH):
        with open(HYSTERIA_CONFIG_PATH, "r") as f:
            original = f.read()

    with open(HYSTERIA_CONFIG_PATH, "w") as f:
        json.dump(new_config, f, indent=4)

    if not _restart_hysteria():
        if original is not None:
            with open(HYSTERIA_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_hysteria()
        return False, f"{description} failed to restart Hysteria - reverted to the previous working config."

    if not _wait_for_port_listening(check_port):
        if original is not None:
            with open(HYSTERIA_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_hysteria()
        return False, f"{description} restarted, but port {check_port} never came up - reverted. Nothing was left broken."

    return True, f"{description} applied and verified on port {check_port}."


# ==================== HYSTERIA v1 (legacy, separate binary/service) ====================

def _service_active_v1():
    return _run(["systemctl", "is-active", "--quiet", "hysteria-v1"]).returncode == 0


def _restart_hysteria_v1():
    return _run("systemctl restart hysteria-v1").returncode == 0


def _wait_for_port_listening_v1(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("udp",)):
            return True
        time.sleep(delay)
    return False


def _ensure_installed_v1():
    if _run(["which", "hysteria-v1"]).returncode == 0 or os.path.exists(HYSTERIA1_BIN):
        return True
    print(f"{C_CYAN}[i] apernet's own official installer now auto-upgrades v1 installs to v2")
    print(f"    (they explicitly say v1 and v2 are protocol-incompatible), so this uses a")
    print(f"    community-maintained installer that still keeps v1 separate.{C_RESET}")
    res = _run(f"bash <(curl -fsSL {HYSTERIA1_INSTALL_URL})")
    # That installer manages its own binary path/service name — locate whatever it
    # actually produced rather than assume, and normalize to our own fixed path so
    # the rest of this module has one consistent place to look.
    for candidate in ("/usr/local/bin/hysteria", "/usr/bin/hysteria", "/root/hysteria/hysteria"):
        if os.path.exists(candidate) and not os.path.exists(HYSTERIA1_BIN):
            _run(f"cp {candidate} {HYSTERIA1_BIN}")
            break
    ok = os.path.exists(HYSTERIA1_BIN)
    if not ok:
        print(f"{C_RED}[X] Hysteria v1 installer did not produce a usable binary at a known path -")
        print(f"    check network access, or install manually and place the binary at {HYSTERIA1_BIN}.{C_RESET}")
    return ok


def _generate_self_signed_cert_v1():
    os.makedirs(HYSTERIA1_DIR, exist_ok=True)
    cert_path = f"{HYSTERIA1_DIR}/cert.crt"
    key_path = f"{HYSTERIA1_DIR}/private.key"
    _run(f"openssl req -x509 -nodes -newkey rsa:2048 "
         f"-keyout {key_path} -out {cert_path} -subj '/CN=bing.com' -days 36500")
    ok = os.path.exists(cert_path) and os.path.exists(key_path)
    return ok, cert_path, key_path


def _write_service_v1(listen_port):
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


def _apply_config_safely_v1(new_config, description, check_port):
    original = None
    if os.path.exists(HYSTERIA1_CONFIG_PATH):
        with open(HYSTERIA1_CONFIG_PATH, "r") as f:
            original = f.read()

    with open(HYSTERIA1_CONFIG_PATH, "w") as f:
        json.dump(new_config, f, indent=4)

    if not _restart_hysteria_v1():
        if original is not None:
            with open(HYSTERIA1_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_hysteria_v1()
        return False, f"{description} failed to restart Hysteria v1 - reverted to the previous working config."

    if not _wait_for_port_listening_v1(check_port):
        if original is not None:
            with open(HYSTERIA1_CONFIG_PATH, "w") as f:
                f.write(original)
            _restart_hysteria_v1()
        return False, f"{description} restarted, but port {check_port} never came up - reverted. Nothing was left broken."

    return True, f"{description} applied and verified on port {check_port}."


def hysteria_v1_submenu(ports_dict):
    """Separate submenu for the legacy v1 install - kept distinct from v2's menu
    rather than merged into one flow, since v1 and v2 are different binaries,
    different config schemas, and different systemd units that can coexist."""
    while True:
        hy1_port = ports_dict.get('HYSTERIA1_PORT', 'Not configured')
        is_active = _service_active_v1()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("================================================================")
        print("              HYSTERIA 1.x ADMINISTRATOR (LEGACY)           ")
        print("================================================================")
        print(f"      PORT: {hy1_port}")
        print(f"{C_YELLOW}      Note: v1 and v2 are protocol-incompatible - clients must use")
        print(f"      the matching version's client, they can't interconnect.{C_RESET}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL HYSTERIA 1.x (Wizard)")
        print(" [2]> VIEW SERVICE LOGS")
        print(" [3]> RESTART SERVICE")
        print(f" [4]> START/STOP SERVICE [{status_label}]")
        print("================================================================")
        print(" [0] RETURN  [5] UNINSTALL HYSTERIA 1.x")
        print("================================================================")

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("================================================================")
            print("             HYSTERIA 1.x SETUP WIZARD                      ")
            print("================================================================")

            listen_port = prompt_port(" Enter main listen port (e.g., 36712): ", default=36712)
            if str(listen_port) != str(hy1_port) and check_system_port_in_use(listen_port, ("udp",)):
                print(f"{C_RED}[X] UDP port {listen_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            obfs_pass = input(" Enter OBFS password (v1 uses a flat string, blank to skip): ").strip()
            up_mbps_raw = input(" Upload speed limit in Mbps (blank for 0 = unlimited): ").strip()
            down_mbps_raw = input(" Download speed limit in Mbps (blank for 0 = unlimited): ").strip()
            up_mbps = int(up_mbps_raw) if up_mbps_raw.isdigit() else 0
            down_mbps = int(down_mbps_raw) if down_mbps_raw.isdigit() else 0

            if not _ensure_installed_v1():
                input("\nPress Enter to continue...")
                continue

            cert_ok, cert_path, key_path = _generate_self_signed_cert_v1()
            if not cert_ok:
                print(f"{C_RED}[X] Certificate generation failed - cannot proceed without one.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            # Real v1 schema, confirmed directly from an actual v1.3.2 server's own
            # output (flat obfs string, flat up_mbps/down_mbps - NOT the nested
            # objects v2 uses) - not assumed by analogy with v2.
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

            _write_service_v1(listen_port)
            open_firewall_port(listen_port, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable hysteria-v1")

            ok, msg = _apply_config_safely_v1(config_data, f"Hysteria v1 on port {listen_port}", listen_port)
            if ok:
                ports_dict['HYSTERIA1_PORT'] = str(listen_port)
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(listen_port, ("udp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("================================================================")
            print("                 HYSTERIA 1.x SERVICE LOGS                  ")
            print("================================================================")
            os.system("journalctl -u hysteria-v1 -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '3':
            if _restart_hysteria_v1():
                print(f"{C_GREEN}[OK] Hysteria v1 service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] Hysteria v1 failed to restart - check 'journalctl -u hysteria-v1'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if is_active:
                _run("systemctl stop hysteria-v1")
                print(f"{C_YELLOW}[!] Hysteria v1 service stopped.{C_RESET}")
            else:
                _run("systemctl start hysteria-v1")
                if _service_active_v1():
                    print(f"{C_GREEN}[OK] Hysteria v1 service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] Hysteria v1 failed to start - check 'journalctl -u hysteria-v1'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            print("================================================================")
            print("                UNINSTALL HYSTERIA 1.x                      ")
            print("================================================================")
            confirm = input(" Are you sure you want to completely remove Hysteria 1.x? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop hysteria-v1")
                _run("systemctl disable hysteria-v1")
                _run(f"rm -rf {HYSTERIA1_DIR} {HYSTERIA1_BIN} {HYSTERIA1_SERVICE_PATH}")
                _run("systemctl daemon-reload")
                if str(hy1_port).isdigit():
                    close_firewall_port(int(hy1_port), ("udp",))
                    persist_firewall_rules()
                ports_dict.pop('HYSTERIA1_PORT', None)
                print(f"{C_GREEN}[OK] Hysteria 1.x removed and purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")


def hysteria_admin_manager(ports_dict):
    """Hysteria2 Administrator Module."""
    while True:
        hysteria_port = ports_dict.get('HYSTERIA_PORT', 'Not configured')
        hysteria_range = ports_dict.get('HYSTERIA_RANGE', 'None configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("================================================================")
        print("                    HYSTERIA2 ADMINISTRATOR                 ")
        print("================================================================")
        print(f"      PORT: {hysteria_port}  |  PORT-HOP RANGE: {hysteria_range}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL HYSTERIA2 (Wizard)")
        print(" [2]> SET UP PORT HOPPING RANGE")
        print(" [3]> CONFIGURE OBFS & AUTH PASSWORD")
        print(" [4]> MANUAL CONFIGURATION (nano)")
        print(" [5]> VIEW SERVICE LOGS")
        print(" [6]> RESTART SERVICE")
        print(f" [7]> START/STOP SERVICE [{status_label}]")
        print(" [9]> HYSTERIA 1.x (LEGACY) SUBMENU")
        print("================================================================")
        print(" [0] RETURN  [8] UNINSTALL HYSTERIA2")
        print("================================================================")

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '9':
            hysteria_v1_submenu(ports_dict)

        elif choice == '1':
            clear_screen()
            print("================================================================")
            print("               HYSTERIA2 SETUP WIZARD                       ")
            print("================================================================")

            listen_port = prompt_port(" Enter main listen port (e.g., 443): ", default=443)
            if str(listen_port) != str(hysteria_port) and check_system_port_in_use(listen_port, ("udp",)):
                print(f"{C_RED}[X] UDP port {listen_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            auth_password = input(" Enter authentication password (blank to auto-generate a strong one): ").strip()
            if not auth_password:
                import secrets
                auth_password = secrets.token_urlsafe(16)
                print(f"{C_CYAN}[i] Generated password: {auth_password}{C_RESET}")

            domain = input(" Domain name for a real Let's Encrypt cert via ACME (blank = self-signed cert): ").strip()
            email = ""
            if domain:
                email = input(" Email address for ACME registration: ").strip()

            obfs_pass = input(" Enter Salamander OBFS password (blank to skip - NOT recommended for censored networks): ").strip()

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            config_data = {
                "listen": f":{listen_port}",
                "auth": {
                    "type": "password",
                    "password": auth_password,
                },
                "masquerade": {
                    "type": "proxy",
                    "proxy": {
                        "url": "https://news.ycombinator.com/",
                        "rewriteHost": True,
                    },
                },
            }

            if domain and email:
                config_data["acme"] = {"domains": [domain], "email": email}
            else:
                ok, cert_path, key_path = _generate_self_signed_cert()
                if not ok:
                    print(f"{C_RED}[X] Certificate generation failed - cannot proceed without one.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                config_data["tls"] = {"cert": cert_path, "key": key_path}
                if not domain:
                    print(f"{C_CYAN}[i] Using a self-signed certificate - clients will need 'insecure: true'")
                    print(f"    in their tls config, or pinSHA256 fingerprint verification.{C_RESET}")

            if obfs_pass:
                config_data["obfs"] = {"type": "salamander", "password": obfs_pass}

            open_firewall_port(listen_port, ("udp",))
            persist_firewall_rules()
            _run("systemctl enable hysteria-server")

            ok, msg = _apply_config_safely(config_data, f"Hysteria2 on port {listen_port}", listen_port)
            if ok:
                ports_dict['HYSTERIA_PORT'] = str(listen_port)
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(listen_port, ("udp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("================================================================")
            print("                  PORT HOPPING SETUP                        ")
            print("================================================================")
            print(" Port hopping spreads client traffic across a wide UDP port range")
            print(" that all redirect to your real listen port - this is a real,")
            print(" documented Hysteria2 feature, set up at the firewall/NAT level.")

            if hysteria_port == 'Not configured':
                print(f"{C_RED}[X] Configure Hysteria2 first (option 1).{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            new_range = input(f" Enter port range, e.g. 20000-45000 [Current: {hysteria_range}]: ").strip()
            if not new_range:
                print(f"{C_YELLOW}[i] Range update skipped.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            m = re.match(r'^(\d+)-(\d+)$', new_range)
            if not m or not (1 <= int(m.group(1)) <= 65535 and 1 <= int(m.group(2)) <= 65535 and int(m.group(1)) < int(m.group(2))):
                print(f"{C_RED}[X] Invalid range - use START-END with both parts 1-65535, e.g. 20000-45000.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            start_port, end_port = m.group(1), m.group(2)
            # iptables --dport ranges use a COLON, not a dash - the dash format the
            # admin types is the human-friendly one, translated here for the actual rule.
            iptables_range = f"{start_port}:{end_port}"

            check = _run(["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "udp",
                          "--dport", iptables_range, "-j", "REDIRECT", "--to-ports", str(hysteria_port)])
            if check.returncode != 0:
                add = _run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp",
                           "--dport", iptables_range, "-j", "REDIRECT", "--to-ports", str(hysteria_port)])
                if add.returncode != 0:
                    print(f"{C_RED}[X] Failed to add the NAT redirect rule: {add.stderr.strip()}{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue

            open_firewall_port(int(start_port), ("udp",))  # ufw/firewalld need at least a representative rule
            _run(f"ufw allow {start_port}:{end_port}/udp")
            persist_firewall_rules()

            ports_dict['HYSTERIA_RANGE'] = new_range
            print(f"{C_GREEN}[OK] Port hopping range {new_range} now redirects to {hysteria_port}.{C_RESET}")
            print(f"{C_CYAN}    Clients set server_ports: \"{new_range}\" with a hop_interval on their end.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("================================================================")
            print("                CONFIGURE OBFS & AUTHENTICATION             ")
            print("================================================================")
            if not os.path.exists(HYSTERIA_CONFIG_PATH):
                print(f"{C_RED}[X] Configuration file not found. Please run the setup wizard first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            with open(HYSTERIA_CONFIG_PATH, "r") as f:
                cfg = json.load(f)

            print(f" Current Password: {cfg.get('auth', {}).get('password', 'N/A')}")
            new_pass = input(" Enter new authentication password (blank to keep current): ").strip()
            new_obfs = input(" Enter new Salamander OBFS password (blank to keep current, 'none' to disable): ").strip()

            if new_pass:
                cfg.setdefault("auth", {"type": "password"})["password"] = new_pass
            if new_obfs.lower() == 'none':
                cfg.pop("obfs", None)
            elif new_obfs:
                cfg["obfs"] = {"type": "salamander", "password": new_obfs}

            listen_port = int((cfg.get("listen", ":443") or ":443").lstrip(":") or 443)
            ok, msg = _apply_config_safely(cfg, "Auth/OBFS update", listen_port)
            if ok:
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if not os.path.exists(HYSTERIA_CONFIG_PATH):
                os.makedirs(HYSTERIA_DIR, exist_ok=True)
                with open(HYSTERIA_CONFIG_PATH, "w") as f:
                    f.write("{}")
            os.system(f"nano {HYSTERIA_CONFIG_PATH}")
            if _restart_hysteria():
                print(f"{C_GREEN}[OK] Configuration saved and Hysteria restarted.{C_RESET}")
            else:
                print(f"{C_RED}[X] Hysteria failed to restart with the edited config - check it manually")
                print(f"    (systemctl status hysteria-server / journalctl -u hysteria-server).{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            print("================================================================")
            print("                   HYSTERIA SERVICE LOGS                    ")
            print("================================================================")
            os.system("journalctl -u hysteria-server -n 50 --no-pager 2>/dev/null || journalctl -u hysteria -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if _restart_hysteria():
                print(f"{C_GREEN}[OK] Hysteria service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] Hysteria failed to restart - check 'journalctl -u hysteria-server'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '7':
            if is_active:
                _run("systemctl stop hysteria-server")
                _run("systemctl stop hysteria")
                print(f"{C_YELLOW}[!] Hysteria service stopped.{C_RESET}")
            else:
                _run("systemctl start hysteria-server")
                if _service_active():
                    print(f"{C_GREEN}[OK] Hysteria service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] Hysteria failed to start - check 'journalctl -u hysteria-server'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            print("================================================================")
            print("                    UNINSTALL HYSTERIA2                     ")
            print("================================================================")
            confirm = input(" Are you sure you want to completely remove Hysteria2? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop hysteria-server")
                _run("systemctl disable hysteria-server")
                _run("rm -rf /etc/hysteria /usr/local/bin/hysteria")
                if str(hysteria_port).isdigit():
                    close_firewall_port(int(hysteria_port), ("udp",))
                persist_firewall_rules()
                ports_dict.pop('HYSTERIA_PORT', None)
                ports_dict.pop('HYSTERIA_RANGE', None)
                print(f"{C_GREEN}[OK] Hysteria2 removed and purged successfully.{C_RESET}")
                print(f"{C_YELLOW}[!] Any port-hopping NAT redirect rules were left in the firewall -")
                print(f"    remove them manually via iptables if no longer needed.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
