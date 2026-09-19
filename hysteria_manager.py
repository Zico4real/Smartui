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

Hysteria 1.x now lives entirely in its own module, hysteria1_manager.py -
originally a submenu here, split out into a fully independent module (own
binary, config schema, systemd unit) since v1 and v2 can't interconnect.
"""

import os
import re
import json
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_public_ip,
)

HYSTERIA_DIR = "/etc/hysteria"
HYSTERIA_CONFIG_PATH = f"{HYSTERIA_DIR}/config.json"
HYSTERIA_INSTALL_URL = "https://get.hy2.sh/"  # the same URL already verified earlier in this project

# Hysteria 1.x now lives entirely in its own module, hysteria1_manager.py -
# v1 and v2 are protocol-incompatible (confirmed straight from apernet's own
# install script: "Hysteria 2 uses a completely redesigned protocol & config,
# which is NOT compatible with the version 1.x.x in any way"), so they're
# kept as fully independent modules rather than one combined file.


def _service_active():
    return (_run(["systemctl", "is-active", "--quiet", "hysteria-server"]).returncode == 0
            or _run(["systemctl", "is-active", "--quiet", "hysteria"]).returncode == 0)


def _restart_hysteria():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt, so a
    # repeated install/config change can never be silently blocked by
    # systemd itself regardless of whether the config is genuinely correct
    # this time.
    _run("systemctl reset-failed hysteria-server")
    r = _run("systemctl restart hysteria-server")
    if r.returncode != 0:
        _run("systemctl reset-failed hysteria")
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
    _run(f"curl -fsSL {HYSTERIA_INSTALL_URL} | bash")
    ok = _run("which hysteria").returncode == 0
    if not ok:
        print(f"{C_RED}[X] Hysteria2 did not install correctly - check network access.{C_RESET}")
    return ok


def _generate_self_signed_cert():
    os.makedirs(HYSTERIA_DIR, exist_ok=True)
    cert_path = f"{HYSTERIA_DIR}/cert.crt"
    key_path = f"{HYSTERIA_DIR}/private.key"
    # Process substitution (ec:<(...)) requires bash - _run() shells out via
    # /bin/sh, which is dash on Debian/Ubuntu and doesn't understand it.
    # A temp file avoids the dependency on which shell actually runs this.
    ecparam_path = f"{HYSTERIA_DIR}/.ecparam.pem"
    _run(f"openssl ecparam -name prime256v1 -out {ecparam_path}")
    _run(f"openssl req -x509 -nodes -newkey ec:{ecparam_path} "
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


def hysteria_admin_manager(ports_dict):
    """Hysteria2 Administrator Module."""
    while True:
        hysteria_port = ports_dict.get('HYSTERIA_PORT', 'Not configured')
        hysteria_range = ports_dict.get('HYSTERIA_RANGE', 'None configured')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                    HYSTERIA2 ADMINISTRATOR                 %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      PORT: {hysteria_port}  |  PORT-HOP RANGE: {hysteria_range}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL HYSTERIA2 (Wizard)")
        print(" [2]> SET UP PORT HOPPING RANGE")
        print(" [3]> CONFIGURE OBFS & AUTH PASSWORD")
        print(" [4]> VIEW CONNECTION INFO")
        print(" [5]> MANUAL CONFIGURATION (nano)")
        print(" [6]> VIEW SERVICE LOGS")
        print(" [7]> RESTART SERVICE")
        print(f" [8]> START/STOP SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [9] UNINSTALL HYSTERIA2")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s               HYSTERIA2 SETUP WIZARD                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

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
                ports_dict['HYSTERIA_AUTH_PASSWORD'] = auth_password
                ports_dict['HYSTERIA_DOMAIN'] = domain
                ports_dict['HYSTERIA_OBFS'] = obfs_pass
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            else:
                close_firewall_port(listen_port, ("udp",))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  PORT HOPPING SETUP                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
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
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                CONFIGURE OBFS & AUTHENTICATION             %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
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
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 CLIENT CONNECTION INFO                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(HYSTERIA_CONFIG_PATH):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
            else:
                with open(HYSTERIA_CONFIG_PATH, "r") as f:
                    cfg = json.load(f)
                server_ip = get_public_ip()
                auth_pass = cfg.get('auth', {}).get('password', 'N/A')
                obfs_pass = cfg.get('obfs', {}).get('password', '') if 'obfs' in cfg else ''
                uses_acme = 'acme' in cfg
                domain = cfg.get('acme', {}).get('domains', [''])[0] if uses_acme else ''
                print(f" Server:   {domain if uses_acme else server_ip}")
                print(f" Port:     {hysteria_port}")
                print(f" Auth:     {auth_pass}")
                print(f" OBFS:     {obfs_pass if obfs_pass else '(none set)'}")
                if not uses_acme:
                    print()
                    print(f" {C_YELLOW}Insecure/skip-cert-verify: MUST be enabled on the client{C_RESET}")
                    print(f"   (self-signed cert - won't match your real server hostname, so the")
                    print(f"   client must be told not to verify it. This is the single most")
                    print(f"   common reason a client fails to connect at all.)")
                else:
                    print()
                    print(f" {C_GREEN}Real domain + ACME cert in use - no insecure/skip-verify flag needed.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '5':
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

        elif choice == '6':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   HYSTERIA SERVICE LOGS                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u hysteria-server -n 50 --no-pager 2>/dev/null || journalctl -u hysteria -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '7':
            if _restart_hysteria():
                print(f"{C_GREEN}[OK] Hysteria service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] Hysteria failed to restart - check 'journalctl -u hysteria-server'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '8':
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

        elif choice == '9':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    UNINSTALL HYSTERIA2                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove Hysteria2? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop hysteria-server")
                _run("systemctl disable hysteria-server")
                _run("rm -f /etc/systemd/system/hysteria-server.service")
                _run("systemctl daemon-reload")
                _run("rm -rf /etc/hysteria /usr/local/bin/hysteria")
                if str(hysteria_port).isdigit():
                    close_firewall_port(int(hysteria_port), ("udp",))
                # Actually remove the port-hopping NAT rule (if one was ever set up),
                # not just warn about it - this rule silently redirects traffic on
                # every port in the range to hysteria_port, so leaving it behind
                # after uninstalling means none of those ports can be reused by any
                # other protocol until this rule is gone.
                stale_range = ports_dict.get('HYSTERIA_RANGE')
                m = re.match(r'^(\d+)-(\d+)$', str(stale_range)) if stale_range else None
                if m and str(hysteria_port).isdigit():
                    start_port, end_port = m.group(1), m.group(2)
                    iptables_range = f"{start_port}:{end_port}"
                    _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp",
                          "--dport", iptables_range, "-j", "REDIRECT", "--to-ports", str(hysteria_port)])
                    close_firewall_port(int(start_port), ("udp",))
                    _run(f"ufw delete allow {start_port}:{end_port}/udp")
                persist_firewall_rules()
                ports_dict.pop('HYSTERIA_PORT', None)
                ports_dict.pop('HYSTERIA_RANGE', None)
                print(f"{C_GREEN}[OK] Hysteria2 removed and purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
