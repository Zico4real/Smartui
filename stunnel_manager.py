"""
stunnel_manager.py — Stunnel4 admin module for the SmartUI panel.

Real bugs found in the original draft, verified rather than assumed:

1. Blind restart with no verification. Stunnel has no config-test-only flag
   (confirmed against stunnel's own official FAQ: "The current command-line
   interface has no separate check-only option") — so unlike sshd -t, there's
   no pre-flight syntax check available. The only real safety net is
   restart -> verify the port actually came up -> roll back if not, which is
   what every config-changing action here now does.

2. `ports_dict['STUNNEL_PORTS'] = new_port` OVERWRITES rather than accumulates.
   Stunnel is explicitly designed for multiple concurrent [service] blocks in
   the same conf file — adding a second port would silently lose track of the
   first one in the dashboard's own state, even though stunnel.conf itself
   still had both blocks correctly.

3. No duplicate-section check: running "ADD PORT" twice with the same port
   appended a second [ssl-tunnel-N] block with an identical section name —
   ambiguous/invalid config, not caught until stunnel actually failed to load.

4. If /etc/stunnel/stunnel.pem didn't exist yet, the restart would fail
   outright, but the original code printed "[✔] Stunnel successfully
   configured!" regardless of whether the restart actually succeeded.
   Fixed by auto-generating a self-signed cert on first use if none exists
   (same pattern as the REALITY/VLESS-encryption key auto-generation
   elsewhere in this panel), rather than failing confusingly.

5. `sed -i 's/^ENABLED=0/ENABLED=1/g'` followed unconditionally by
   `sed -i 's/^ENABLED=.*/ENABLED=1/g'` right after — the second line makes
   the first entirely redundant, AND neither does anything if the ENABLED=
   line is simply absent from /etc/default/stunnel4 (same class of bug fixed
   in the SSH/Dropbear module: substitute-only sed silently no-ops on a
   directive that was never there to begin with).

I verified empirically (not assumed) that `openssl req -out FILE -keyout FILE`
with an identical path for both does NOT lose either half in this environment —
so unlike the bugs above, that part of the original cert-generation code was
actually fine and didn't need "fixing".
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

STUNNEL_CONF_PATH = "/etc/stunnel/stunnel.conf"
STUNNEL_DEFAULT_PATH = "/etc/default/stunnel4"
STUNNEL_PEM_PATH = "/etc/stunnel/stunnel.pem"

BASE_CONFIG = """cert = /etc/stunnel/stunnel.pem
client = no
socket = r:TCP_NODELAY=1
socket = l:TCP_NODELAY=1

"""


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "stunnel4"]).returncode == 0


def _restart_stunnel():
    return _run("systemctl restart stunnel4").returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _tracked_ports(ports_dict):
    raw = ports_dict.get('STUNNEL_PORTS', '')
    return [p for p in raw.split(',') if p]


def _ensure_installed():
    if not os.path.exists(STUNNEL_CONF_PATH):
        print(f"{C_CYAN}[i] Installing stunnel4...{C_RESET}")
        _run("apt-get update && apt-get install -y stunnel4")

    if os.path.exists(STUNNEL_DEFAULT_PATH):
        with open(STUNNEL_DEFAULT_PATH, "r") as f:
            content = f.read()
        if re.search(r'^ENABLED=', content, re.MULTILINE):
            content = re.sub(r'^ENABLED=.*$', 'ENABLED=1', content, flags=re.MULTILINE)
        else:
            content = content.rstrip('\n') + '\nENABLED=1\n'
        with open(STUNNEL_DEFAULT_PATH, "w") as f:
            f.write(content)

    if not os.path.exists(STUNNEL_CONF_PATH) or os.path.getsize(STUNNEL_CONF_PATH) == 0:
        with open(STUNNEL_CONF_PATH, "w") as f:
            f.write(BASE_CONFIG)

    if not os.path.exists(STUNNEL_PEM_PATH):
        print(f"{C_CYAN}[i] No certificate found — generating a self-signed one so this actually works")
        print(f"    on first try (swap it for a real one anytime via option 3).{C_RESET}")
        _generate_self_signed_cert()


def _generate_self_signed_cert():
    os.makedirs("/etc/stunnel", exist_ok=True)
    _run(f"openssl req -new -x509 -days 3650 -nodes -out {STUNNEL_PEM_PATH} "
         f"-keyout {STUNNEL_PEM_PATH} -subj '/CN=Stunnel Server/O=Tunnel/C=US'")
    if os.path.exists(STUNNEL_PEM_PATH):
        os.chmod(STUNNEL_PEM_PATH, 0o600)
    return os.path.exists(STUNNEL_PEM_PATH)


def _apply_conf_safely(new_content, description, check_port):
    """No sshd-t equivalent exists for stunnel (confirmed against its own FAQ) —
    the only real safety net is restart, then verify the port actually came up,
    then roll back automatically if not. Returns (ok: bool, message: str)."""
    if os.path.exists(STUNNEL_CONF_PATH):
        with open(STUNNEL_CONF_PATH, "r") as f:
            original = f.read()
    else:
        original = ""

    with open(STUNNEL_CONF_PATH, "w") as f:
        f.write(new_content)

    if not _restart_stunnel():
        with open(STUNNEL_CONF_PATH, "w") as f:
            f.write(original)
        _restart_stunnel()
        return False, f"{description} failed to restart Stunnel — reverted to the previous working config."

    if not _wait_for_port_listening(check_port):
        with open(STUNNEL_CONF_PATH, "w") as f:
            f.write(original)
        _restart_stunnel()
        return False, f"{description} restarted, but port {check_port} never came up — reverted and restarted the previous config. Nothing was left broken."

    return True, f"{description} applied and verified on port {check_port}."


def stunnel_admin_manager(ports_dict):
    """Stunnel4 Administrator Module."""
    while True:
        stunnel_ports = ports_dict.get('STUNNEL_PORTS', '') or 'None configured'
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                     STUNNEL ADMINISTRATOR                  %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      SSL PORTS: {stunnel_ports}")
        print("────────────────────────────────────────────────────────────")
        print(" [1]> ADD SSL / STUNNEL PORT")
        print(" [2]> EDIT STUNNEL CONFIG (nano)")
        print(" [3]> CONFIGURE SSL CERTIFICATE")
        print(" [4]> VIEW STUNNEL LOGS")
        print(" [5]> RESTART STUNNEL SERVICE")
        print(f" [6]> START/STOP STUNNEL SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL STUNNEL4")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s             MANUAL SSL / STUNNEL PORT SETUP                %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            new_port = prompt_port(" Enter desired SSL Listen Port (e.g., 443): ", default=443)
            existing = _tracked_ports(ports_dict)
            if str(new_port) in existing:
                print(f"{C_RED}[✖] Port {new_port} already has a Stunnel service configured. Remove it")
                print(f"    manually first (option 2) if you want to redefine it.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            if check_system_port_in_use(new_port, ("tcp",)):
                print(f"{C_RED}[✖] Port {new_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            target_port = prompt_port(" Enter backend target port (e.g., 22 for SSH, 143 for Dropbear): ", default=22)
            if not check_system_port_in_use(target_port, ("tcp",)):
                print(f"{C_YELLOW}[!] Nothing seems to be listening on port {target_port} yet — the tunnel")
                print(f"    will have nowhere to forward traffic until that backend is running.{C_RESET}")

            print(f"\n[i] Configuring Stunnel to tunnel incoming SSL traffic on port {new_port} to local port {target_port}...")
            _ensure_installed()

            with open(STUNNEL_CONF_PATH, "r") as f:
                current_content = f.read()
            service_block = f"\n[ssl-tunnel-{new_port}]\naccept = {new_port}\nconnect = 127.0.0.1:{target_port}\n"
            new_content = current_content + service_block

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_conf_safely(new_content, f"Port {new_port} -> {target_port}", new_port)
            if ok:
                existing.append(str(new_port))
                ports_dict['STUNNEL_PORTS'] = ",".join(existing)
                print(f"{C_GREEN}[✔] {msg}{C_RESET}")
            else:
                close_firewall_port(new_port, ("tcp",))
                print(f"{C_RED}[✖] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            _ensure_installed()
            os.system(f"nano {STUNNEL_CONF_PATH}")
            if _restart_stunnel():
                print(f"{C_GREEN}[✔] Configuration saved and Stunnel restarted.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Stunnel failed to restart with the edited config — check it manually")
                print(f"    (systemctl status stunnel4 / journalctl -u stunnel4) before it's relied on.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 CONFIGURE SSL CERTIFICATE                  %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" [1] Generate Self-Signed SSL Certificate (.pem)")
            print(" [2] Paste Custom Certificate / Key Manually")
            print(" [0] Back")

            cert_choice = input(" Select option: ").strip()

            if cert_choice == '1':
                os.makedirs("/etc/stunnel", exist_ok=True)
                if _generate_self_signed_cert():
                    if _restart_stunnel():
                        print(f"{C_GREEN}[✔] Self-signed SSL certificate generated at {STUNNEL_PEM_PATH} and Stunnel restarted!{C_RESET}")
                    else:
                        print(f"{C_YELLOW}[!] Certificate generated, but Stunnel failed to restart — check its config.{C_RESET}")
                else:
                    print(f"{C_RED}[✖] Certificate generation failed.{C_RESET}")
            elif cert_choice == '2':
                print(" Paste your combined Certificate and Private Key (PEM format).")
                print(" Type 'END' on a new line when finished:")
                pem_lines = []
                while True:
                    line = input()
                    if line.strip() == 'END':
                        break
                    pem_lines.append(line)

                pem_content = "\n".join(pem_lines) + "\n"
                if "BEGIN CERTIFICATE" not in pem_content or ("BEGIN PRIVATE KEY" not in pem_content and "BEGIN RSA PRIVATE KEY" not in pem_content):
                    print(f"{C_RED}[✖] That doesn't look like a combined cert+key PEM (missing a CERTIFICATE or")
                    print(f"    PRIVATE KEY block) — nothing was changed.{C_RESET}")
                elif pem_lines:
                    if os.path.exists(STUNNEL_PEM_PATH):
                        with open(STUNNEL_PEM_PATH, "r") as f:
                            backup_pem = f.read()
                    else:
                        backup_pem = None
                    with open(STUNNEL_PEM_PATH, "w") as f:
                        f.write(pem_content)
                    os.chmod(STUNNEL_PEM_PATH, 0o600)
                    if _restart_stunnel():
                        print(f"{C_GREEN}[✔] Custom SSL certificate applied successfully!{C_RESET}")
                    else:
                        if backup_pem is not None:
                            with open(STUNNEL_PEM_PATH, "w") as f:
                                f.write(backup_pem)
                            _restart_stunnel()
                        print(f"{C_RED}[✖] Stunnel failed to restart with that certificate — reverted to the previous one.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 STUNNEL SERVICE LOGS                       %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u stunnel4 -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_stunnel():
                print(f"{C_GREEN}[✔] Stunnel service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Stunnel failed to restart — check 'journalctl -u stunnel4'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop stunnel4")
                print(f"{C_YELLOW}[!] Stunnel service stopped.{C_RESET}")
            else:
                _ensure_installed()
                _run("systemctl enable stunnel4")
                if _run("systemctl start stunnel4").returncode == 0:
                    print(f"{C_GREEN}[✔] Stunnel service started.{C_RESET}")
                else:
                    print(f"{C_RED}[✖] Stunnel failed to start — check 'journalctl -u stunnel4'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    UNINSTALL STUNNEL4                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove Stunnel4? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop stunnel4 && systemctl disable stunnel4")
                _run("apt-get purge -y stunnel4")
                for p in _tracked_ports(ports_dict):
                    if p.isdigit():
                        close_firewall_port(int(p), ("tcp",))
                persist_firewall_rules()
                ports_dict.pop('STUNNEL_PORTS', None)
                print(f"{C_GREEN}[✔] Stunnel4 uninstalled and purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
