"""
ssh_dropbear_manager.py — SSH and Dropbear admin modules for the SmartUI panel.

The most consequential bug found in the original draft of these modules: SSH port
changes had ZERO safety net. sshd_config was edited and the service blindly
restarted with no syntax check beforehand and no verification the new port
actually came up afterward. If the new port collided with something else, or the
edit was malformed, sshd could fail to (re)start entirely — on a remote VPS with
no other access configured, that's a full lockout with no recovery path short of
the hosting provider's out-of-band console. Every port change here now goes
through: pre-flight config syntax test -> apply -> restart -> verify the port is
actually listening -> automatic rollback to the previous working config if not.

Also fixed: the original SSH banner code checked `grep -q ... ` by reading its
stdout, but `-q` suppresses ALL output including on a match — so that check was
always "no match found" and a duplicate `Banner /etc/issue.net` line got
appended to sshd_config on every single run of that menu option. And several
sed substitutions here (SSH's `Port`, `PermitRootLogin`, `PasswordAuthentication`
directives) only matched lines that already existed in sshd_config — modern
Ubuntu images often omit these lines entirely and rely on compiled-in defaults,
so those substitutions would silently do nothing while still printing "[✔]
enabled/disabled successfully" — a false sense of having changed something,
which matters more than usual here since two of those three are security
settings.
"""

import os
import re
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_public_ip,
)

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
DROPBEAR_CONF_PATH = "/etc/default/dropbear"
BANNER_PATH = "/etc/issue.net"


def _service_active(name):
    return _run(["systemctl", "is-active", "--quiet", name]).returncode == 0


def _service_enabled(name):
    return _run(["systemctl", "is-enabled", "--quiet", name]).returncode == 0


def _restart_ssh():
    # Ubuntu names the unit "ssh", most other distros "sshd" — try both,
    # matching the same fallback pattern the original menu display used.
    r = _run("systemctl restart ssh")
    if r.returncode != 0:
        r = _run("systemctl restart sshd")
    return r.returncode == 0


def _wait_for_port_listening(port, proto="tcp", tries=6, delay=1):
    """Give a freshly (re)started daemon a moment to actually bind before
    declaring success or failure — systemd reporting a unit as 'active' only
    means the process forked successfully, not that it survived long enough to
    bind its port."""
    for _ in range(tries):
        if check_system_port_in_use(port, (proto,)):
            return True
        time.sleep(delay)
    return False


# ==================== SSH (OpenSSH) ====================

def _set_sshd_directive(content, directive, value):
    """Replace an existing (possibly commented-out) directive line, or append a
    new one if it isn't present at all — the append case is exactly what the
    original code was missing for the Port/PermitRootLogin/PasswordAuthentication
    directives, which silently no-op'd on configs that never had those lines."""
    pattern = rf'^\s*#?\s*{directive}\s+.*$'
    if re.search(pattern, content, re.MULTILINE):
        return re.sub(pattern, f'{directive} {value}', content, count=1, flags=re.MULTILINE)
    return content.rstrip('\n') + f'\n{directive} {value}\n'


def _apply_sshd_config_safely(new_content, description):
    """The actual safety net: test syntax before touching the running service,
    verify it's really listening afterward, and roll back automatically if not.
    Returns (ok: bool, message: str)."""
    if not os.path.exists(SSHD_CONFIG_PATH):
        return False, f"{SSHD_CONFIG_PATH} not found."

    with open(SSHD_CONFIG_PATH, "r") as f:
        original = f.read()

    with open(SSHD_CONFIG_PATH, "w") as f:
        f.write(new_content)

    test = _run(["sshd", "-t"])
    if test.returncode != 0:
        with open(SSHD_CONFIG_PATH, "w") as f:
            f.write(original)
        return False, f"Config failed 'sshd -t' validation — reverted, nothing was changed:\n{test.stderr.strip()}"

    port_match = re.search(r'^\s*Port\s+(\d+)', new_content, re.MULTILINE)
    check_port = int(port_match.group(1)) if port_match else 22

    if not _restart_ssh():
        with open(SSHD_CONFIG_PATH, "w") as f:
            f.write(original)
        _restart_ssh()
        return False, f"{description} passed syntax check but the service failed to restart — reverted and restarted the previous config."

    if not _wait_for_port_listening(check_port):
        with open(SSHD_CONFIG_PATH, "w") as f:
            f.write(original)
        _restart_ssh()
        return False, f"{description} applied and service restarted, but port {check_port} never came up — reverted to the previous working config and restarted it. Nothing was left broken."

    return True, f"{description} applied and verified on port {check_port}."


def _change_ssh_port(new_port, old_port_str, ports_dict):
    try:
        old_port = int(old_port_str)
    except ValueError:
        old_port = 22

    if new_port == old_port:
        print(f"{C_YELLOW}[i] Already on port {new_port} — nothing to do.{C_RESET}")
        return

    if check_system_port_in_use(new_port, ("tcp",)):
        print(f"{C_RED}[✖] Port {new_port} is already in use by another service. Not touching SSH.{C_RESET}")
        return

    with open(SSHD_CONFIG_PATH, "r") as f:
        content = f.read()
    new_content = _set_sshd_directive(content, "Port", str(new_port))

    # Open the new port before restarting (so the moment sshd comes up on it,
    # it's reachable) — close the old one only AFTER we've confirmed the new
    # one actually works, never before.
    open_firewall_port(new_port, ("tcp",))
    persist_firewall_rules()

    ok, msg = _apply_sshd_config_safely(new_content, f"SSH port change to {new_port}")
    if ok:
        close_firewall_port(old_port, ("tcp",))
        persist_firewall_rules()
        ports_dict['SSH_PORT'] = str(new_port)
        print(f"{C_GREEN}[✔] {msg}{C_RESET}")
        print(f"{C_CYAN}    Old port {old_port} closed on the firewall.{C_RESET}")
    else:
        # Roll back the firewall opening too, since the port change didn't stick.
        close_firewall_port(new_port, ("tcp",))
        print(f"{C_RED}[✖] {msg}{C_RESET}")


def ssh_admin_manager(ports_dict):
    """OpenSSH Administrator Module."""
    while True:
        ssh_port = ports_dict.get('SSH_PORT', '22')
        is_active = _service_active("ssh") or _service_active("sshd")
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                     SSH ADMINISTRATOR                      %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"     PORTS: {ssh_port}")
        print("────────────────────────────────────────────────────────────")
        print(" [1]> MODIFY SSH PORT")
        print(" [2]> CONFIGURE SSH BANNER")
        print(" [3]> SET UP PASSWORD AND ROOT ACCESS")
        print("------------------------------------------------------------")
        print(f" [4]> START/STOP SSH SERVER [{status_label}]")
        print(" [5]> RESTART SSH SERVER")
        print(" %s[7]>%s HCR / BHTTP CLIENT CONNECTION INFO" % (C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [6] UNINSTALL OPENSSH-SERVER")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s              HCR / BHTTP CLIENT CONNECTION INFO             %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            server_ip = get_public_ip()
            print(f"{C_YELLOW} These aren't separate server protocols - both are client-side")
            print(f" transport modes (in apps like HTTP Custom / HTTP Injector) that")
            print(f" wrap SSH traffic differently on the way in. Both connect to the")
            print(f" same SSH server already running here - nothing extra to install.{C_RESET}")
            print()
            print(f" Server IP:   {server_ip}")
            print(f" SSH Port:    {ssh_port}")
            print(f" Username/Password: your existing SSH account credentials")
            print()
            print(f" {C_BOLD}HCR (HTTP Core Relay){C_RESET} — confirmed from HTTP Custom's own changelog")
            print(f" as an SSH transport mode. In the app: select SSH, choose the HCR")
            print(f" transport, enter the server IP/port/credentials above.")
            print()
            print(f" {C_BOLD}BHTTP{C_RESET} — {C_YELLOW}I could not independently confirm exactly which app or")
            print(f" mode this refers to{C_RESET}, unlike HCR. It's very likely another similarly-")
            print(f" named client transport in the same app family (HTTP Custom, HTTP")
            print(f" Injector, and similar all have several). Try pointing whichever app")
            print(f" your customers use at the same IP/port/credentials above under a")
            print(f" 'BHTTP' or similarly-named SSH transport option - if that doesn't")
            print(f" connect, it's likely a different mode with different requirements,")
            print(f" and I'd want the exact app name to check further.")
            input("\nPress Enter to continue...")

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     MODIFY SSH PORT                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            new_port_raw = input(f" Enter new SSH port (Current: {ssh_port}): ").strip()
            if new_port_raw.isdigit() and 1 <= int(new_port_raw) <= 65535:
                _change_ssh_port(int(new_port_raw), ssh_port, ports_dict)
            else:
                print(f"{C_RED}[✖] Invalid port — must be a number between 1 and 65535.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  CONFIGURE SSH BANNER                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" Enter your custom SSH login banner text below.")
            print(" Type 'END' on a new line when finished, or leave blank to disable:")

            banner_lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                banner_lines.append(line)
                if not line and not banner_lines[:-1]:
                    break

            if banner_lines and any(banner_lines):
                with open(BANNER_PATH, "w") as f:
                    f.write("\n".join(banner_lines) + "\n")

                with open(SSHD_CONFIG_PATH, "r") as f:
                    content = f.read()
                new_content = _set_sshd_directive(content, "Banner", BANNER_PATH)
                ok, msg = _apply_sshd_config_safely(new_content, "SSH banner")
                if ok:
                    print(f"{C_GREEN}[✔] Custom SSH banner configured and applied successfully!{C_RESET}")
                else:
                    print(f"{C_RED}[✖] {msg}{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Banner setup skipped or cleared.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s              SET UP PASSWORD & ROOT ACCESS                 %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" [1] Enable Root Login (PermitRootLogin yes)")
            print(" [2] Secure/Disable Root Login (PermitRootLogin prohibit-password)")
            print(" [3] Enable Password Authentication (PasswordAuthentication yes)")
            print(" [4] Disable Password Authentication (PasswordAuthentication no)")
            print(" [0] Back")

            sec_choice = input(" Select option: ").strip()
            directive_map = {
                '1': ("PermitRootLogin", "yes", "Root login enabled"),
                '2': ("PermitRootLogin", "prohibit-password", "Root login set to prohibit-password"),
                '3': ("PasswordAuthentication", "yes", "Password authentication enabled"),
                '4': ("PasswordAuthentication", "no", "Password authentication disabled"),
            }
            if sec_choice in directive_map:
                directive, value, label = directive_map[sec_choice]
                with open(SSHD_CONFIG_PATH, "r") as f:
                    content = f.read()
                new_content = _set_sshd_directive(content, directive, value)
                ok, msg = _apply_sshd_config_safely(new_content, label)
                if ok:
                    print(f"{C_GREEN}[✔] {msg}{C_RESET}")
                else:
                    print(f"{C_RED}[✖] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if is_active:
                _run("systemctl stop ssh")
                _run("systemctl stop sshd")
                print(f"{C_YELLOW}[!] SSH Server stopped.{C_RESET}")
            else:
                _run("systemctl start ssh")
                _run("systemctl start sshd")
                print(f"{C_GREEN}[✔] SSH Server started.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_ssh():
                print(f"{C_GREEN}[✔] SSH server restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[✖] SSH server failed to restart — check 'sshd -t' and journalctl.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 UNINSTALL OPENSSH-SERVER                   %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(f"{C_RED}[!] This will remove your only way to manage this server via SSH.{C_RESET}")
            confirm = input(" Are you sure you want to completely remove openssh-server? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("apt-get purge -y openssh-server")
                print(f"{C_GREEN}[✔] OpenSSH server purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")


# ==================== Dropbear ====================

def _parse_ports(raw):
    """Validate a comma/space-separated port list. Returns (valid_ports, invalid_tokens)."""
    tokens = [t for t in raw.replace(',', ' ').split() if t]
    valid, invalid = [], []
    for t in tokens:
        if t.isdigit() and 1 <= int(t) <= 65535:
            valid.append(int(t))
        else:
            invalid.append(t)
    return valid, invalid


def _restart_dropbear():
    return _run("systemctl restart dropbear").returncode == 0


def dropbear_admin_manager(ports_dict):
    """Dropbear Administrator Module."""
    while True:
        dropbear_ports = ports_dict.get('DROPBEAR_PORTS', '443')
        is_active = _service_active("dropbear")
        is_enabled = _service_enabled("dropbear")
        status_label = "ON" if is_active else "OFF"
        fix_status_label = "ON" if is_enabled else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                    DROPBEAR ADMINISTRATOR                  %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      PUERTOS: {dropbear_ports}")
        print("────────────────────────────────────────────────────────────")
        print(" [1]> REDEFINING PORTS")
        print(" [2]> MANUAL CONFIGURATION (nano)")
        print(f" [3]> START FIX WITH THE SYSTEM [{fix_status_label}]")
        print(" [4]> CONFIGURE SSH BANNER")
        print("------------------------------------------------------------")
        print(" [5]> SERVICE STATUS")
        print(" [6]> RESTART SERVICE")
        print(f" [7]> START/STOP SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [8] UNINSTALL DROPBEAR")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     REDEFINE DROPBEAR PORTS                %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            new_ports_raw = input(f" Enter new port(s), e.g., 443 or 443,80 (Current: {dropbear_ports}): ").strip()

            if not new_ports_raw:
                print(f"{C_RED}[✖] No input provided.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            valid_ports, invalid_tokens = _parse_ports(new_ports_raw)
            if invalid_tokens:
                print(f"{C_RED}[✖] Invalid port(s): {', '.join(invalid_tokens)}. Nothing was changed —")
                print(f"    writing that straight into Dropbear's config would have kept it from starting.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            already_used = [p for p in valid_ports if check_system_port_in_use(p, ("tcp",))]
            if already_used:
                print(f"{C_RED}[✖] Port(s) already in use by another service: {', '.join(str(p) for p in already_used)}.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            if not os.path.exists(DROPBEAR_CONF_PATH):
                print(f"{C_CYAN}[i] Installing dropbear package...{C_RESET}")
                _run("apt-get update && apt-get install -y dropbear")

            if os.path.exists(DROPBEAR_CONF_PATH):
                with open(DROPBEAR_CONF_PATH, "r") as f:
                    content = f.read()

                new_ports_str = ",".join(str(p) for p in valid_ports)
                if "DROPBEAR_PORT=" in content:
                    content = re.sub(r'^DROPBEAR_PORT=.*$', f'DROPBEAR_PORT={new_ports_str}', content, flags=re.MULTILINE)
                else:
                    content = content.rstrip('\n') + f"\nDROPBEAR_PORT={new_ports_str}\n"
                content = re.sub(r'^NO_START=1', 'NO_START=0', content, flags=re.MULTILINE)

                with open(DROPBEAR_CONF_PATH, "w") as f:
                    f.write(content)

                old_ports, _ = _parse_ports(dropbear_ports)
                for p in valid_ports:
                    open_firewall_port(p, ("tcp",))
                persist_firewall_rules()

                if _restart_dropbear() and any(_wait_for_port_listening(p) for p in valid_ports):
                    for p in old_ports:
                        if p not in valid_ports:
                            close_firewall_port(p, ("tcp",))
                    persist_firewall_rules()
                    ports_dict['DROPBEAR_PORTS'] = new_ports_str
                    print(f"{C_GREEN}[✔] Dropbear ports successfully updated to: {new_ports_str}!{C_RESET}")
                else:
                    # Roll back — same principle as the SSH path: never leave the
                    # admin's only remaining access broken.
                    with open(DROPBEAR_CONF_PATH, "w") as f:
                        old_str = ",".join(str(p) for p in old_ports) if old_ports else dropbear_ports
                        rolled_back = re.sub(r'^DROPBEAR_PORT=.*$', f'DROPBEAR_PORT={old_str}', content, flags=re.MULTILINE)
                        f.write(rolled_back)
                    _restart_dropbear()
                    for p in valid_ports:
                        close_firewall_port(p, ("tcp",))
                    persist_firewall_rules()
                    print(f"{C_RED}[✖] New port(s) never came up — reverted to {dropbear_ports} and restarted.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Error: {DROPBEAR_CONF_PATH} not found.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            if not os.path.exists(DROPBEAR_CONF_PATH):
                _run("apt-get update && apt-get install -y dropbear")
            os.system(f"nano {DROPBEAR_CONF_PATH}")
            if _restart_dropbear():
                print(f"{C_GREEN}[✔] Configuration saved and Dropbear restarted.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Dropbear failed to restart with the edited config — check it manually")
                print(f"    (systemctl status dropbear / journalctl -u dropbear) before it's exposed.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            if is_enabled:
                _run("systemctl disable dropbear")
                if os.path.exists(DROPBEAR_CONF_PATH):
                    with open(DROPBEAR_CONF_PATH) as f:
                        c = f.read()
                    with open(DROPBEAR_CONF_PATH, "w") as f:
                        f.write(re.sub(r'^NO_START=0', 'NO_START=1', c, flags=re.MULTILINE))
                print(f"{C_YELLOW}[!] Dropbear removed from system startup (Disabled).{C_RESET}")
            else:
                _run("systemctl enable dropbear")
                if os.path.exists(DROPBEAR_CONF_PATH):
                    with open(DROPBEAR_CONF_PATH) as f:
                        c = f.read()
                    with open(DROPBEAR_CONF_PATH, "w") as f:
                        f.write(re.sub(r'^NO_START=1', 'NO_START=0', c, flags=re.MULTILINE))
                print(f"{C_GREEN}[✔] Dropbear fixed/set to start automatically with the system (Enabled).{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  CONFIGURE DROPBEAR BANNER                 %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" Enter your custom banner text below.")
            print(" Type 'END' on a new line when finished, or leave blank to cancel:")

            banner_lines = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                banner_lines.append(line)
                if not line and not banner_lines[:-1]:
                    break

            if banner_lines and any(banner_lines):
                with open(BANNER_PATH, "w") as f:
                    f.write("\n".join(banner_lines) + "\n")

                if os.path.exists(DROPBEAR_CONF_PATH):
                    with open(DROPBEAR_CONF_PATH, "r") as f:
                        conf_data = f.read()

                    # Preserve any OTHER flags already in DROPBEAR_EXTRA_ARGS instead of
                    # overwriting the whole line — the original code discarded anything
                    # else an admin had set there.
                    m = re.search(r'^DROPBEAR_EXTRA_ARGS="([^"]*)"', conf_data, re.MULTILINE)
                    existing_args = m.group(1) if m else ""
                    existing_args = re.sub(r'-b\s+\S+', '', existing_args).strip()
                    new_args = f"{existing_args} -b {BANNER_PATH}".strip()

                    if "DROPBEAR_EXTRA_ARGS=" in conf_data:
                        conf_data = re.sub(r'^DROPBEAR_EXTRA_ARGS=.*$', f'DROPBEAR_EXTRA_ARGS="{new_args}"', conf_data, flags=re.MULTILINE)
                    else:
                        conf_data = conf_data.rstrip('\n') + f'\nDROPBEAR_EXTRA_ARGS="{new_args}"\n'

                    with open(DROPBEAR_CONF_PATH, "w") as f:
                        f.write(conf_data)

                if _restart_dropbear():
                    print(f"{C_GREEN}[✔] Custom Dropbear banner configured successfully!{C_RESET}")
                else:
                    print(f"{C_RED}[✖] Dropbear failed to restart after the banner change — check it manually.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Banner configuration skipped.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            os.system("systemctl status dropbear --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if _restart_dropbear():
                print(f"{C_GREEN}[✔] Dropbear service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Dropbear failed to restart — check its config.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '7':
            if is_active:
                _run("systemctl stop dropbear")
                print(f"{C_YELLOW}[!] Dropbear service stopped.{C_RESET}")
            else:
                if not os.path.exists(DROPBEAR_CONF_PATH):
                    _run("apt-get update && apt-get install -y dropbear")
                _run("systemctl start dropbear")
                print(f"{C_GREEN}[✔] Dropbear service started.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    UNINSTALL DROPBEAR                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove Dropbear? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop dropbear")
                _run("systemctl disable dropbear")
                _run("apt-get purge -y dropbear")
                old_ports, _ = _parse_ports(dropbear_ports)
                for p in old_ports:
                    close_firewall_port(p, ("tcp",))
                persist_firewall_rules()
                ports_dict.pop('DROPBEAR_PORTS', None)
                print(f"{C_GREEN}[✔] Dropbear uninstalled and purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
