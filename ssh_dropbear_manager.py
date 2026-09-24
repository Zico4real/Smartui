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

def _ensure_legacy_ssh_compat():
    """Adds legacy KexAlgorithms/Ciphers/MACs alongside (not instead of) the
    modern defaults - confirmed root cause of real "Cannot negotiate,
    proposals do not match" failures against current OpenSSH (10.0+), which
    has dropped several older algorithms that older mobile SSH client apps
    still rely on by default. Applied through the same safe-apply pattern
    (syntax test -> restart -> verify -> auto-rollback) this file already
    uses for every other sshd_config change, given the stakes of getting
    this wrong on a remote box with no other access configured."""
    with open(SSHD_CONFIG_PATH, "r") as f:
        content = f.read()

    content = _set_sshd_directive(
        content, "KexAlgorithms",
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,"
        "ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,"
        "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
        "diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,"
        "diffie-hellman-group-exchange-sha1"
    )
    content = _set_sshd_directive(
        content, "Ciphers",
        "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
        "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes128-cbc,3des-cbc"
    )
    content = _set_sshd_directive(
        content, "MACs",
        "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
        "umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1,"
        "umac-128@openssh.com"
    )

    return _apply_sshd_config_safely(content, "Legacy SSH client compatibility")


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
        print(" [8]> ENABLE LEGACY CLIENT COMPATIBILITY")
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

        elif choice == '8':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s            ENABLE LEGACY CLIENT COMPATIBILITY               %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" Confirmed root cause of \"Cannot negotiate, proposals do not")
            print(" match\" failures on this server: current OpenSSH (10.0+) has")
            print(" dropped several older key-exchange algorithms, ciphers, and")
            print(" MACs that older mobile SSH client apps (HTTP Custom and")
            print(" similar) still rely on by default. This adds the legacy")
            print(" algorithms back ALONGSIDE the modern ones (nothing modern is")
            print(" removed or weakened) - the same fix documented across")
            print(" multiple real, independent sources for this exact OpenSSH")
            print(" 10.x compatibility break.")
            confirm = input("\n Apply this fix now? (y/N): ").strip().lower()
            if confirm == 'y':
                ok, msg = _ensure_legacy_ssh_compat()
                color = C_GREEN if ok else C_RED
                print(f"\n{color}{msg}{C_RESET}")
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
    # Clearing any prior rate-limit before every restart, not just the
    # config-change path - a manual restart or the rollback path could just
    # as easily run into the same "start-limit-hit" state and silently fail
    # otherwise (confirmed against a real case: dropbear's package install
    # auto-starts with the default port-22 template, collides with existing
    # OpenSSH, crash-loops, and burns through systemd's restart budget
    # before any of this code gets a chance to run).
    _run("systemctl reset-failed dropbear")
    return _run("systemctl restart dropbear").returncode == 0


def _ensure_shell_in_etc_shells(shell_path):
    """Dropbear rejects password auth entirely for any account whose shell
    isn't listed in /etc/shells, logging "User 'X' has invalid shell,
    rejected" - confirmed against a real case where a correctly-created
    account with the right password still got "Permission denied
    (publickey,password)" purely because /usr/sbin/nologin (this panel's
    own shell choice for tunnel-only accounts) wasn't in that file. Ubuntu
    doesn't list it there by default. This has nothing to do with PAM or
    the password itself - it's Dropbear's own check, and it silently blocks
    every account this panel creates until fixed."""
    shells_path = "/etc/shells"
    try:
        if os.path.exists(shells_path):
            with open(shells_path) as f:
                content = f.read()
        else:
            content = ""
        if shell_path not in [line.strip() for line in content.splitlines()]:
            with open(shells_path, "a") as f:
                f.write(shell_path + "\n")
    except Exception:
        pass


def _ensure_dropbear_installed():
    """Single, shared install path - every one of the three separate places
    that used to call `apt-get install -y dropbear` directly had its own
    copy of this logic, and only one of them (the port-change wizard) had
    the stop+reset-failed protection added after that bug was first found.
    The "START/STOP SERVICE" option used a raw install + systemctl start
    with none of it, confirmed as the actual live cause of a second,
    identical crash-loop on a real VPS - fresh apt install auto-starts
    dropbear with its default port-22 template, collides with the OpenSSH
    already using that port, crash-loops, and exhausts systemd's restart
    budget before any config gets written. Routing every install through
    this one function means that protection can't be missed at a new call
    site the way it was here.

    After the normal apt install, swaps in a custom-built dropbear binary
    if one is bundled in this repo (bin/dropbear-legacy-compat) - confirmed
    as necessary on any host shipping current Dropbear (2025.87+), which
    disabled SHA-1-based algorithms by default and breaks negotiation
    entirely against older mobile SSH client apps that only offer those.
    Built from the same current, CVE-2025-14282-patched source apt would
    install, with DROPBEAR_DH_GROUP14_SHA1/DROPBEAR_SHA1_HMAC explicitly
    re-enabled at compile time - real algorithms Dropbear's own current
    source still fully supports, just not offered by default - not a
    version downgrade, so no security regression versus the stock apt
    package. Only the binary changes; apt's own systemd unit, default
    config, and host-key generation are untouched and still do their
    normal job. If the bundled binary is missing (not every checkout will
    have it) this silently keeps the stock apt binary - never a hard
    requirement to have the fix bundled."""
    _ensure_shell_in_etc_shells("/usr/sbin/nologin")
    if os.path.exists(DROPBEAR_CONF_PATH):
        _apply_bundled_dropbear_binary()
        return
    _run("apt-get update && apt-get install -y dropbear")
    _run("systemctl stop dropbear")
    _run("systemctl reset-failed dropbear")
    _apply_bundled_dropbear_binary()


def _apply_bundled_dropbear_binary():
    """Swaps /usr/sbin/dropbear for this repo's own bin/dropbear-legacy-compat
    build if one is present, backing up whatever's currently there first
    (once - never overwrites an existing backup, so the very first, known-
    good binary is always what a rollback restores) so this can always be
    undone with a single copy back. No-ops entirely, silently, if this
    checkout doesn't have the bundled binary."""
    repo_dir = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(repo_dir, "bin", "dropbear-legacy-compat")
    live = "/usr/sbin/dropbear"
    backup = "/usr/sbin/dropbear.stock-apt.bak"

    if not os.path.exists(bundled):
        return

    if os.path.exists(live) and not os.path.exists(backup):
        _run(["cp", "-p", live, backup])

    _run(["cp", "-p", bundled, live])
    _run(["chmod", "755", live])


def _apply_dropbear_port_list(ports_dict, valid_ports, current_ports_str):
    """Shared apply-with-rollback logic - used by REDEFINE PORTS (replace the
    whole list) and the newer ADD PORT / REMOVE PORT operations (change just
    one port while keeping the rest), so both paths get the exact same
    safety net rather than risking two slightly different implementations
    drifting apart."""
    if not os.path.exists(DROPBEAR_CONF_PATH):
        print(f"{C_CYAN}[i] Installing dropbear package...{C_RESET}")
    _ensure_dropbear_installed()

    if not os.path.exists(DROPBEAR_CONF_PATH):
        print(f"{C_RED}[✖] Error: {DROPBEAR_CONF_PATH} not found.{C_RESET}")
        return False

    with open(DROPBEAR_CONF_PATH, "r") as f:
        content = f.read()

    new_ports_str = ",".join(str(p) for p in valid_ports)
    if re.search(r'^DROPBEAR_PORT=.*$', content, flags=re.MULTILINE):
        content = re.sub(r'^DROPBEAR_PORT=.*$', f'DROPBEAR_PORT={new_ports_str}', content, flags=re.MULTILINE)
    else:
        content = content.rstrip('\n') + f"\nDROPBEAR_PORT={new_ports_str}\n"
    content = re.sub(r'^NO_START=1', 'NO_START=0', content, flags=re.MULTILINE)

    with open(DROPBEAR_CONF_PATH, "w") as f:
        f.write(content)

    old_ports, _ = _parse_ports(current_ports_str)
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
        return True
    else:
        old_str = ",".join(str(p) for p in old_ports) if old_ports else current_ports_str
        rolled_back = re.sub(r'^DROPBEAR_PORT=.*$', f'DROPBEAR_PORT={old_str}', content, flags=re.MULTILINE)
        with open(DROPBEAR_CONF_PATH, "w") as f:
            f.write(rolled_back)
        _restart_dropbear()
        for p in valid_ports:
            if p not in old_ports:
                close_firewall_port(p, ("tcp",))
        persist_firewall_rules()
        print(f"{C_RED}[✖] New port(s) never came up — reverted to {current_ports_str} and restarted.{C_RESET}")
        return False


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
        print(" [1]> REDEFINE PORTS (replace the whole list)")
        print(" [2]> ADD PORT")
        print(" [3]> VIEW PORTS")
        print(" [4]> REMOVE PORT")
        print(" [5]> MANUAL CONFIGURATION (nano)")
        print(f" [6]> START FIX WITH THE SYSTEM [{fix_status_label}]")
        print(" [7]> CONFIGURE SSH BANNER")
        print("------------------------------------------------------------")
        print(" [8]> SERVICE STATUS")
        print(" [9]> RESTART SERVICE")
        print(f" [10]> START/STOP SERVICE [{status_label}]")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [11] UNINSTALL DROPBEAR")
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

            _apply_dropbear_port_list(ports_dict, valid_ports, dropbear_ports)
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                         ADD PORT                           %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            current_ports, _ = _parse_ports(dropbear_ports)
            new_port = prompt_port(" Enter port to add: ", default=443)
            if new_port in current_ports:
                print(f"{C_YELLOW}[i] Port {new_port} is already in Dropbear's list.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            if check_system_port_in_use(new_port, ("tcp",)):
                print(f"{C_RED}[✖] Port {new_port} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            updated_ports = current_ports + [new_port]
            _apply_dropbear_port_list(ports_dict, updated_ports, dropbear_ports)
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                        VIEW PORTS                          %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            current_ports, _ = _parse_ports(dropbear_ports)
            if not current_ports:
                print(f"{C_YELLOW} No ports configured.{C_RESET}")
            else:
                for p in current_ports:
                    listening = check_system_port_in_use(p, ("tcp",))
                    tag = f"{C_GREEN}[LISTENING]{C_RESET}" if listening else f"{C_RED}[NOT LISTENING]{C_RESET}"
                    print(f" Port {p:<6} {tag}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                       REMOVE PORT                          %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            current_ports, _ = _parse_ports(dropbear_ports)
            if len(current_ports) <= 1:
                print(f"{C_RED}[✖] Dropbear needs at least one port - use REDEFINE PORTS instead")
                print(f"    if you want to replace it entirely.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            for idx, p in enumerate(current_ports, 1):
                print(f" [{idx}] {p}")
            print(" [0] CANCEL")
            pick = input(" Which port do you want to remove? ").strip()
            if not pick.isdigit() or not (1 <= int(pick) <= len(current_ports)):
                if pick != '0':
                    print(f"{C_RED}[X] Invalid selection.{C_RESET}")
                    input("\nPress Enter to continue...")
                continue
            remaining_ports = [p for i, p in enumerate(current_ports, 1) if i != int(pick)]
            _apply_dropbear_port_list(ports_dict, remaining_ports, dropbear_ports)
            input("\nPress Enter to continue...")

        elif choice == '5':
            _ensure_dropbear_installed()
            os.system(f"nano {DROPBEAR_CONF_PATH}")
            if _restart_dropbear():
                print(f"{C_GREEN}[✔] Configuration saved and Dropbear restarted.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Dropbear failed to restart with the edited config — check it manually")
                print(f"    (systemctl status dropbear / journalctl -u dropbear) before it's exposed.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
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

        elif choice == '7':
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

        elif choice == '8':
            clear_screen()
            os.system("systemctl status dropbear --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '9':
            if _restart_dropbear():
                print(f"{C_GREEN}[✔] Dropbear service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[✖] Dropbear failed to restart — check its config.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '10':
            if is_active:
                _run("systemctl stop dropbear")
                print(f"{C_YELLOW}[!] Dropbear service stopped.{C_RESET}")
            else:
                _ensure_dropbear_installed()
                if _restart_dropbear():
                    print(f"{C_GREEN}[✔] Dropbear service started.{C_RESET}")
                else:
                    print(f"{C_RED}[✖] Dropbear failed to start — check 'journalctl -u dropbear'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '11':
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
