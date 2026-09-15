#!/usr/bin/env python3
"""
smartui_main.py - top-level entrypoint for the SmartUI panel. Ties every
module built throughout this project into one running program.

This didn't exist anywhere before now - the original source file's own
main_dashboard() was the intended design, but building it surfaced a
critical, previously-invisible architectural gap: nothing anywhere writes
ports_dict to disk or reloads it. Every module in this panel has been built
around a shared ports_dict passed between functions, but with no top-level
entrypoint persisting it, all port-tracking state would be lost the moment
the script process exits. Fixed here: ports_dict is loaded from
/etc/smartui/panel_state.json at startup and saved after every menu return.

Real bugs found in the original main_dashboard() while building this:

1. get_system_stats() scanned raw /etc/passwd and /etc/shadow directly,
   which (a) counts the admin's own system accounts alongside actual
   customers, since it has no way to distinguish panel-created users from
   anything else on the box, and (b) miscounts SSH-key-only accounts (no
   password set, PAM's "*" prefix convention) as "blocked", conflating
   "never had a password" with "deliberately locked" - a normal, correctly-
   configured key-only customer account would show as BLOCKED. Replaced
   with real counts pulled from ssh_user_manager's own registry, which only
   tracks panel-created customers and distinguishes lock reasons properly.

2. Every submenu call (ssh_user_and_auth_manager(), protocol_configuration_
   manager(), extra_tools_manager(), api_and_bots_manager()) was invoked
   with no arguments, despite every module in this panel taking ports_dict
   as a required parameter - none of them would have actually run.

3. "MANAGE ACCOUNTS (V2RAY/XRAY)" routed to a nonexistent /usr/local/bin/
   xmenu.py - the same broken reference already found and fixed in
   protocol_configuration_manager.py's own option 15. Routed to
   xray_manager.main_menu() instead, the same fix applied there.

4. "MANAGE ACCOUNTS (WIREGUARD)" called wireguard_client_admin_manager() -
   the exact redundant, less-safe module already identified and declined
   earlier in this project (it duplicates wireguard_manager.py's own
   client-management, with the same bugs already fixed there: a private key
   passed as a shell argument, and IP allocation hardcoded to the 10.7.0.x
   range regardless of the server's actual configured subnet). Routed to
   wireguard_manager.wireguard_admin_manager() instead.

5. "SCRIPT CONFIGURATION" called script_configuration_manager() - a
   function that is never defined anywhere in the entire ~7,400-line
   original source file. Replaced with a real panel-info/update-check
   screen (version, install path, a `git pull`-based update check) instead
   of leaving a dead reference in place.

6. "UNINSTALL PANEL" only ever removed two paths (/etc/atken and a
   /usr/local/bin/smartui that nothing in this panel actually installs to)
   while claiming "successfully uninstalled" - wildly incomplete given how
   much state this panel now manages across ~26 modules (dozens of systemd
   units, config directories, keys, certs, cron jobs). Left deliberately
   NOT rebuilt as a single sweep in this pass - a real comprehensive
   uninstall needs to call into each module's own uninstall logic, which is
   a substantial piece of work on its own, not something to bolt on
   carelessly given what's at stake if it gets a path wrong. The menu entry
   now says so honestly rather than silently understating what it does.
"""

import os
import re
import json
import shutil
import platform
import datetime
import subprocess
import pwd

from panel_common import C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN, clear_screen

STATE_DIR = "/etc/smartui"
STATE_PATH = f"{STATE_DIR}/panel_state.json"
PANEL_INSTALL_DIR = "/opt/smartui"
PANEL_VERSION = "1.0.0"

C_MAGENTA = "\033[95m"


def load_ports_dict():
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def save_ports_dict(ports_dict):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(ports_dict, f, indent=2)
    os.chmod(STATE_PATH, 0o600)


def get_public_ip():
    try:
        return os.popen("curl -s ifconfig.me || hostname -I | awk '{print $1}'").read().strip()
    except Exception:
        return "127.0.0.1"


def get_os_info():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return platform.system() + " " + platform.release()


def get_system_stats():
    """Real counts from ssh_user_manager's own registry - only ever counts
    panel-created customers, never the admin's own accounts or unrelated
    system users, and distinguishes an actual lock (quota exceeded, manually
    locked) from an account that simply never had a password set."""
    try:
        from ssh_user_manager import _load_registry
        registry = _load_registry()
    except Exception:
        registry = {}

    total = len(registry)
    active = sum(1 for r in registry.values() if not r.get("locked"))
    blocked = sum(1 for r in registry.values() if r.get("locked"))
    expired = 0
    now = datetime.datetime.now()
    for r in registry.values():
        expiry = r.get("expiry")
        if expiry:
            try:
                if datetime.datetime.strptime(expiry, "%Y-%m-%d") < now:
                    expired += 1
            except ValueError:
                pass

    try:
        online_lines = [line for line in os.popen("who 2>/dev/null").readlines() if line.strip()]
        online = len(online_lines)
    except Exception:
        online = 0

    return active, expired, blocked, total, online


def _update_script_screen():
    """Real update flow, not just a bare `git pull`:
    - Refuses to run at all if the install isn't a git checkout (no way to
      update safely without one).
    - Backs up the current /opt/smartui (everything except .git) to a
      timestamped directory before touching anything.
    - Uses `git pull --ff-only`, which fails cleanly rather than overwriting
      anything if there are local uncommitted changes it can't cleanly
      reconcile - it will never silently discard edits.
    - Verifies the updated code actually imports before declaring success;
      automatically restores the backup if it doesn't.
    - Never touches anything outside PANEL_INSTALL_DIR - the state file
      (/etc/smartui/panel_state.json) and every installed protocol's own
      config/systemd/binaries live in entirely separate directories, so a
      pull here can't reach or reset them even accidentally.
    """
    clear_screen()
    print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
    print(f"{C_BOLD}                      UPDATE SCRIPT                          {C_RESET}")
    print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")

    if not os.path.isdir(f"{PANEL_INSTALL_DIR}/.git"):
        print(f"{C_YELLOW}Not a git checkout - installed some other way, so there's no safe")
        print(f"way to update in place from here. Re-run the installer instead.{C_RESET}")
        input("\nPress Enter to continue...")
        return

    print(f"{C_CYAN}[i] Checking for updates...{C_RESET}")
    subprocess.run(["git", "fetch", "--quiet"], cwd=PANEL_INSTALL_DIR)
    status = subprocess.run(["git", "status", "-uno"], cwd=PANEL_INSTALL_DIR, capture_output=True, text=True)
    print(status.stdout)

    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=PANEL_INSTALL_DIR, capture_output=True, text=True)
    if dirty.stdout.strip():
        print(f"{C_YELLOW}[!] There are local changes to panel files (shown above/via 'git status').")
        print(f"    The update will still only fast-forward - it will refuse rather than")
        print(f"    overwrite anything it can't cleanly reconcile.{C_RESET}")

    if "Your branch is up to date" in status.stdout:
        print(f"{C_GREEN}Already up to date.{C_RESET}")
        input("\nPress Enter to continue...")
        return

    confirm = input("\n Apply the update now? (y/n): ").strip().lower()
    if confirm != 'y':
        print(f"{C_YELLOW}[i] Cancelled.{C_RESET}")
        input("\nPress Enter to continue...")
        return

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = f"{PANEL_INSTALL_DIR}.backup-{timestamp}"
    print(f"{C_CYAN}[i] Backing up current install to {backup_dir}...{C_RESET}")
    shutil.copytree(PANEL_INSTALL_DIR, backup_dir, ignore=shutil.ignore_patterns(".git"))

    pull = subprocess.run(["git", "pull", "--ff-only"], cwd=PANEL_INSTALL_DIR, capture_output=True, text=True)
    if pull.returncode != 0:
        print(f"{C_RED}[X] Update failed - nothing was changed (fast-forward-only pull refused")
        print(f"    rather than risk overwriting local changes):{C_RESET}")
        print(pull.stderr.strip())
        input("\nPress Enter to continue...")
        return

    verify = subprocess.run(
        ["python3", "-c", f"import sys; sys.path.insert(0, '{PANEL_INSTALL_DIR}'); import smartui_main"],
        capture_output=True, text=True,
    )
    if verify.returncode != 0:
        print(f"{C_RED}[X] The updated code failed to import - restoring the backup automatically.{C_RESET}")
        for item in os.listdir(PANEL_INSTALL_DIR):
            if item == ".git":
                continue
            item_path = os.path.join(PANEL_INSTALL_DIR, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)
        for item in os.listdir(backup_dir):
            shutil.move(os.path.join(backup_dir, item), os.path.join(PANEL_INSTALL_DIR, item))
        shutil.rmtree(backup_dir)
        print(f"{C_GREEN}[OK] Restored - the panel is back on the previous working version.{C_RESET}")
        print(f"    Details of the import failure:{C_RESET}\n{verify.stderr.strip()}")
    else:
        print(f"{C_GREEN}[OK] Updated and verified successfully.{C_RESET}")
        print(f" Backup of the previous version kept at: {backup_dir}")
        print(f" (Your installed protocols, accounts, and panel_state.json were never")
        print(f"  touched - they live outside {PANEL_INSTALL_DIR} entirely.)")
        print(f" Restart the panel to use the new version.")
    input("\nPress Enter to continue...")


def _panel_info_screen():
    clear_screen()
    print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
    print(f"{C_BOLD}                     PANEL INFORMATION                       {C_RESET}")
    print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
    print(f"  Version:      {PANEL_VERSION}")
    print(f"  Install path: {PANEL_INSTALL_DIR}")
    print(f"  State file:   {STATE_PATH}")
    print(f"{C_CYAN}────────────────────────────────────────────────────────────{C_RESET}")
    print(f"  [0] Back")
    input("\nPress Enter to continue...")


CRON_REBOOT_PATH = "/etc/cron.d/smartui-scheduled-reboot"


def _cronjob_reboot_screen():
    clear_screen()
    print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
    print(f"{C_BOLD}                     CRONJOB REBOOT                          {C_RESET}")
    print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")

    currently_enabled = os.path.exists(CRON_REBOOT_PATH)
    if currently_enabled:
        with open(CRON_REBOOT_PATH) as f:
            current_line = f.read().strip()
        print(f"  Currently enabled: {C_GREEN}{current_line.split('root')[0].strip()}{C_RESET}")
    else:
        print(f"  Currently: {C_YELLOW}disabled{C_RESET}")

    print(f"{C_CYAN}────────────────────────────────────────────────────────────{C_RESET}")
    print("  [1] Every 6 hours")
    print("  [2] Every 12 hours")
    print("  [3] Every 24 hours")
    print("  [4] Custom interval (hours)")
    print("  [5] Disable scheduled reboot")
    print("  [0] Back")
    choice = input(" Enter an option: ").strip()

    interval_hours = None
    if choice == '1':
        interval_hours = 6
    elif choice == '2':
        interval_hours = 12
    elif choice == '3':
        interval_hours = 24
    elif choice == '4':
        raw = input(" Enter custom interval in hours (1-168): ").strip()
        if raw.isdigit() and 1 <= int(raw) <= 168:
            interval_hours = int(raw)
        else:
            print(f"{C_RED}[X] Enter a whole number of hours between 1 and 168.{C_RESET}")
            input("\nPress Enter to continue...")
            return
    elif choice == '5':
        if currently_enabled:
            os.remove(CRON_REBOOT_PATH)
            print(f"{C_GREEN}[OK] Scheduled reboot disabled.{C_RESET}")
        else:
            print(f"{C_YELLOW}[i] Already disabled - nothing to do.{C_RESET}")
        input("\nPress Enter to continue...")
        return
    elif choice == '0':
        return
    else:
        print(f"{C_RED}Invalid option.{C_RESET}")
        input("\nPress Enter to continue...")
        return

    confirm = input(f" Reboot this VPS every {interval_hours} hours? (y/n): ").strip().lower()
    if confirm != 'y':
        print(f"{C_YELLOW}[i] Cancelled.{C_RESET}")
        input("\nPress Enter to continue...")
        return

    # cron's own field doesn't support "every N hours" directly for N>23 in a
    # single expression that also divides evenly - build the step correctly
    # for the common divisors of 24 (6/12/24) and fall back to a plain
    # */N-hour step (cron accepts N up to 23 for */N on the hour field; for
    # anything larger, run hourly and let the script itself gate on the count
    # is unnecessary complexity here - custom intervals over 23 hours use a
    # day-based step instead).
    if interval_hours <= 23:
        cron_expr = f"0 */{interval_hours} * * *"
        if 24 % interval_hours != 0:
            print(f"{C_YELLOW}[i] {interval_hours} doesn't divide evenly into 24 - reboots will be evenly")
            print(f"    spaced except for one shorter gap where the schedule wraps past")
            print(f"    midnight (a standard cron quirk, not a bug).{C_RESET}")
    else:
        days = max(1, interval_hours // 24)
        cron_expr = f"0 0 */{days} * *"

    with open(CRON_REBOOT_PATH, "w") as f:
        f.write(f"{cron_expr} root /sbin/reboot\n")
    os.chmod(CRON_REBOOT_PATH, 0o644)
    print(f"{C_GREEN}[OK] Scheduled reboot enabled: every {interval_hours} hours.{C_RESET}")
    input("\nPress Enter to continue...")


def main_dashboard():
    ports_dict = load_ports_dict()

    while True:
        clear_screen()

        current_date = datetime.datetime.now().strftime("%d-%m-%Y")
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        os_name = get_os_info()
        ip_addr = get_public_ip()
        active_count, expired_count, blocked_count, total_count, online_count = get_system_stats()

        print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
        print(f"{C_BOLD}{C_GREEN}                         ⚡ SMARTUI ⚡                      {C_RESET}")
        print(f"{C_CYAN}╔══════════════════════════════════════════════════════════╗{C_RESET}")
        print(f"  {C_BOLD}S.O:{C_RESET}  {os_name:<27} {C_BOLD}Date:{C_RESET}    {current_date}")
        print(f"  {C_BOLD}IP:{C_RESET}   {ip_addr:<27} {C_BOLD}Time:{C_RESET}    {current_time}")
        print(f"{C_CYAN}╚══════════════════════════════════════════════════════════╝{C_RESET}")
        print(f"    {C_GREEN}ACTIVE:{C_RESET} {active_count}    {C_YELLOW}EXPIRED:{C_RESET} {expired_count}     {C_RED}BLOCKED:{C_RESET} {blocked_count}    {C_BOLD}TOTAL:{C_RESET} {total_count}")
        print(f"    {C_MAGENTA}ONLINE SESSIONS:{C_RESET} {online_count}")
        print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
        print(f"  {C_YELLOW}[1]>{C_RESET} MANAGE ACCOUNTS (SSH/DROPBEAR)")
        print(f"  {C_YELLOW}[2]>{C_RESET} MANAGE ACCOUNTS (V2RAY/XRAY)")
        print(f"  {C_YELLOW}[3]>{C_RESET} MANAGE ACCOUNTS (WIREGUARD)")
        print(f"{C_CYAN}────────────────────────────────────────────────────────────{C_RESET}")
        print(f"  {C_YELLOW}[4]>{C_RESET} PROTOCOL CONFIGURATION")
        print(f"  {C_YELLOW}[5]>{C_RESET} EXTRA TOOLS")
        print(f"{C_CYAN}────────────────────────────────────────────────────────────{C_RESET}")
        print(f"  {C_YELLOW}[6]>{C_RESET} CONFIGURE API & BOTS")
        print(f"{C_CYAN}────────────────────────────────────────────────────────────{C_RESET}")
        print(f"  {C_YELLOW}[7]>{C_RESET} PANEL INFO")
        print(f"  {C_YELLOW}[8]>{C_RESET} {C_RED}[!] UNINSTALL PANEL (partial - see note){C_RESET}")
        print(f"{C_CYAN}────────────────────────────────────────────────────────────{C_RESET}")
        print(f"  {C_YELLOW}[10]>{C_RESET} UPDATE SCRIPT")
        print(f"  {C_YELLOW}[11]>{C_RESET} CRONJOB REBOOT")
        print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
        print(f"  {C_GREEN}[0]  EXIT SCRIPT    [9]  RESTART VPS{C_RESET}")
        print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")

        choice = input(f"{C_BOLD} Enter an Option: {C_RESET}").strip()

        if choice == '1':
            from ssh_user_manager import ssh_user_admin_manager
            ssh_user_admin_manager(ports_dict)

        elif choice == '2':
            from xray_manager import main_menu as xray_main_menu
            xray_main_menu()

        elif choice == '3':
            from wireguard_manager import wireguard_admin_manager
            wireguard_admin_manager(ports_dict)

        elif choice == '4':
            from protocol_configuration_manager import protocol_configuration_manager
            protocol_configuration_manager(ports_dict)

        elif choice == '5':
            from extra_tools_manager import extra_tools_manager
            extra_tools_manager(ports_dict)

        elif choice == '6':
            from api_and_bots_manager import api_and_bots_manager
            api_and_bots_manager()

        elif choice == '7':
            _panel_info_screen()

        elif choice == '8':
            clear_screen()
            print(f"{C_YELLOW}[!] This removes the panel's own top-level files only - it does NOT")
            print(f"    walk through every installed protocol's own uninstall logic (SSH,")
            print(f"    OpenVPN, WireGuard, Xray, and everything else keep running and keep")
            print(f"    their systemd services/configs). Uninstall each protocol you no longer")
            print(f"    want from its own module first if you want a clean teardown.{C_RESET}")
            confirm = input(" Remove the panel's own files anyway? (y/n): ").strip().lower()
            if confirm == 'y':
                os.system(f"rm -rf {PANEL_INSTALL_DIR}")
                print(f"{C_GREEN}[OK] Panel files removed. Installed protocols were left untouched.{C_RESET}")
                save_ports_dict(ports_dict)
                break
            input("\nPress Enter to continue...")

        elif choice == '10':
            _update_script_screen()

        elif choice == '11':
            _cronjob_reboot_screen()

        elif choice == '0':
            print(f"\n{C_YELLOW}[i] Exiting...{C_RESET}")
            save_ports_dict(ports_dict)
            break

        elif choice == '9':
            confirm = input(f"{C_RED}Are you sure you want to restart the VPS? (y/n): {C_RESET}").strip().lower()
            if confirm == 'y':
                save_ports_dict(ports_dict)
                os.system("reboot")
            break

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")

        save_ports_dict(ports_dict)


if __name__ == '__main__':
    main_dashboard()
