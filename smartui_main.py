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
import platform
import datetime
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


def _panel_info_screen():
    clear_screen()
    print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
    print(f"{C_BOLD}                     PANEL INFORMATION                       {C_RESET}")
    print(f"{C_CYAN}════════════════════════════════════════════════════════════{C_RESET}")
    print(f"  Version:      {PANEL_VERSION}")
    print(f"  Install path: {PANEL_INSTALL_DIR}")
    print(f"  State file:   {STATE_PATH}")
    print(f"{C_CYAN}────────────────────────────────────────────────────────────{C_RESET}")
    if os.path.isdir(f"{PANEL_INSTALL_DIR}/.git"):
        print(f"  [1] Check for updates (git pull)")
        print(f"  [0] Back")
        choice = input(" Enter an option: ").strip()
        if choice == '1':
            print(f"\n{C_CYAN}[i] Checking for updates...{C_RESET}")
            os.system(f"cd {PANEL_INSTALL_DIR} && git fetch --quiet && git status -uno")
            confirm = input("\n Pull the latest changes now? (y/n): ").strip().lower()
            if confirm == 'y':
                result = os.system(f"cd {PANEL_INSTALL_DIR} && git pull")
                if result == 0:
                    print(f"{C_GREEN}[OK] Updated. Restart the panel to use the new version.{C_RESET}")
                else:
                    print(f"{C_RED}[X] git pull failed - check output above.{C_RESET}")
            input("\nPress Enter to continue...")
    else:
        print(f"  {C_YELLOW}Not a git checkout - installed some other way, so there's no{C_RESET}")
        print(f"  {C_YELLOW}update check available here. Re-run the installer to update.{C_RESET}")
        print(f"  [0] Back")
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
        print(f"  {C_YELLOW}[7]>{C_RESET} PANEL INFO / CHECK FOR UPDATES")
        print(f"  {C_YELLOW}[8]>{C_RESET} {C_RED}[!] UNINSTALL PANEL (partial - see note){C_RESET}")
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
