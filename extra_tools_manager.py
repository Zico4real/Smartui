"""
extra_tools_manager.py - Extra Tools module for the SmartUI panel.

Two sub-features were dropped rather than rebuilt, because they duplicate
(and are less safe than) modules already fixed elsewhere in this panel:

  - "SSH/Dropbear Banner Administrator" duplicates ssh_dropbear_manager.py's
    banner options, and is mislabeled there too - it only ever touched
    sshd_config, never actually reaching Dropbear's own config despite the
    name promising both.
  - "Set Up Password and Root Access" is the exact unsafe version (blind sed
    chains, no `sshd -t` test, no restart verification, no rollback) that was
    already found and fixed in ssh_dropbear_manager.py. Rebuilding the unsafe
    version here would leave two paths to the same setting - one with a real
    safety net against SSH lockout, one without - a real regression risk on
    its own. Both menu options here now just point at the already-fixed
    originals instead.

One sub-feature needed more than a bug fix. "Plugins Script" was a
completely unrestricted download-and-execute-as-root primitive:
    curl {any URL typed in} -o script.sh && chmod +x && ./script.sh
with no preview, no verification, no allowlist - it works exactly as
written, which is the problem: it's a generic root-RCE gadget triggered by
whatever URL gets typed into it. Rebuilt with a fetch-and-preview step, a
best-effort red-flag scan, and an explicit typed confirmation before
anything executes - turning "curl | bash on command" into "look before you
leap", not removing the capability outright, since an admin with local panel
access legitimately might want to run their own setup scripts.

Other real bugs fixed, matching classes already fixed elsewhere in this
panel:

1. Several iptables-based tools (torrent/port blocking, DDoS protection)
   always used -A (append) with no -C (check) first, so running the same
   menu option twice duplicated every rule. Fixed to check-before-insert.

2. Nothing verified its own result - BBR, timezone, SSL cert, and Fail2ban
   all printed "[OK]" unconditionally regardless of whether the underlying
   command actually succeeded. Fixed to check real state afterward.

3. BBR was appended to /etc/sysctl.conf directly and non-idempotently.
   Moved to a dedicated sysctl.d drop-in file, the same pattern already used
   for OpenVPN/WireGuard IP forwarding.

4. Fail2ban's jail.local was overwritten unconditionally on every run,
   silently discarding any customization made since. Now backs it up first.

5. Being honest about a real limitation rather than letting it look like a
   working feature: the torrent-blocking technique (iptables string match on
   packet payloads) has been largely ineffective against real-world torrent
   traffic since encrypted peer protocol became the default in virtually
   every popular BitTorrent client around 2006, specifically to evade this
   exact kind of DPI string matching.

6. The DDoS SYN-rate limit was hardcoded at 5/sec - reasonable for a small
   server, but potentially self-inflicted DoS against an actively-used
   reseller panel's own paying customers reconnecting during a busy period.
   Made configurable with a clear warning.
"""

import os
import re
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, run_cmd as _run, ensure_firewall_active_safely, detect_firewall,
)

BBR_SYSCTL_PATH = "/etc/sysctl.d/99-bbr.conf"
PLUGIN_LOG_PATH = "/var/log/panel-plugin-executions.log"

RISKY_PATTERNS = [
    (r'rm\s+-rf\s+/(?!\S)', "removes the filesystem root"),
    (r'rm\s+-rf\s+/\*', "wildcard-deletes from root"),
    (r'curl.{0,80}\|\s*(sudo\s+)?(bash|sh)\b', "pipes a second remote download straight into a shell"),
    (r'wget.{0,80}\|\s*(sudo\s+)?(bash|sh)\b', "pipes a second remote download straight into a shell"),
    (r'base64\s+-d.{0,40}\|\s*(bash|sh)\b', "decodes and executes an obfuscated blob"),
    (r'/dev/tcp/', "opens a raw reverse-shell-style socket"),
    (r'\bnc\s+-e\b', "spawns a shell over netcat (classic reverse shell pattern)"),
    (r'authorized_keys', "touches SSH authorized_keys - could add a backdoor key"),
    (r'passwd\s+-d\b', "removes a password (could disable auth on an account)"),
]


def extra_tools_manager(ports_dict):
    """Extra Tools Module - system utilities, hardening, and optimizations."""
    while True:
        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                        EXTRA TOOLS                         %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" %s[1]>%s SSL CERTIFICATE MANAGER" % (C_YELLOW, C_RESET))
        print(" %s[2]>%s SSH/DROPBEAR BANNER (use SSH Administrator instead)" % (C_YELLOW, C_RESET))
        print(" %s[3]>%s ROOT PASSWORD/ACCESS (use SSH Administrator instead)" % (C_YELLOW, C_RESET))
        print("----------------------------------------------------------------")
        print(" %s[4]>%s KERNEL ACCELERATION (BBR)" % (C_YELLOW, C_RESET))
        print("----------------------------------------------------------------")
        print(" %s[5]>%s BLOCKING TORRENT, PORTS AND KEYWORDS" % (C_YELLOW, C_RESET))
        print(" %s[6]>%s FAIL2BAN ADMINISTRATOR" % (C_YELLOW, C_RESET))
        print(" %s[7]>%s DDOS PROTECTION" % (C_YELLOW, C_RESET))
        print("----------------------------------------------------------------")
        print(" %s[8]>%s MODIFY TIME ZONE" % (C_YELLOW, C_RESET))
        print("----------------------------------------------------------------")
        print(" %s[9]>%s SPEEDTEST OOKLA" % (C_YELLOW, C_RESET))
        print(" %s[10]>%s PLUGINS SCRIPT" % (C_YELLOW, C_RESET))
        print("----------------------------------------------------------------")
        fw_backend = detect_firewall()
        if fw_backend:
            print(" [11]> DISABLE FIREWALL — currently: %sactive (%s)%s" % (C_GREEN, fw_backend, C_RESET))
        else:
            print(" [11]> ENABLE FIREWALL (guarded) — currently: %sINACTIVE%s" % (C_RED, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" %s[0]%s Back" % (C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 SSL CERTIFICATE MANAGER                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            domain = input(" Enter your domain name (e.g., panel.yourdomain.com): ").strip()
            email = input(" Enter your email address: ").strip()
            if not (domain and email):
                print("%s[X] Domain and email cannot be empty.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            print("\n[i] Generating Let's Encrypt SSL certificate for %s..." % domain)
            _run("apt-get update && apt-get install -y certbot")

            was_active = {}
            for svc in ("nginx", "apache2"):
                chk = _run(["systemctl", "is-active", svc])
                was_active[svc] = chk.returncode == 0
            _run("systemctl stop nginx apache2 2>/dev/null")

            result = _run(["certbot", "certonly", "--standalone", "--agree-tos",
                           "-m", email, "-d", domain, "--force-renewal", "-n"])

            for svc, active in was_active.items():
                if active:
                    _run(["systemctl", "start", svc])

            if result.returncode == 0:
                print("%s[OK] SSL certificate generated for %s.%s" % (C_GREEN, domain, C_RESET))
                print("     /etc/letsencrypt/live/%s/fullchain.pem" % domain)
                print("%s[i] certbot's own systemd timer handles renewal automatically going" % C_CYAN)
                print("    forward - no extra setup needed for that part.%s" % C_RESET)
            else:
                print("%s[X] Certificate generation failed - check that port 80 is actually free" % C_RED)
                print("    and DNS for %s points at this server:\n%s%s" % (domain, result.stderr.strip(), C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            print("%s[i] Use SSH Administrator's banner options instead - they correctly" % C_CYAN)
            print("    cover both SSH and Dropbear (this menu's old version only ever")
            print("    touched sshd_config, despite its own label).%s" % C_RESET)
            input("\nPress Enter to continue...")

        elif choice == '3':
            print("%s[i] Use SSH Administrator's 'SET UP PASSWORD AND ROOT ACCESS' option" % C_CYAN)
            print("    instead - it tests the config before applying it and automatically")
            print("    rolls back if the change would break SSH access. This menu's old")
            print("    version had none of that and could lock you out of the server.%s" % C_RESET)
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 KERNEL ACCELERATION (BBR)                  %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("[i] Applying TCP BBR congestion control...")
            with open(BBR_SYSCTL_PATH, "w") as f:
                f.write("net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n")
            _run(["sysctl", "-p", BBR_SYSCTL_PATH])

            check = _run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"])
            active_cc = check.stdout.strip()
            if active_cc == "bbr":
                print("%s[OK] BBR is active (confirmed: net.ipv4.tcp_congestion_control=bbr).%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] BBR did not actually activate (currently: '%s') - this kernel may" % (C_RED, active_cc))
                print("    not support it, common on some OpenVZ/container-based VPS plans.%s" % C_RESET)
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s           BLOCKING TORRENT, PORTS AND KEYWORDS             %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s[i] Honest caveat: this matches plaintext byte patterns in packets." % C_YELLOW)
            print("    Virtually every popular BitTorrent client has defaulted to encrypted")
            print("    peer protocol since ~2006 specifically to evade this exact technique -")
            print("    it will catch legacy/plaintext traffic, not modern encrypted torrents.%s\n" % C_RESET)

            string_patterns = ["BitTorrent", "BitTorrent protocol", "peer_id=", ".torrent", "announce.php?passkey="]
            for pattern in string_patterns:
                check = _run(["iptables", "-C", "FORWARD", "-m", "string", "--string", pattern, "--algo", "bm", "-j", "DROP"])
                if check.returncode != 0:
                    _run(["iptables", "-A", "FORWARD", "-m", "string", "--string", pattern, "--algo", "bm", "-j", "DROP"])

            for proto in ("tcp", "udp"):
                check = _run(["iptables", "-C", "FORWARD", "-p", proto, "--dport", "6881:6889", "-j", "DROP"])
                if check.returncode != 0:
                    _run(["iptables", "-A", "FORWARD", "-p", proto, "--dport", "6881:6889", "-j", "DROP"])

            print("%s[OK] Filtering rules applied (idempotent - safe to re-run).%s" % (C_GREEN, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                 FAIL2BAN ADMINISTRATOR                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("[i] Installing and configuring Fail2ban...")
            _run("apt-get update && apt-get install -y fail2ban")

            jail_path = "/etc/fail2ban/jail.local"
            if os.path.exists(jail_path):
                _run(["cp", jail_path, jail_path + ".bak"])
                print("%s[i] Existing jail.local backed up to jail.local.bak before overwriting.%s" % (C_CYAN, C_RESET))

            jail_local = """[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
"""
            with open(jail_path, "w") as f:
                f.write(jail_local)

            _run(["systemctl", "enable", "fail2ban"])
            restart = _run(["systemctl", "restart", "fail2ban"])
            time.sleep(1)
            active = _run(["systemctl", "is-active", "--quiet", "fail2ban"]).returncode == 0
            if restart.returncode == 0 and active:
                print("%s[OK] Fail2ban installed and running.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Fail2ban failed to start - check 'journalctl -u fail2ban'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    DDOS PROTECTION                         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s[!] The SYN rate limit below applies to your WHOLE server, including" % C_YELLOW)
            print("    legitimate customers reconnecting. Too low a value on an actively-")
            print("    used reseller panel can lock out your own paying users during busy")
            print("    periods - size it for your actual expected connection volume.%s\n" % C_RESET)

            rate_raw = input(" New connections allowed per second [default 5]: ").strip()
            rate = rate_raw if rate_raw.isdigit() else "5"
            burst_raw = input(" Burst allowance [default 10]: ").strip()
            burst = burst_raw if burst_raw.isdigit() else "10"

            print("\n[i] Applying SYN-flood and port-scan mitigation rules...")
            rules = [
                ["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-m", "limit",
                 "--limit", "%s/s" % rate, "--limit-burst", burst, "-j", "ACCEPT"],
                ["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-j", "DROP"],
                ["iptables", "-A", "INPUT", "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"],
                ["iptables", "-A", "INPUT", "-p", "tcp", "--tcp-flags", "SYN,FIN", "SYN,FIN", "-j", "DROP"],
            ]
            for rule in rules:
                check_rule = rule.copy()
                check_rule[1] = "-C"
                check = _run(check_rule)
                if check.returncode != 0:
                    _run(rule)

            print("%s[OK] Anti-DDoS rules applied (idempotent - safe to re-run).%s" % (C_GREEN, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    MODIFY TIME ZONE                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            current = _run(["timedatectl", "show", "--property=Timezone", "--value"]).stdout.strip()
            print(" Current Timezone: %s" % current)
            tz = input("\nEnter desired timezone (e.g., UTC, America/New_York, Europe/London): ").strip()
            if not tz:
                print("%s[X] Timezone cannot be empty.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            _run(["timedatectl", "set-timezone", tz])
            new_tz = _run(["timedatectl", "show", "--property=Timezone", "--value"]).stdout.strip()
            if new_tz == tz:
                print("%s[OK] Timezone updated to %s.%s" % (C_GREEN, tz, C_RESET))
            else:
                print("%s[X] '%s' doesn't look like a valid timezone (still set to %s) - check" % (C_RED, tz, new_tz))
                print("    'timedatectl list-timezones' for valid values.%s" % C_RESET)
            input("\nPress Enter to continue...")

        elif choice == '9':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     SPEEDTEST OOKLA                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if _run("which speedtest").returncode != 0:
                print("[i] Installing Ookla Speedtest CLI...")
                _run("curl -s https://install.speedtest.net/app/cli/install.deb.sh | bash")
                _run("apt-get install -y speedtest")

            print("\n[i] Running bandwidth speed test...\n")
            os.system("speedtest --accept-license --accept-gdpr")
            input("\nPress Enter to continue...")

        elif choice == '10':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     PLUGINS SCRIPT                         %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s[!] This downloads and runs a script AS ROOT. Only use sources you" % C_YELLOW)
            print("    actually trust - this is real, unrestricted code execution.%s\n" % C_RESET)

            plugin_url = input(" Enter plugin script URL (https:// only): ").strip()
            if not plugin_url.startswith("https://"):
                print("%s[X] Only https:// URLs are accepted - http:// can be tampered with" % C_RED)
                print("    in transit by anyone between you and the server.%s" % C_RESET)
                input("\nPress Enter to continue...")
                continue

            fetch = _run(["curl", "-sL", plugin_url])
            if fetch.returncode != 0 or not fetch.stdout.strip():
                print("%s[X] Couldn't fetch anything from that URL.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            script_content = fetch.stdout
            print("\n--- First 30 lines of the script ---")
            for line in script_content.splitlines()[:30]:
                print(" %s" % line)
            print("--- end preview (%d lines total) ---\n" % len(script_content.splitlines()))

            flags = []
            for pattern, why in RISKY_PATTERNS:
                if re.search(pattern, script_content):
                    flags.append(why)
            if flags:
                print("%s[!] This script contains patterns worth a closer look before running:%s" % (C_RED, C_RESET))
                for flag_reason in flags:
                    print("    - %s" % flag_reason)
                print()

            confirm = input(" Type RUN to execute this exact script as root, anything else cancels: ").strip()
            if confirm != "RUN":
                print("%s[i] Cancelled - nothing was executed.%s" % (C_YELLOW, C_RESET))
                input("\nPress Enter to continue...")
                continue

            script_path = "/tmp/panel_plugin_%d.sh" % int(time.time())
            with open(script_path, "w") as f:
                f.write(script_content)
            os.chmod(script_path, 0o700)

            with open(PLUGIN_LOG_PATH, "a") as f:
                f.write("%s | %s | flags: %s\n" % (
                    time.strftime("%Y-%m-%d %H:%M:%S"), plugin_url, "; ".join(flags) if flags else "none"))

            print("\n[i] Executing...")
            result = _run(["bash", script_path])
            print(result.stdout)
            if result.returncode == 0:
                print("%s[OK] Plugin script completed.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Plugin script exited with an error (code %d):%s" % (C_RED, result.returncode, C_RESET))
                print(result.stderr)
            input("\nPress Enter to continue...")

        elif choice == '11':
            clear_screen()
            fw_backend = detect_firewall()
            if fw_backend:
                print(" [!] Disabling the firewall makes every port on this server reachable")
                print("     again by default (the same state it was in before you enabled it) -")
                print("     including any internal ports meant to stay hidden behind gates like")
                print("     the DNSTT multi-engine router.")
                confirm = input(" Type YES to disable the firewall: ").strip()
                if confirm == "YES":
                    if fw_backend == "ufw":
                        result = _run(["ufw", "disable"])
                    elif fw_backend == "firewalld":
                        result = _run(["systemctl", "stop", "firewalld"])
                    else:
                        result = _run(["systemctl", "stop", "iptables"])
                    if result.returncode == 0:
                        print("%s[OK] Firewall disabled.%s" % (C_GREEN, C_RESET))
                    else:
                        print("%s[X] Failed to disable - check manually.%s" % (C_RED, C_RESET))
                else:
                    print("%s[i] Cancelled - firewall left active.%s" % (C_YELLOW, C_RESET))
            else:
                ensure_firewall_active_safely(ports_dict)
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
