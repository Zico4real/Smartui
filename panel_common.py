"""
panel_common.py — shared plumbing for the SmartUI multi-protocol panel.

Every protocol module (V2Ray/Xray, DNSTT/Slipstream, and whatever comes next)
imports from here instead of reimplementing its own port-checking or firewall
logic. Keeping this in one place is what "wiring everything together" means in
practice: fix a bug here once, and every module that uses it is fixed.
"""

import os
import re
import socket
import subprocess
import random
import sys

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_MAGENTA = "\033[95m"


def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')


def get_public_ip():
    """Shared, single source of truth for the server's own public IP - used
    everywhere a module previously asked the admin to type it in manually."""
    try:
        result = subprocess.run(
            "curl -s ifconfig.me || hostname -I | awk '{print $1}'",
            shell=True, executable="/bin/bash", capture_output=True, text=True, timeout=10,
        )
        ip = result.stdout.strip()
        return ip if ip else "127.0.0.1"
    except Exception:
        return "127.0.0.1"


def get_live_port_from_service(service_path, pattern):
    """Reads a systemd unit file and extracts a port using the given regex
    pattern (must have exactly one capture group for the port number).
    Returns None if the file doesn't exist or the pattern doesn't match.

    Exists because ports_dict can drift out of sync with what's actually
    deployed - confirmed on a real install where ports_dict recorded one
    port while the running service was genuinely configured for a
    different one. Reading the port straight out of the live unit file is
    the real source of truth, immune to that drift regardless of how it
    happens - every module that bakes a port into its own systemd unit
    should reconcile against this on load rather than trust ports_dict
    blindly."""
    if not os.path.exists(service_path):
        return None
    with open(service_path) as f:
        content = f.read()
    m = re.search(pattern, content)
    return m.group(1) if m else None


def print_header(title, width=64):
    """Shared menu-header style, matching the homepage (smartui_main.py) look
    exactly: a cyan double-line divider, a bold centered title, then another
    divider. Every module should call this instead of building its own
    ad-hoc header - before this existed, headers were inconsistent across
    modules (plain '=' vs the '═' box-drawing character, some colored, most
    not), which is what made only the homepage look distinct."""
    print("%s%s%s" % (C_CYAN, "═" * width, C_RESET))
    print("%s%s%s" % (C_BOLD, title.center(width), C_RESET))
    print("%s%s%s" % (C_CYAN, "═" * width, C_RESET))


def print_divider(width=64):
    """A plain divider line in the same style, for use between sections of
    a menu without repeating a title."""
    print("%s%s%s" % (C_CYAN, "─" * width, C_RESET))


def run_cmd(cmd, **kw):
    """subprocess.run wrapper that always captures output, so callers can check
    success instead of blindly continuing after a failed step. Accepts either a
    string (run through the shell) or an argument list (run directly)."""
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, **kw)


# ==================== PORT / BIND CHECKS ====================

def check_system_port_in_use(p, needed_protocols=("tcp",)):
    """Checks the kernel's own socket table directly rather than testing by
    binding. A bind-test is unreliable for UDP specifically: Linux allows
    multiple UDP sockets to bind the same port simultaneously when both set
    SO_REUSEADDR (unlike TCP, where LISTEN is exclusive even with
    SO_REUSEADDR) - confirmed directly with a real test: binding a second
    UDP socket to a port a real listener already held succeeded, when it
    should have failed. That false negative was the actual cause of
    genuinely-running UDP services (DNSTT, Hysteria, WireGuard, ZIVPN,
    BadVPN, ICMP, UDP Droid - anything UDP-based) showing as unconfirmed
    ([ON?]) in Protocol Manager, and could just as easily have let a real
    port conflict go undetected before installing something new onto an
    already-occupied port - "port conflict" being exactly what was
    suspected. Reading /proc/net/{tcp,udp} directly has no such blind spot
    and needs no external tool (ss, netstat) to be installed."""
    target_hex = "%04X" % p
    proc_files = {
        "tcp": ["/proc/net/tcp", "/proc/net/tcp6"],
        "udp": ["/proc/net/udp", "/proc/net/udp6"],
    }
    for proto in needed_protocols:
        for path in proc_files.get(proto, []):
            try:
                with open(path) as f:
                    next(f, None)  # header line
                    for line in f:
                        fields = line.split()
                        if len(fields) < 2:
                            continue
                        local_addr = fields[1]
                        if ":" not in local_addr:
                            continue
                        _, port_hex = local_addr.rsplit(":", 1)
                        if port_hex.upper() == target_hex:
                            return True
            except FileNotFoundError:
                continue
    return False


def find_free_internal_port(start=20000, end=59999, tries=50):
    """Pick a free loopback-only port for a service that's only ever reached via
    another front (fallback routing, Nginx proxy_pass), never directly from outside."""
    for _ in range(tries):
        p = random.randint(start, end)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", p))
            return p
        except OSError:
            continue
    return None


def prompt_port(prompt_text, default=443):
    """Prompt for a port, re-asking until a valid 1-65535 integer is given."""
    while True:
        raw = input(prompt_text).strip()
        if not raw:
            return default
        try:
            p = int(raw)
        except ValueError:
            print(f"{C_RED}Please enter a numeric port.{C_RESET}")
            continue
        if 1 <= p <= 65535:
            return p
        print(f"{C_RED}Port must be between 1 and 65535.{C_RESET}")


# ==================== FIREWALL / PORT BINDING ====================

def detect_firewall():
    """Return 'ufw', 'firewalld', 'iptables', 'nftables', or None based on what's
    active/available. Checked in this order because a host can have more than one
    tool installed but only one actually managing the active ruleset."""
    try:
        res = subprocess.run(["which", "ufw"], capture_output=True, text=True)
        if res.returncode == 0:
            status = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if "active" in status.stdout.lower():
                return "ufw"
    except Exception:
        pass
    try:
        res = subprocess.run(["which", "firewall-cmd"], capture_output=True, text=True)
        if res.returncode == 0:
            status = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True)
            if "running" in status.stdout.lower():
                return "firewalld"
    except Exception:
        pass
    try:
        res = subprocess.run(["which", "iptables"], capture_output=True, text=True)
        if res.returncode == 0:
            # The binary is present on nearly every Linux system regardless of
            # whether it's actually blocking anything - ufw itself is a
            # frontend for iptables underneath. Checking only "does the
            # binary exist" meant that successfully disabling ufw still left
            # this reporting "active (iptables)" right afterward, since the
            # binary is still there - making it look like disabling never
            # worked. Checking for an actual rule or a non-default DROP/REJECT
            # policy is what actually tells us it's doing something.
            rules = subprocess.run(["iptables", "-L", "-n"], capture_output=True, text=True)
            has_rules = False
            for line in rules.stdout.split("\n"):
                line = line.strip()
                if not line or line.startswith("Chain") or line.startswith("target"):
                    continue
                has_rules = True
                break
            if has_rules or "policy DROP" in rules.stdout or "policy REJECT" in rules.stdout:
                return "iptables"
    except Exception:
        pass
    try:
        res = subprocess.run(["which", "nft"], capture_output=True, text=True)
        if res.returncode == 0:
            # Only usable if a table we can actually add rules to already exists —
            # matches the same check the MasterDnsVPN installer uses before relying
            # on nftables, since an nft binary with no base ruleset isn't "managing"
            # anything yet.
            check = subprocess.run(["nft", "list", "table", "inet", "filter"], capture_output=True, text=True)
            if check.returncode == 0:
                return "nftables"
    except Exception:
        pass
    return None


def open_firewall_port(port, protocols=("tcp",)):
    """Open a port in whichever firewall is active. Silently no-ops if none is managed."""
    fw = detect_firewall()
    if not fw:
        return
    for proto in protocols:
        try:
            if fw == "ufw":
                subprocess.run(["ufw", "allow", f"{port}/{proto}"], capture_output=True, text=True)
            elif fw == "firewalld":
                subprocess.run(["firewall-cmd", "--permanent", f"--add-port={port}/{proto}"], capture_output=True, text=True)
                subprocess.run(["firewall-cmd", "--reload"], capture_output=True, text=True)
            elif fw == "iptables":
                check = subprocess.run(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                                        capture_output=True, text=True)
                if check.returncode != 0:
                    subprocess.run(["iptables", "-I", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                                    capture_output=True, text=True)
            elif fw == "nftables":
                subprocess.run(f"nft add rule inet filter input {proto} dport {port} accept",
                                shell=True, capture_output=True, text=True)
        except Exception:
            pass


def close_firewall_port(port, protocols=("tcp",)):
    """Close/unbind a port in whichever firewall is active, e.g. after the last user
    or the last service on it is removed."""
    fw = detect_firewall()
    if not fw:
        return
    for proto in protocols:
        try:
            if fw == "ufw":
                subprocess.run(["ufw", "delete", "allow", f"{port}/{proto}"], capture_output=True, text=True)
            elif fw == "firewalld":
                subprocess.run(["firewall-cmd", "--permanent", f"--remove-port={port}/{proto}"], capture_output=True, text=True)
                subprocess.run(["firewall-cmd", "--reload"], capture_output=True, text=True)
            elif fw == "iptables":
                subprocess.run(["iptables", "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                                capture_output=True, text=True)
            elif fw == "nftables":
                # nft has no direct "delete by match" — would need a handle lookup first.
                # Left as a manual step; noted wherever this is called for a teardown.
                pass
        except Exception:
            pass


def open_firewall_icmp():
    """ICMP has no port concept at all (confirmed - not an oversight: even the Hans
    tunnel's own upstream maintainers note "ICMP does not technically have port
    numbers"), so open_firewall_port/-dport is meaningless here. The one thing that
    reliably works regardless of ufw/firewalld being layered on top is a direct
    netfilter INPUT rule - both of those ultimately program the same underlying
    iptables machinery, so this rule takes effect either way. What it can't safely
    do is guarantee ufw's/firewalld's OWN default ICMP handling isn't separately
    restricting it (that lives in ufw's before.rules or firewalld's icmp-block
    config, both host-specific enough that scripting an edit risks breaking
    something the admin set deliberately) - so this warns rather than guesses
    there."""
    check = subprocess.run(["iptables", "-C", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "ACCEPT"],
                            capture_output=True, text=True)
    if check.returncode != 0:
        subprocess.run(["iptables", "-I", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "ACCEPT"],
                        capture_output=True, text=True)

    fw = detect_firewall()
    if fw in ("ufw", "firewalld"):
        print(f"{C_YELLOW}[i] {fw} is active - it usually allows ICMP echo by default, but if the")
        print(f"    tunnel doesn't connect, check {'`/etc/ufw/before.rules`' if fw == 'ufw' else 'firewalld icmp-block settings'}")
        print(f"    for an explicit ICMP block.{C_RESET}")


def close_firewall_icmp():
    subprocess.run(["iptables", "-D", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", "ACCEPT"],
                    capture_output=True, text=True)


def resolve_port53_conflict():
    """Port 53 is the single most common install blocker on stock Ubuntu/Debian —
    systemd-resolved's stub listener squats on it by default. Modeled directly on
    MasterDnsVPN's own installer (the most battle-tested version of this logic
    available), so dnstt/Slipstream/MasterDNS all get the same real fix instead of
    three separate guesses. Safe to call even when nothing is actually conflicting."""
    if not check_system_port_in_use(53, ("udp", "tcp")):
        return True

    resolved_active = subprocess.run(["systemctl", "is-active", "--quiet", "systemd-resolved"]).returncode == 0
    if resolved_active:
        resolved_conf = "/etc/systemd/resolved.conf"
        backup = resolved_conf + ".bak"
        try:
            if os.path.exists(resolved_conf) and not os.path.exists(backup):
                subprocess.run(["cp", "-a", resolved_conf, backup])
            content = ""
            if os.path.exists(resolved_conf):
                with open(resolved_conf) as f:
                    content = f.read()
            if "DNSStubListener=" in content:
                content = re.sub(r'^#?\s*DNSStubListener=.*$', 'DNSStubListener=no', content, flags=re.MULTILINE)
            else:
                content += "\nDNSStubListener=no\n"
            if "DNS=" not in content:
                content += "DNS=8.8.8.8\n"
            with open(resolved_conf, "w") as f:
                f.write(content)
            subprocess.run(["systemctl", "restart", "systemd-resolved"], capture_output=True, text=True)
        except Exception:
            pass

    # Other common resolvers/DNS proxies that can also be squatting on 53.
    for svc in ("bind9", "named", "dnsmasq", "unbound", "pdns", "knot-resolver",
                "kresd@1", "dnscrypt-proxy", "smartdns", "coredns", "pihole-FTL"):
        try:
            subprocess.run(["systemctl", "stop", svc], capture_output=True, text=True)
            subprocess.run(["systemctl", "disable", svc], capture_output=True, text=True)
        except Exception:
            pass

    return not check_system_port_in_use(53, ("udp", "tcp"))


def nat_redirect_udp(src_port, dst_port):
    """Idempotently add a PREROUTING NAT redirect (used by dnstt's documented
    53->5300 pattern). Checks with -C before inserting so re-running this doesn't
    stack duplicate rules on every reinstall."""
    try:
        check = subprocess.run(
            ["iptables", "-t", "nat", "-C", "PREROUTING", "-p", "udp", "--dport", str(src_port),
             "-j", "REDIRECT", "--to-port", str(dst_port)],
            capture_output=True, text=True
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "udp", "--dport", str(src_port),
                 "-j", "REDIRECT", "--to-port", str(dst_port)],
                capture_output=True, text=True
            )
        return True
    except Exception:
        return False


def remove_nat_redirect_udp(src_port, dst_port):
    try:
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", str(src_port),
             "-j", "REDIRECT", "--to-port", str(dst_port)],
            capture_output=True, text=True
        )
    except Exception:
        pass


def _all_active_ports(ports_dict, extra_ports=None):
    """Every port currently in use across the panel, gathered two ways for
    safety margin: (1) every ports_dict key ending in _PORT/_PORTS, parsed as
    one-or-more comma-separated integers - covers every module that follows
    the established naming convention without needing per-module knowledge
    here; (2) every port the OS actually shows as listening right now, since
    ports_dict can be incomplete (Xray manages its own config.json, not
    ports_dict) or stale. Better to over-collect than under-collect when the
    cost of missing one is a total lockout, not just a broken tunnel."""
    found = set()

    for key, value in ports_dict.items():
        if not (key.endswith("_PORT") or key.endswith("_PORTS")):
            continue
        if not value:
            continue
        for piece in str(value).split(","):
            piece = piece.strip()
            if piece.isdigit():
                found.add(int(piece))

    if extra_ports:
        for p in extra_ports:
            if str(p).isdigit():
                found.add(int(p))

    try:
        ss_res = subprocess.run(["ss", "-tulnH"], capture_output=True, text=True)
        for line in ss_res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                addr_port = parts[4]
                if ":" in addr_port:
                    port_str = addr_port.rsplit(":", 1)[-1]
                    if port_str.isdigit():
                        found.add(int(port_str))
    except Exception:
        pass

    return found


def _live_ssh_port():
    """Cross-checks ports_dict's recorded SSH port against what sshd_config
    actually says right now, preferring the live value - the same
    "verify against reality, not just recorded state" principle applied to
    the original SSH port-change safety net. Falls back to 22 if neither
    source gives a clear answer."""
    try:
        with open("/etc/ssh/sshd_config") as f:
            content = f.read()
        m = re.search(r'^Port\s+(\d+)', content, re.MULTILINE)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return 22


def ensure_firewall_active_safely(ports_dict, extra_ports=None, revert_seconds=90):
    """Guarded flow for turning on a firewall where none is currently active
    (open_firewall_port()/detect_firewall() silently do nothing in that
    state, which means every port - including internal ports meant to stay
    unreachable - is open by default on a fresh VPS with no firewall
    enabled). Never called automatically as a side effect of anything else
    in this panel - doing that silently is exactly how an admin ends up
    locked out of SSH. Must be explicitly invoked.

    Safety design, in order:
      1. If a firewall is already active, this is a no-op - report and stop.
      2. Enumerate every port currently in use across the whole panel (plus
         whatever's actually listening at the OS level) and show the admin
         the full list before doing anything.
      3. Explicit confirmation required before any firewall state changes.
      4. Every one of those ports is explicitly allowed BEFORE ufw is
         enabled - ufw accepts `allow` rules while inactive and applies them
         once turned on, so this ordering is safe.
      5. Enabled non-interactively (`ufw --force enable`), never left
         waiting on ufw's own interactive "this may disrupt existing ssh
         connections" prompt.
      6. A TIMED AUTO-REVERT is scheduled immediately after enabling and
         runs regardless of what happens next - this is the real safety net,
         protecting against any gap in step 2's port enumeration, not just
         the confirmation step. It only gets cancelled if the admin
         positively confirms continued access within the window.
    """
    if detect_firewall():
        print(f"{C_GREEN}[i] A firewall is already active - nothing to do.{C_RESET}")
        return True

    ssh_port = _live_ssh_port()
    ports_dict_ssh = ports_dict.get('SSH_PORT')
    if ports_dict_ssh and str(ports_dict_ssh).isdigit() and int(ports_dict_ssh) != ssh_port:
        print(f"{C_YELLOW}[!] sshd_config reports SSH on port {ssh_port}, but the panel has")
        print(f"    {ports_dict_ssh} recorded - using the live value ({ssh_port}), since that's")
        print(f"    what's actually enforced.{C_RESET}")

    all_ports = _all_active_ports(ports_dict, extra_ports)
    all_ports.add(ssh_port)
    all_ports.add(22)  # always allowed regardless of what's configured - the fallback of last resort

    print("================================================================")
    print("            ENABLE FIREWALL — GUARDED ACTIVATION             ")
    print("================================================================")
    print(f"{C_YELLOW} No firewall is currently active, which means every port on this")
    print(f" server is reachable by default - including internal ports meant to")
    print(f" stay hidden behind things like the DNSTT multi-engine router.{C_RESET}")
    print()
    print(f" Before enabling ufw, these {len(all_ports)} ports will be explicitly allowed")
    print(f" (gathered from every configured module, plus everything currently")
    print(f" listening at the OS level, plus SSH as a hard-coded fallback):")
    print(f"   {', '.join(str(p) for p in sorted(all_ports))}")
    print()
    print(f" SSH specifically: port {ssh_port} (confirmed from sshd_config directly)")
    print("================================================================")

    confirm = input(" Type YES to proceed with enabling the firewall: ").strip()
    if confirm != "YES":
        print(f"{C_YELLOW}[i] Cancelled - firewall left inactive, nothing changed.{C_RESET}")
        return False

    _run_apt_ufw_install()

    for port in all_ports:
        subprocess.run(["ufw", "allow", f"{port}/tcp"], capture_output=True, text=True)
        subprocess.run(["ufw", "allow", f"{port}/udp"], capture_output=True, text=True)

    verify = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    missing = [p for p in all_ports if str(p) not in verify.stdout]
    if missing:
        print(f"{C_RED}[X] These ports didn't confirm as allowed before enabling - aborting")
        print(f"    rather than risk enabling with a gap: {missing}{C_RESET}")
        return False

    enable_res = subprocess.run(["ufw", "--force", "enable"], capture_output=True, text=True)
    if enable_res.returncode != 0:
        print(f"{C_RED}[X] ufw enable failed - nothing was left half-enabled:\n{enable_res.stderr.strip()}{C_RESET}")
        return False

    # The real safety net: scheduled regardless of what happens in the
    # confirmation step below, and only cancelled by a positive response.
    revert_proc = subprocess.Popen(
        ["setsid", "bash", "-c", f"sleep {revert_seconds} && ufw disable"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )

    print(f"\n{C_GREEN}[OK] Firewall enabled.{C_RESET}")
    print(f"{C_YELLOW}[!] AUTO-REVERT ARMED: unless you confirm within {revert_seconds} seconds, the")
    print(f"    firewall will automatically disable itself. Open a NEW connection now")
    print(f"    (don't rely only on this current session) and confirm it still works.{C_RESET}")

    import select
    print(f"\n Type YES within {revert_seconds} seconds to keep the firewall enabled: ", end="", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], revert_seconds)
    if ready:
        response = sys.stdin.readline().strip()
    else:
        response = ""

    if response == "YES":
        revert_proc.terminate()
        try:
            revert_proc.wait(timeout=2)
        except Exception:
            pass
        subprocess.run(["pkill", "-f", f"sleep {revert_seconds} && ufw disable"], capture_output=True, text=True)
        persist_firewall_rules()
        print(f"\n{C_GREEN}[OK] Confirmed - firewall stays enabled, auto-revert cancelled.{C_RESET}")
        return True
    else:
        print(f"\n{C_YELLOW}[!] No confirmation received - the firewall will auto-revert to")
        print(f"    disabled within {revert_seconds} seconds of being enabled (may have already).{C_RESET}")
        return False


def _run_apt_ufw_install():
    subprocess.run(["apt-get", "update"], capture_output=True, text=True)
    subprocess.run(["apt-get", "install", "-y", "ufw"], capture_output=True, text=True)


KNOWN_SERVICE_KEYS = {
    'SSH_PORT': ('sshd', 'tcp'),
    'DROPBEAR_PORTS': ('dropbear', 'tcp'),
    'STUNNEL_PORTS': ('stunnel', 'tcp'),
    'SS_PORT': ('shadowsocks', 'tcp'),
    'HYSTERIA_PORT': ('hysteria2', 'udp'),
    'HYSTERIA1_PORT': ('hysteria-v1', 'udp'),
    'ZIVPN_PORT': ('zivpn', 'udp'),
    'WS_PORT': ('ws-epro', 'tcp'),
    'BADVPN_PORT': ('badvpn-udpgw', 'udp'),
    'SQUID_PORT': ('squid', 'tcp'),
    'OPENVPN_PORT': ('openvpn', 'udp'),
}


def list_known_targets(ports_dict):
    """Build the redirect-target picker list from what THIS panel manages
    (ports_dict) plus a live scan of anything else listening on the box we
    don't manage (e.g. a separately-installed x-ui, systemd-resolved) - a
    useful list needs services outside this panel's own bookkeeping too, so
    ports_dict alone wouldn't be enough. Shared here (rather than duplicated
    per-module) so every protocol's redirect flow shows the same list
    instead of drifting apart."""
    targets = []
    seen_ports = set()
    for key, (label, proto) in KNOWN_SERVICE_KEYS.items():
        val = ports_dict.get(key)
        if val:
            for p in str(val).split(','):
                if p.isdigit() and p not in seen_ports:
                    targets.append((label, int(p)))
                    seen_ports.add(p)

    ss = subprocess.run("ss -tlnp 2>/dev/null", shell=True, capture_output=True, text=True)
    if ss.returncode == 0:
        for line in ss.stdout.splitlines():
            m = re.search(r':(\d+)\s+.*users:\(\("([^"]+)"', line)
            if m:
                port, proc = m.group(1), m.group(2)
                if port not in seen_ports:
                    targets.append((proc, int(port)))
                    seen_ports.add(port)
    return targets


def pick_redirect_target(ports_dict, prompt_title="TO WHICH PORT WILL TRAFFIC BE REDIRECTED?"):
    """Shows a numbered list of known/live ports to pick from, with a manual-
    entry fallback - the redirect-by-list UX every protocol's redirect flow
    should share, rather than a bare 'type a port number' prompt."""
    targets = list_known_targets(ports_dict)
    clear_screen()
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("%s         %s          %s" % (C_BOLD, prompt_title, C_RESET))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    if not targets:
        print(" (nothing detected yet - enter a port manually)")
    for i, (label, port) in enumerate(targets, 1):
        print(" [%2d] > %-20s %s" % (i, label, port))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print(" [0] CANCEL               [%d] ENTER MANUALLY" % (len(targets) + 1))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

    choice = input(" Enter an option: ").strip()
    if choice == '0' or not choice:
        return None
    if choice.isdigit() and int(choice) == len(targets) + 1:
        return prompt_port(" Enter target port manually: ", default=22)
    if choice.isdigit() and 1 <= int(choice) <= len(targets):
        return targets[int(choice) - 1][1]
    print("%s[X] Invalid selection.%s" % (C_RED, C_RESET))
    return None


def persist_firewall_rules():
    """Best-effort: save iptables rules across reboots when netfilter-persistent is
    available. No-ops quietly for ufw/firewalld, which persist their own rules already."""
    try:
        if detect_firewall() == "iptables":
            res = subprocess.run(["which", "netfilter-persistent"], capture_output=True, text=True)
            if res.returncode == 0:
                # Explicitly enable rather than assume the package's postinst trigger
                # already did — cheap, idempotent, and closes the gap if it didn't.
                subprocess.run(["systemctl", "enable", "netfilter-persistent"], capture_output=True, text=True)
                subprocess.run(["netfilter-persistent", "save"], capture_output=True, text=True)
            else:
                # No netfilter-persistent means nothing will actually RESTORE these
                # on boot — this is a manual-recovery snapshot, not true persistence.
                # In practice this branch rarely triggers here: both DNS-tunnel
                # install paths (_install_dnstt/_install_vaydns) already apt-get
                # install iptables-persistent before ever calling this. It's the
                # honest fallback for any other caller that hasn't.
                os.makedirs("/etc/iptables", exist_ok=True)
                subprocess.run("iptables-save > /etc/iptables/rules.v4", shell=True)
                subprocess.run("ip6tables-save > /etc/iptables/rules.v6", shell=True)
    except Exception:
        pass


def is_valid_hostname(name):
    """Very loose but real validation — enough to keep obviously-broken or shell-hostile
    input out of commands built with string interpolation, without being a full RFC parser."""
    if not name or len(name) > 253:
        return False
    return bool(re.match(r'^[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$', name))
