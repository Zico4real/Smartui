"""
vpn_common.py - shared plumbing for the three "classic VPN" modules
(ikev2_manager.py, l2tp_manager.py, sstp_manager.py).

Kept in one place so a fix lands once for all three:

  * USER ACCESS - these VPNs log customers in with their existing SSH
    accounts (same accounts as SSH/Dropbear/Squid/Psiphon/ICMP/UDP Droid).
    Passwords come from ssh_user_manager's plaintext store
    (/etc/ssh_users/plaintext_passwords.json). Per-protocol access mode
    ("all SSH users" or "selected users only") lives in
    /etc/smartui-vpn/access.json. A small systemd timer re-runs the sync so
    accounts created or deleted later in the panel are picked up without
    anyone opening a VPN menu.
  * NAT / FORWARDING - ip_forward drop-in, MASQUERADE, FORWARD accepts and
    TCP MSS clamping (the classic "connects but pages won't load" fix).
  * PORT MOD SAFETY LAYER - a self-contained copy of the lockout protection
    added to openvpn_manager.py/psiphon_manager.py after the incident where
    a blanket redirect swallowed SSH: live listeners, sshd ports, the admin's
    own session port and every ports_dict number are never redirected, only
    explicit ranges are accepted (never "all ports"), rules are not saved to
    disk until the admin confirms, and an out-of-session systemd timer
    removes them automatically if the admin does not confirm in time.
    Copied here (not imported) so these modules work no matter which version
    of openvpn_manager.py is deployed.
  * IPsec firewall protocols (ESP/AH), /dev/ppp check, apt helper, misc.
"""

import os
import re
import json
import time
import pwd

from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, detect_firewall,
    persist_firewall_rules, run_cmd as _run,
)

VPN_DIR = "/etc/smartui-vpn"
ACCESS_PATH = VPN_DIR + "/access.json"
SSH_PASSWORD_STORE_PATH = "/etc/ssh_users/plaintext_passwords.json"

SYNC_SCRIPT_PATH = "/usr/local/bin/smartui-vpn-sync.py"
SYNC_SERVICE_PATH = "/etc/systemd/system/smartui-vpn-sync.service"
SYNC_TIMER_PATH = "/etc/systemd/system/smartui-vpn-sync.timer"

PROTOCOL_KEYS = ("ikev2", "l2tp", "sstp")

BAR = "%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET)


def header(title):
    clear_screen()
    print(BAR)
    print("%s%s%s" % (C_BOLD, title.center(64), C_RESET))
    print(BAR)


def pause():
    input("\nPress Enter to continue...")


# ---------------------------------------------------------------------------
# Small system helpers
# ---------------------------------------------------------------------------

def service_active(name):
    return _run(["systemctl", "is-active", "--quiet", name]).returncode == 0


def unit_exists(name):
    res = _run(["systemctl", "list-unit-files", name + ".service", "--no-legend"])
    return name in (res.stdout or "")


def restart_unit(name):
    _run(["systemctl", "reset-failed", name])
    return _run(["systemctl", "restart", name]).returncode == 0


def wait_listening(port, protos=("tcp",), tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(int(port), protos):
            return True
        time.sleep(delay)
    return False


def read_file(path, default=None):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return default


def write_file(path, content, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)


def default_interface():
    res = _run("ip route show default")
    m = re.search(r'dev (\S+)', res.stdout or "")
    return m.group(1) if m else "eth0"


def apt_install(packages, required=True):
    """Returns (ok, error_text). Non-interactive; refreshes the index first."""
    env = "DEBIAN_FRONTEND=noninteractive "
    _run("apt-get update -y")
    res = _run(env + "apt-get install -y " + " ".join(packages))
    if res.returncode != 0:
        return False, (res.stderr or res.stdout or "").strip()[-600:]
    return True, None


def apt_install_optional(packages):
    """Each package on its own so one missing/renamed package can't sink the
    rest. Returns the list that failed."""
    failed = []
    for pkg in packages:
        res = _run("DEBIAN_FRONTEND=noninteractive apt-get install -y " + pkg)
        if res.returncode != 0:
            failed.append(pkg)
    return failed


def pkg_installed(pkg):
    return _run(["dpkg", "-s", pkg]).returncode == 0


def ensure_ppp_support():
    """L2TP and SSTP both need the kernel's PPP driver. Containers (OpenVZ,
    some LXC) often lack it. Returns (ok, message)."""
    _run("modprobe ppp_generic")
    _run("modprobe ppp_async")
    if os.path.exists("/dev/ppp"):
        return True, None
    _run("mknod /dev/ppp c 108 0")
    if os.path.exists("/dev/ppp"):
        return True, None
    return False, ("/dev/ppp is missing and could not be created - this VPS does not expose the "
                   "kernel PPP driver (typical of OpenVZ/LXC containers). Ask the provider to enable "
                   "PPP, or use a KVM/full-virtualisation VPS.")


# ---------------------------------------------------------------------------
# Forwarding / NAT
# ---------------------------------------------------------------------------

def _sysctl_dropin(name):
    return "/etc/sysctl.d/99-smartui-%s.conf" % name


def ensure_ip_forwarding(name):
    _run("sysctl -w net.ipv4.ip_forward=1")
    write_file(_sysctl_dropin(name),
               "net.ipv4.ip_forward=1\n"
               "net.ipv4.conf.all.send_redirects=0\n"
               "net.ipv4.conf.default.send_redirects=0\n"
               "net.ipv4.conf.all.accept_redirects=0\n")
    _run("sysctl -p " + _sysctl_dropin(name))


def remove_ip_forwarding_dropin(name):
    """Removes only this protocol's drop-in; ip_forward itself is left on
    because other tunnels (OpenVPN, WireGuard, ICMP...) share it."""
    try:
        os.remove(_sysctl_dropin(name))
    except FileNotFoundError:
        pass


def _nat_rules(subnet, iface, tag):
    comment = ["-m", "comment", "--comment", "smartui-" + tag]
    return [
        ("nat", "POSTROUTING", ["-s", subnet, "-o", iface] + comment + ["-j", "MASQUERADE"]),
        ("filter", "FORWARD", ["-s", subnet] + comment + ["-j", "ACCEPT"]),
        ("filter", "FORWARD", ["-d", subnet, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED"]
         + comment + ["-j", "ACCEPT"]),
        ("mangle", "FORWARD", ["-s", subnet, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN"]
         + comment + ["-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
        ("mangle", "FORWARD", ["-d", subnet, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN"]
         + comment + ["-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
    ]


def ensure_nat(subnet, iface, tag):
    """Idempotent: checks with -C before inserting. FORWARD rules go in at
    the top so a restrictive default policy cannot swallow VPN traffic."""
    for table, chain, spec in _nat_rules(subnet, iface, tag):
        chk = _run(["iptables", "-t", table, "-C", chain] + spec)
        if chk.returncode != 0:
            action = "-A" if chain == "POSTROUTING" else "-I"
            _run(["iptables", "-t", table, action, chain] + spec)


def remove_nat(subnet, iface, tag):
    for table, chain, spec in _nat_rules(subnet, iface, tag):
        for _ in range(5):  # remove duplicates too
            if _run(["iptables", "-t", table, "-D", chain] + spec).returncode != 0:
                break


def nat_present(subnet, iface, tag):
    table, chain, spec = _nat_rules(subnet, iface, tag)[0]
    return _run(["iptables", "-t", table, "-C", chain] + spec).returncode == 0


# ---------------------------------------------------------------------------
# IPsec protocols (ESP / AH) in whichever firewall is active
# ---------------------------------------------------------------------------

def open_ipsec_protocols():
    fw = detect_firewall()
    if not fw:
        return
    try:
        if fw == "ufw":
            for p in ("esp", "ah"):
                _run(["ufw", "allow", "proto", p, "from", "any", "to", "any"])
        elif fw == "firewalld":
            for p in ("esp", "ah"):
                _run(["firewall-cmd", "--permanent", "--add-protocol=" + p])
            _run(["firewall-cmd", "--reload"])
        elif fw == "iptables":
            for p in ("esp", "ah"):
                if _run(["iptables", "-C", "INPUT", "-p", p, "-j", "ACCEPT"]).returncode != 0:
                    _run(["iptables", "-I", "INPUT", "-p", p, "-j", "ACCEPT"])
    except Exception:
        pass


def close_ipsec_protocols():
    fw = detect_firewall()
    if not fw:
        return
    try:
        if fw == "ufw":
            for p in ("esp", "ah"):
                _run(["ufw", "delete", "allow", "proto", p, "from", "any", "to", "any"])
        elif fw == "firewalld":
            for p in ("esp", "ah"):
                _run(["firewall-cmd", "--permanent", "--remove-protocol=" + p])
            _run(["firewall-cmd", "--reload"])
        elif fw == "iptables":
            for p in ("esp", "ah"):
                _run(["iptables", "-D", "INPUT", "-p", p, "-j", "ACCEPT"])
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Users / access control
# ---------------------------------------------------------------------------

def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {} if default is None else default


def load_ssh_passwords():
    data = load_json(SSH_PASSWORD_STORE_PATH)
    return data if isinstance(data, dict) else {}


def _shadow_entries():
    entries = {}
    try:
        with open("/etc/shadow") as f:
            for line in f:
                parts = line.rstrip("\n").split(":")
                if len(parts) >= 8:
                    entries[parts[0]] = parts
    except Exception:
        return None
    return entries


def account_problem(username, shadow=None):
    """None if the account can log in, otherwise a short reason."""
    try:
        pwd.getpwnam(username)
    except KeyError:
        return "no such system user"
    if shadow is None:
        shadow = _shadow_entries()
    if shadow and username in shadow:
        parts = shadow[username]
        if parts[1].startswith("!") or parts[1].startswith("*"):
            return "locked"
        if parts[7].isdigit() and int(parts[7]) < int(time.time() // 86400):
            return "expired"
    return None


def get_access(proto):
    data = load_json(ACCESS_PATH)
    entry = data.get(proto) or {}
    return {
        "enabled": bool(entry.get("enabled", False)),
        "mode": entry.get("mode", "all"),
        "users": list(entry.get("users", [])),
    }


def set_access(proto, enabled=None, mode=None, users=None):
    data = load_json(ACCESS_PATH)
    entry = data.get(proto) or {"enabled": False, "mode": "all", "users": []}
    if enabled is not None:
        entry["enabled"] = bool(enabled)
    if mode is not None:
        entry["mode"] = mode
    if users is not None:
        entry["users"] = sorted(set(users))
    data[proto] = entry
    os.makedirs(VPN_DIR, exist_ok=True)
    write_file(ACCESS_PATH, json.dumps(data, indent=2), 0o600)


def drop_access(proto):
    data = load_json(ACCESS_PATH)
    data.pop(proto, None)
    write_file(ACCESS_PATH, json.dumps(data, indent=2), 0o600)


def allowed_users(proto):
    """[(username, password)] for every account that may use this VPN right
    now: has a stored password, still a usable system account, and passes the
    protocol's access mode."""
    access = get_access(proto)
    passwords = load_ssh_passwords()
    shadow = _shadow_entries()
    result = []
    for user, password in sorted(passwords.items()):
        if not isinstance(password, str) or not password:
            continue
        if access["mode"] == "selected" and user not in access["users"]:
            continue
        if account_problem(user, shadow):
            continue
        result.append((user, password))
    return result


def all_accounts_report(proto):
    """[(username, status_text, is_allowed)] for the user-management screen."""
    access = get_access(proto)
    passwords = load_ssh_passwords()
    shadow = _shadow_entries()
    rows = []
    for user in sorted(passwords):
        problem = account_problem(user, shadow)
        if problem:
            rows.append((user, problem, False))
        elif access["mode"] == "selected" and user not in access["users"]:
            rows.append((user, "no VPN access", False))
        else:
            rows.append((user, "allowed", True))
    return rows


SAFE_BARE = re.compile(r'^[^\s"\'\\#]+$')


def chap_quote(value):
    """pppd chap-secrets quoting."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def sanitize_id(username):
    return re.sub(r'[^A-Za-z0-9_.-]', '_', username)


# --- writers for each backend: each returns True if the file changed ------

def _write_if_changed(path, content, mode=0o600):
    if read_file(path) == content:
        return False
    write_file(path, content, mode)
    return True


L2TP_BEGIN = "# BEGIN SMARTUI-L2TP (managed - do not edit between markers)"
L2TP_END = "# END SMARTUI-L2TP"
PPP_CHAP_SECRETS = "/etc/ppp/chap-secrets"
SSTP_CHAP_SECRETS = "/etc/accel-ppp/smartui-sstp-chap-secrets"
IKEV2_SECRETS_CONF = "/etc/swanctl/conf.d/smartui-ikev2-users.conf"


def sync_l2tp():
    users = allowed_users("l2tp")
    lines = [L2TP_BEGIN]
    for user, password in users:
        lines.append("%s l2tpd %s *" % (chap_quote(user), chap_quote(password)))
    lines.append(L2TP_END)
    block = "\n".join(lines) + "\n"
    existing = read_file(PPP_CHAP_SECRETS, "") or ""
    pattern = re.compile(re.escape(L2TP_BEGIN) + r".*?" + re.escape(L2TP_END) + r"\n?", re.S)
    if get_access("l2tp")["enabled"]:
        new = pattern.sub("", existing)
        if new and not new.endswith("\n"):
            new += "\n"
        new += block
    else:
        new = pattern.sub("", existing)
    changed = new != existing
    if changed:
        write_file(PPP_CHAP_SECRETS, new, 0o600)
    return len(users), changed


def sync_sstp():
    users = allowed_users("sstp")
    lines = ["# managed by SmartUI - regenerated automatically"]
    skipped = 0
    for user, password in users:
        if SAFE_BARE.match(user) and SAFE_BARE.match(password):
            lines.append("%s * %s *" % (user, password))
        else:
            skipped += 1  # accel-ppp's parser can't take whitespace/quotes in a bare field
    changed = _write_if_changed(SSTP_CHAP_SECRETS, "\n".join(lines) + "\n")
    return len(users) - skipped, changed


def sync_ikev2():
    users = allowed_users("ikev2")
    lines = ["# managed by SmartUI - regenerated automatically", "secrets {"]
    count = 0
    for user, password in users:
        if '"' in password or "\\" in password or "\n" in password or "\n" in user:
            continue  # strongSwan quoting - skipped rather than written wrong
        lines.append('  eap-%s {\n    id = %s\n    secret = "%s"\n  }' % (sanitize_id(user), user, password))
        count += 1
    lines.append("}")
    changed = _write_if_changed(IKEV2_SECRETS_CONF, "\n".join(lines) + "\n")
    return count, changed


def sync_all(reload=True):
    """Re-syncs every installed VPN. Called by the systemd timer and by the
    menus. Returns {proto: (count, changed)}."""
    access = load_json(ACCESS_PATH)
    result = {}
    if (access.get("l2tp") or {}).get("enabled"):
        result["l2tp"] = sync_l2tp()
    if (access.get("sstp") or {}).get("enabled"):
        result["sstp"] = sync_sstp()
        if result["sstp"][1] and reload:
            # accel-ppp re-reads chap-secrets only on a config reload
            _run(["accel-cmd", "-p", "2001", "reload"])
    if (access.get("ikev2") or {}).get("enabled"):
        result["ikev2"] = sync_ikev2()
        if result["ikev2"][1] and reload:
            _run(["swanctl", "--load-creds"])
    return result


def sync_now(proto=None):
    """Menu-side convenience: sync and return the count for one protocol."""
    res = sync_all()
    return res.get(proto, (0, False))[0] if proto else res


SYNC_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
# Deployed by vpn_common.py - keeps IKEv2/L2TP/SSTP logins in step with the
# panel's SSH accounts. Thin wrapper: the real logic lives in vpn_common.py.
import sys
sys.path.insert(0, %(panel_dir)r)
try:
    import vpn_common
    res = vpn_common.sync_all()
    for k, (count, changed) in sorted(res.items()):
        print("%%s: %%d account(s)%%s" %% (k, count, " (updated)" if changed else ""))
except Exception as e:
    print("smartui-vpn-sync failed: %%s" %% e)
    sys.exit(1)
'''


def ensure_sync_timer():
    """Installs/updates the helper script and a 2-minute timer."""
    panel_dir = os.path.dirname(os.path.abspath(__file__))
    script = SYNC_SCRIPT_TEMPLATE % {"panel_dir": panel_dir}
    if read_file(SYNC_SCRIPT_PATH) != script:
        write_file(SYNC_SCRIPT_PATH, script, 0o755)
    svc = ("[Unit]\nDescription=SmartUI VPN account sync\n\n[Service]\nType=oneshot\n"
           "ExecStart=/usr/bin/python3 %s\n" % SYNC_SCRIPT_PATH)
    timer = ("[Unit]\nDescription=SmartUI VPN account sync timer\n\n[Timer]\nOnBootSec=60\n"
             "OnUnitActiveSec=120\nUnit=smartui-vpn-sync.service\n\n[Install]\nWantedBy=timers.target\n")
    changed = False
    if read_file(SYNC_SERVICE_PATH) != svc:
        write_file(SYNC_SERVICE_PATH, svc); changed = True
    if read_file(SYNC_TIMER_PATH) != timer:
        write_file(SYNC_TIMER_PATH, timer); changed = True
    if changed:
        _run("systemctl daemon-reload")
    _run("systemctl enable --now smartui-vpn-sync.timer")


def remove_sync_timer_if_unused():
    data = load_json(ACCESS_PATH)
    if any((data.get(k) or {}).get("enabled") for k in PROTOCOL_KEYS):
        return
    _run("systemctl disable --now smartui-vpn-sync.timer")
    for p in (SYNC_TIMER_PATH, SYNC_SERVICE_PATH, SYNC_SCRIPT_PATH):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
    _run("systemctl daemon-reload")


def user_access_menu(proto, title, on_change=None):
    """Shared MANAGE USER ACCESS screen. `on_change` (optional) is called
    after any change that needs the backend reloaded."""
    while True:
        access = get_access(proto)
        rows = all_accounts_report(proto)
        header(title + " - USER ACCESS")
        print(" Logins use the panel's SSH accounts (same username/password as SSH).")
        mode_txt = "ALL SSH accounts" if access["mode"] == "all" else "SELECTED accounts only"
        print(" Access mode : %s%s%s" % (C_YELLOW, mode_txt, C_RESET))
        print(" Allowed now : %d of %d account(s)" % (sum(1 for r in rows if r[2]), len(rows)))
        print("----------------------------------------------------------------")
        if not rows:
            print(" (no SSH accounts with a stored password yet - create some in SSH MANAGER)")
        for user, status, ok in rows[:40]:
            col = C_GREEN if ok else C_RED
            print("   %-24s %s%s%s" % (user, col, status, C_RESET))
        if len(rows) > 40:
            print("   ... and %d more" % (len(rows) - 40))
        print(BAR)
        print(" [1]> SWITCH MODE (all accounts / selected only)")
        print(" [2]> GRANT VPN ACCESS TO AN ACCOUNT   (selected mode)")
        print(" [3]> REVOKE VPN ACCESS FROM AN ACCOUNT (selected mode)")
        print(" [4]> SYNC ACCOUNTS NOW")
        print(BAR)
        print(" [0] RETURN")
        print(BAR)
        choice = input(" Enter an Option: ").strip()
        if choice == '0':
            return
        if choice == '1':
            new_mode = "selected" if access["mode"] == "all" else "all"
            set_access(proto, mode=new_mode)
            sync_all()
            if on_change:
                on_change()
            print(f"{C_GREEN}[OK] Mode is now: {'SELECTED accounts only' if new_mode == 'selected' else 'ALL SSH accounts'}.{C_RESET}")
            pause()
        elif choice in ('2', '3'):
            name = input(" Account name: ").strip()
            if name not in load_ssh_passwords():
                print(f"{C_RED}[X] '{name}' has no stored SSH password - create it in SSH MANAGER first.{C_RESET}")
                pause()
                continue
            users = set(access["users"])
            if choice == '2':
                users.add(name)
            else:
                users.discard(name)
            set_access(proto, users=sorted(users))
            sync_all()
            if on_change:
                on_change()
            if access["mode"] != "selected":
                print(f"{C_YELLOW}[i] Saved, but the mode is 'ALL' - switch to SELECTED mode (option 1) for this list to apply.{C_RESET}")
            else:
                print(f"{C_GREEN}[OK] Updated.{C_RESET}")
            pause()
        elif choice == '4':
            res = sync_all()
            print(f"{C_GREEN}[OK] Synced: {', '.join('%s=%d' % (k, v[0]) for k, v in res.items()) or 'nothing installed'}{C_RESET}")
            pause()
        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            pause()


# ---------------------------------------------------------------------------
# PORT MOD SAFETY LAYER (self-contained copy - see module docstring)
# ---------------------------------------------------------------------------

PORTMOD_REVERT_SCRIPT = "/usr/local/bin/portmod-revert.sh"
PORTMOD_REVERT_SECONDS = 120
PORTMOD_REVERT_SCRIPT_CONTENT = """#!/bin/sh
# Removes every nat/PREROUTING rule carrying the given PORT MOD comment tag.
TAG="$1"
[ -n "$TAG" ] || exit 1
for T in iptables ip6tables; do
  command -v ${T}-save >/dev/null 2>&1 || continue
  ${T}-save -t nat | grep -v -E -- "--comment \\"?${TAG}\\"?( |$)" | ${T}-restore -T nat
done
exit 0
"""


def tag_in_line(tag, line):
    return re.search(r'(?<![\w-])' + re.escape(tag) + r'(?![\w-])', line) is not None


def parse_port_ranges(raw):
    """'5000-10000,20000:30000' -> ['5000:10000', '20000:30000']; None on any
    problem (never silently widens). Single ports like '8443' are accepted."""
    ranges = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        sep = "-" if "-" in part else (":" if ":" in part else None)
        if sep is None:
            if part.isdigit() and 1 <= int(part) <= 65535:
                ranges.append("%d:%d" % (int(part), int(part)))
                continue
            return None
        lo, hi = part.split(sep, 1)
        lo, hi = lo.strip(), hi.strip()
        if not (lo.isdigit() and hi.isdigit()):
            return None
        lo, hi = int(lo), int(hi)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
            return None
        ranges.append("%d:%d" % (lo, hi))
    return ranges or None


def _listening_ports(proto):
    flag = "-lun" if proto == "udp" else "-ltn"
    res = _run(["ss", "-H", flag])
    found = set()
    for line in (res.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 4:
            port = parts[3].rsplit(":", 1)[-1]
            if port.isdigit():
                found.add(int(port))
    return found


def _sshd_ports():
    ports = {22}
    paths = ["/etc/ssh/sshd_config"]
    try:
        import glob
        paths += sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
    except Exception:
        pass
    for path in paths:
        try:
            with open(path) as f:
                for line in f:
                    m = re.match(r'\s*Port\s+(\d+)', line, re.IGNORECASE)
                    if m:
                        ports.add(int(m.group(1)))
        except Exception:
            pass
    return ports


def _current_session_port():
    parts = os.environ.get("SSH_CONNECTION", "").split()
    if len(parts) == 4 and parts[3].isdigit():
        return int(parts[3])
    return None


def _ports_from_dict(ports_dict):
    found = set()
    for val in (ports_dict or {}).values():
        for piece in str(val).replace(";", ",").split(","):
            piece = piece.strip()
            if piece.isdigit() and 1 <= int(piece) <= 65535:
                found.add(int(piece))
    return found


def protected_ports(proto, real_ports, ports_dict=None):
    protected = {22, 53}
    protected |= _sshd_ports()
    protected |= _listening_ports(proto)
    protected |= _ports_from_dict(ports_dict)
    sess = _current_session_port()
    if sess:
        protected.add(sess)
    # the real ports themselves are never redirected onto one another
    protected |= set(int(p) for p in real_ports)
    return protected


def _revert_unit(tag):
    return "portmod-revert-" + re.sub(r'[^A-Za-z0-9_-]', '_', tag)


def _arm_revert_timer(tag, seconds=PORTMOD_REVERT_SECONDS):
    try:
        with open(PORTMOD_REVERT_SCRIPT, "w") as f:
            f.write(PORTMOD_REVERT_SCRIPT_CONTENT)
        os.chmod(PORTMOD_REVERT_SCRIPT, 0o755)
    except Exception:
        return False
    unit = _revert_unit(tag)
    _run(["systemctl", "stop", unit + ".timer"])
    _run(["systemctl", "reset-failed", unit + ".service"])
    r = _run(["systemd-run", "--quiet", "--unit=" + unit,
              "--on-active=%d" % int(seconds), PORTMOD_REVERT_SCRIPT, tag])
    return r.returncode == 0


def _cancel_revert_timer(tag):
    unit = _revert_unit(tag)
    _run(["systemctl", "stop", unit + ".timer"])
    _run(["systemctl", "reset-failed", unit + ".service"])


def portmod_active(tag):
    res = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n"])
    return any(tag_in_line(tag, l) for l in (res.stdout or "").splitlines())


def portmod_disable(tag):
    for tool in ("iptables", "ip6tables"):
        for _ in range(500):
            res = _run([tool, "-t", "nat", "-L", "PREROUTING", "--line-numbers", "-n"])
            line_no = None
            for line in (res.stdout or "").splitlines():
                if tag_in_line(tag, line):
                    line_no = line.split()[0]
                    break
            if not line_no or not line_no.isdigit():
                break
            _run([tool, "-t", "nat", "-D", "PREROUTING", line_no])
    persist_firewall_rules()


def portmod_enable(tag, proto, mapping, ports_dict=None):
    """mapping = [(ranges_list, real_port), ...]. Exclusions (RETURN) are
    inserted before any REDIRECT. Does NOT persist - guarded_enable does,
    only after confirmation."""
    reals = [rp for _, rp in mapping]
    exclude = protected_ports(proto, reals, ports_dict)
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    for tool in ("iptables", "ip6tables"):
        for p in sorted(exclude):
            _run([tool, "-t", "nat", "-A", "PREROUTING", "-p", proto, "--dport", str(p),
                  "-m", "comment", "--comment", tag, "-j", "RETURN"])
        for ranges, real_port in mapping:
            for rng in ranges:
                _run([tool, "-t", "nat", "-A", "PREROUTING", "-p", proto, "--dport", rng,
                      "-m", "comment", "--comment", tag, "-j", "REDIRECT", "--to-port", str(real_port)])
    return portmod_active(tag)


def guarded_enable(tag, enable_fn, is_active_fn):
    armed = _arm_revert_timer(tag)
    if armed:
        print(f"{C_CYAN}[i] Safety timer armed: unless you confirm within {PORTMOD_REVERT_SECONDS}s,")
        print(f"    these rules are removed automatically (and nothing is saved to disk).{C_RESET}")
    else:
        print(f"{C_YELLOW}[!] Could not arm the automatic-revert safety timer (systemd-run missing?).")
        print(f"    Without it, a mistake here could lock you out of this server.{C_RESET}")
        if input(" Type YES to continue anyway: ").strip() != "YES":
            print(f"{C_YELLOW}[i] Cancelled - nothing changed.{C_RESET}")
            return False
    ok = enable_fn()
    if not ok:
        _cancel_revert_timer(tag)
        return False
    print(f"{C_GREEN}[OK] Rules are live (not yet saved).{C_RESET}")
    print(f"{C_YELLOW} TEST NOW from a SECOND window: open a NEW SSH login to this server and")
    print(f" connect with the VPN client.  Only if both work, come back here and")
    print(f" press Enter to keep it.{C_RESET}")
    input(" Press Enter to KEEP PORT MOD (or do nothing to let it revert)... ")
    if not is_active_fn():
        print(f"{C_RED}[X] The safety timer already removed the rules - PORT MOD is OFF.{C_RESET}")
        return False
    _cancel_revert_timer(tag)
    persist_firewall_rules()
    return True


def save_state_now(ports_dict):
    """Persist ports_dict immediately (same reasoning as openvpn_manager)."""
    try:
        from smartui_main import save_ports_dict
        save_ports_dict(ports_dict)
    except Exception:
        pass


def portmod_menu(tag, label, proto, targets, ports_dict):
    """Shared PORT REDIRECTION screen.
    targets = [(display_name, real_port), ...]; the admin picks which real
    port each range goes to when there is more than one."""
    while True:
        active = portmod_active(tag)
        header(label + " - PORT REDIRECTION (PORT MOD)")
        print(" Sends EXTRA ports/ranges (%s) to this VPN's real port(s):" % proto.upper())
        for name, port in targets:
            print("     %-12s -> %s/%s" % (name, port, proto))
        print(" Status: %s" % (f"{C_GREEN}ON{C_RESET}" if active else f"{C_RED}OFF{C_RESET}"))
        print("----------------------------------------------------------------")
        print(" Safety: SSH, every live listener, every port in the panel and your own")
        print(" session port are NEVER redirected; only the ranges you type are used;")
        print(" and nothing is kept unless you confirm after testing.")
        print(BAR)
        print(" [1]> ENABLE / CHANGE PORT MOD (explicit ranges)")
        print(" [2]> DISABLE PORT MOD")
        print(BAR)
        print(" [0] RETURN")
        print(BAR)
        choice = input(" Enter an Option: ").strip()
        if choice == '0':
            return
        if choice == '1':
            mapping = []
            for name, port in targets:
                raw = input(f" Ranges to send to {name} ({port}) e.g. 5000-6000,8000-9000 [blank = none]: ").strip()
                if not raw:
                    continue
                ranges = parse_port_ranges(raw)
                if not ranges:
                    print(f"{C_RED}[X] Could not read '{raw}'. Use numbers like 5000-6000 or 8443, comma separated.{C_RESET}")
                    pause()
                    mapping = None
                    break
                mapping.append((ranges, port))
            if mapping is None:
                continue
            if not mapping:
                print(f"{C_YELLOW}[i] Nothing entered - unchanged.{C_RESET}")
                pause()
                continue
            if input(" Apply with the safety timer? (y/n): ").strip().lower() != 'y':
                continue
            portmod_disable(tag)
            ok = guarded_enable(tag, lambda: portmod_enable(tag, proto, mapping, ports_dict),
                                lambda: portmod_active(tag))
            if not ok:
                portmod_disable(tag)
                print(f"{C_RED}[X] PORT MOD is OFF - not applied or not confirmed. Nothing was saved.{C_RESET}")
            else:
                print(f"{C_GREEN}[OK] PORT MOD enabled and saved.{C_RESET}")
            pause()
        elif choice == '2':
            if not active:
                print(f"{C_YELLOW}[i] Already off.{C_RESET}")
            else:
                portmod_disable(tag)
                print(f"{C_GREEN}[OK] PORT MOD disabled.{C_RESET}")
            pause()
        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            pause()


# ---------------------------------------------------------------------------
# Registration with the panel's shared redirect-target picker
# ---------------------------------------------------------------------------

def register_known_keys(extra):
    """panel_common.KNOWN_SERVICE_KEYS drives the 'redirect to which port?'
    picker used by other modules. Register at runtime instead of editing
    panel_common.py."""
    try:
        import panel_common
        for key, value in extra.items():
            panel_common.KNOWN_SERVICE_KEYS.setdefault(key, value)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# strongSwan (shared by IKEv2 and L2TP/IPsec - ONE charon process serves both)
# ---------------------------------------------------------------------------

STRONGSWAN_UNIT = "strongswan"
CHARON_PORTS_CONF = "/etc/strongswan.d/smartui-charon.conf"
SWANCTL_DIR = "/etc/swanctl"
IKEV2_CONF = SWANCTL_DIR + "/conf.d/smartui-ikev2.conf"
L2TP_IPSEC_CONF = SWANCTL_DIR + "/conf.d/smartui-l2tp.conf"
DEFAULT_IKE_PORT = 500
DEFAULT_NATT_PORT = 4500


def starter_conflict():
    """The legacy 'starter' front-end (ipsec.conf) can't coexist with
    charon-systemd on the same ports."""
    return service_active("strongswan-starter") or service_active("ipsec")


def ensure_strongswan_installed():
    """Returns (ok, error). Core packages are required; the extra plugin
    packages (EAP-MSCHAPv2, MD4, curve25519...) are attempted one by one
    because their names differ between Debian/Ubuntu releases."""
    if not (pkg_installed("strongswan-swanctl") and pkg_installed("charon-systemd")
            and pkg_installed("strongswan-pki")):
        ok, err = apt_install(["strongswan-swanctl", "charon-systemd", "strongswan-pki"])
        if not ok:
            return False, ("Could not install strongSwan (swanctl edition). Needs Debian 10+/Ubuntu 20.04+.\n" + (err or ""))
    apt_install_optional(["libcharon-extra-plugins", "libcharon-extauth-plugins",
                          "libstrongswan-extra-plugins", "libstrongswan-standard-plugins"])
    return True, None


def get_charon_ports():
    text = read_file(CHARON_PORTS_CONF, "") or ""
    ike = re.search(r'smartui-ike-port=(\d+)', text)
    natt = re.search(r'smartui-natt-port=(\d+)', text)
    return (int(ike.group(1)) if ike else DEFAULT_IKE_PORT,
            int(natt.group(1)) if natt else DEFAULT_NATT_PORT)


def write_charon_ports(ike_port, natt_port):
    write_file(CHARON_PORTS_CONF,
               "# smartui-ike-port=%d\n# smartui-natt-port=%d\ncharon {\n    port = %d\n    port_nat_t = %d\n}\n"
               % (ike_port, natt_port, ike_port, natt_port))


def swanctl_reload():
    return _run("swanctl --load-all --noprompt").returncode == 0


def restart_strongswan():
    ok = restart_unit(STRONGSWAN_UNIT)
    if ok:
        time.sleep(1)
        swanctl_reload()
    return ok


def strongswan_in_use_by_other(proto):
    """True if the OTHER strongSwan-based protocol is still installed, in
    which case the shared charon service must not be stopped/removed."""
    other = IKEV2_CONF if proto == "l2tp" else L2TP_IPSEC_CONF
    return os.path.exists(other)


def list_ike_sas():
    res = _run("swanctl --list-sas")
    return (res.stdout or "").strip() or "(no active IPsec sessions)"


def local_ts_check():
    return True
