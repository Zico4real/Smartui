"""
openvpn_manager.py - OpenVPN admin module for the SmartUI panel.

Two independently severe "doesn't actually work at all" bugs found in the
original draft:

1. server.conf referenced ca.crt, server.crt, server.key, and dh2048.pem -
   but the original code only ran `make-cadir` (which just copies the
   Easy-RSA template SCRIPTS into place) and never actually built a PKI at
   all: no `easyrsa init-pki`, no CA, no server cert, no DH params, and
   nothing ever copied those files into /etc/openvpn/ where the config
   expects them. OpenVPN cannot start without them - there is no scenario
   where the original "[OK] successfully installed and running" message was
   ever true. Fixed with the real, full Easy-RSA 3.x sequence, verifying each
   step actually produced its output file before moving to the next, and
   copying the results into place.

2. No NAT/MASQUERADE rule anywhere. Even with a working PKI, clients using
   `redirect-gateway` (full-tunnel mode, which the wizard offers and defaults
   to) would have zero actual internet access - their traffic would reach the
   server's tun0 interface and go nowhere, since nothing translates it to the
   server's public IP before it leaves. Added an idempotent MASQUERADE rule
   on the server's real outbound interface (detected via the default route,
   never hardcoded as eth0 - the same reasoning applied to the dnstt NAT
   redirect earlier in this panel, since interface names vary by provider).

Other real bugs found:

3. "MANAGE CLIENTS (Add/Revoke)" created an empty directory and printed
   "(Configure keys via Easy-RSA integration)" - a placeholder with no actual
   client cert generation and no revocation logic at all, despite promising
   both in its own menu label. Implemented for real: `easyrsa build-client-
   full`, a proper unified inline .ovpn profile (ca/cert/key/tls-crypt
   embedded directly, the modern standard format), and `easyrsa revoke` +
   `easyrsa gen-crl` wired into a `crl-verify` directive that the original
   config never had either - without it, revocation would have had zero
   actual enforcement effect even if the revoke command itself worked.

4. `sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf`
   silently does nothing if that exact commented line isn't present (common
   on modern Ubuntu, which increasingly manages this via /etc/sysctl.d/ drop-
   ins) - meaning IP forwarding might not survive a reboot even though
   `sysctl -w` made it work for the current session. Fixed by writing our own
   dedicated drop-in file instead of depending on the exact pre-existing
   contents of sysctl.conf.

5. No config-test flag exists for OpenVPN either (confirmed: there's an open,
   unresolved upstream GitHub issue - OpenVPN/openvpn#566 - explicitly asking
   for one that doesn't exist) - same restart-verify-rollback safety net used
   for Stunnel/Hysteria, not a squid -k parse-style pre-flight check.
"""

import os
import re
import shutil
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    get_public_ip, run_cmd as _run,
)

OPENVPN_DIR = "/etc/openvpn"
EASYRSA_DIR = f"{OPENVPN_DIR}/easy-rsa"
PKI_DIR = f"{EASYRSA_DIR}/pki"
# Confirmed as the real, direct cause of a genuine bug report: the standard
# openvpn-server@.service template unit (the one systemd actually enables
# and starts at boot) looks for its config at /etc/openvpn/server/<name>.conf
# - confirmed against multiple independent, consistent sources (the Debian
# wiki's own OpenVPN page among them). Writing straight to
# /etc/openvpn/server.conf (no server/ subdirectory) meant that unit could
# never find its config at all, failing immediately on every single boot
# with "Error opening configuration file: server.conf" and restarting in a
# tight loop (confirmed directly from a real journalctl capture showing the
# restart counter climbing past 40). This is exactly why it appeared to
# work fine during manual testing, though: this module's own restart
# function falls back to the older, plain openvpn.service unit if the
# first attempt fails, and THAT unit does scan /etc/openvpn/*.conf
# directly - but that fallback only exists in this module's own Python
# code, which never runs at boot at all, so only the broken, correctly-
# named unit ever gets a chance to start automatically.
OPENVPN_SERVER_DIR = f"{OPENVPN_DIR}/server"
SERVER_CONF_PATH = f"{OPENVPN_SERVER_DIR}/server.conf"
CLIENT_DIR = f"{OPENVPN_DIR}/client-configs"
SYSCTL_DROPIN_PATH = "/etc/sysctl.d/99-openvpn-forward.conf"
# NOT 10.8.0.0: the ICMP tunnel (icmp_manager.py) is hard-wired to 10.8.0.0/24 by
# its Android client, and two tunnels sharing one subnet means the kernel sends
# one of them the other's return traffic - "connected, but no internet".
VPN_SUBNET = "10.12.0.0"
LEGACY_VPN_SUBNET = "10.8.0.0"
VPN_NETMASK = "255.255.255.0"
CA_EXPORT_PATH = "/root/smartui-openvpn-ca.crt"
BAR_LINE = "----------------------------------------------------------------"


def _service_active():
    return (_run(["systemctl", "is-active", "--quiet", "openvpn-server@server"]).returncode == 0
            or _run(["systemctl", "is-active", "--quiet", "openvpn"]).returncode == 0)


def _restart_openvpn():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt, so a
    # repeated install/config change can never be silently blocked by
    # systemd itself regardless of whether the config is genuinely correct
    # this time.
    _run("systemctl reset-failed openvpn-server@server")
    r = _run("systemctl restart openvpn-server@server")
    if r.returncode != 0:
        _run("systemctl reset-failed openvpn")
        r = _run("systemctl restart openvpn")
    return r.returncode == 0


def _wait_for_port_listening(port, proto, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, (proto,)):
            return True
        time.sleep(delay)
    return False


def _default_interface():
    """Detect the real outbound interface rather than hardcode eth0 - names
    vary by provider (ens3, enp1s0, eth0...), and hardcoding one caused
    exactly this kind of silent-no-op bug elsewhere in this panel."""
    res = _run("ip route show default")
    m = re.search(r'dev (\S+)', res.stdout)
    return m.group(1) if m else "eth0"


def _easyrsa(*args):
    return _run(f"cd {EASYRSA_DIR} && ./easyrsa --batch " + " ".join(args))


def _ensure_pki():
    """The actual missing piece: build a real, complete PKI instead of just
    copying the Easy-RSA scripts into place and stopping there."""
    os.makedirs(OPENVPN_DIR, exist_ok=True)
    os.makedirs(OPENVPN_SERVER_DIR, exist_ok=True)

    if not os.path.exists(EASYRSA_DIR):
        print(f"{C_CYAN}[i] Setting up Easy-RSA...{C_RESET}")
        _run(f"make-cadir {EASYRSA_DIR}")
        if not os.path.exists(EASYRSA_DIR):
            print(f"{C_RED}[X] Could not set up Easy-RSA directory.{C_RESET}")
            return False

    ca_cert = f"{PKI_DIR}/ca.crt"
    server_cert = f"{PKI_DIR}/issued/server.crt"
    server_key = f"{PKI_DIR}/private/server.key"
    dh_pem = f"{PKI_DIR}/dh.pem"

    if not os.path.exists(PKI_DIR):
        print(f"{C_CYAN}[i] Initializing PKI...{C_RESET}")
        _easyrsa("init-pki")
        if not os.path.exists(PKI_DIR):
            print(f"{C_RED}[X] PKI initialization failed.{C_RESET}")
            return False

    if not os.path.exists(ca_cert):
        print(f"{C_CYAN}[i] Building Certificate Authority...{C_RESET}")
        _easyrsa("build-ca", "nopass")
        if not os.path.exists(ca_cert):
            print(f"{C_RED}[X] CA build failed - {ca_cert} was never created.{C_RESET}")
            return False

    if not os.path.exists(server_cert) or not os.path.exists(server_key):
        print(f"{C_CYAN}[i] Building server certificate (this can take a moment)...{C_RESET}")
        _easyrsa("build-server-full", "server", "nopass")
        if not os.path.exists(server_cert) or not os.path.exists(server_key):
            print(f"{C_RED}[X] Server certificate build failed.{C_RESET}")
            return False

    if not os.path.exists(dh_pem):
        print(f"{C_CYAN}[i] Generating Diffie-Hellman parameters (this can take a while)...{C_RESET}")
        _easyrsa("gen-dh")
        if not os.path.exists(dh_pem):
            print(f"{C_RED}[X] DH parameter generation failed.{C_RESET}")
            return False

    tc_key = f"{OPENVPN_DIR}/tc.key"
    if not os.path.exists(tc_key):
        print(f"{C_CYAN}[i] Generating tls-crypt key (hides the TLS handshake from casual DPI)...{C_RESET}")
        _run(f"openvpn --genkey secret {tc_key}")
        if not os.path.exists(tc_key):
            print(f"{C_RED}[X] tls-crypt key generation failed.{C_RESET}")
            return False

    # Copy everything server.conf actually references into /etc/openvpn/,
    # where its relative paths expect to find them.
    _run(f"cp {ca_cert} {OPENVPN_DIR}/ca.crt")
    _run(f"cp {server_cert} {OPENVPN_DIR}/server.crt")
    _run(f"cp {server_key} {OPENVPN_DIR}/server.key")
    _run(f"cp {dh_pem} {OPENVPN_DIR}/dh2048.pem")

    return all(os.path.exists(p) for p in (
        f"{OPENVPN_DIR}/ca.crt", f"{OPENVPN_DIR}/server.crt",
        f"{OPENVPN_DIR}/server.key", f"{OPENVPN_DIR}/dh2048.pem", tc_key
    ))


def _ensure_crl_generated():
    crl_pki = f"{PKI_DIR}/crl.pem"
    _easyrsa("gen-crl")
    if os.path.exists(crl_pki):
        _run(f"cp {crl_pki} {OPENVPN_DIR}/crl.pem")
        _run(f"chmod 644 {OPENVPN_DIR}/crl.pem")
    return os.path.exists(f"{OPENVPN_DIR}/crl.pem")


def _dev_for(name):
    """Main instance keeps the dynamic 'tun' (it gets tun0). Every additional instance gets its OWN
    fixed device name, because a dynamic 'dev tun' hands out the first free number, which can be
    tun1 - the device the ICMP tunnel hard-codes - and then icmp-vpn cannot start (busy)."""
    if name == "server":
        return "tun"
    import zlib
    return "tun%d" % (20 + zlib.crc32(name.encode()) % 70)


def _build_config(listen_port, listen_proto, redirect_gateway=True, subnet=None, name="server", local_addr=None):
    # subnet / name / local_addr are used by the additional instances (UDP / TCP / SSL / WebSocket
    # profiles); the main instance keeps calling this exactly as before.
    subnet = subnet or VPN_SUBNET
    ipp_path = f"{OPENVPN_DIR}/ipp.txt" if name == "server" else f"{OPENVPN_DIR}/ipp-{name}.txt"
    status_path = f"{OPENVPN_DIR}/openvpn-status.log" if name == "server" else f"{OPENVPN_DIR}/openvpn-status-{name}.log"
    local_line = f"local {local_addr}\n" if local_addr else ""
    # "explicit-exit-notify" is UDP-only: OpenVPN refuses to start a TCP server that has it, so a
    # TCP config made by the old template failed to restart and was rolled back to UDP.
    exit_notify = "explicit-exit-notify 1\n" if str(listen_proto).lower().startswith("udp") else ""
    redirect_directive = 'push "redirect-gateway def1 bypass-dhcp"' if redirect_gateway else '# push redirect-gateway skipped'
    # Absolute paths for every referenced file, not relative ones -
    # confirmed necessary alongside the directory fix above: a relative
    # path like "ca.crt" depends entirely on OpenVPN's working directory at
    # startup, which a systemd service has no guaranteed relationship to
    # the config file's own new location. Absolute paths remove that
    # ambiguity entirely, regardless of which directory the process
    # actually starts in.
    return f"""{local_line}port {listen_port}
proto {listen_proto}
dev {_dev_for(name)}
ca {OPENVPN_DIR}/ca.crt
cert {OPENVPN_DIR}/server.crt
key {OPENVPN_DIR}/server.key
dh {OPENVPN_DIR}/dh2048.pem
tls-crypt {OPENVPN_DIR}/tc.key
crl-verify {OPENVPN_DIR}/crl.pem
auth SHA256
cipher AES-256-GCM
server {subnet} {VPN_NETMASK}
ifconfig-pool-persist {ipp_path}
{redirect_directive}
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
persist-key
persist-tun
status {status_path}
verb 3
{exit_notify}"""


def _ensure_ip_forwarding():
    _run("sysctl -w net.ipv4.ip_forward=1")
    # A dedicated drop-in file instead of sed-ing the pre-existing sysctl.conf -
    # sysctl reads every file under /etc/sysctl.d/, so this guarantees it
    # survives a reboot without depending on what sysctl.conf already contains.
    with open(SYSCTL_DROPIN_PATH, "w") as f:
        f.write("net.ipv4.ip_forward=1\n")
    _run(f"sysctl -p {SYSCTL_DROPIN_PATH}")


def _migrate_legacy_subnet():
    """Upgrade path: an OpenVPN server installed on the old 10.8.0.0/24 subnet
    is moved to VPN_SUBNET in place. Client .ovpn profiles are unaffected
    (the subnet is pushed by the server, never stored in the profile).
    Returns True if it changed anything."""
    if not os.path.exists(SERVER_CONF_PATH):
        return False
    with open(SERVER_CONF_PATH) as f:
        conf = f.read()
    old_line = f"server {LEGACY_VPN_SUBNET} {VPN_NETMASK}"
    if old_line not in conf:
        return False
    with open(SERVER_CONF_PATH, "w") as f:
        f.write(conf.replace(old_line, f"server {VPN_SUBNET} {VPN_NETMASK}"))
    # old address leases belong to the old subnet
    try:
        os.remove(f"{OPENVPN_DIR}/ipp.txt")
    except FileNotFoundError:
        pass
    _ensure_masquerade(_default_interface())
    persist_firewall_rules()
    return _restart_openvpn()


def _ensure_masquerade(interface, subnet=None):
    subnet = subnet or VPN_SUBNET
    check = _run(["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", f"{subnet}/24",
                  "-o", interface, "-j", "MASQUERADE"])
    if check.returncode != 0:
        _run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", f"{subnet}/24",
              "-o", interface, "-j", "MASQUERADE"])


def _remove_masquerade(interface, subnet=None):
    subnet = subnet or VPN_SUBNET
    _run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", f"{subnet}/24",
          "-o", interface, "-j", "MASQUERADE"])


# ---------------------------------------------------------------------------
# OPENVPN MOD - same "redirect a wider range of ports to the real listening
# port" idea already shipped for ZIVPN/UDP Droid/Psiphon, adapted here:
#   - OpenVPN has no separate IP-gate the way Psiphon/ICMP/UDP Droid do -
#     clients already authenticate with a real TLS client cert
#     (remote-cert-tls server + crl-verify), so there's nothing to worry
#     about "bypassing" the way there was for a gate chain. A redirected
#     connection just reaches the same openvpn-server@server process on its
#     real port, which still requires the same valid cert either way.
#   - Matches whichever protocol OpenVPN is actually configured for
#     (-p udp or -p tcp) - redirecting the other protocol's range would be
#     pointless, since nothing is listening there.
# ---------------------------------------------------------------------------

OPENVPN_MOD_COMMENT = "openvpn-mod"


def _mod_active():
    """Checks the live iptables rule table rather than ports_dict, same
    reasoning as every other MOD feature in this panel - the rule table is
    the only real source of truth."""
    res = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "-n"])
    return any(_tag_in_line(OPENVPN_MOD_COMMENT, l) for l in res.stdout.splitlines())


def _parse_port_ranges(raw):
    """Parses '5000-10000,10001-20000' into iptables-style --dport range
    strings. Returns None if anything fails to parse - never silently
    falls back to a wider range than asked for. Same helper already
    proven in zivpn_manager.py/udp_droid_manager.py/psiphon_manager.py."""
    ranges = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        sep = "-" if "-" in part else (":" if ":" in part else None)
        if sep is None:
            return None
        lo, hi = part.split(sep, 1)
        lo, hi = lo.strip(), hi.strip()
        if not (lo.isdigit() and hi.isdigit()):
            return None
        lo, hi = int(lo), int(hi)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
            return None
        ranges.append(f"{lo}:{hi}")
    return ranges or None


# ---------------------------------------------------------------------------
# PORT MOD SAFETY LAYER (shared with psiphon_manager.py, which imports it)
#
# Added after a real incident: a TCP PORT MOD redirected every TCP port to
# the tunnel and the exclusion list only held a handful of hand-picked
# ports, so SSH (and other services' ports and HTTP gates) got swallowed and
# the admin was locked out of the VPS. Hysteria 1's UDP MOD never had that
# problem only because SSH is TCP and it is a UDP redirect - its exclusion
# list is the same hand-picked kind and would break the same way for TCP.
# The rules below don't depend on anyone remembering every port:
#   1. Every port that has a LIVE LISTENER right now (ss), for this
#      protocol, is never redirected - this automatically covers sshd on
#      whatever port it uses, dropbear, stunnel, squid, the panel, and
#      every protocol's HTTP gate, including ones installed later than
#      this file was written.
#   2. sshd's configured Port lines are excluded even if sshd is down.
#   3. The port of the admin's own current SSH session (SSH_CONNECTION) is
#      excluded, so the session running this panel can never be cut off.
#   4. Every number recorded in ports_dict is excluded too, including
#      comma-separated lists (DROPBEAR_PORTS, STUNNEL_PORTS, ...), which the
#      old code silently skipped because "109,143".isdigit() is False.
#   5. Turning a MOD on is guarded by an automatic revert timer that runs
#      OUTSIDE this SSH session: if you don't confirm within the time
#      limit, the rules are removed again and nothing is saved to disk, so
#      even a reboot comes back clean.
# ---------------------------------------------------------------------------

PORTMOD_REVERT_SCRIPT = "/usr/local/bin/portmod-revert.sh"
PORTMOD_REVERT_SECONDS = 120
PORTMOD_REVERT_SCRIPT_CONTENT = """#!/bin/sh
# Removes every nat/PREROUTING rule carrying the given PORT MOD comment tag.
# Run by a transient systemd timer if the admin does not confirm a freshly
# enabled PORT MOD in time (see openvpn_manager._guarded_enable).
TAG="$1"
[ -n "$TAG" ] || exit 1
for T in iptables ip6tables; do
  command -v ${T}-save >/dev/null 2>&1 || continue
  ${T}-save -t nat | grep -v -E -- "--comment \\"?${TAG}\\"?( |$)" | ${T}-restore -T nat
done
exit 0
"""


def _tag_in_line(tag, line):
    """True only if `tag` appears as a whole comment token - 'psiphonmod_a'
    must never match 'psiphonmod_ab' or 'psiphonmod_a-2'."""
    return re.search(r'(?<![\w-])' + re.escape(tag) + r'(?![\w-])', line) is not None


def _listening_ports(proto):
    """Every port with a live listener for this protocol, IPv4 and IPv6."""
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
    """Server-side port of the admin's own SSH connection, if this panel is
    being run over SSH (SSH_CONNECTION = 'client_ip client_port server_ip
    server_port')."""
    parts = os.environ.get("SSH_CONNECTION", "").split()
    if len(parts) == 4 and parts[3].isdigit():
        return int(parts[3])
    return None


def _ports_from_dict(ports_dict):
    found = set()
    for val in (ports_dict or {}).values():
        for piece in str(val).replace(";", ",").split(","):
            piece = piece.strip()
            if piece.isdigit():
                n = int(piece)
                if 1 <= n <= 65535:
                    found.add(n)
    return found


def _protected_ports(proto, real_port, ports_dict=None):
    """Everything a blanket REDIRECT must never touch (see the block comment
    above). `real_port` itself is dropped from the set - redirecting it to
    itself is pointless and a RETURN there is equivalent."""
    protected = {22, 53}
    protected |= _sshd_ports()
    protected |= _listening_ports(proto)
    protected |= _ports_from_dict(ports_dict)
    sess = _current_session_port()
    if sess:
        protected.add(sess)
    protected.discard(real_port)
    return protected


def _revert_unit(tag):
    return "portmod-revert-" + re.sub(r'[^A-Za-z0-9_-]', '_', tag)


def _arm_revert_timer(tag, seconds=PORTMOD_REVERT_SECONDS):
    """Schedules removal of this tag's rules via a transient systemd timer,
    independent of this SSH session and this Python process."""
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


def _guarded_enable(tag, enable_fn, is_active_fn):
    """Turns a PORT MOD on with a lockout safety net. Returns True only if
    the admin confirmed it and it was saved."""
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
    print(f" connect with the tunnel client.  Only if both work, come back here and")
    print(f" press Enter to keep it.{C_RESET}")
    input(" Press Enter to KEEP PORT MOD (or do nothing to let it revert)... ")

    if not is_active_fn():
        print(f"{C_RED}[X] The safety timer already removed the rules - PORT MOD is OFF.{C_RESET}")
        return False
    _cancel_revert_timer(tag)
    persist_firewall_rules()
    return True



def _enable_port_mod(real_port, proto, ports_dict=None, port_ranges=None):
    """Redirects traffic on a range of ports (matching OpenVPN's own
    configured protocol) to wherever OpenVPN is actually listening.
    Exclusions go in BEFORE the blanket rule(s) (iptables stops at the first
    match) and come from _protected_ports() - live listeners, sshd, the
    admin's own session port, and everything in ports_dict - never from a
    short hand-written list. Does NOT persist: _guarded_enable() persists
    only after the admin confirms."""
    ranges = port_ranges or ["1:65535"]

    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    iface = _default_interface()
    _run(["sysctl", "-w", "net.ipv4.conf.%s.rp_filter=0" % iface])
    _run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"])

    exclude_ports = _protected_ports(proto, real_port, ports_dict)

    for tool in ("iptables", "ip6tables"):
        for p in sorted(exclude_ports):
            _run([tool, "-t", "nat", "-A", "PREROUTING", "-p", proto,
                  "--dport", str(p), "-m", "comment", "--comment", OPENVPN_MOD_COMMENT,
                  "-j", "RETURN"])
        for rng in ranges:
            _run([tool, "-t", "nat", "-A", "PREROUTING", "-p", proto,
                  "--dport", rng, "-m", "comment", "--comment", OPENVPN_MOD_COMMENT,
                  "-j", "REDIRECT", "--to-port", str(real_port)])

    return _mod_active()


def _disable_port_mod():
    while True:
        res = _run(["iptables", "-t", "nat", "-L", "PREROUTING", "--line-numbers", "-n"])
        line_no = None
        for line in res.stdout.splitlines():
            if _tag_in_line(OPENVPN_MOD_COMMENT, line):
                line_no = line.split()[0]
                break
        if not line_no or not line_no.isdigit():
            break
        _run(["iptables", "-t", "nat", "-D", "PREROUTING", line_no])
    while True:
        res6 = _run(["ip6tables", "-t", "nat", "-L", "PREROUTING", "--line-numbers", "-n"])
        line_no = None
        for line in res6.stdout.splitlines():
            if _tag_in_line(OPENVPN_MOD_COMMENT, line):
                line_no = line.split()[0]
                break
        if not line_no or not line_no.isdigit():
            break
        _run(["ip6tables", "-t", "nat", "-D", "PREROUTING", line_no])
    persist_firewall_rules()


def _apply_config_safely(new_content, description, check_port, check_proto):
    original = None
    if os.path.exists(SERVER_CONF_PATH):
        with open(SERVER_CONF_PATH, "r") as f:
            original = f.read()

    os.makedirs(OPENVPN_SERVER_DIR, exist_ok=True)
    with open(SERVER_CONF_PATH, "w") as f:
        f.write(new_content)

    # Cleanup for anyone upgrading from before this fix: a stale config at
    # the old, wrong path (/etc/openvpn/server.conf, no server/
    # subdirectory) served no purpose once the correct one exists here, and
    # leaving it around only risked confusion later.
    old_wrong_path = f"{OPENVPN_DIR}/server.conf"
    if os.path.exists(old_wrong_path):
        try:
            os.remove(old_wrong_path)
        except Exception:
            pass

    if not _restart_openvpn():
        if original is not None:
            with open(SERVER_CONF_PATH, "w") as f:
                f.write(original)
            _restart_openvpn()
        else:
            # Same fix as the identical bug already found and fixed for
            # Hysteria2/MULTIPLEXING/BadVPN elsewhere in this panel: on a
            # genuine first-ever attempt (no prior working config to
            # revert to), leaving the broken new config sitting on disk -
            # while telling the admin it was "reverted" - meant every
            # later attempt's own rollback-on-failure would restore THIS
            # same broken config as its own baseline, so every subsequent
            # attempt failed identically regardless of what was actually
            # entered.
            try:
                os.remove(SERVER_CONF_PATH)
            except FileNotFoundError:
                pass
        return False, f"{description} failed to restart OpenVPN - reverted to the previous working config."

    if not _wait_for_port_listening(check_port, check_proto):
        if original is not None:
            with open(SERVER_CONF_PATH, "w") as f:
                f.write(original)
            _restart_openvpn()
        else:
            # Same fix as above, for the other failure path.
            try:
                os.remove(SERVER_CONF_PATH)
            except FileNotFoundError:
                pass
        return False, f"{description} restarted, but port {check_port}/{check_proto} never came up - reverted. Nothing was left broken."

    return True, f"{description} applied and verified on port {check_port}/{check_proto}."


def _generate_client_profile(client_name, server_ip, listen_port, listen_proto, suffix="", note=""):
    client_cert = f"{PKI_DIR}/issued/{client_name}.crt"
    client_key = f"{PKI_DIR}/private/{client_name}.key"
    ca_cert = f"{PKI_DIR}/ca.crt"
    tc_key = f"{OPENVPN_DIR}/tc.key"

    if not (os.path.exists(client_cert) and os.path.exists(client_key)):
        return None

    def read(path):
        with open(path) as f:
            return f.read()

    note_text = "".join("# %s\n" % ln for ln in note.splitlines()) if note else ""
    ovpn_content = f"""{note_text}client
dev tun
proto {listen_proto}
remote {server_ip} {listen_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-GCM
verb 3
<ca>
{read(ca_cert)}</ca>
<cert>
{read(client_cert)}</cert>
<key>
{read(client_key)}</key>
<tls-crypt>
{read(tc_key)}</tls-crypt>
"""
    os.makedirs(CLIENT_DIR, exist_ok=True)
    profile_path = f"{CLIENT_DIR}/{client_name}{suffix}.ovpn"
    with open(profile_path, "w") as f:
        f.write(ovpn_content)
    return profile_path


def create_client(client_name, listen_port, listen_proto):
    """Extracted for reuse - the SSH/master user manager needs to be able to
    create a linked OpenVPN client the same way this menu does, rather than
    duplicating the cert-generation logic a second time.
    Returns (ok: bool, profile_path_or_error: str)."""
    if not client_name or not re.match(r'^[A-Za-z0-9_-]+$', client_name):
        return False, "Client name must contain only letters, numbers, hyphens, underscores."
    if not os.path.exists(PKI_DIR):
        return False, "OpenVPN PKI not initialized - install OpenVPN first."
    if os.path.exists(f"{PKI_DIR}/issued/{client_name}.crt"):
        return False, f"A client named '{client_name}' already exists."

    _easyrsa("build-client-full", client_name, "nopass")
    if not os.path.exists(f"{PKI_DIR}/issued/{client_name}.crt"):
        return False, "Client certificate generation failed."

    server_ip = os.popen(r"curl -4 -s ifconfig.me || hostname -I | tr ' ' '\n' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -n1").read().strip()
    profile_path = _generate_client_profile(client_name, server_ip, listen_port, listen_proto)
    if not profile_path:
        return False, "Certificate was created but the .ovpn profile couldn't be assembled."
    try:
        _generate_extra_profiles(client_name, server_ip)
    except Exception:
        pass
    return True, profile_path


def _save_state_now(ports_dict):
    """Persists ports_dict to disk immediately, rather than waiting for the
    main menu loop to save it after this whole module returns. Confirmed as
    the real, direct cause of a genuine bug report - the same class of
    issue already found and fixed for DNSTT elsewhere in this panel: the
    main loop only ever calls save_ports_dict() as its very last line, once
    a submenu function fully returns, so an admin who changes something
    here and stays on this module's own screens afterward (exactly what
    happened - the port/protocol change succeeded, but Protocol Manager
    still showed the old state) has that change sitting only in memory
    until they navigate all the way back out. Lazy-imported to avoid a
    circular import, since smartui_main.py is what imports this module,
    not the reverse."""
    try:
        from smartui_main import save_ports_dict
        save_ports_dict(ports_dict)
    except Exception:
        pass


def _ca_cert_path():
    """The CA certificate (public part only - never the CA key). Prefers the
    copy the server config actually references, falls back to the PKI one."""
    for p in (f"{OPENVPN_DIR}/ca.crt", f"{PKI_DIR}/ca.crt"):
        if os.path.exists(p):
            return p
    return None


def _read_text(path, default=""):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return default


def _list_client_profiles():
    try:
        return sorted(f[:-5] for f in os.listdir(CLIENT_DIR) if f.endswith(".ovpn"))
    except Exception:
        return []


def _connection_info(ports_dict):
    """Same idea as sstp_manager._connection_info: one screen with everything
    a customer needs to connect, plus [C] to show/export the CA certificate
    on screen so it can be copied from the terminal."""
    port = ports_dict.get('OPENVPN_PORT', 'Not configured')
    proto = str(ports_dict.get('OPENVPN_PROTO', 'udp')).lower()
    conf = _read_text(SERVER_CONF_PATH)
    full_tunnel = ('redirect-gateway' in conf) and ('# push redirect-gateway' not in conf)
    ca_path = _ca_cert_path()
    profiles = _list_client_profiles()
    host = get_public_ip() or "<server-ip>"

    clear_screen()
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("%s            OPENVPN CONNECTION INFO / CLIENT SETUP              %s" % (C_BOLD, C_RESET))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print(f" Server         : {C_YELLOW}{host}:{port}{C_RESET}   ({proto.upper()})")
    print(f" Service        : {'ON' if _service_active() else 'OFF'}")
    print(" Login          : a client certificate (one .ovpn profile per client)")
    print(f" Encryption     : AES-256-GCM, auth SHA256, tls-crypt (handshake hidden)")
    print(f" Routing        : {'full tunnel (all client traffic goes through the VPN)' if full_tunnel else 'split (only VPN subnet pushed)'}")
    print(f" VPN subnet     : {VPN_SUBNET}/24   DNS pushed: 1.1.1.1, 8.8.8.8")
    print(f" Certificate    : {'own CA (' + ca_path + ')' if ca_path else 'CA not found - run option 1 first'}")
    print(f" Client profiles: {len(profiles)} in {CLIENT_DIR}")
    for name in profiles[:15]:
        print(f"                  - {name}.ovpn")
    if len(profiles) > 15:
        print(f"                  ... and {len(profiles) - 15} more")
    if _mod_active():
        print(f" PORT MOD       : {C_GREEN}ON{C_RESET} - {proto.upper()} ports redirect to {port}")
    for role, info in _load_extras().get("roles", {}).items():
        print(f" Extra profile  : {ROLE_INFO[role]['label']:<9} port {info.get('port')}  ({'ON' if _role_active(role) else 'OFF'})  -> <client>-{role}.ovpn")
    print(BAR_LINE)
    print(" The .ovpn profile already CONTAINS the CA, the client certificate, the")
    print(" client key and the tls-crypt key, so clients do not need to import the CA")
    print(" separately - just import the one file. Create one with option [3] > Add.")
    print(BAR_LINE)
    print(" ANDROID: install 'OpenVPN for Android' or 'OpenVPN Connect', import the .ovpn.")
    print(" iOS    : 'OpenVPN Connect' - import the .ovpn (AirDrop/Files).")
    print(" WINDOWS: 'OpenVPN GUI' / 'OpenVPN Connect' - put the .ovpn in")
    print("          C:\\Users\\<you>\\OpenVPN\\config and connect.")
    print(" LINUX  : sudo openvpn --config client.ovpn   (or NetworkManager import).")
    print(" Get a profile off this server with SFTP/SCP from:")
    print(f"          {CLIENT_DIR}/<client>.ovpn")
    print(BAR_LINE)
    print(" [C] EXPORT / SHOW CA CERTIFICATE")
    print(" [P] SHOW A CLIENT PROFILE (.ovpn) ON SCREEN     [0] RETURN")
    ch = input(" Enter an Option: ").strip().lower()
    if ch == 'c':
        if ca_path:
            print()
            try:
                shutil.copyfile(ca_path, CA_EXPORT_PATH)
                print(f"{C_GREEN}[OK] Copied to {CA_EXPORT_PATH} - download it with SFTP, or copy the text below.{C_RESET}\n")
            except Exception as e:
                print(f"{C_YELLOW}[!] Could not write {CA_EXPORT_PATH} ({e}) - the certificate is shown below anyway.{C_RESET}\n")
            print(_read_text(ca_path))
            print(f"{C_CYAN}[i] This is only the PUBLIC CA certificate - safe to share. A client still needs")
            print(f"    its own .ovpn profile (certificate + key + tls-crypt) to connect.{C_RESET}")
        else:
            print(f"{C_RED}[X] No CA certificate found - run option 1 (install) first.{C_RESET}")
        input("\nPress Enter to continue...")
    elif ch == 'p':
        _show_client_profile(profiles)



def _show_client_profile(profiles):
    """Prints one client's full .ovpn on screen so it can be copied from the
    terminal. The file embeds that client's PRIVATE KEY, hence the warning
    and the confirmation."""
    if not profiles:
        print(f"{C_RED}[X] No client profiles yet - create one with option [3] > Add a client.{C_RESET}")
        input("\nPress Enter to continue...")
        return
    print("\n Available profiles: " + ", ".join(profiles))
    name = input(" Client name to show: ").strip()
    if name not in profiles:
        print(f"{C_RED}[X] No such profile.{C_RESET}")
        input("\nPress Enter to continue...")
        return
    print(f"{C_YELLOW}[!] This file contains '{name}' PRIVATE KEY. Give it ONLY to that client;")
    print(f"    anyone holding it can connect as them (revoke in option [3] if it leaks).{C_RESET}")
    if input(" Show it on screen? (y/n): ").strip().lower() != 'y':
        print(f"{C_YELLOW}[i] Cancelled.{C_RESET}")
        input("\nPress Enter to continue...")
        return
    path = f"{CLIENT_DIR}/{name}.ovpn"
    print(f"\n{C_CYAN}----- BEGIN PROFILE (copy everything from 'client' to the last </tls-crypt>) -----{C_RESET}")
    print(_read_text(path))
    print(f"{C_CYAN}----- END PROFILE -----{C_RESET}")
    print(f" Save it on the phone as {name}.ovpn, or fetch it by SFTP from {path}")
    input("\nPress Enter to continue...")

# ---------------------------------------------------------------------------
# MORE PROTOCOLS - several OpenVPN profiles at the same time.
#
# The main instance (option 1/2: openvpn-server@server) is never touched by
# this block. Each extra profile is its own piece, so UDP, TCP, SSL and
# WebSocket can all be installed, changed and removed independently:
#
#   UDP / TCP  a second OpenVPN instance (openvpn-server@ovpn-udp / ovpn-tcp)
#              for the protocol the main instance does not use.
#   SSL        a TLS front (ovpn-ssl.service) that hands the decrypted
#              stream to a private OpenVPN-TCP backend.
#   WEBSOCKET  an HTTP-upgrade front (ovpn-ws.service) -> same backend.
#   SSLPayload needs nothing extra: the app's payload/remote-proxy goes in
#              front of the plain TCP profile.
#
# All instances share the same CA, server certificate, tls-crypt key and CRL,
# so a client created once works for every profile (<client>.ovpn for the
# main one, <client>-udp / -tcp / -ssl / -ws .ovpn for the extras). Each
# instance has its own VPN subnet, with its own NAT rule.
# ---------------------------------------------------------------------------

EXTRAS_PATH = f"{OPENVPN_DIR}/smartui-extras.json"
BRIDGE_DIR = f"{OPENVPN_DIR}/bridge"
BRIDGE_SCRIPT = "/usr/local/bin/ovpn-front-bridge.py"
INT_NAME = "ovpn-int"
INT_SUBNET = "10.18.0.0"
INT_DEFAULT_PORT = 11940
ROLE_INFO = {
    "udp": {"label": "UDP", "proto": "udp", "subnet": "10.16.0.0", "name": "ovpn-udp", "default": 1194},
    "tcp": {"label": "TCP", "proto": "tcp", "subnet": "10.17.0.0", "name": "ovpn-tcp", "default": 1194},
    "ssl": {"label": "SSL", "proto": "tcp", "unit": "ovpn-ssl", "default": 443},
    "ws": {"label": "WEBSOCKET", "proto": "tcp", "unit": "ovpn-ws", "default": 80},
}
ROLE_NOTE = {
    "udp": "Transport: OVPN UDP",
    "tcp": "Transport: OVPN TCP (also the target of OVPN SSLPayload: the front proxy connects to this TCP port)",
    "ssl": "Transport: OVPN SSL - in the app pick OVPN SSL and fill the SNI",
    "ws": "Transport: OVPN WebSocket - in the app pick OVPN WebSocket (payload / remote proxy optional)",
}

BRIDGE_SCRIPT_CONTENT = r'''#!/usr/bin/env python3
# SmartUI OpenVPN front. Usage: ovpn-front-bridge.py <ssl|ws> <listen_port> <backend_port> [cert key]
#   ssl : TLS terminator. Anything the client sends after the TLS handshake that looks like an
#         HTTP payload is swallowed, then the stream is relayed raw to the OpenVPN-TCP backend.
#   ws  : answers the HTTP "Upgrade: websocket" request with 101, then relays raw bytes.
import asyncio, base64, hashlib, ssl, sys

MODE = sys.argv[1]
LISTEN = int(sys.argv[2])
BACKEND = int(sys.argv[3])
CERT = sys.argv[4] if len(sys.argv) > 4 else None
KEY = sys.argv[5] if len(sys.argv) > 5 else None
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
HTTP_START = (b"GET ", b"POST", b"HEAD", b"PUT ", b"CONNE", b"OPTIO", b"PATCH", b"DELET", b"HTTP/")


async def read_head(reader, first=b""):
    data = first
    while b"\r\n\r\n" not in data:
        if len(data) > 16384:
            raise ValueError("header too large")
        chunk = await reader.read(4096)
        if not chunk:
            raise EOFError
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    return head, rest


async def pump(r, w):
    try:
        while True:
            d = await r.read(65536)
            if not d:
                break
            w.write(d)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def handle(reader, writer):
    try:
        rest = b""
        if MODE == "ws":
            head, rest = await asyncio.wait_for(read_head(reader), 20)
            key = None
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip()
            resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            if key:
                resp += b"Sec-WebSocket-Accept: " + base64.b64encode(hashlib.sha1(key + GUID).digest()) + b"\r\n"
            writer.write(resp + b"\r\n")
            await writer.drain()
        else:
            first = await asyncio.wait_for(reader.read(8), 20)
            if not first:
                return
            if first.startswith(HTTP_START):
                head, rest = await asyncio.wait_for(read_head(reader, first), 20)
            else:
                rest = first
        back_r, back_w = await asyncio.open_connection("127.0.0.1", BACKEND)
        if rest:
            back_w.write(rest)
            await back_w.drain()
        await asyncio.gather(pump(reader, back_w), pump(back_r, writer))
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    ctx = None
    if MODE == "ssl":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
    server = await asyncio.start_server(handle, "0.0.0.0", LISTEN, ssl=ctx, backlog=256)
    async with server:
        await server.serve_forever()


asyncio.run(main())
'''


def _load_extras():
    try:
        import json
        with open(EXTRAS_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            data.setdefault("roles", {})
            return data
    except Exception:
        pass
    return {"roles": {}}


def _save_extras(data, ports_dict=None):
    import json
    os.makedirs(OPENVPN_DIR, exist_ok=True)
    with open(EXTRAS_PATH, "w") as f:
        json.dump(data, f, indent=2)
    if ports_dict is not None:
        roles = data.get("roles", {})
        if roles:
            ports_dict['OPENVPN_EXTRAS'] = ",".join("%s:%s" % (r, i.get("port")) for r, i in roles.items())
        else:
            ports_dict.pop('OPENVPN_EXTRAS', None)
        _save_state_now(ports_dict)


def _inst_conf(name):
    return f"{OPENVPN_SERVER_DIR}/{name}.conf"


def _inst_active(name):
    return _run(["systemctl", "is-active", "--quiet", f"openvpn-server@{name}"]).returncode == 0


def _role_unit(role):
    info = ROLE_INFO[role]
    return info.get("unit") or None


def _role_active(role):
    info = ROLE_INFO[role]
    if "unit" in info:
        return _run(["systemctl", "is-active", "--quiet", info["unit"]]).returncode == 0
    return _inst_active(info["name"])


def _apply_instance(name, content, port, proto):
    """Same write / restart / verify / roll back idea as _apply_config_safely,
    for an additional instance. Returns (ok, message)."""
    path = _inst_conf(name)
    original = _read_text(path, None)
    os.makedirs(OPENVPN_SERVER_DIR, exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    svc = f"openvpn-server@{name}"
    _run(f"systemctl enable {svc}")
    _run(f"systemctl reset-failed {svc}")
    ok = _run(f"systemctl restart {svc}").returncode == 0 and _wait_for_port_listening(port, proto)
    if ok:
        return True, f"{name} is listening on {port}/{proto}."
    if original is not None:
        with open(path, "w") as f:
            f.write(original)
        _run(f"systemctl restart {svc}")
    else:
        _run(f"systemctl stop {svc}")
        _run(f"systemctl disable {svc}")
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    return False, f"{name} did not come up on {port}/{proto} - check 'journalctl -u {svc}'. Nothing was left installed."


def _remove_instance(name, subnet):
    svc = f"openvpn-server@{name}"
    _run(f"systemctl stop {svc}")
    _run(f"systemctl disable {svc}")
    _run(f"systemctl reset-failed {svc}")
    for path in (_inst_conf(name), f"{OPENVPN_DIR}/ipp-{name}.txt", f"{OPENVPN_DIR}/openvpn-status-{name}.log"):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    _remove_masquerade(_default_interface(), subnet)


def _ensure_internal_backend(extras):
    """Private OpenVPN-TCP instance on 127.0.0.1 that the SSL / WebSocket fronts forward to."""
    port = int(extras.get("int_port") or INT_DEFAULT_PORT)
    if _inst_active(INT_NAME) and check_system_port_in_use(port, ("tcp",)):
        return True, port, ""
    if check_system_port_in_use(port, ("tcp",)) and not _inst_active(INT_NAME):
        for cand in range(INT_DEFAULT_PORT, INT_DEFAULT_PORT + 50):
            if not check_system_port_in_use(cand, ("tcp",)):
                port = cand
                break
    _ensure_ip_forwarding()
    _ensure_masquerade(_default_interface(), INT_SUBNET)
    persist_firewall_rules()
    content = _build_config(port, "tcp", True, subnet=INT_SUBNET, name=INT_NAME, local_addr="127.0.0.1")
    ok, msg = _apply_instance(INT_NAME, content, port, "tcp")
    if ok:
        extras["int_port"] = port
    return ok, port, msg


def _ensure_ssl_cert():
    crt, key = f"{BRIDGE_DIR}/ssl.crt", f"{BRIDGE_DIR}/ssl.key"
    if os.path.exists(crt) and os.path.exists(key):
        return crt, key
    os.makedirs(BRIDGE_DIR, exist_ok=True)
    cn = get_public_ip() or "smartui-openvpn"
    _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
          "-days", "3650", "-subj", f"/CN={cn}"])
    if os.path.exists(key):
        os.chmod(key, 0o600)
    return (crt, key) if os.path.exists(crt) and os.path.exists(key) else (None, None)


def _bridge_unit_path(role):
    return f"/etc/systemd/system/{ROLE_INFO[role]['unit']}.service"


def _apply_bridge(role, port, backend_port):
    unit = ROLE_INFO[role]["unit"]
    args = f"{role} {port} {backend_port}"
    if role == "ssl":
        crt, key = _ensure_ssl_cert()
        if not crt:
            return False, "Could not create the TLS certificate (is openssl installed?)."
        args += f" {crt} {key}"
    with open(BRIDGE_SCRIPT, "w") as f:
        f.write(BRIDGE_SCRIPT_CONTENT)
    os.chmod(BRIDGE_SCRIPT, 0o755)
    path = _bridge_unit_path(role)
    original = _read_text(path, None)
    py = shutil.which("python3") or "/usr/bin/python3"
    with open(path, "w") as f:
        f.write(f"""[Unit]
Description=SmartUI OpenVPN {ROLE_INFO[role]['label']} front on port {port}
After=network.target openvpn-server@{INT_NAME}.service

[Service]
Type=simple
User=root
ExecStart={py} {BRIDGE_SCRIPT} {args}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""")
    _run("systemctl daemon-reload")
    _run(f"systemctl enable {unit}")
    _run(f"systemctl reset-failed {unit}")
    ok = _run(f"systemctl restart {unit}").returncode == 0 and _wait_for_port_listening(port, "tcp")
    if ok:
        return True, f"{ROLE_INFO[role]['label']} front is listening on TCP {port}."
    if original is not None:
        with open(path, "w") as f:
            f.write(original)
        _run("systemctl daemon-reload")
        _run(f"systemctl restart {unit}")
    else:
        _run(f"systemctl stop {unit}")
        _run(f"systemctl disable {unit}")
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        _run("systemctl daemon-reload")
    return False, f"{ROLE_INFO[role]['label']} front did not come up on {port} - check 'journalctl -u {unit}'."


def _install_role(role, port, ports_dict):
    """Installs (or moves to a new port) one extra profile. Returns (ok, message)."""
    info = ROLE_INFO[role]
    extras = _load_extras()
    old = extras["roles"].get(role, {}).get("port")
    if "unit" in info:
        ok, bport, msg = _ensure_internal_backend(extras)
        if not ok:
            return False, "Private OpenVPN backend failed: " + msg
        open_firewall_port(port, ("tcp",))
        persist_firewall_rules()
        ok, msg = _apply_bridge(role, port, bport)
    else:
        redirect = True
        main_conf = _read_text(SERVER_CONF_PATH)
        if main_conf and "# push redirect-gateway" in main_conf:
            redirect = False
        _ensure_ip_forwarding()
        _ensure_masquerade(_default_interface(), info["subnet"])
        open_firewall_port(port, (info["proto"],))
        persist_firewall_rules()
        content = _build_config(port, info["proto"], redirect, subnet=info["subnet"], name=info["name"])
        ok, msg = _apply_instance(info["name"], content, port, info["proto"])
    if not ok:
        if old != port:
            close_firewall_port(port, (info["proto"],))
            persist_firewall_rules()
        return False, msg
    extras["roles"][role] = {"port": int(port)}
    _save_extras(extras, ports_dict)
    if old and int(old) != int(port):
        close_firewall_port(int(old), (info["proto"],))
        persist_firewall_rules()
    return True, msg


def _remove_role(role, ports_dict):
    info = ROLE_INFO[role]
    extras = _load_extras()
    port = extras["roles"].pop(role, {}).get("port")
    if "unit" in info:
        unit = info["unit"]
        _run(f"systemctl stop {unit}")
        _run(f"systemctl disable {unit}")
        try:
            os.remove(_bridge_unit_path(role))
        except FileNotFoundError:
            pass
        _run("systemctl daemon-reload")
        if not any(r in extras["roles"] for r in ("ssl", "ws")):
            _remove_instance(INT_NAME, INT_SUBNET)
    else:
        _remove_instance(info["name"], info["subnet"])
    if port:
        close_firewall_port(int(port), (info["proto"],))
    persist_firewall_rules()
    _save_extras(extras, ports_dict)
    for client in _list_client_profiles():
        if client.endswith("-" + role) and not os.path.exists(f"{PKI_DIR}/issued/{client}.crt"):
            try:
                os.remove(f"{CLIENT_DIR}/{client}.ovpn")
            except FileNotFoundError:
                pass


def _remove_all_extras(ports_dict):
    for role in list(_load_extras().get("roles", {})):
        _remove_role(role, ports_dict)
    _remove_instance(INT_NAME, INT_SUBNET)
    try:
        os.remove(BRIDGE_SCRIPT)
    except FileNotFoundError:
        pass


def _generate_extra_profiles(client_name, server_ip):
    """One extra .ovpn per installed extra profile, same client certificate."""
    made = []
    for role, info in _load_extras().get("roles", {}).items():
        path = _generate_client_profile(client_name, server_ip, info.get("port"), ROLE_INFO[role]["proto"],
                                        suffix="-" + role, note=ROLE_NOTE[role])
        if path:
            made.append(path)
    return made


def _client_names():
    names = []
    for n in _list_client_profiles():
        if any(n.endswith("-" + r) for r in ROLE_INFO) and not os.path.exists(f"{PKI_DIR}/issued/{n}.crt"):
            continue
        names.append(n)
    return names


def _more_protocols_menu(ports_dict):
    while True:
        if not os.path.exists(SERVER_CONF_PATH):
            print(f"{C_RED}[X] Install the main OpenVPN first (option 1) - the extra profiles share its")
            print(f"    certificates and keys.{C_RESET}")
            input("\nPress Enter to continue...")
            return
        main_port = ports_dict.get('OPENVPN_PORT', '?')
        main_proto = str(ports_dict.get('OPENVPN_PROTO', 'udp')).lower()
        extras = _load_extras().get("roles", {})
        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s      MORE OPENVPN PROTOCOLS (run side by side)              %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f" Main OpenVPN : {main_port}/{main_proto.upper()}   (profile <client>.ovpn)")
        print(BAR_LINE)
        keys = ["udp", "tcp", "ssl", "ws"]
        for i, role in enumerate(keys, 1):
            label = ROLE_INFO[role]["label"]
            if role in ("udp", "tcp") and role == main_proto:
                state = f"{C_CYAN}is the MAIN instance (change it with option [2] of the OpenVPN menu){C_RESET}"
            elif role in extras:
                state = "%s%s%s  port %s  -> <client>-%s.ovpn" % (
                    C_GREEN if _role_active(role) else C_RED, "ON" if _role_active(role) else "OFF", C_RESET,
                    extras[role].get("port"), role)
            else:
                state = "not installed"
            print(f" [{i}]> {label:<10} {state}")
        print(" [5]> CREATE THE EXTRA PROFILES FOR EXISTING CLIENTS")
        print(BAR_LINE)
        print(" SSLPayload needs no server part: it uses the TCP profile behind the app's payload/proxy.")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN")
        ch = input(" Enter an Option: ").strip()
        if ch == '0':
            return
        if ch == '5':
            server_ip = get_public_ip() or os.popen("hostname -I | awk '{print $1}'").read().strip()
            total = 0
            for name in _client_names():
                total += len(_generate_extra_profiles(name, server_ip))
            print(f"{C_GREEN}[OK] {total} extra profile file(s) written to {CLIENT_DIR}.{C_RESET}")
            input("\nPress Enter to continue...")
            continue
        if ch not in ("1", "2", "3", "4"):
            continue
        role = keys[int(ch) - 1]
        info = ROLE_INFO[role]
        if role in ("udp", "tcp") and role == main_proto:
            print(f"{C_YELLOW}[i] {info['label']} is already the main instance.{C_RESET}")
            input("\nPress Enter to continue...")
            continue
        if role in extras:
            print(f"\n {info['label']} is installed on port {extras[role].get('port')}.")
            print(" [1] Change port   [2] Restart   [3] Remove   [0] Back")
            sub = input(" Select option: ").strip()
            if sub == '1':
                cur = int(extras[role].get("port"))
                new_port = prompt_port(f" New port [Current: {cur}]: ", default=cur)
                if new_port != cur and check_system_port_in_use(new_port, (info["proto"],)):
                    print(f"{C_RED}[X] Port {new_port}/{info['proto']} is already in use.{C_RESET}")
                else:
                    ok, msg = _install_role(role, new_port, ports_dict)
                    print((C_GREEN + "[OK] " if ok else C_RED + "[X] ") + msg + C_RESET)
                    if ok:
                        print(f"{C_YELLOW}[i] Use option [5] to rewrite the client profiles with the new port.{C_RESET}")
            elif sub == '2':
                if "unit" in info:
                    ok = _run(f"systemctl restart {info['unit']}").returncode == 0
                else:
                    ok = _run(f"systemctl restart openvpn-server@{info['name']}").returncode == 0
                print(f"{C_GREEN}[OK] Restarted.{C_RESET}" if ok else f"{C_RED}[X] Restart failed.{C_RESET}")
            elif sub == '3':
                if input(f" Remove the {info['label']} profile? (y/n): ").strip().lower() == 'y':
                    _remove_role(role, ports_dict)
                    print(f"{C_GREEN}[OK] {info['label']} removed.{C_RESET}")
            input("\nPress Enter to continue...")
            continue
        port = prompt_port(f" {info['label']} listen port (e.g. {info['default']}): ", default=info["default"])
        if check_system_port_in_use(port, (info["proto"],)):
            print(f"{C_RED}[X] Port {port}/{info['proto']} is already in use by another service.{C_RESET}")
            if port in (443, 80):
                print(f"{C_YELLOW}    (Multiplexing / Stunnel / a web server may hold it - pick another port.){C_RESET}")
            input("\nPress Enter to continue...")
            continue
        if role == "ssl":
            print(f"{C_CYAN}[i] A self-signed certificate is created for the SSL front. In the app the SNI is free,")
            print(f"    the server does not check it.{C_RESET}")
        print(f"{C_CYAN}[i] Installing {info['label']}...{C_RESET}")
        ok, msg = _install_role(role, port, ports_dict)
        if ok:
            server_ip = get_public_ip() or os.popen("hostname -I | awk '{print $1}'").read().strip()
            made = 0
            for name in _client_names():
                made += len([1 for r, p in [(role, _generate_client_profile(
                    name, server_ip, port, info["proto"], suffix="-" + role, note=ROLE_NOTE[role]))] if p])
            print(f"{C_GREEN}[OK] {msg}{C_RESET}")
            print(f"     {made} client profile(s) written as {CLIENT_DIR}/<client>-{role}.ovpn")
        else:
            print(f"{C_RED}[X] {msg}{C_RESET}")
        input("\nPress Enter to continue...")


def _fix_tcp_exit_notify():
    """A TCP server.conf written by the old template contains the UDP-only
    'explicit-exit-notify' line, which stops OpenVPN from starting. Strip it."""
    if not os.path.exists(SERVER_CONF_PATH):
        return False
    conf = _read_text(SERVER_CONF_PATH)
    if not re.search(r'(?m)^proto\s+tcp', conf) or "explicit-exit-notify" not in conf:
        return False
    with open(SERVER_CONF_PATH, "w") as f:
        f.write(re.sub(r'(?m)^explicit-exit-notify.*\n?', '', conf))
    return _restart_openvpn()


def _fix_extra_tun_names():
    """Extra instances installed earlier use 'dev tun' and can occupy tun1, which blocks the ICMP
    tunnel. Give each its own fixed name, restart it, then bring ICMP back if it is installed."""
    changed = []
    try:
        names = [f[:-5] for f in os.listdir(OPENVPN_SERVER_DIR) if f.endswith(".conf") and f != "server.conf"]
    except Exception:
        return changed
    for name in names:
        path = _inst_conf(name)
        conf = _read_text(path)
        if not re.search(r'(?m)^dev\s+tun\s*$', conf):
            continue
        with open(path, "w") as f:
            f.write(re.sub(r'(?m)^dev\s+tun\s*$', "dev " + _dev_for(name), conf, count=1))
        _run(["systemctl", "restart", f"openvpn-server@{name}"])
        changed.append(name)
    if changed and os.path.exists("/etc/systemd/system/icmp-vpn.service"):
        _run(["systemctl", "reset-failed", "icmp-vpn"])
        _run(["systemctl", "restart", "icmp-vpn"])
        _run(["systemctl", "restart", "icmp-vpn-gate"])
    return changed


def openvpn_admin_manager(ports_dict):
    """OpenVPN Administrator Module."""
    _fix_extra_tun_names()
    if _fix_tcp_exit_notify():
        print(f"{C_GREEN}[OK] The TCP server config had a UDP-only line that stopped OpenVPN from starting - removed, service restarted.{C_RESET}")
        input("\nPress Enter to continue...")
    if _migrate_legacy_subnet():
        print(f"{C_GREEN}[OK] OpenVPN moved from {LEGACY_VPN_SUBNET}/24 to {VPN_SUBNET}/24 (it clashed with the")
        print(f"     ICMP tunnel subnet and caused 'connected but no internet'). Reconnect the app.{C_RESET}")
        input("\nPress Enter to continue...")

    while True:
        ovpn_port = ports_dict.get('OPENVPN_PORT', 'Not configured')
        ovpn_proto = ports_dict.get('OPENVPN_PROTO', 'udp')
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        mod_on = _mod_active()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                   OPENVPN ADMINISTRATOR                    %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(f"      PORT: {ovpn_port}  |  PROTOCOL: {ovpn_proto.upper() if isinstance(ovpn_proto, str) else ovpn_proto}")
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL OPENVPN (Wizard)")
        print(" [2]> CHANGE PORT & PROTOCOL (TCP/UDP)")
        print(" [3]> MANAGE CLIENTS (Add/Revoke)")
        print(" [4]> VIEW SERVICE LOGS")
        print(" [5]> RESTART OPENVPN SERVICE")
        print(f" [6]> START/STOP OPENVPN SERVICE [{status_label}]")
        print(f" [8]> PORT MOD (redirect a range of ports here) [{'ON' if mod_on else 'OFF'}]")
        print(" [9]> CONNECTION INFO / CLIENT SETUP")
        print(" [10]> MORE PROTOCOLS (UDP / TCP / SSL / WEBSOCKET profiles)")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [7] UNINSTALL OPENVPN")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s            OPENVPN INSTALLATION WIZARD                     %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            proto_choice = input(" Select Protocol ([1] UDP / [2] TCP) [Default: UDP]: ").strip()
            listen_proto = "tcp" if proto_choice == '2' else "udp"

            listen_port = prompt_port(" Enter desired OpenVPN Listen Port (e.g., 1194 or 443): ", default=1194)
            if str(listen_port) != str(ovpn_port) and check_system_port_in_use(listen_port, (listen_proto,)):
                print(f"{C_RED}[X] Port {listen_port}/{listen_proto} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            redirect_gateway = input(" Enable full traffic redirection (route ALL client traffic through the VPN)? (y/n) [Default: y]: ").strip().lower() != 'n'

            print(f"\n[i] Installing OpenVPN and Easy-RSA packages...")
            _run("apt-get update && apt-get install -y openvpn easy-rsa iptables")

            if not _ensure_pki():
                input("\nPress Enter to continue...")
                continue
            if not _ensure_crl_generated():
                print(f"{C_RED}[X] CRL generation failed - revocation wouldn't be enforceable without it.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            new_content = _build_config(listen_port, listen_proto, redirect_gateway)

            _ensure_ip_forwarding()
            interface = _default_interface()
            _ensure_masquerade(interface)
            open_firewall_port(listen_port, (listen_proto,))
            persist_firewall_rules()
            _run("systemctl enable openvpn-server@server")

            ok, msg = _apply_config_safely(new_content, f"OpenVPN on port {listen_port}/{listen_proto}", listen_port, listen_proto)
            if ok:
                ports_dict['OPENVPN_PORT'] = str(listen_port)
                ports_dict['OPENVPN_PROTO'] = listen_proto
                _save_state_now(ports_dict)
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
                print(f"{C_CYAN}    NAT/MASQUERADE enabled on {interface} so clients actually reach the internet.{C_RESET}")
            else:
                close_firewall_port(listen_port, (listen_proto,))
                _remove_masquerade(interface)
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s              CHANGE PORT & PROTOCOL SETTINGS               %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(SERVER_CONF_PATH):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(f" Enter new OpenVPN port [Current: {ovpn_port}]: ",
                                    default=int(ovpn_port) if str(ovpn_port).isdigit() else 1194)
            proto_choice = input(" Select Protocol ([1] UDP / [2] TCP): ").strip()
            new_proto = "tcp" if proto_choice == '2' else "udp"

            if (str(new_port), new_proto) != (str(ovpn_port), ovpn_proto) and check_system_port_in_use(new_port, (new_proto,)):
                print(f"{C_RED}[X] Port {new_port}/{new_proto} is already in use by another service.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            with open(SERVER_CONF_PATH, "r") as f:
                existing = f.read()
            redirect_gw = 'redirect-gateway' in existing and not '# push redirect-gateway' in existing
            new_content = _build_config(new_port, new_proto, redirect_gw)

            # PORT MOD's redirect rules point at the OLD real port/protocol -
            # left in place across a port/protocol change they'd either
            # redirect to a port nothing listens on anymore, or (same port
            # number, different protocol) silently stop matching anything.
            # Safer to drop them now and have the admin explicitly turn MOD
            # back on against the new port/protocol than leave a stale rule
            # that looks active but does nothing.
            mod_was_on = _mod_active()
            if mod_was_on:
                _disable_port_mod()

            open_firewall_port(new_port, (new_proto,))
            persist_firewall_rules()

            ok, msg = _apply_config_safely(new_content, f"Port change to {new_port}/{new_proto}", new_port, new_proto)
            if ok:
                old_port, old_proto = ovpn_port, ovpn_proto
                ports_dict['OPENVPN_PORT'] = str(new_port)
                ports_dict['OPENVPN_PROTO'] = new_proto
                _save_state_now(ports_dict)
                if str(old_port).isdigit() and (str(old_port), old_proto) != (str(new_port), new_proto):
                    close_firewall_port(int(old_port), (old_proto,))
                    persist_firewall_rules()
                print(f"{C_GREEN}[OK] {msg}{C_RESET}")
                if mod_was_on:
                    print(f"{C_YELLOW}[!] PORT MOD was ON and has been turned off (it pointed at the old")
                    print(f"    port/protocol) - re-enable it from this menu (option 8) if you still")
                    print(f"    want a range redirected to the new port.{C_RESET}")
            else:
                close_firewall_port(new_port, (new_proto,))
                print(f"{C_RED}[X] {msg}{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   MANAGE OPENVPN CLIENTS                   %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(PKI_DIR):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            print(" [1] Add a client")
            print(" [2] Revoke a client")
            print(" [0] Back")
            sub = input(" Select option: ").strip()

            if sub == '1':
                client_name = input(" Enter client profile name (e.g., user1): ").strip()
                print(f"{C_CYAN}[i] Generating client certificate...{C_RESET}")
                ok, result = create_client(client_name, ovpn_port, ovpn_proto)
                if ok:
                    existing_clients = ports_dict.get('OPENVPN_CLIENTS', '')
                    clients = [c for c in existing_clients.split(',') if c] if existing_clients else []
                    clients.append(client_name)
                    ports_dict['OPENVPN_CLIENTS'] = ",".join(clients)
                    print(f"{C_GREEN}[OK] Client '{client_name}' created. Profile ready at:{C_RESET}")
                    print(f"     {result}")
                else:
                    print(f"{C_RED}[X] {result}{C_RESET}")

            elif sub == '2':
                client_name = input(" Enter client name to revoke: ").strip()
                if not os.path.exists(f"{PKI_DIR}/issued/{client_name}.crt"):
                    print(f"{C_RED}[X] No such client.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                confirm = input(f" Revoke '{client_name}'? This immediately blocks their access. (y/n): ").strip().lower()
                if confirm == 'y':
                    _easyrsa("revoke", client_name)
                    if _ensure_crl_generated():
                        for sfx in ("",) + tuple("-" + r for r in ROLE_INFO):
                            try:
                                os.remove(f"{CLIENT_DIR}/{client_name}{sfx}.ovpn")
                            except FileNotFoundError:
                                pass
                        existing_clients = ports_dict.get('OPENVPN_CLIENTS', '')
                        clients = [c for c in existing_clients.split(',') if c and c != client_name]
                        ports_dict['OPENVPN_CLIENTS'] = ",".join(clients)
                        print(f"{C_GREEN}[OK] '{client_name}' revoked - the CRL was regenerated so this takes effect")
                        print(f"     immediately without needing a restart (crl-verify checks it on each connect).{C_RESET}")
                    else:
                        print(f"{C_RED}[X] Revoke command ran but CRL regeneration failed - revocation may not be enforced yet.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  OPENVPN SERVICE LOGS                      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            os.system("journalctl -u openvpn-server@server -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '5':
            if _restart_openvpn():
                print(f"{C_GREEN}[OK] OpenVPN service restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] OpenVPN failed to restart - check 'journalctl -u openvpn-server@server'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if is_active:
                _run("systemctl stop openvpn-server@server")
                print(f"{C_YELLOW}[!] OpenVPN service stopped.{C_RESET}")
            else:
                if not os.path.exists(SERVER_CONF_PATH):
                    print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start openvpn-server@server")
                if _service_active():
                    print(f"{C_GREEN}[OK] OpenVPN service started.{C_RESET}")
                else:
                    print(f"{C_RED}[X] OpenVPN failed to start - check 'journalctl -u openvpn-server@server'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                   UNINSTALL OPENVPN                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Are you sure you want to completely remove OpenVPN? (y/n): ").strip().lower()
            if confirm == 'y':
                if _mod_active():
                    _disable_port_mod()
                try:
                    _remove_all_extras(ports_dict)
                except Exception:
                    pass
                _run("systemctl stop openvpn-server@server && systemctl disable openvpn-server@server")
                _run("apt-get purge -y openvpn easy-rsa")
                if str(ovpn_port).isdigit():
                    close_firewall_port(int(ovpn_port), (ovpn_proto,))
                    persist_firewall_rules()
                interface = _default_interface()
                _remove_masquerade(interface)
                _run(f"rm -f {SYSCTL_DROPIN_PATH}")
                _run(f"rm -rf {OPENVPN_DIR}")
                ports_dict.pop('OPENVPN_PORT', None)
                ports_dict.pop('OPENVPN_PROTO', None)
                ports_dict.pop('OPENVPN_CLIENTS', None)
                _save_state_now(ports_dict)
                print(f"{C_GREEN}[OK] OpenVPN purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                        PORT MOD                            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not os.path.exists(SERVER_CONF_PATH):
                print(f"{C_RED}[X] Not installed yet - run option 1 first - there's no real port")
                print(f"    yet to redirect traffic to.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            if mod_on:
                print(f" Currently ON - every {ovpn_proto.upper()} port redirects to OpenVPN's real port.")
                confirm = input(" Turn PORT MOD off? (y/n): ").strip().lower()
                if confirm == 'y':
                    _disable_port_mod()
                    print(f"{C_GREEN}[OK] PORT MOD disabled - only the configured port ({ovpn_port}) works now.{C_RESET}")
                else:
                    print(f"{C_YELLOW}[i] Cancelled.{C_RESET}")
            else:
                print(f" This redirects {ovpn_proto.upper()} traffic on this server to your real")
                print(f" OpenVPN port ({ovpn_port}) - clients can connect on a redirected port")
                print(" instead of the real one, which helps on networks that throttle or")
                print(" block specific well-known ports.")
                print()
                print(f"{C_YELLOW}[i] Clients still need a valid certificate either way - this only")
                print(f"    widens which port reaches the server, not who's allowed through.{C_RESET}")
                print()
                allow_all = (str(ovpn_proto).lower() == "udp")
                if allow_all:
                    print(f" [1] ALL {ovpn_proto.upper()} ports (1-65535) - default")
                else:
                    print(f"{C_YELLOW} A blanket redirect of every TCP port is not offered: it is what")
                    print(f" locked an admin out of their server. Choose explicit range(s).{C_RESET}")
                print(" [2] Custom range(s), e.g. 5000-10000,10001-20000")
                range_choice = input(" Select (blank = %s): " % ("1" if allow_all else "2")).strip() or ("1" if allow_all else "2")
                if range_choice == "1" and not allow_all:
                    range_choice = "2"
                port_ranges = None
                if range_choice == "2":
                    raw_ranges = input(" Enter range(s), comma-separated (e.g. 5000-10000,10001-20000): ").strip()
                    port_ranges = _parse_port_ranges(raw_ranges)
                    if not port_ranges:
                        print(f"{C_RED}[X] Couldn't parse that - expected things like '5000-10000', each")
                        print(f"    endpoint 1-65535. Nothing changed.{C_RESET}")
                        input("\nPress Enter to continue...")
                        continue
                confirm = input(" Turn PORT MOD on? (y/n): ").strip().lower()
                if confirm == 'y':
                    if _guarded_enable(OPENVPN_MOD_COMMENT,
                                       lambda: _enable_port_mod(int(ovpn_port), ovpn_proto, ports_dict, port_ranges),
                                       _mod_active):
                        scope = ", ".join(port_ranges) if port_ranges else f"every {ovpn_proto.upper()} port (1-65535)"
                        print(f"{C_GREEN}[OK] PORT MOD enabled - {scope} now reaches OpenVPN on {ovpn_port}.{C_RESET}")
                    else:
                        print(f"{C_RED}[X] PORT MOD is OFF - it was not applied or not confirmed. Nothing was saved.{C_RESET}")
                else:
                    print(f"{C_YELLOW}[i] Cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == '9':
            if not os.path.exists(SERVER_CONF_PATH):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            _connection_info(ports_dict)

        elif choice == '10':
            _more_protocols_menu(ports_dict)

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
