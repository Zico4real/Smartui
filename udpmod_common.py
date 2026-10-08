#!/usr/bin/env python3
"""udpmod_common.py - ONE shared arbiter for every "UDP MOD" / port-hopping rule.

WHY THIS FILE EXISTS
--------------------
Hysteria 1, ZIVPN (UDP Custom), UDP Droid and Hysteria 2 (port hopping) each
used to add their own wide `-t nat PREROUTING ... -j REDIRECT` rule. iptables
stops at the FIRST rule that matches a packet, so as soon as two of them
covered the same ports only the one earlier in the chain received any
traffic - the others silently stopped working (UDP Droid even inserted itself
at the very top, shadowing everything else). Whichever UDP MOD was switched
on last or first "won", and the rest looked broken.

HOW IT WORKS NOW
----------------
Nobody touches iptables directly any more. Each protocol only tells this
module "I am <owner>, my real port is N, my ranges are R". This module keeps
that in a small state file and then REBUILDS all UDP MOD rules from scratch:

  * Ports that must never be redirected (53, 123, 500, 1194, 1701, 4500,
    51820, every port something is listening on, every owner's real port)
    are cut OUT of the ranges - there are no RETURN rules any more, so
    nothing after them in the chain can be skipped by accident.
  * Where two owners' ranges overlap, the NARROWER range wins (a specific
    range beats a catch-all). The result is a set of non-overlapping
    segments, so install order and rule order no longer matter at all.
  * Every rule carries its owner's comment tag, so one protocol can be turned
    off without touching the others. Old-style rules with those tags are
    adopted automatically on upgrade.

Because the state is rebuilt from the Python files each time, a brand-new VPS
gets the same correct behaviour with no manual iptables work.
"""

import json
import os
import shlex
import subprocess

# owner -> iptables comment tag (kept identical to the tags older versions
# of the managers used, so existing rules are recognised and adopted).
OWNER_TAGS = {
    "hysteria1": "hysteria1-udpmod",
    "zivpn": "zivpn-udpmod",
    "udpdroid": "udpdroid-udpmod",
    "hysteria2": "hysteria2-hop",
}
OWNER_LABELS = {
    "hysteria1": "Hysteria 1",
    "zivpn": "ZIVPN / UDP Custom",
    "udpdroid": "UDP Droid",
    "hysteria2": "Hysteria 2 (port hop)",
}
# Suggested non-overlapping defaults, offered when the user does not have a
# range in mind.
DEFAULT_RANGES = {
    "hysteria1": "10000:19999",
    "zivpn": "20000:29999",
    "hysteria2": "30000:39999",
    "udpdroid": "40000:49999",
}

# UDP ports that belong to other tunnel protocols on this server and must never
# be redirected: DNS router 53, NTP/Hysteria2 123, IPsec 500/4500, OpenVPN 1194,
# L2TP 1701, WireGuard 51820.
RESERVED_UDP_PORTS = {53, 123, 500, 1194, 1701, 4500, 51820}

STATE_PATH = "/etc/zedsocks-udpmod.json"

# Legacy "wide" UDP redirects that nobody tagged (an old hand-typed
# `--dport 1:65000 -j REDIRECT`, for instance) are reported when they span at
# least this many ports.
LEGACY_MIN_SPAN = 100


# --------------------------------------------------------------------------
# low-level helpers
# --------------------------------------------------------------------------
class _Res:
    def __init__(self, rc=1, out="", err=""):
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        return _Res(r.returncode, r.stdout or "", r.stderr or "")
    except Exception as e:  # tool missing, etc.
        return _Res(127, "", str(e))


def _tables():
    return ("iptables", "ip6tables")


def _list_rules(tool):
    """Rules of nat/PREROUTING as token lists (from `-S`)."""
    res = _run([tool, "-t", "nat", "-S", "PREROUTING"])
    rules = []
    if res.returncode != 0:
        return rules
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line.startswith("-A PREROUTING"):
            continue
        try:
            rules.append(shlex.split(line))
        except ValueError:
            continue
    return rules


def _opt(tokens, name):
    """Value after `name` in tokens, or None."""
    for i, t in enumerate(tokens):
        if t == name and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def _is_negated(tokens, name):
    for i, t in enumerate(tokens):
        if t == name and i > 0 and tokens[i - 1] == "!":
            return True
    return False


def _delete_rule(tool, tokens):
    spec = ["-D"] + tokens[1:]  # "-A PREROUTING ..." -> "-D PREROUTING ..."
    return _run([tool, "-t", "nat"] + spec).returncode == 0


def listening_udp_ports():
    """UDP ports something on this machine is already listening on."""
    found = set()
    res = _run(["ss", "-H", "-lun"])
    for line in res.stdout.splitlines():
        cols = line.split()
        if len(cols) >= 4:
            port = cols[3].rsplit(":", 1)[-1]
            if port.isdigit():
                found.add(int(port))
    return found


def public_iface():
    """The server's public (default-route) network interface. UDP MOD rules
    are restricted to packets ARRIVING on it, so traffic coming out of
    the tunnels themselves (tun*/ppp*/wg*/ipsec*) is never redirected.
    Override with env UDPMOD_IFACE. Returns None if it cannot be found
    (rules then fall back to the old interface-less form)."""
    env = os.environ.get("UDPMOD_IFACE")
    if env:
        return env
    for cmd in (["ip", "-o", "route", "get", "1.1.1.1"], ["ip", "-o", "-4", "route", "show", "default"]):
        out = _run(cmd).stdout.split()
        if "dev" in out and out.index("dev") + 1 < len(out):
            return out[out.index("dev") + 1]
    return None


def _persist():
    try:
        from panel_common import persist_firewall_rules
        persist_firewall_rules()
    except Exception:
        pass


def _kernel_prep():
    # Needed so REDIRECTed traffic from odd source ports is not dropped by
    # reverse-path filtering.
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    iface = None
    try:
        from openvpn_manager import _default_interface
        iface = _default_interface()
    except Exception:
        iface = None
    if iface:
        _run(["sysctl", "-w", "net.ipv4.conf.%s.rp_filter=0" % iface])
    _run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"])


# --------------------------------------------------------------------------
# range helpers
# --------------------------------------------------------------------------
def parse_ranges(text):
    """'10000-19999, 22000:22999 5000' -> ['10000:19999','22000:22999','5000'].
    Empty text -> []. Invalid text -> None."""
    out = []
    if text is None:
        return []
    for part in str(text).replace(",", " ").split():
        part = part.strip()
        if not part:
            continue
        part = part.replace("-", ":")
        bits = part.split(":")
        if len(bits) > 2 or not all(b.isdigit() for b in bits):
            return None
        lo = int(bits[0])
        hi = int(bits[-1])
        if not (1 <= lo <= hi <= 65535):
            return None
        out.append("%d:%d" % (lo, hi) if lo != hi else str(lo))
    return out


def _to_intervals(ranges):
    iv = []
    for r in ranges or []:
        r = str(r).replace("-", ":")
        a, _, b = r.partition(":")
        if not a.isdigit():
            continue
        lo = int(a)
        hi = int(b) if b.isdigit() else lo
        if 1 <= lo <= hi <= 65535:
            iv.append((lo, hi))
    return _merge(iv)


def _merge(iv):
    iv = sorted(iv)
    out = []
    for lo, hi in iv:
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _subtract(a, b):
    """Intervals in a that are not in b (both merged & sorted)."""
    res = []
    for lo, hi in a:
        cur = lo
        for blo, bhi in b:
            if bhi < cur or blo > hi:
                continue
            if blo > cur:
                res.append((cur, blo - 1))
            cur = max(cur, bhi + 1)
            if cur > hi:
                break
        if cur <= hi:
            res.append((cur, hi))
    return res


def _span(iv):
    return sum(hi - lo + 1 for lo, hi in iv)


def _fmt(iv):
    return ",".join(("%d:%d" % (lo, hi)) if lo != hi else str(lo) for lo, hi in iv)


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------
def _load_state():
    try:
        with open(STATE_PATH) as f:
            st = json.load(f)
        if not isinstance(st, dict):
            raise ValueError
    except Exception:
        st = {}
    st.setdefault("owners", {})
    st.setdefault("exclude", [])
    return st


def _save_state(st):
    try:
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f, indent=1, sort_keys=True)
        os.replace(tmp, STATE_PATH)
    except Exception:
        pass  # best effort - live rules are re-adopted if the file is lost


def _adopt_live(st):
    """Owners that have live tagged REDIRECT rules but are missing from the
    state file (rules created by an older version of the panel) are taken
    over, so rebuilding never throws them away."""
    tag_to_owner = {v: k for k, v in OWNER_TAGS.items()}
    adopted = {}
    for rule in _list_rules("iptables"):
        tag = _opt(rule, "--comment")
        owner = tag_to_owner.get(tag)
        if not owner or owner in st["owners"]:
            continue
        if _opt(rule, "-j") != "REDIRECT":
            continue
        port = _opt(rule, "--to-ports") or _opt(rule, "--to-port")
        dport = _opt(rule, "--dport")
        if not (port and port.isdigit() and dport):
            continue
        ent = adopted.setdefault(owner, {"real_port": int(port), "ranges": [], "seq": len(adopted) + _max_seq(st) + 1})
        for r in parse_ranges(dport) or []:
            if r not in ent["ranges"]:
                ent["ranges"].append(r)
    for owner, ent in adopted.items():
        st["owners"][owner] = ent
    return st


def _max_seq(st):
    return max([int(e.get("seq", 0) or 0) for e in st["owners"].values()] or [0])


# --------------------------------------------------------------------------
# planning (pure - easy to test)
# --------------------------------------------------------------------------
def plan(owners, excluded_ports):
    """-> {owner: [(lo,hi), ...]} non-overlapping segments, narrower owner first
    wins; excluded ports are cut out of everything."""
    ex = _merge([(p, p) for p in sorted(set(excluded_ports)) if 1 <= p <= 65535])
    wants = {}
    for owner, ent in owners.items():
        wants[owner] = _to_intervals(ent.get("ranges") or [])
    # narrower range first; for equal width the one applied FIRST keeps the ports
    order = sorted(wants, key=lambda o: (_span(wants[o]), int(owners[o].get("seq", 0) or 0), o))
    covered = []
    result = {}
    for owner in order:
        segs = _subtract(_subtract(wants[owner], ex), covered)
        result[owner] = segs
        covered = _merge(covered + segs)
    return result


def _excluded_ports(st):
    ex = set(RESERVED_UDP_PORTS)
    try:
        ex |= listening_udp_ports()
    except Exception:
        pass
    for p in st.get("exclude", []):
        if str(p).isdigit():
            ex.add(int(p))
    for ent in st["owners"].values():
        rp = ent.get("real_port")
        if str(rp).isdigit():
            ex.add(int(rp))
    return ex


# --------------------------------------------------------------------------
# rebuild
# --------------------------------------------------------------------------
def _purge_tagged():
    tags = set(OWNER_TAGS.values())
    for tool in _tables():
        for _ in range(500):  # safety bound
            victim = None
            for rule in _list_rules(tool):
                if _opt(rule, "--comment") in tags:
                    victim = rule
                    break
            if victim is None:
                break
            if not _delete_rule(tool, victim):
                break


def _rebuild(st):
    segs = plan(st["owners"], _excluded_ports(st))
    _purge_tagged()
    iface = public_iface()
    st["iface"] = iface or ""
    _save_state(st)
    for tool in _tables():
        for owner, iv in segs.items():
            ent = st["owners"][owner]
            tag = OWNER_TAGS[owner]
            for lo, hi in iv:
                dport = "%d:%d" % (lo, hi) if lo != hi else str(lo)
                _run([tool, "-t", "nat", "-A", "PREROUTING"] + (["-i", iface] if iface else []) +
                     ["-p", "udp", "--dport", dport, "-m", "comment", "--comment", tag,
                      "-j", "REDIRECT", "--to-port", str(ent["real_port"])])
    _persist()
    return segs


def set_owner(owner, real_port, ranges=None, extra_exclude=None):
    """Turn UDP MOD on (or change it) for `owner`.
    ranges: list like ['10000:19999'] ; empty/None = every free UDP port.
    Returns (ok, info) with info = {"segments": [...], "shadowed": bool,
    "overlaps": [(other_owner, 'a:b'), ...], "message": str}."""
    if owner not in OWNER_TAGS:
        return False, {"message": "unknown owner %r" % owner}
    _kernel_prep()
    st = _adopt_live(_load_state())
    ranges = list(ranges) if ranges else ["1:65535"]
    prev = st["owners"].get(owner) or {}
    seq = prev.get("seq") or (_max_seq(st) + 1)
    st["owners"][owner] = {"real_port": int(real_port), "ranges": ranges, "seq": seq}
    if extra_exclude:
        cur = set(int(p) for p in st["exclude"] if str(p).isdigit())
        for p in extra_exclude:
            if str(p).isdigit() and int(p) != int(real_port):
                cur.add(int(p))
        st["exclude"] = sorted(cur)
    _save_state(st)
    segs = _rebuild(st)
    mine = segs.get(owner, [])
    info = {"segments": mine, "shadowed": not mine, "overlaps": [], "message": ""}
    want = _to_intervals(ranges)
    for other, ent in st["owners"].items():
        if other == owner:
            continue
        ov = _subtract(want, _subtract(want, _to_intervals(ent.get("ranges") or [])))
        # only report real conflicts, i.e. where somebody ends up losing ports
        if ov:
            info["overlaps"].append((other, _fmt(ov)))
    if not mine:
        winners = [o for o, v in segs.items() if o != owner and _subtract(want, _subtract(want, v))]
        who = ", ".join(OWNER_LABELS[o] for o in winners) or "reserved ports"
        info["message"] = ("%s is registered. Every redirected port in %s is currently served by %s "
                           "(narrower range, or applied first, keeps shared ports). %s's own real port %s "
                           "still works directly, and it takes over automatically if %s is turned off." % (
                               OWNER_LABELS[owner], ",".join(ranges), who, OWNER_LABELS[owner], real_port, who))
        return True, info
    live = any(_opt(r, "--comment") == OWNER_TAGS[owner] for r in _list_rules("iptables"))
    info["message"] = "UDP MOD active for %s on %s -> port %s" % (OWNER_LABELS[owner], _fmt(mine), real_port)
    return live, info


def clear_owner(owner):
    st = _adopt_live(_load_state())
    st["owners"].pop(owner, None)
    _save_state(st)
    _rebuild(st)  # other owners are re-planned (they may regain ports)
    # an owner left with no state must also have no live tagged rules
    return True


def is_active(owner):
    tag = OWNER_TAGS.get(owner)
    live = any(_opt(r, "--comment") == tag for r in _list_rules("iptables"))
    if live:
        return True
    st = _load_state()
    ent = st["owners"].get(owner)
    if ent is None:
        return False
    # registered but every port is taken by a narrower owner / reserved
    segs = plan(st["owners"], _excluded_ports(st))
    return not segs.get(owner)


def shadowed_by(owner):
    """Owner is registered but gets NO ports. Returns the list of owner labels
    that hold the ports it asked for (empty list = reserved ports only), or
    None when the owner is not shadowed (off, or receiving at least some
    ports)."""
    st = _load_state()
    ent = st["owners"].get(owner)
    if ent is None:
        return None
    segs = plan(st["owners"], _excluded_ports(st))
    if segs.get(owner):
        return None
    want = _to_intervals(ent.get("ranges") or [])
    winners = [OWNER_LABELS[o] for o, v in segs.items()
               if o != owner and _subtract(want, _subtract(want, v))]
    return winners


def status_label(owner):
    """Text for the menus: 'ON', 'OFF', or 'ON - NO PORTS (taken by X)'. A
    protocol can be registered yet receive nothing when another protocol's
    range wins every port it asked for - which used to look identical to a
    working 'ON'."""
    if not is_active(owner):
        return "OFF"
    taken = shadowed_by(owner)
    if taken is None:
        return "ON"
    return "ON - NO PORTS (taken by %s)" % (", ".join(taken) if taken else "reserved ports")


def get_ranges(owner):
    ent = _load_state()["owners"].get(owner)
    if ent:
        return list(ent.get("ranges") or [])
    return []


def reapply_all():
    """Re-plan and rewrite all rules (e.g. after a new service started
    listening on a UDP port that now needs excluding)."""
    st = _adopt_live(_load_state())
    _save_state(st)
    return _rebuild(st)


# --------------------------------------------------------------------------
# legacy / foreign rules
# --------------------------------------------------------------------------
def find_legacy_catchalls():
    """Untagged wide UDP REDIRECT rules in nat/PREROUTING that are sitting
    in the way (hand-typed `--dport 1:65000 -j REDIRECT --to-ports 123`,
    rules from older panels, ...). Returns [(tool, tokens, text)]."""
    tags = set(OWNER_TAGS.values())
    found = []
    for tool in _tables():
        for rule in _list_rules(tool):
            if _opt(rule, "--comment") in tags:
                continue
            if _opt(rule, "-p") != "udp" or _opt(rule, "-j") != "REDIRECT":
                continue
            if _is_negated(rule, "--dport"):
                continue
            dport = _opt(rule, "--dport")
            if not dport:
                continue
            span = _span(_to_intervals(parse_ranges(dport) or []))
            if span >= LEGACY_MIN_SPAN:
                found.append((tool, rule, " ".join(shlex.quote(t) for t in rule)))
    return found


def remove_legacy(found):
    n = 0
    for tool, rule, _txt in found:
        if _delete_rule(tool, rule):
            n += 1
    if n:
        _persist()
    return n


# --------------------------------------------------------------------------
# presentation helpers shared by the four menus
# --------------------------------------------------------------------------
def summary_lines():
    st = _adopt_live(_load_state())
    if not st["owners"]:
        return ["  (no UDP MOD / port-hop rules are registered)"]
    segs = plan(st["owners"], _excluded_ports(st))
    lines = []
    for owner in sorted(st["owners"], key=lambda o: (_span(_to_intervals(st["owners"][o].get("ranges") or [])), o)):
        ent = st["owners"][owner]
        eff = segs.get(owner, [])
        lines.append("  %-22s -> port %-6s asked: %-22s effective: %s" % (
            OWNER_LABELS[owner], ent.get("real_port"), ",".join(ent.get("ranges") or []),
            _fmt(eff) if eff else "NONE (shadowed)"))
    return lines


def prompt_and_resolve_legacy(input_fn=input):
    """If untagged wide redirects exist, show them and offer to remove them."""
    found = find_legacy_catchalls()
    if not found:
        return
    print("\n [!] Found wide UDP redirect rule(s) that are NOT managed by the panel.")
    print("     They sit in front of the panel's rules and swallow the traffic:")
    seen = set()
    for _tool, _rule, txt in found:
        if txt not in seen:
            print("       " + txt)
            seen.add(txt)
    ans = input_fn(" Remove them now? (y/n): ").strip().lower()
    if ans == "y":
        n = remove_legacy(found)
        print(" [OK] Removed %d rule(s)." % n)
    else:
        print(" [i] Left in place - UDP MOD may not receive traffic until they are removed.")


def prompt_ranges(owner, input_fn=input):
    """Ask which UDP ports this protocol should answer on. Returns a list of
    ranges ([] = every free port) or None if the user cancelled."""
    st = _adopt_live(_load_state())
    label = OWNER_LABELS.get(owner, owner)
    suggestion = DEFAULT_RANGES.get(owner, "")
    print("\n UDP MOD ports for %s." % label)
    print(" Several protocols can use UDP MOD at the same time, but each one needs")
    print(" its OWN port range, otherwise the clients cannot be told apart.")
    others = [(o, e) for o, e in st["owners"].items() if o != owner]
    if others:
        print(" Already taken:")
        for o, e in others:
            print("   - %-22s %s" % (OWNER_LABELS[o], ",".join(e.get("ranges") or [])))
    print(" Use the SAME ports your client app connects to (the port or range typed in the app).")
    print(" Enter ranges like  10000-19999  (several allowed, separated by commas).")
    print(" Press Enter (or type 'all') to take every port nobody else claimed - lowest")
    print(" priority, so other protocols' ranges are never taken from them.")
    if suggestion:
        print(" (Only if you have no range in mind: %s does not overlap the other defaults.)" % suggestion)
    print(" Type 0 to cancel.")
    while True:
        raw = input_fn(" Ports [all]: ").strip()
        if raw == "0":
            return None
        if raw == "":
            raw = "all"
        if raw.lower() == "all":
            return []
        rngs = parse_ranges(raw)
        if rngs:
            return rngs
        print(" Invalid range, try again (example: 10000-19999).")


# keys in the panel's ports_dict that hold other services' UDP ports
_PORT_KEYS = ('ZIVPN_PORT', 'BADVPN_PORT', 'ICMP_GATE_PORT', 'HYSTERIA_PORT',
              'HYSTERIA1_PORT', 'UDPDROID_TUNNEL_PORT')


def extra_ports_from_dict(ports_dict, real_port):
    """Other protocols' configured UDP ports (even if not running yet)."""
    out = set()
    for key in _PORT_KEYS:
        val = (ports_dict or {}).get(key)
        if val and str(val).isdigit() and int(val) != int(real_port):
            out.add(int(val))
    return out


def enable(owner, real_port, ports_dict=None, ranges=None):
    """set_owner + human-readable report. Returns True when the owner is
    actually receiving traffic."""
    ok, info = set_owner(owner, real_port, ranges, extra_ports_from_dict(ports_dict, real_port))
    if info.get("message"):
        print(" " + info["message"])
    for other, ov in info.get("overlaps", []):
        print(" [i] Ports %s are also wanted by %s - the narrower range wins them." % (ov, OWNER_LABELS[other]))
    return ok


# --------------------------------------------------------------------------
# command line:  python3 udpmod_common.py status | clear-all | clear <owner>
# --------------------------------------------------------------------------
def _cli(argv):
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "status":
        print("== public interface used for UDP MOD: %s ==" % (public_iface() or "unknown (no -i filter)"))
        print("== registered UDP MOD owners ==")
        for ln in summary_lines():
            print(ln)
        print("\n== state file %s ==" % STATE_PATH)
        try:
            print(open(STATE_PATH).read())
        except Exception:
            print("(none)")
        print("== nat PREROUTING (iptables) ==")
        print(_run(["iptables", "-t", "nat", "-S", "PREROUTING"]).stdout or "(empty)")
        print("== UDP listeners ==")
        print(_run(["ss", "-H", "-lun"]).stdout or "(none)")
        leg = find_legacy_catchalls()
        if leg:
            print("== wide redirects NOT managed by the panel ==")
            for _t, _r, txt in leg:
                print("  " + txt)
    elif cmd == "reapply":
        reapply_all()
        print("UDP MOD rules rebuilt (public interface: %s)." % (public_iface() or "unknown - no interface filter"))
    elif cmd == "set" and len(argv) >= 4 and argv[2] in OWNER_TAGS and argv[3].isdigit():
        # python3 udpmod_common.py set <owner> <real_port> [ranges e.g. 1-20000,30000-40000]
        rng = parse_ranges(argv[4]) if len(argv) > 4 else None
        if len(argv) > 4 and not rng:
            print("Could not parse ranges %r" % argv[4]); return
        ok, info = set_owner(argv[2], int(argv[3]), rng)
        print(info.get("message") or ("ok" if ok else "failed"))
    elif cmd == "clear-all":
        st = {"owners": {}, "exclude": []}
        _save_state(st)
        _rebuild(st)
        print("All panel-managed UDP MOD / port-hop rules removed. Real ports are untouched.")
    elif cmd == "clear" and len(argv) > 2 and argv[2] in OWNER_TAGS:
        clear_owner(argv[2])
        print("Removed %s." % argv[2])
    else:
        print("usage: udpmod_common.py status | reapply | clear-all | clear <%s> | set <%s> <real_port> [ranges]" % ("|".join(OWNER_TAGS), "|".join(OWNER_TAGS)))


if __name__ == "__main__":
    import sys
    _cli(sys.argv)
