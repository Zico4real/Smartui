"""
vpn_boot_persist.py - makes SSTP, IKEv2 and L2TP come back by themselves after a
reboot.

Why it exists
-------------
Each of those three modules enables its own systemd unit, but several things
they rely on are only done ONCE, at install time, and do not survive a reboot:

  * the kernel PPP modules (ppp_generic, ...) and /dev/ppp - loaded with a
    plain `modprobe` / `mknod`, never configured to load at boot;
  * the NAT / FORWARD / MSS rules for the client pool - plain `iptables`
    commands; when the server has no netfilter-persistent they are simply gone
    after a reboot (clients connect, then "no internet");
  * the INPUT accept rules, ESP/AH and the "block plain L2TP" rules in the same
    situation;
  * strongSwan's connections/credentials, which have to be loaded with
    `swanctl --load-all` after charon starts;
  * start order - the services can start before the network is up, and a
    service that fails once at boot is never retried.

What it does
------------
ensure()        Installed by the Protocol Manager every time its screen loads
                (cheap and idempotent). Writes
                  /etc/modules-load.d/smartui-vpn.conf   PPP modules at boot
                  /etc/tmpfiles.d/smartui-vpn.conf       /dev/ppp node at boot
                  /etc/systemd/system/<unit>.service.d/smartui-vpn.conf
                                                         start after the network, always restart
                  /usr/local/bin/smartui-vpn-boot.py + smartui-vpn-boot.service
                                                         the restore pass below
restore_all()   Run by that boot service (twice: right after boot and again
                ~45 s later, so a slow network or firewall restore cannot win a
                race). For every protocol that is INSTALLED it re-applies
                forwarding + NAT + firewall rules, enables and starts the
                services and reloads strongSwan - exactly the state the
                install wizard left. It never installs, removes or reconfigures
                anything and never calls `netfilter-persistent save`, so it
                cannot overwrite a good saved rule set with a half-restored one.

Uses only the public helpers of vpn_common / sstp_manager / ikev2_manager /
l2tp_manager that already exist, and does nothing for a protocol that is not
installed. Every step is wrapped, so one failure never blocks the others.
"""

import os
import sys
import time
import subprocess

BOOT_SCRIPT = "/usr/local/bin/smartui-vpn-boot.py"
BOOT_UNIT = "/etc/systemd/system/smartui-vpn-boot.service"
MODULES_CONF = "/etc/modules-load.d/smartui-vpn.conf"
TMPFILES_CONF = "/etc/tmpfiles.d/smartui-vpn.conf"
DROPIN_NAME = "smartui-vpn.conf"

PPP_MODULES = ("ppp_generic", "ppp_async", "ppp_mppe", "l2tp_ppp", "l2tp_netlink", "pppox")

_last_ensure = 0.0


def _run(cmd):
    try:
        if isinstance(cmd, str):
            return subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return subprocess.run(cmd, capture_output=True, text=True)
    except Exception as e:  # never let a missing tool stop the rest
        class _R:
            returncode = 1
            stdout = ""
            stderr = str(e)
        return _R()


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return None


def _write_if_changed(path, content, mode=0o644):
    if _read(path) == content:
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)
    return True


def _panel_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _load_modules():
    """(sstp, ikev2, l2tp, vc) - each may be None when that module is absent."""
    mods = {}
    for name in ("vpn_common", "sstp_manager", "ikev2_manager", "l2tp_manager"):
        try:
            mods[name] = __import__(name)
        except Exception:
            mods[name] = None
    return mods["sstp_manager"], mods["ikev2_manager"], mods["l2tp_manager"], mods["vpn_common"]


def _installed(mod):
    try:
        return bool(mod is not None and mod._installed())
    except Exception:
        return False


def installed_protocols():
    sstp, ikev2, l2tp, _vc = _load_modules()
    found = []
    if _installed(sstp):
        found.append("sstp")
    if _installed(ikev2):
        found.append("ikev2")
    if _installed(l2tp):
        found.append("l2tp")
    return found


def _unit_exists(unit):
    return _run(["systemctl", "cat", unit]).returncode == 0


# ---------------------------------------------------------------- install ---

BOOT_SCRIPT_TEMPLATE = '''#!/usr/bin/env python3
# Deployed by vpn_boot_persist.py - restores SSTP / IKEv2 / L2TP after a reboot.
import sys, time
sys.path.insert(0, %(panel_dir)r)
try:
    import vpn_boot_persist
except Exception as e:
    print("smartui-vpn-boot: cannot load vpn_boot_persist: %%s" %% e)
    sys.exit(1)
vpn_boot_persist.restore_all()
time.sleep(45)          # second pass: network / firewall restore may have finished meanwhile
vpn_boot_persist.restore_all()
'''

BOOT_UNIT_CONTENT = """[Unit]
Description=SmartUI VPN restore after boot (SSTP / IKEv2 / L2TP)
After=network-online.target netfilter-persistent.service ufw.service firewalld.service nftables.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 %s
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
""" % BOOT_SCRIPT

DROPIN_CONTENT = """[Unit]
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=3
"""


def ensure(force=False):
    """Idempotent. Returns the list of installed protocols it protects."""
    global _last_ensure
    now = time.time()
    if not force and now - _last_ensure < 60:
        return []
    _last_ensure = now

    protos = installed_protocols()
    if not protos:
        return []

    changed_units = False
    try:
        # kernel modules at boot (only the ones this kernel actually has)
        available = [m for m in PPP_MODULES if _run(["modprobe", "-n", "-q", m]).returncode == 0]
        if available:
            _write_if_changed(MODULES_CONF, "# SmartUI VPN (SSTP / L2TP)\n" + "\n".join(available) + "\n")
        for m in available:
            _run(["modprobe", m])
        # /dev/ppp at boot (containers / minimal udev)
        if os.path.exists("/dev/ppp"):
            _write_if_changed(TMPFILES_CONF, "c /dev/ppp 0600 root root - 108:0\n")
    except Exception:
        pass

    # start-after-network + always-restart for every service these protocols use
    units = []
    _sstp, _ikev2, _l2tp, vc = _load_modules()
    if "sstp" in protos:
        units.append("smartui-sstp")
    if "l2tp" in protos:
        units.append("xl2tpd")
    if "ikev2" in protos or "l2tp" in protos:
        units.append(getattr(vc, "STRONGSWAN_UNIT", "strongswan") if vc else "strongswan")
    for unit in dict.fromkeys(units):
        try:
            if _unit_exists(unit):
                path = "/etc/systemd/system/%s.service.d/%s" % (unit, DROPIN_NAME)
                changed_units |= _write_if_changed(path, DROPIN_CONTENT)
        except Exception:
            pass
        _run(["systemctl", "enable", unit])

    try:
        changed_units |= _write_if_changed(BOOT_SCRIPT, BOOT_SCRIPT_TEMPLATE % {"panel_dir": _panel_dir()}, 0o755)
        changed_units |= _write_if_changed(BOOT_UNIT, BOOT_UNIT_CONTENT)
    except Exception:
        pass
    if changed_units:
        _run("systemctl daemon-reload")
    _run(["systemctl", "enable", "smartui-vpn-boot.service"])
    return protos


# ---------------------------------------------------------------- restore ---

def _log(msg):
    print("smartui-vpn-boot: " + msg)
    sys.stdout.flush()


def _iptables_firewall(vc):
    try:
        return vc.detect_firewall() == "iptables"
    except Exception:
        try:
            from panel_common import detect_firewall
            return detect_firewall() == "iptables"
        except Exception:
            return False


def _open_port(vc, port, proto):
    """Only plain iptables needs re-opening (ufw / firewalld / nftables keep
    their own rules across reboots, and re-adding would duplicate nft rules)."""
    if not _iptables_firewall(vc):
        return
    try:
        from panel_common import open_firewall_port
        open_firewall_port(int(port), (proto,))
    except Exception:
        pass


def _start_unit(vc, unit, want_reload_strongswan=False):
    _run(["systemctl", "enable", unit])
    if not vc.service_active(unit):
        _run(["systemctl", "reset-failed", unit])
        ok = _run(["systemctl", "restart", unit]).returncode == 0
        _log("%s %s" % (unit, "started" if ok else "FAILED to start"))
    if want_reload_strongswan:
        time.sleep(1)
        vc.swanctl_reload()


def _restore_sstp(vc, m):
    meta = m._load_meta()
    port = m.get_port()
    vc.ensure_ppp_support()
    vc.ensure_ip_forwarding(m.SYSCTL_NAME)
    vc.ensure_nat(meta["subnet"], vc.default_interface(), m.NAT_TAG)
    _open_port(vc, port, "tcp")
    _start_unit(vc, m.SERVICE)
    _log("SSTP restored (TCP %s)" % port)


def _restore_ikev2(vc, m):
    meta = m._load_meta()
    ike, natt = vc.get_charon_ports()
    vc.ensure_ip_forwarding(m.SYSCTL_NAME)
    vc.ensure_nat(meta["subnet"], vc.default_interface(), m.NAT_TAG)
    _open_port(vc, ike, "udp")
    _open_port(vc, natt, "udp")
    if _iptables_firewall(vc):
        vc.open_ipsec_protocols()
    _start_unit(vc, vc.STRONGSWAN_UNIT, want_reload_strongswan=True)
    _log("IKEv2 restored (UDP %s/%s)" % (ike, natt))


def _restore_l2tp(vc, m):
    meta = m._load_meta()
    port = m.get_port()
    vc.ensure_ppp_support()
    vc.ensure_ip_forwarding(m.SYSCTL_NAME)
    vc.ensure_nat(meta["subnet"], vc.default_interface(), m.NAT_TAG)
    if meta.get("mode") == "ipsec":
        ike, natt = vc.get_charon_ports()
        if _iptables_firewall(vc):
            _open_port(vc, ike, "udp")
            _open_port(vc, natt, "udp")
            vc.open_ipsec_protocols()
            try:
                m._ipsec_only_rules(meta.get("ipsec_only", True), port)
            except Exception:
                pass
        _start_unit(vc, vc.STRONGSWAN_UNIT, want_reload_strongswan=True)
    else:
        _open_port(vc, port, "udp")
    _start_unit(vc, "xl2tpd")
    _log("L2TP restored (UDP %s, %s)" % (port, meta.get("mode")))


def restore_all():
    sstp, ikev2, l2tp, vc = _load_modules()
    if vc is None:
        _log("vpn_common not found - nothing to restore")
        return
    # account files first (cheap, and the services read them when they start)
    try:
        vc.sync_all(reload=False)
    except TypeError:
        try:
            vc.sync_all()
        except Exception:
            pass
    except Exception:
        pass

    steps = []
    if _installed(sstp):
        steps.append(("SSTP", lambda: _restore_sstp(vc, sstp)))
    if _installed(ikev2):
        steps.append(("IKEv2", lambda: _restore_ikev2(vc, ikev2)))
    if _installed(l2tp):
        steps.append(("L2TP", lambda: _restore_l2tp(vc, l2tp)))
    if not steps:
        _log("no SSTP / IKEv2 / L2TP installed - nothing to do")
        return
    for name, fn in steps:
        try:
            fn()
        except Exception as e:
            _log("%s restore error: %s" % (name, e))
    try:
        vc.sync_all()
    except Exception:
        pass


if __name__ == "__main__":
    sys.path.insert(0, _panel_dir())
    if len(sys.argv) > 1 and sys.argv[1] == "ensure":
        print("protected:", ensure(force=True))
    else:
        restore_all()
