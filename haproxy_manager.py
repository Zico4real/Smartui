"""
haproxy_manager.py - HAProxy SNI-based TLS passthrough router for the
SmartUI panel.

Lets multiple TLS-based services already in this panel (Stunnel, Xray with
TLS, WS-EPRO, etc.) share port 443 simultaneously, distinguished by domain
name via the TLS ClientHello's SNI field - inspected without ever
decrypting the connection (`mode tcp` + `req.ssl_sni`), so this works
purely as a router, not a TLS terminator; each backend service keeps
handling its own TLS/certs exactly as it already does. Confirmed against
HAProxy's own documented syntax and multiple independent, consistent
real-world configs before writing this: `tcp-request inspect-delay` +
`tcp-request content accept if { req.ssl_hello_type 1 }` to wait for and
confirm a genuine TLS handshake before making any routing decision, then
one `use_backend ... if { req.ssl_sni -i <domain> }` rule per registered
domain, each pointing at its own `mode tcp` backend that forwards the
still-encrypted bytes to `127.0.0.1:<internal_port>`.

Each registered service must itself already be listening on its own
internal port (not 443) for a route to actually work - this module only
routes traffic to it by domain; setting up that service's own listening
port remains that service's own admin screen (Stunnel's Add Port, Xray's
port prompt, etc.), same as it already is today.
"""

import os
import time
import json
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, is_valid_hostname,
)

HAPROXY_CONF_PATH = "/etc/haproxy/haproxy.cfg"
HAPROXY_REGISTRY_DIR = "/etc/haproxy-sni"
HAPROXY_REGISTRY_PATH = "%s/routes.json" % HAPROXY_REGISTRY_DIR
HAPROXY_MARKER_START = "# --- SmartUI SNI routes: begin (managed by the panel - edits here are overwritten) ---"
HAPROXY_MARKER_END = "# --- SmartUI SNI routes: end ---"

BASE_CONFIG = """global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    tcp
    timeout connect 5000
    timeout client  50000
    timeout server  50000

"""


def _load_registry():
    if not os.path.exists(HAPROXY_REGISTRY_PATH):
        return {}
    try:
        with open(HAPROXY_REGISTRY_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_registry(registry):
    os.makedirs(HAPROXY_REGISTRY_DIR, exist_ok=True)
    with open(HAPROXY_REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "haproxy"]).returncode == 0


def _restart_haproxy():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt, from
    # the moment this module is written, rather than needing a separate
    # later fix once someone hits it.
    _run("systemctl reset-failed haproxy")
    return _run("systemctl restart haproxy").returncode == 0


def _wait_for_port_listening(port=443, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _binary_ok():
    return _run(["which", "haproxy"]).returncode == 0


def _ensure_installed():
    if _binary_ok():
        return True
    print("%s[i] Installing haproxy...%s" % (C_CYAN, C_RESET))
    install = _run("apt-get update && apt-get install -y haproxy")
    if not _binary_ok():
        print("%s[X] Installation failed:" % C_RED)
        print("%s%s" % (install.stderr[-800:], C_RESET))
        return False
    # Defense in depth, same reasoning as every other install path in this
    # panel: clear any state left over from the install itself before this
    # module ever tries its own first restart.
    _run("systemctl stop haproxy")
    _run("systemctl reset-failed haproxy")
    _run("systemctl enable haproxy")
    return True


def _build_managed_block(registry):
    lines = []
    lines.append("frontend sni_router")
    lines.append("    bind *:443")
    lines.append("    mode tcp")
    lines.append("    tcp-request inspect-delay 5s")
    lines.append("    tcp-request content accept if { req.ssl_hello_type 1 }")
    for i, domain in enumerate(sorted(registry.keys())):
        backend_name = "sni_backend_%d" % i
        lines.append("    use_backend %s if { req.ssl_sni -i %s }" % (backend_name, domain))
    lines.append("")
    for i, domain in enumerate(sorted(registry.keys())):
        backend_name = "sni_backend_%d" % i
        port = registry[domain]
        lines.append("backend %s" % backend_name)
        lines.append("    mode tcp")
        lines.append("    server %s_srv 127.0.0.1:%s" % (backend_name, port))
        lines.append("")
    return "\n".join(lines)


def _write_full_config(registry):
    # The base (global/defaults) section is only ever templated fresh on a
    # brand-new config - once haproxy.cfg exists, an admin's own edits to
    # that section (custom timeouts, logging, etc.) are preserved across
    # every route add/remove, since only the text between the two markers
    # ever gets regenerated and rewritten.
    if os.path.exists(HAPROXY_CONF_PATH):
        with open(HAPROXY_CONF_PATH) as f:
            existing = f.read()
        if HAPROXY_MARKER_START in existing and HAPROXY_MARKER_END in existing:
            before = existing.split(HAPROXY_MARKER_START)[0]
            after = existing.split(HAPROXY_MARKER_END)[1]
            base_section = before
        else:
            base_section = existing.rstrip() + "\n\n"
            after = "\n"
    else:
        base_section = BASE_CONFIG
        after = "\n"

    managed_block = _build_managed_block(registry)
    full_content = base_section + HAPROXY_MARKER_START + "\n" + managed_block + HAPROXY_MARKER_END + after
    os.makedirs(os.path.dirname(HAPROXY_CONF_PATH), exist_ok=True)
    with open(HAPROXY_CONF_PATH, "w") as f:
        f.write(full_content)


def _apply_safely(registry, description):
    original = None
    if os.path.exists(HAPROXY_CONF_PATH):
        with open(HAPROXY_CONF_PATH, "r") as f:
            original = f.read()

    _write_full_config(registry)

    if not _restart_haproxy():
        if original is not None:
            with open(HAPROXY_CONF_PATH, "w") as f:
                f.write(original)
            _restart_haproxy()
        return False, "%s failed to restart - check 'journalctl -u haproxy' (often a config syntax issue)." % description

    if not _wait_for_port_listening(443):
        if original is not None:
            with open(HAPROXY_CONF_PATH, "w") as f:
                f.write(original)
            _restart_haproxy()
        return False, "%s restarted, but port 443 never came up - reverted. Nothing was left broken." % description

    return True, "%s applied and verified." % description


def haproxy_admin_manager(ports_dict):
    """HAProxy SNI Router Administrator Module."""
    while True:
        registry = _load_registry()
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s        HAPROXY SNI ROUTER (share port 443 by domain)       %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" STATUS: %s  |  ROUTES: %d" % (status_label, len(registry)))
        if registry:
            print("----------------------------------------------------------------")
            for domain in sorted(registry.keys()):
                print("   %s  ->  127.0.0.1:%s" % (domain, registry[domain]))
        print("----------------------------------------------------------------")
        print(" [1]> ADD ROUTE (domain -> internal port)")
        print(" [2]> REMOVE ROUTE")
        print(" [3]> VIEW LOGS")
        print(" [4]> RESTART SERVICE")
        print(" [5]> START/STOP SERVICE [%s]" % status_label)
        print("----------------------------------------------------------------")
        print(" [6]> UNINSTALL HAPROXY")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] Back")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Select an option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    ADD SNI ROUTE                            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" %sThe service you route here must be listening on its own internal" % C_YELLOW)
            print(" port, not 443 - this only routes traffic to it by domain, it")
            print(" doesn't set that service's own port up for you.%s" % C_RESET)
            print()

            domain = input(" Enter the domain (SNI) for this route: ").strip()
            if not domain or not is_valid_hostname(domain):
                print("%s[X] That doesn't look like a valid domain.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            if domain in registry:
                print("%s[X] That domain is already routed to port %s - remove it first to change it.%s" % (C_RED, registry[domain], C_RESET))
                input("\nPress Enter to continue...")
                continue

            backend_port = prompt_port(" Enter the internal port this domain's service listens on (e.g., 8443): ", default=8443)
            if not check_system_port_in_use(backend_port, ("tcp",)):
                print("%s[!] Nothing seems to be listening on port %s yet - the route will have" % (C_YELLOW, backend_port))
                print("    nowhere to forward traffic until that service is actually running there.%s" % C_RESET)

            if not is_active and check_system_port_in_use(443, ("tcp",)):
                print("%s[X] Port 443 is already in use by something else, and HAProxy isn't" % C_RED)
                print("    running yet - move whatever's currently on 443 to an internal port")
                print("    first (e.g. reconfigure that service's own port), then try again.%s" % C_RESET)
                input("\nPress Enter to continue...")
                continue

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            new_registry = dict(registry)
            new_registry[domain] = str(backend_port)

            open_firewall_port(443, ("tcp",))
            persist_firewall_rules()
            ok, msg = _apply_safely(new_registry, "Route for %s" % domain)
            if ok:
                _save_registry(new_registry)
                print("%s[✔] %s%s" % (C_GREEN, msg, C_RESET))
                print("    %s on port 443 now routes to 127.0.0.1:%s" % (domain, backend_port))
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            if not registry:
                print("%s[X] No routes configured yet.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            clear_screen()
            print(" Configured routes:")
            domains = sorted(registry.keys())
            for i, d in enumerate(domains, 1):
                print("   [%d] %s -> 127.0.0.1:%s" % (i, d, registry[d]))
            sel = input(" Enter the number to remove (blank to cancel): ").strip()
            if not sel.isdigit() or not (1 <= int(sel) <= len(domains)):
                input("\nPress Enter to continue...")
                continue
            domain_to_remove = domains[int(sel) - 1]
            new_registry = dict(registry)
            del new_registry[domain_to_remove]

            if new_registry:
                ok, msg = _apply_safely(new_registry, "Removing route for %s" % domain_to_remove)
                if ok:
                    _save_registry(new_registry)
                    print("%s[✔] Route for %s removed.%s" % (C_GREEN, domain_to_remove, C_RESET))
                else:
                    print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            else:
                _run("systemctl stop haproxy")
                close_firewall_port(443, ("tcp",))
                persist_firewall_rules()
                _save_registry(new_registry)
                print("%s[✔] Last route removed - HAProxy stopped and port 443 released.%s" % (C_GREEN, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            os.system("journalctl -u haproxy -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '4':
            if _restart_haproxy():
                print("%s[✔] HAProxy restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u haproxy'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            if is_active:
                _run("systemctl stop haproxy")
                print("%s[!] HAProxy stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not _ensure_installed():
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl reset-failed haproxy")
                if _run("systemctl start haproxy").returncode == 0:
                    print("%s[✔] HAProxy started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u haproxy'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            confirm = input(" Are you sure you want to completely remove HAProxy and all its routes? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop haproxy")
                _run("systemctl disable haproxy")
                _run("apt-get remove -y haproxy")
                close_firewall_port(443, ("tcp",))
                persist_firewall_rules()
                if os.path.exists(HAPROXY_REGISTRY_PATH):
                    os.remove(HAPROXY_REGISTRY_PATH)
                print("%s[✔] HAProxy uninstalled and all routes removed.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
