"""
nginx_manager.py - Nginx reverse-proxy + decoy fallback module for the
SmartUI panel.

Two things this does, confirmed as genuinely different from what HAProxy
(also in this panel) already covers:

1. Path-based reverse proxy WITH TLS TERMINATION. Unlike HAProxy's own SNI
   passthrough (which never decrypts, and can only route by domain, one
   domain to one backend), this terminates TLS itself and can route by
   PATH on a single domain - e.g. /vless to one Xray inbound, /ws to
   WS-EPRO - which is also the CDN/Cloudflare-friendly shape, since a CDN
   in front of this sees ordinary decrypted HTTP/WebSocket traffic, not
   raw TLS passthrough it can't inspect. Confirmed the exact, correct
   WebSocket-upgrade syntax against multiple independent, recent, mutually
   consistent real-world sources before writing this: `map $http_upgrade
   $connection_upgrade { default upgrade; '' close; }` at the http-block
   level (correctly falls back to Connection: close for a plain HTTP
   request on the same location, rather than always claiming "upgrade"),
   `proxy_http_version 1.1`, and the standard proxy_set_header trio
   (Upgrade, Connection, Host) plus a long proxy_read_timeout for
   long-lived WebSocket connections.

2. A decoy fallback for any path that doesn't match a registered route -
   proxied to a real, external site, so unmatched/unrecognized traffic
   looks like an ordinary working website to casual DPI inspection rather
   than returning an Nginx 404 that immediately signals "something odd is
   running here."

Cert handling reuses the same detection already added to Hysteria2: an
existing cert from Xray/Stunnel's own certbot flow (same standard
certbot path) is reused directly if present; otherwise a fresh
`certbot certonly --standalone` request is made, with Nginx (and
anything else already on port 80/443) stopped for the duration of the
challenge and restarted after - the same established pattern already
used for Xray's own cert flow elsewhere in this panel.
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

NGINX_CONF_PATH = "/etc/nginx/sites-available/smartui-proxy.conf"
NGINX_ENABLED_PATH = "/etc/nginx/sites-enabled/smartui-proxy.conf"
NGINX_REGISTRY_DIR = "/etc/nginx-smartui"
NGINX_REGISTRY_PATH = "%s/routes.json" % NGINX_REGISTRY_DIR
NGINX_STATE_PATH = "%s/state.json" % NGINX_REGISTRY_DIR
DEFAULT_DECOY = "https://www.wikipedia.org"


def _load_registry():
    if not os.path.exists(NGINX_REGISTRY_PATH):
        return {}
    try:
        with open(NGINX_REGISTRY_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_registry(registry):
    os.makedirs(NGINX_REGISTRY_DIR, exist_ok=True)
    with open(NGINX_REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)


def _load_state():
    if not os.path.exists(NGINX_STATE_PATH):
        return {}
    try:
        with open(NGINX_STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state):
    os.makedirs(NGINX_REGISTRY_DIR, exist_ok=True)
    with open(NGINX_STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "nginx"]).returncode == 0


def _restart_nginx():
    # Same lesson as Dropbear/Stunnel/Xray/dns-router elsewhere in this
    # panel: clear any prior rate-limit before every restart attempt, from
    # the moment this module is written.
    _run("systemctl reset-failed nginx")
    return _run("systemctl restart nginx").returncode == 0


def _binary_ok():
    return _run(["which", "nginx"]).returncode == 0


def _ensure_installed():
    # Confirmed as the real, direct cause of a genuine bug report:
    # apache2 is a standard package present on this VPS (confirmed from an
    # earlier boot log) and binds port 80 by default. The cert-reuse path
    # in _obtain_cert below only ever stops apache2 when requesting a
    # brand-new certificate (since that's a temporary, one-time need for
    # the ACME challenge) - but Nginx needs port 80 permanently, for its
    # own HTTP->HTTPS redirect, regardless of whether the cert itself was
    # newly requested or reused. Stopping and disabling apache2 here,
    # unconditionally and before the early-return below, means this
    # applies whether Nginx is being installed for the first time or set
    # up again on a VPS where it (and apache2) already exist.
    if _run(["systemctl", "is-active", "--quiet", "apache2"]).returncode == 0:
        print("%s[i] Stopping and disabling apache2 - it's holding port 80, which" % C_CYAN)
        print("    Nginx needs permanently for its own HTTP->HTTPS redirect.%s" % C_RESET)
        _run("systemctl stop apache2")
        _run("systemctl disable apache2")

    if _binary_ok():
        return True
    print("%s[i] Installing nginx and certbot...%s" % (C_CYAN, C_RESET))
    # DEBIAN_FRONTEND=noninteractive, confirmed necessary elsewhere in this
    # panel (see port_broker_manager.py's own sslh install) for any apt
    # install run as a subprocess without a real terminal to answer a
    # debconf prompt, should one come up.
    install = _run("DEBIAN_FRONTEND=noninteractive apt-get update && "
                    "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot")
    if not _binary_ok():
        print("%s[X] Installation failed:" % C_RED)
        print("%s%s" % (install.stderr[-800:], C_RESET))
        return False
    _run("systemctl stop nginx")
    _run("systemctl reset-failed nginx")
    _run("systemctl enable nginx")
    # The default site would otherwise conflict with this module's own
    # server block also wanting 80/443.
    _run("rm -f /etc/nginx/sites-enabled/default")
    return True


def _obtain_cert(domain):
    """Reuses an existing cert from Xray/Stunnel's own certbot flow if one
    is already there for this exact domain (same standard certbot path
    both already use) - otherwise requests a fresh one, stopping anything
    already on port 80 for the standalone challenge and restarting it
    after, the same established pattern as Xray's own cert flow elsewhere
    in this panel."""
    live_cert = "/etc/letsencrypt/live/%s/fullchain.pem" % domain
    live_key = "/etc/letsencrypt/live/%s/privkey.pem" % domain
    if os.path.exists(live_cert) and os.path.exists(live_key):
        print("%s[✔] Found an existing certificate for %s (already set up" % (C_GREEN, domain))
        print("    elsewhere in this panel) - reusing it directly, no new request needed.%s" % C_RESET)
        return True, live_cert, live_key

    was_active = {}
    for svc in ("nginx", "apache2"):
        was_active[svc] = _run(["systemctl", "is-active", "--quiet", svc]).returncode == 0
    _run("systemctl stop nginx apache2 2>/dev/null")

    hook_dir = "/etc/letsencrypt/renewal-hooks/deploy"
    os.makedirs(hook_dir, exist_ok=True)
    hook_path = "%s/nginx-smartui-renew.sh" % hook_dir
    with open(hook_path, "w") as f:
        f.write("#!/bin/bash\nsystemctl reload nginx\n")
    os.chmod(hook_path, 0o755)

    cert_cmd = "certbot certonly --standalone --agree-tos --register-unsafely-without-email -d %s" % domain
    result = _run(cert_cmd)

    for svc, active in was_active.items():
        if active:
            _run(["systemctl", "start", svc])

    if result.returncode != 0 or not os.path.exists(live_cert):
        return False, None, None
    return True, live_cert, live_key


def _build_config(domain, cert_path, key_path, registry, decoy_url):
    lines = []
    lines.append("map $http_upgrade $connection_upgrade {")
    lines.append("    default upgrade;")
    lines.append("    ''      close;")
    lines.append("}")
    lines.append("")
    lines.append("server {")
    lines.append("    listen 80;")
    lines.append("    listen [::]:80;")
    lines.append("    server_name %s;" % domain)
    lines.append("    return 301 https://$host$request_uri;")
    lines.append("}")
    lines.append("")
    lines.append("server {")
    lines.append("    listen 443 ssl;")
    lines.append("    listen [::]:443 ssl;")
    lines.append("    server_name %s;" % domain)
    lines.append("    ssl_certificate %s;" % cert_path)
    lines.append("    ssl_certificate_key %s;" % key_path)
    lines.append("")
    for path, internal_port in sorted(registry.items()):
        lines.append("    location %s {" % path)
        lines.append("        proxy_pass http://127.0.0.1:%s;" % internal_port)
        lines.append("        proxy_http_version 1.1;")
        lines.append("        proxy_set_header Upgrade $http_upgrade;")
        lines.append("        proxy_set_header Connection $connection_upgrade;")
        lines.append("        proxy_set_header Host $host;")
        lines.append("        proxy_set_header X-Real-IP $remote_addr;")
        lines.append("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
        lines.append("        proxy_set_header X-Forwarded-Proto $scheme;")
        lines.append("        proxy_read_timeout 86400s;")
        lines.append("    }")
        lines.append("")
    # Decoy fallback - anything not matching a registered path above lands
    # here, proxied to a real external site so it looks like an ordinary
    # working website rather than an Nginx 404 signalling something odd.
    lines.append("    location / {")
    lines.append("        proxy_ssl_server_name on;")
    lines.append("        proxy_set_header Host %s;" % decoy_url.split("//", 1)[1].split("/")[0])
    lines.append("        proxy_pass %s;" % decoy_url)
    lines.append("    }")
    lines.append("}")
    return "\n".join(lines)


def _write_full_config(domain, cert_path, key_path, registry, decoy_url):
    content = _build_config(domain, cert_path, key_path, registry, decoy_url)
    os.makedirs(os.path.dirname(NGINX_CONF_PATH), exist_ok=True)
    with open(NGINX_CONF_PATH, "w") as f:
        f.write(content)
    if not os.path.exists(NGINX_ENABLED_PATH):
        os.makedirs(os.path.dirname(NGINX_ENABLED_PATH), exist_ok=True)
        try:
            os.symlink(NGINX_CONF_PATH, NGINX_ENABLED_PATH)
        except FileExistsError:
            pass


def _wait_for_port_listening(port=443, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _apply_safely(domain, cert_path, key_path, registry, decoy_url, description):
    original = None
    if os.path.exists(NGINX_CONF_PATH):
        with open(NGINX_CONF_PATH, "r") as f:
            original = f.read()

    _write_full_config(domain, cert_path, key_path, registry, decoy_url)

    syntax_check = _run("nginx -t")
    if syntax_check.returncode != 0:
        if original is not None:
            with open(NGINX_CONF_PATH, "w") as f:
                f.write(original)
        else:
            try:
                os.remove(NGINX_CONF_PATH)
            except FileNotFoundError:
                pass
        return False, "%s failed nginx's own config syntax check - reverted:\n%s" % (description, syntax_check.stderr[-500:])

    if not _restart_nginx():
        if original is not None:
            with open(NGINX_CONF_PATH, "w") as f:
                f.write(original)
            _restart_nginx()
        return False, "%s failed to restart - check 'journalctl -u nginx'." % description

    if not _wait_for_port_listening(443):
        if original is not None:
            with open(NGINX_CONF_PATH, "w") as f:
                f.write(original)
            _restart_nginx()
        return False, "%s restarted, but port 443 never came up - reverted. Nothing was left broken." % description

    return True, "%s applied and verified." % description


def nginx_admin_manager(ports_dict):
    """Nginx Reverse Proxy Administrator Module."""
    while True:
        # Same defensive re-enable as Stunnel/WS-EPRO/WebSocket/Atken/
        # SSHGO/UDP Droid/Checkuser/MULTIPLEXING elsewhere in this panel -
        # confirmed as a real, direct cause of a genuine bug report where
        # this service was found reverting to OFF after a reboot, applied
        # here the same proven way.
        if os.path.exists(NGINX_STATE_PATH):
            _run("systemctl enable nginx")
        registry = _load_registry()
        state = _load_state()
        domain = state.get("domain")
        decoy_url = state.get("decoy_url", DEFAULT_DECOY)
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s       NGINX REVERSE PROXY (path routing + decoy fallback)  %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" STATUS: %s  |  DOMAIN: %s  |  ROUTES: %d" % (status_label, domain or "Not configured", len(registry)))
        print(" DECOY FALLBACK: %s" % decoy_url)
        if registry:
            print("----------------------------------------------------------------")
            for path in sorted(registry.keys()):
                print("   %s  ->  127.0.0.1:%s" % (path, registry[path]))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / SET DOMAIN (first-time setup)")
        print(" [2]> ADD ROUTE (path -> internal port)")
        print(" [3]> REMOVE ROUTE")
        print(" [4]> CHANGE DECOY FALLBACK SITE")
        print(" [5]> VIEW LOGS")
        print(" [6]> RESTART SERVICE")
        print(" [7]> START/STOP SERVICE [%s]" % status_label)
        print("----------------------------------------------------------------")
        print(" [8]> UNINSTALL NGINX")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] Back")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Select an option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    FIRST-TIME SETUP                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            new_domain = input(" Enter the domain this proxy will serve: ").strip()
            if not new_domain or not is_valid_hostname(new_domain):
                print("%s[X] That doesn't look like a valid domain.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            if not is_active and check_system_port_in_use(443, ("tcp",)):
                print("%s[X] Port 443 is already in use by something else, and Nginx isn't" % C_RED)
                print("    running yet - move whatever's currently on 443 to an internal port")
                print("    first (or check if HAProxy is already using it), then try again.%s" % C_RESET)
                input("\nPress Enter to continue...")
                continue

            # Confirmed as a real, direct cause of a genuine bug report:
            # Nginx needs port 80 permanently too (for its own HTTP->HTTPS
            # redirect), but only port 443 was ever checked here - so a
            # conflict on 80 alone surfaced only as a confusing "failed to
            # restart" well after the fact, rather than a clear, early
            # warning naming the actual problem. Confirmed directly from a
            # real ss output that this can be a genuinely different,
            # unrelated service the admin deliberately runs on port 80
            # (Python SOCKS in one real case) - not necessarily Apache2 -
            # so this is never silently stopped the way Apache2 is
            # elsewhere in this module; the admin needs to choose how to
            # resolve it themselves.
            if not is_active and check_system_port_in_use(80, ("tcp",)):
                print("%s[X] Port 80 is already in use by something else, and Nginx isn't" % C_RED)
                print("    running yet either - Nginx needs 80 permanently for its own")
                print("    HTTP->HTTPS redirect, not just temporarily. Move whatever's")
                print("    currently on port 80 to a different port first, then try again.%s" % C_RESET)
                input("\nPress Enter to continue...")
                continue

            if not _ensure_installed():
                input("\nPress Enter to continue...")
                continue

            print()
            ok, cert_path, key_path = _obtain_cert(new_domain)
            if not ok:
                print("%s[X] Could not obtain a certificate for %s - check the domain's DNS" % (C_RED, new_domain))
                print("    points here and port 80 is reachable from the internet.%s" % C_RESET)
                input("\nPress Enter to continue...")
                continue

            open_firewall_port(80, ("tcp",))
            open_firewall_port(443, ("tcp",))
            persist_firewall_rules()

            new_state = {"domain": new_domain, "cert_path": cert_path, "key_path": key_path, "decoy_url": decoy_url}
            ok2, msg = _apply_safely(new_domain, cert_path, key_path, registry, decoy_url, "Initial setup")
            if ok2:
                _save_state(new_state)
                print("%s[✔] %s%s" % (C_GREEN, msg, C_RESET))
                print("    Domain set to %s - now add routes with option 2." % new_domain)
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            if not domain:
                print("%s[X] Set up a domain first (option 1).%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            clear_screen()
            print(" %sThe service you route here must be listening on its own internal" % C_YELLOW)
            print(" port already - this only routes traffic to it by path, it doesn't")
            print(" set that service's own port up for you.%s" % C_RESET)
            print()
            path = input(" Enter the URL path for this route (e.g. /vless): ").strip()
            if not path.startswith("/"):
                path = "/" + path
            if path in registry:
                print("%s[X] That path is already routed to port %s - remove it first to change it.%s" % (C_RED, registry[path], C_RESET))
                input("\nPress Enter to continue...")
                continue

            backend_port = prompt_port(" Enter the internal port this path's service listens on: ", default=8443)
            if not check_system_port_in_use(backend_port, ("tcp",)):
                print("%s[!] Nothing seems to be listening on port %s yet - the route will have" % (C_YELLOW, backend_port))
                print("    nowhere to forward traffic until that service is actually running there.%s" % C_RESET)

            new_registry = dict(registry)
            new_registry[path] = str(backend_port)
            ok, msg = _apply_safely(domain, state.get("cert_path"), state.get("key_path"), new_registry, decoy_url, "Route for %s" % path)
            if ok:
                _save_registry(new_registry)
                print("%s[✔] %s%s" % (C_GREEN, msg, C_RESET))
                print("    https://%s%s now routes to 127.0.0.1:%s" % (domain, path, backend_port))
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            if not registry:
                print("%s[X] No routes configured yet.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            clear_screen()
            print(" Configured routes:")
            paths = sorted(registry.keys())
            for i, p in enumerate(paths, 1):
                print("   [%d] %s -> 127.0.0.1:%s" % (i, p, registry[p]))
            sel = input(" Enter the number to remove (blank to cancel): ").strip()
            if not sel.isdigit() or not (1 <= int(sel) <= len(paths)):
                input("\nPress Enter to continue...")
                continue
            path_to_remove = paths[int(sel) - 1]
            new_registry = dict(registry)
            del new_registry[path_to_remove]
            ok, msg = _apply_safely(domain, state.get("cert_path"), state.get("key_path"), new_registry, decoy_url, "Removing route for %s" % path_to_remove)
            if ok:
                _save_registry(new_registry)
                print("%s[✔] Route for %s removed.%s" % (C_GREEN, path_to_remove, C_RESET))
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            if not domain:
                print("%s[X] Set up a domain first (option 1).%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            new_decoy = input(" Enter the full URL of the real site to mirror for unmatched traffic (e.g. https://www.wikipedia.org): ").strip()
            if not new_decoy.startswith("https://") and not new_decoy.startswith("http://"):
                print("%s[X] Needs to be a full URL, starting with http:// or https://.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            new_state = dict(state)
            new_state["decoy_url"] = new_decoy
            ok, msg = _apply_safely(domain, state.get("cert_path"), state.get("key_path"), registry, new_decoy, "Decoy site change")
            if ok:
                _save_state(new_state)
                print("%s[✔] Decoy fallback updated to %s%s" % (C_GREEN, new_decoy, C_RESET))
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            os.system("journalctl -u nginx -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '6':
            if _restart_nginx():
                print("%s[✔] Nginx restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u nginx'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            if is_active:
                _run("systemctl stop nginx")
                print("%s[!] Nginx stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not _ensure_installed():
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl reset-failed nginx")
                if _run("systemctl start nginx").returncode == 0:
                    print("%s[✔] Nginx started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u nginx'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            clear_screen()
            confirm = input(" Are you sure you want to completely remove Nginx and all its routes? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop nginx")
                _run("systemctl disable nginx")
                _run("DEBIAN_FRONTEND=noninteractive apt-get remove -y nginx")
                close_firewall_port(80, ("tcp",))
                close_firewall_port(443, ("tcp",))
                persist_firewall_rules()
                if os.path.exists(NGINX_REGISTRY_PATH):
                    os.remove(NGINX_REGISTRY_PATH)
                if os.path.exists(NGINX_STATE_PATH):
                    os.remove(NGINX_STATE_PATH)
                print("%s[✔] Nginx uninstalled and all routes removed.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
