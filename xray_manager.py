#!/usr/bin/env python3
import json
import uuid
import os
import re
import urllib.parse
import subprocess
import socket
import base64
import secrets
import time
import copy
from datetime import datetime, timedelta

# Paths & Flags
INSTALL_FLAG = "/etc/xray/.installed"
CONFIG_PATH = "/usr/local/etc/xray/config.json"
TRACKER_PATH = "/usr/local/etc/xray/users_tracker.json"
REALITY_KEYS_PATH = "/usr/local/etc/xray/reality_keys.json"
PANEL_CONFIG_PATH = "/usr/local/etc/xray/panel_config.json"
HYSTERIA_CONFIG_PATH = "/etc/hysteria/config.yaml"
HYSTERIA_TRACKER_PATH = "/etc/hysteria/users_tracker.json"
HYSTERIA_INSTALL_FLAG = "/etc/hysteria/.installed"

# ANSI Color Codes
C_CYAN = "\033[96m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"

def clear_screen():
    os.system("clear")

_domain_cache = None

def get_domain():
    global _domain_cache
    if _domain_cache:
        return _domain_cache

    if os.path.exists(PANEL_CONFIG_PATH):
        try:
            with open(PANEL_CONFIG_PATH, "r") as f:
                cfg = json.load(f)
            if cfg.get("domain"):
                _domain_cache = cfg["domain"]
                return _domain_cache
        except Exception:
            pass

    print(f"{C_YELLOW}No domain configured yet.{C_RESET}")
    domain = input(f"{C_GREEN}Enter the domain this server's certificate is for: {C_RESET}").strip()
    os.makedirs(os.path.dirname(PANEL_CONFIG_PATH), exist_ok=True)
    with open(PANEL_CONFIG_PATH, "w") as f:
        json.dump({"domain": domain}, f, indent=2)
    _domain_cache = domain
    return domain

def get_cert_paths():
    domain = get_domain()
    return (f"/usr/local/etc/xray/cert/{domain}.crt", f"/usr/local/etc/xray/cert/{domain}.key")

def load_tracker():
    if not os.path.exists(TRACKER_PATH):
        return {}
    try:
        with open(TRACKER_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_tracker(tracker):
    os.makedirs(os.path.dirname(TRACKER_PATH), exist_ok=True)
    with open(TRACKER_PATH, "w") as f:
        json.dump(tracker, f, indent=2)

def remove_allow_insecure(obj):
    if isinstance(obj, dict):
        obj.pop("allowInsecure", None)
        for k, v in obj.items():
            remove_allow_insecure(v)
    elif isinstance(obj, list):
        for item in obj:
            remove_allow_insecure(item)
    return obj

# ==================== LEGACY mKCP MIGRATION (header/seed -> finalmask) ====================
# Current Xray-core (26.x) hard-rejects kcpSettings.header / kcpSettings.seed at
# config-build time. Any config.json written before this script switched to
# finalmask (or hand-edited, or produced by another tool) still has those fields
# and will fail `xray run -test` outright. This walks the config once at load
# time and rewrites any legacy mKCP block in place, so an existing file heals
# itself the next time this script touches it — no manual profile recreation
# needed just to get Xray to start again.
LEGACY_KCP_HEADER_MAP = {
    "none": "mkcp-original",       # previously-implicit default obfuscation
    "": "mkcp-original",
    "srtp": "header-srtp",
    "utp": "header-utp",
    "wechat-video": "header-wechat",
    "dtls": "header-dtls",
    "wireguard": "header-wireguard",
}

def migrate_legacy_kcp(obj):
    """Recursively find any streamSettings block still using the removed
    kcpSettings.header/seed fields and convert it to the equivalent finalmask/udp
    entries. Returns (obj, changed) so the caller knows whether to persist."""
    changed = False

    def walk(node):
        nonlocal changed
        if isinstance(node, dict):
            if node.get("network") == "kcp" and isinstance(node.get("kcpSettings"), dict):
                kcp = node["kcpSettings"]
                legacy_header = kcp.pop("header", None)
                legacy_seed = kcp.pop("seed", None)
                if legacy_header is not None or legacy_seed is not None:
                    changed = True
                    header_type = legacy_header.get("type") if isinstance(legacy_header, dict) else None
                    masks = [{"type": LEGACY_KCP_HEADER_MAP.get(header_type, "mkcp-original"), "settings": {}}]
                    if legacy_seed:
                        masks.append({"type": "mkcp-aes128gcm", "settings": {"password": legacy_seed}})
                    existing_fm = node.get("finalmask")
                    if isinstance(existing_fm, dict) and isinstance(existing_fm.get("udp"), list):
                        existing_fm["udp"] = masks + existing_fm["udp"]
                    else:
                        node["finalmask"] = {"udp": masks}
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(obj)
    return obj, changed

def load_xray_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    try:
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
        config = remove_allow_insecure(config)
        config, migrated = migrate_legacy_kcp(config)
        if migrated:
            with open(CONFIG_PATH, "w") as f:
                json.dump(config, f, indent=2)
            print(f"{C_YELLOW}[!] Migrated an mKCP inbound off the removed header/seed fields onto finalmask (required by current Xray-core). Restart Xray for it to take effect.{C_RESET}")
        return config
    except Exception:
        return None

def save_xray_config(config):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    remove_allow_insecure(config)
    migrate_legacy_kcp(config)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

def load_reality_keys():
    if not os.path.exists(REALITY_KEYS_PATH):
        return None
    try:
        with open(REALITY_KEYS_PATH, "r") as f:
            keys = json.load(f)
        if keys.get("private_key") and keys.get("public_key"):
            return keys
    except Exception:
        pass
    return None

# ==================== VLESS NATIVE ENCRYPTION (POST-QUANTUM) ====================
# Merged into Xray-core in 2025/26 (PR #5067): an optional payload-encryption layer
# for VLESS using ML-KEM-768 (post-quantum) + X25519, independent of outer TLS. One
# keypair is shared by every user on a VLESS-Encryption-enabled inbound, the same way
# REALITY's keypair is shared, so we generate/cache it once.
VLESS_ENC_KEYS_PATH = "/usr/local/etc/xray/vless_enc_keys.json"

def load_vless_enc_keys():
    if not os.path.exists(VLESS_ENC_KEYS_PATH):
        return None
    try:
        with open(VLESS_ENC_KEYS_PATH, "r") as f:
            keys = json.load(f)
        if keys.get("decryption") and keys.get("encryption"):
            return keys
    except Exception:
        pass
    return None

def generate_vless_enc_keys():
    """Runs `xray vlessenc` and keeps the ML-KEM-768 (post-quantum) block, since that's
    the point of offering this over plain X25519. Returns None if the installed
    Xray-core is too old to have the vlessenc subcommand."""
    try:
        result = subprocess.run(["xray", "vlessenc", "-i", "mlkem768"], capture_output=True, text=True)
        if result.returncode != 0:
            return None
        output = result.stdout
        decs = re.findall(r'"decryption":\s*"([^"]*)"', output)
        encs = re.findall(r'"encryption":\s*"([^"]*)"', output)
        if not decs or not encs:
            return None
        # The command prints the X25519 block first, then the ML-KEM-768 (post-quantum)
        # block — take the last of each so we default to the stronger option.
        keys = {"decryption": decs[-1], "encryption": encs[-1]}
        os.makedirs(os.path.dirname(VLESS_ENC_KEYS_PATH), exist_ok=True)
        with open(VLESS_ENC_KEYS_PATH, "w") as f:
            json.dump(keys, f, indent=2)
        return keys
    except Exception:
        return None

def get_or_create_vless_enc_keys():
    keys = load_vless_enc_keys()
    if keys:
        return keys
    return generate_vless_enc_keys()

def cert_files_exist():
    cert_file, key_file = get_cert_paths()
    return os.path.exists(cert_file) and os.path.exists(key_file)

def restart_xray(verify_port=None, verify_proto="tcp"):
    """Real restart verification with config test and active status check.

    A single fixed 1-second sleep before the one-shot is-active check was
    the actual bug behind repeated "failed to stay active after restart"
    reports: Xray-core, especially with an existing multi-user/multi-inbound
    config, can genuinely take longer than 1 second to finish initializing
    (parsing a large config, loading TLS certs, etc.) - a transient,
    still-starting state was being reported as outright failure. Polling
    for up to several seconds, the same pattern used throughout the rest of
    this panel, gives it the time it may genuinely need.

    When verify_port is given, this also confirms that specific port is
    actually listening - systemctl is-active only reflects whether the
    xray PROCESS is still running, not whether a particular new inbound
    actually bound successfully. Xray-core often keeps running even if one
    inbound among several fails, so process-level "active" alone can't
    catch a per-inbound port conflict - only checking the actual port can.
    """
    try:
        if os.path.exists("/usr/local/bin/xray") or os.path.exists("/usr/bin/xray"):
            test_res = subprocess.run(["xray", "-test", "-config", CONFIG_PATH], capture_output=True, text=True)
            if test_res.returncode != 0:
                print(f"{C_RED}Xray configuration test failed:\n{test_res.stderr}{C_RESET}")
                return False
    except Exception:
        pass

    try:
        # Same lesson as Dropbear and Stunnel elsewhere in this panel:
        # repeated restart attempts (each failed config change triggers
        # one, and the rollback-on-failure logic triggers another
        # immediately after) can exhaust systemd's default restart-rate
        # budget. Once that happens, "systemctl restart" itself succeeds
        # (systemd accepts the request) but the service never actually
        # becomes active again - it stays in its prior failed state,
        # which is indistinguishable from a genuine config/port problem
        # without this fix. Clearing it before every attempt is what
        # actually lets a new attempt run at all, regardless of which
        # protocol or transport was being configured.
        subprocess.run(["systemctl", "reset-failed", "xray"], capture_output=True, text=True)
        subprocess.run(["systemctl", "restart", "xray"], check=True)
        active = False
        for _ in range(8):
            time.sleep(1)
            res = subprocess.run(["systemctl", "is-active", "xray"], capture_output=True, text=True)
            if res.returncode == 0 and "active" in res.stdout:
                active = True
                break
        if not active:
            print(f"{C_RED}Xray service failed to stay active after restart (possible port conflict or syntax error).{C_RESET}")
            return False
        if verify_port is not None:
            for _ in range(6):
                if check_system_port_in_use(int(verify_port), (verify_proto,)):
                    return True
                time.sleep(1)
            print(f"{C_RED}Xray is running, but port {verify_port} never came up - the new inbound")
            print(f"likely conflicts with something already using that port.{C_RESET}")
            return False
        return True
    except Exception as e:
        print(f"{C_RED}Failed to restart Xray service: {e}{C_RESET}")
        return False

def get_server_ip():
    try:
        ip = subprocess.check_output("curl -s ifconfig.me", shell=True, text=True).strip()
        if ip:
            return ip
    except Exception:
        pass
    return "127.0.0.1"

# ==================== SAME-PORT MULTI-PROTOCOL (PATH MULTIPLEXING) ====================
# Transports whose traffic carries a distinguishable HTTP path, so a "front" inbound
# can tell different protocols apart on the same external port.
PATH_ROUTABLE_TRANSPORTS = {"ws", "xhttp", "httpupgrade", "grpc"}
# Xray protocols whose inbound settings actually support a "fallbacks" array. VMess and
# Shadowsocks do NOT — they can only ever be a multiplexing *target*, never the front door.
FALLBACK_CAPABLE_PROTOCOLS = {"vless", "trojan"}
NTLS_MUX_PATH = "/usr/local/etc/xray/ntls_mux.json"
NGINX_MUX_CONF_DIR = "/etc/nginx/conf.d"

def check_system_port_in_use(p, needed_protocols=("tcp",)):
    """Checks the kernel's own socket table directly rather than testing by
    binding. A bind-test is unreliable for UDP specifically (mKCP,
    Shadowsocks UDP): Linux allows multiple UDP sockets to bind the same
    port simultaneously when both set SO_REUSEADDR (unlike TCP, where
    LISTEN is exclusive even with SO_REUSEADDR) - confirmed directly with a
    real test, a second UDP bind to an already-listening port succeeded
    when it should have failed. That false negative could let a genuine
    port conflict go undetected. Reading /proc/net/{tcp,udp} directly has
    no such blind spot."""
    target_hex = "%04X" % p
    proc_files = {
        "tcp": ["/proc/net/tcp", "/proc/net/tcp6"],
        "udp": ["/proc/net/udp", "/proc/net/udp6"],
    }
    for proto in needed_protocols:
        for path in proc_files.get(proto, []):
            try:
                with open(path) as f:
                    next(f, None)
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
    """Pick a free loopback-only port for an inbound that will only ever be reached
    via another inbound's fallback / Nginx proxy_pass, never directly from outside."""
    import random
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

def load_ntls_mux():
    if not os.path.exists(NTLS_MUX_PATH):
        return {}
    try:
        with open(NTLS_MUX_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_ntls_mux(mux):
    os.makedirs(os.path.dirname(NTLS_MUX_PATH), exist_ok=True)
    with open(NTLS_MUX_PATH, "w") as f:
        json.dump(mux, f, indent=2)

def write_nginx_mux_conf(port, routes):
    """routes: {path: dest_port}. Writes one server block for this external port that
    demuxes by path to each protocol's loopback-only Xray inbound."""
    locations = []
    for path, dest_port in routes.items():
        locations.append(f"""
    location {path} {{
        proxy_pass http://127.0.0.1:{dest_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }}""")
    conf = f"""server {{
    listen {port};
    listen [::]:{port};
{''.join(locations)}
}}
"""
    os.makedirs(NGINX_MUX_CONF_DIR, exist_ok=True)
    conf_path = f"{NGINX_MUX_CONF_DIR}/xray-ntls-mux-{port}.conf"
    with open(conf_path, "w") as f:
        f.write(conf)
    return conf_path

def reload_nginx():
    try:
        test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
        if test.returncode != 0:
            print(f"{C_RED}Nginx config test failed:\n{test.stderr}{C_RESET}")
            return False
        subprocess.run(["systemctl", "reload", "nginx"], check=True)
        return True
    except Exception as e:
        print(f"{C_RED}Failed to reload Nginx: {e}{C_RESET}")
        return False

def nginx_installed():
    return subprocess.run(["which", "nginx"], capture_output=True, text=True).returncode == 0

def print_header():
    print(f"{C_CYAN}{C_BOLD}╔════════════════════════════════════════════════════════════╗")
    print(f"║        XRAY ADVANCED MANAGER: MULTI-PROTOCOL PANEL         ║")
    print(f"╚════════════════════════════════════════════════════════════╝{C_RESET}")

# ==================== FIREWALL / PORT BINDING HELPERS ====================

def detect_firewall():
    """Return 'ufw', 'firewalld', 'iptables', or None based on what's active/available."""
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
            return "iptables"
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
                subprocess.run(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                                capture_output=True, text=True)
                check = subprocess.run(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                                        capture_output=True, text=True)
                if check.returncode != 0:
                    subprocess.run(["iptables", "-I", "INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"],
                                    capture_output=True, text=True)
        except Exception:
            pass

def close_firewall_port(port, protocols=("tcp",)):
    """Close/unbind a port in whichever firewall is active, e.g. after the last user on it is removed."""
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
        except Exception:
            pass

def protocols_for_transport(net_type, protocol):
    """Which L4 protocols a given transport actually needs opened on the firewall."""
    if net_type == "kcp":
        return ("udp",)
    if protocol == "shadowsocks":
        return ("tcp", "udp")
    return ("tcp",)

def prune_empty_inbounds(config):
    """Remove inbounds left with zero clients after a deletion, so the port is actually
    freed instead of Xray sitting there listening on a port nobody uses anymore.
    Aware of path multiplexing: keeps a "front" inbound alive only for as long as it
    still routes to something, via its own fallbacks list (Xray-native fallback) or
    the shared Nginx mux table.

    Runs to a FIXED POINT rather than a single pass. A single pass previously refused
    to remove an empty child (e.g. a Trojan inbound on an internal loopback port) as
    long as some front's fallback list still pointed at it — but that front's fallback
    was itself dangling once the child got deleted, and a single pass never got to
    react to its own decisions. That deadlocked cleanup: nothing was ever removed
    (the child was "referenced", the front "had fallbacks"), so an empty front
    permanently occupied the external port — exactly the "port already in use by
    another profile" you keep hitting after deleting the last thing on a multiplexed
    port. Looping until nothing more changes lets an empty child go first, which
    strips the front's now-dangling fallback entry, which then lets the front itself
    (once genuinely empty and routing nowhere) be freed in the same delete.
    Returns [(port, protocols), ...] — only externally-bound ports, for firewall unbind."""
    freed = []
    if not config or "inbounds" not in config:
        return freed

    original_mux = load_ntls_mux()
    mux = copy.deepcopy(original_mux)

    while True:
        inbounds = config["inbounds"]
        live_ports = {ib.get("port") for ib in inbounds}

        # Drop any fallback/mux route whose dest port doesn't correspond to an
        # inbound that's still actually present — recomputed fresh every round.
        for ib in inbounds:
            fbs = ib.get("settings", {}).get("fallbacks")
            if fbs:
                ib["settings"]["fallbacks"] = [fb for fb in fbs if fb.get("dest") in live_ports]
        for port_key in list(mux.keys()):
            routes = mux[port_key]
            new_routes = {p: dp for p, dp in routes.items() if dp in live_ports}
            if new_routes:
                mux[port_key] = new_routes
            else:
                del mux[port_key]

        remaining = []
        removed_this_round = set()
        for ib in inbounds:
            settings = ib.get("settings", {})
            is_empty = "clients" in settings and len(settings["clients"]) == 0
            # A "front" survives only for as long as it still has a live route to
            # something else — a genuine routing purpose independent of its own
            # client list. Being pointed AT by some other still-present fallback/
            # mux entry does NOT itself earn protection: an inbound with zero
            # clients has nothing left to protect, and that stale pointer gets
            # cleaned up above once this inbound is actually removed.
            still_routes_somewhere = bool(settings.get("fallbacks"))
            port = ib.get("port")

            if is_empty and not still_routes_somewhere:
                net_type = ib.get("streamSettings", {}).get("network", "tcp")
                protocol = ib.get("protocol", "")
                if ib.get("listen") != "127.0.0.1":
                    freed.append((port, protocols_for_transport(net_type, protocol)))
                removed_this_round.add(port)
                continue
            remaining.append(ib)

        config["inbounds"] = remaining
        if not removed_this_round:
            break  # fixed point reached — nothing new to cascade

    if mux != original_mux:
        save_ntls_mux(mux)
        removed_port_keys = set(original_mux.keys()) - set(mux.keys())
        for port_key in removed_port_keys:
            conf_path = f"{NGINX_MUX_CONF_DIR}/xray-ntls-mux-{port_key}.conf"
            try:
                if os.path.exists(conf_path):
                    os.remove(conf_path)
            except Exception:
                pass
        for port_key, routes in mux.items():
            write_nginx_mux_conf(int(port_key), routes)
        reload_nginx()

    return freed

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

def build_tls_settings(net_type, sni=None):
    alpn = ["h2"] if net_type == "grpc" else ["h2", "http/1.1"]
    cert_file, key_file = get_cert_paths()
    tls_settings = {
        "serverName": sni or get_domain(),
        "alpn": alpn,
        "certificates": [
            {"certificateFile": cert_file, "keyFile": key_file}
        ]
    }
    return tls_settings

def build_full_client_config(protocol, server_address, port, client_id, server_stream_settings,
                              security, sni, reality_keys=None, reality_fp="chrome", reality_sni="",
                              ss_method=None, socks_port=10808, http_port=10809):
    """Build a complete client-app Xray config — local socks/http inbounds, the
    profile's own outbound, and a DNS routing rule — instead of just a bare
    share link. This is the shape bug-host apps actually need to import (local
    proxy + outbound + routing all in one file), mirroring the reference config
    you originally sent (dns/inbounds/outbounds/routing all present)."""
    client_stream = copy.deepcopy(server_stream_settings)

    if security == "tls":
        tls = client_stream.get("tlsSettings", {})
        tls.pop("certificates", None)
        tls["allowInsecure"] = True
        tls["fingerprint"] = tls.get("fingerprint", "")
        tls["publicKey"] = tls.get("publicKey", "")
        tls["serverName"] = sni or tls.get("serverName", "")
        tls["shortId"] = tls.get("shortId", "")
        tls["show"] = False
        tls["spiderX"] = tls.get("spiderX", "")
        client_stream["tlsSettings"] = tls
    elif security == "reality" and reality_keys:
        client_stream["realitySettings"] = {
            "show": False,
            "fingerprint": reality_fp,
            "serverName": reality_sni,
            "publicKey": reality_keys["public_key"],
            "shortId": reality_keys["short_id"],
            "spiderX": ""
        }

    if protocol == "vless":
        user = {"encryption": "none", "flow": "", "id": client_id, "level": 8, "security": "auto"}
        if security == "reality" and client_stream.get("network") == "tcp":
            user["flow"] = "xtls-rprx-vision"
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": server_address, "port": port, "users": [user]}]},
            "streamSettings": client_stream,
            "mux": {"enabled": False, "concurrency": 8},
            "tag": "proxy"
        }
    elif protocol == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": server_address, "port": port,
                          "users": [{"id": client_id, "alterId": 0, "level": 8, "security": "auto"}]}]},
            "streamSettings": client_stream,
            "mux": {"enabled": False, "concurrency": 8},
            "tag": "proxy"
        }
    elif protocol == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": server_address, "port": port, "password": client_id}]},
            "streamSettings": client_stream,
            "mux": {"enabled": False, "concurrency": 8},
            "tag": "proxy"
        }
    else:  # shadowsocks
        outbound = {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"address": server_address, "port": port,
                          "method": ss_method, "password": client_id}]},
            "streamSettings": client_stream,
            "tag": "proxy"
        }

    return {
        "dns": {
            "hosts": {"domain:googleapis.cn": "googleapis.com"},
            "servers": ["1.1.1.1"]
        },
        "inbounds": [
            {
                "port": socks_port, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls"], "enabled": True},
                "tag": "socks"
            },
            {
                "port": http_port, "protocol": "http",
                "settings": {"userLevel": 8},
                "tag": "http"
            }
        ],
        "log": {"loglevel": "none"},
        "outbounds": [
            outbound,
            {"protocol": "freedom", "settings": {}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"}
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"ip": ["1.1.1.1"], "outboundTag": "proxy", "port": "53", "type": "field"}
            ]
        }
    }

# ==================== STAGE 1: INSTALLATION & SSL ====================


def check_stage1_completed():
    return os.path.exists(INSTALL_FLAG)

def mark_stage1_complete():
    os.makedirs(os.path.dirname(INSTALL_FLAG), exist_ok=True)
    with open(INSTALL_FLAG, "w") as f:
        f.write("installed=true\n")

def stage_1_installer():
    while True:
        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                 V2RAY/XRAY ADMINISTRATOR                   %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] Return / Exit")
        print(" [1] INSTALL V2RAY/XRAY")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input("Enter an Option: ").strip()

        if choice == "0":
            print("Exiting script.")
            return False

        elif choice == "1":
            domain = input("\nEnter your domain for Installation: ").strip()
            if not domain:
                print(f"{C_RED}Domain cannot be empty.{C_RESET}")
                input("\nPress Enter to continue...")
                continue

            while True:
                clear_screen()
                print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
                print("%s                 SSL CERTIFICATE GENERATOR                  %s" % (C_BOLD, C_RESET))
                print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
                print(" [1]> Let's Encrypt")
                print(" [2]> Zerossl")
                print(" [3]> Mode Manual")
                print(" [4]> Url link (.zip)")
                print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
                print(" [0] Return")
                print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

                ssl_choice = input("Enter an Option: ").strip()

                if ssl_choice == "0":
                    break

                elif ssl_choice == "1":
                    print(f"\n[+] Step 1/3: Installing dependencies and Xray-core on the fresh VPS...")
                    subprocess.run("apt-get update && apt-get install -y curl wget certbot", shell=True)

                    xray_install_cmd = "bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install"
                    xray_result = subprocess.run(xray_install_cmd, shell=True)

                    if xray_result.returncode != 0:
                        print(f"{C_RED}[-] Failed to install Xray-core binary.{C_RESET}")
                        input("\nPress Enter to try again...")
                        continue

                    print(f"\n[+] Step 2/3: Obtaining Let's Encrypt SSL certificate for {domain}...")
                    # Remember what was actually running before we stop it for the standalone
                    # cert challenge, so we can put things back the way they were afterward
                    # instead of leaving nginx/apache2 down.
                    was_active = {}
                    for svc in ("nginx", "apache2"):
                        chk = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
                        was_active[svc] = chk.returncode == 0 and "active" in chk.stdout
                    subprocess.run("systemctl stop nginx apache2 xray 2>/dev/null", shell=True)

                    # Deploy hook keeps the panel's copy of the cert (and Xray) in sync with
                    # every future automatic renewal, instead of the cert silently expiring
                    # in ~90 days and taking every user's connection down with it.
                    hook_dir = "/etc/letsencrypt/renewal-hooks/deploy"
                    os.makedirs(hook_dir, exist_ok=True)
                    hook_path = f"{hook_dir}/xray-panel-renew.sh"
                    hook_script = (
                        "#!/bin/bash\n"
                        f"cp /etc/letsencrypt/live/{domain}/fullchain.pem /usr/local/etc/xray/cert/{domain}.crt\n"
                        f"cp /etc/letsencrypt/live/{domain}/privkey.pem /usr/local/etc/xray/cert/{domain}.key\n"
                        "systemctl restart xray\n"
                    )
                    with open(hook_path, "w") as f:
                        f.write(hook_script)
                    os.chmod(hook_path, 0o755)

                    cert_cmd = f"certbot certonly --standalone --agree-tos --register-unsafely-without-email -d {domain}"
                    result = subprocess.run(cert_cmd, shell=True)

                    for svc, active in was_active.items():
                        if active:
                            subprocess.run(["systemctl", "start", svc], capture_output=True, text=True)

                    if result.returncode == 0:
                        print(f"\n{C_GREEN}[+] Step 3/3: SSL Certificate generated and saved successfully!{C_RESET}")

                        os.makedirs("/usr/local/etc/xray/cert", exist_ok=True)
                        live_cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
                        live_key = f"/etc/letsencrypt/live/{domain}/privkey.pem"

                        subprocess.run(f"cp {live_cert} /usr/local/etc/xray/cert/{domain}.crt", shell=True)
                        subprocess.run(f"cp {live_key} /usr/local/etc/xray/cert/{domain}.key", shell=True)

                        global _domain_cache
                        _domain_cache = domain
                        os.makedirs(os.path.dirname(PANEL_CONFIG_PATH), exist_ok=True)
                        with open(PANEL_CONFIG_PATH, "w") as f:
                            json.dump({"domain": domain}, f, indent=2)

                        mark_stage1_complete()
                        subprocess.run("systemctl enable xray && systemctl start xray", shell=True)
                        open_firewall_port(443, ("tcp",))
                        open_firewall_port(80, ("tcp",))

                        print(f"{C_GREEN}Auto-renewal deploy hook installed at {hook_path} — future cert renewals will refresh Xray's copy and restart it automatically.{C_RESET}")
                        input("\nPress Enter to proceed to Manager...")
                        return True
                    else:
                        print(f"{C_RED}[-] Certificate generation failed. Ensure port 80 is open and your domain DNS points to this VPS IP.{C_RESET}")
                        input("\nPress Enter to try again...")

                elif ssl_choice in ("2", "3", "4"):
                    print(f"\n{C_YELLOW}[!] Option {ssl_choice} requires manual setup or external configuration.{C_RESET}")
                    input("\nPress Enter to continue...")
        else:
            print(f"{C_RED}Invalid option. Please select 0 or 1.{C_RESET}")
            input("\nPress Enter to continue...")

    return False

# ==================== STAGE 2: MANAGEMENT PANEL ====================

def add_user():
    global _domain_cache
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[+] NEW USER SETUP: PROTOCOL SELECTION{C_RESET}\n")
    print(f"  {C_GREEN}[1]{C_RESET} VLESS")
    print(f"  {C_GREEN}[2]{C_RESET} VMESS")
    print(f"  {C_GREEN}[3]{C_RESET} TROJAN")
    print(f"  {C_GREEN}[4]{C_RESET} SHADOWSOCKS")
    print(f"  {C_RED}[0]{C_RESET} Back")

    p_choice = input(f"\n{C_BOLD}Select Protocol [1-4]: {C_RESET}").strip()
    proto_map = {"1": "vless", "2": "vmess", "3": "trojan", "4": "shadowsocks"}
    if p_choice not in proto_map:
        return
    protocol = proto_map[p_choice]

    remark = input(f"{C_GREEN}Enter Remark / Username: {C_RESET}").strip()
    if not remark:
        print(f"{C_RED}Username cannot be empty!{C_RESET}")
        input("\nPress Enter...")
        return

    if remark in load_tracker():
        print(f"\n{C_RED}A user named '{remark}' already exists. Xray requires unique client emails per inbound, "
              f"so re-adding the same name (even on a different protocol/port) will make Xray fail to start "
              f"with 'User {remark} already exists'.{C_RESET}")
        print(f"{C_YELLOW}Delete the existing user first (option 2), or choose a different username.{C_RESET}")
        input("\nPress Enter to return...")
        return

    manual_domain = input(f"{C_GREEN}Enter your domain (the address this profile's link/config will connect to; leave blank to use this server's default): {C_RESET}").strip()

    port = prompt_port(f"{C_GREEN}Enter Desired Port (e.g., 443, 8443): {C_RESET}", default=443)

    print(f"\n{C_YELLOW}[+] SELECT STREAM / TRANSPORT ARCHITECTURE{C_RESET}")
    print(f"  {C_GREEN}[1]{C_RESET} WebSocket (WS)")
    print(f"  {C_GREEN}[2]{C_RESET} gRPC")
    print(f"  {C_GREEN}[3]{C_RESET} HTTPUpgrade")
    print(f"  {C_GREEN}[4]{C_RESET} XHTTP")
    print(f"  {C_GREEN}[5]{C_RESET} RAW / TCP")
    print(f"  {C_GREEN}[6]{C_RESET} mKCP")

    s_choice = input(f"\n{C_BOLD}Select Transport [1-6]: {C_RESET}").strip()
    if s_choice not in ("1", "2", "3", "4", "5", "6"):
        return

    net_type_preview = {"1": "ws", "2": "grpc", "3": "httpupgrade", "4": "xhttp", "5": "tcp", "6": "kcp"}[s_choice]

    security = "none"
    reality_keys = None
    reality_sni = ""
    reality_fp = "chrome"
    grpc_mode = "gun"

    if net_type_preview == "kcp":
        security = "none"
    elif net_type_preview in ("xhttp", "tcp"):
        print(f"\n{C_GREEN}Security - Select [1] TLS  [2] NTLS (None)  [3] REALITY: {C_RESET}", end="")
        sec_choice = input().strip()
        if sec_choice == "3":
            reality_keys = load_reality_keys()
            if not reality_keys:
                print(f"\n{C_RED}No REALITY keypair found at {REALITY_KEYS_PATH}.{C_RESET}")
                input("\nPress Enter to return...")
                return
            security = "reality"
        elif sec_choice == "1":
            security = "tls"
        else:
            security = "none"
    else:
        print(f"\n{C_GREEN}Security - Select [1] TLS  [2] NTLS (None): {C_RESET}", end="")
        sec_choice = input().strip()
        security = "none" if sec_choice == "2" else "tls"

    if security == "tls" and not cert_files_exist():
        cert_file, _ = get_cert_paths()
        print(f"\n{C_RED}No certificate found at {cert_file}.{C_RESET}")
        print(f"{C_YELLOW}Run Stage 1 installation again for {get_domain()}, or choose NTLS.{C_RESET}")
        input("\nPress Enter to return...")
        return

    manual_sni = ""
    if security == "tls":
        manual_sni = input(f"{C_GREEN}Enter your serverName (SNI) (leave blank to default to the Host header / this server's domain): {C_RESET}").strip()

    if security == "reality":
        print(f"\n{C_YELLOW}[+] SELECT REALITY DECOY SITE{C_RESET}")
        print(f"  {C_GREEN}[1]{C_RESET} www.microsoft.com")
        print(f"  {C_GREEN}[2]{C_RESET} www.apple.com")
        print(f"  {C_GREEN}[3]{C_RESET} www.google.com")
        print(f"  {C_GREEN}[4]{C_RESET} play.google.com")
        print(f"  {C_GREEN}[5]{C_RESET} Custom...")
        decoy_map = {"1": "www.microsoft.com", "2": "www.apple.com", "3": "www.google.com", "4": "play.google.com"}
        decoy_choice = input(f"Select Decoy [1-5]: {C_RESET}").strip()
        if decoy_choice == "5":
            reality_sni = input(f"{C_GREEN}Enter custom decoy domain: {C_RESET}").strip() or "www.microsoft.com"
        else:
            reality_sni = decoy_map.get(decoy_choice, "www.microsoft.com")

        print(f"\n{C_YELLOW}[+] SELECT TLS FINGERPRINT{C_RESET}")
        print(f"  {C_GREEN}[1]{C_RESET} chrome")
        print(f"  {C_GREEN}[2]{C_RESET} firefox")
        print(f"  {C_GREEN}[3]{C_RESET} safari")
        print(f"  {C_GREEN}[4]{C_RESET} randomized")
        fp_map = {"1": "chrome", "2": "firefox", "3": "safari", "4": "randomized"}
        fp_choice = input(f"Select Fingerprint [1-4] (default chrome): {C_RESET}").strip()
        reality_fp = fp_map.get(fp_choice, "chrome")

    if net_type_preview == "grpc":
        print(f"\n{C_YELLOW}[+] SELECT gRPC MODE{C_RESET}")
        print(f"  {C_GREEN}[1]{C_RESET} gun (default)")
        print(f"  {C_GREEN}[2]{C_RESET} multi")
        gm_choice = input(f"Select Mode [1-2]: {C_RESET}").strip()
        grpc_mode = "multi" if gm_choice == "2" else "gun"

    enable_host = input(f"{C_GREEN}Enable Custom Host Header? [y/N]: {C_RESET}").strip().lower()
    custom_host = ""
    if enable_host == 'y':
        custom_host = input(f"{C_GREEN}Enter Host Domain Value (e.g., cdn.domain.com): {C_RESET}").strip()

    path = input(f"{C_GREEN}Enter Path / ServiceName (default '/{protocol}'): {C_RESET}").strip() or f"/{protocol}"

    xhttp_mode = "auto"
    if s_choice == "4":
        print(f"\n{C_YELLOW}[+] SELECT XHTTP MODE{C_RESET}")
        print(f"  {C_GREEN}[1]{C_RESET} auto")
        print(f"  {C_GREEN}[2]{C_RESET} stream-up")
        print(f"  {C_GREEN}[3]{C_RESET} stream-one")
        print(f"  {C_GREEN}[4]{C_RESET} packet-up")
        xm_choice = input(f"Select Mode [1-4]: {C_RESET}").strip()
        mode_map = {"1": "auto", "2": "stream-up", "3": "stream-one", "4": "packet-up"}
        xhttp_mode = mode_map.get(xm_choice, "auto")

    try:
        days = int(input(f"{C_GREEN}Enter Validity (Days): {C_RESET}").strip())
    except ValueError:
        days = 30

    client_id = str(uuid.uuid4())
    expiry_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    config = load_xray_config()
    if not config:
        config = {"inbounds": [], "outbounds": [{"protocol": "freedom", "tag": "direct"}]}
    # Deep copy BEFORE this inbound gets added - restart_xray() below can fail
    # (genuine port conflict, or anything else that only surfaces at actual
    # startup rather than during -test's static validation), and without a
    # real rollback the new inbound stays permanently written to the config
    # even though the operation reported failure. Confirmed as the actual
    # cause of repeated "failed to stay active" reports across different
    # ports: each failed attempt left its own broken inbound behind, so the
    # config kept accumulating conflicts rather than staying at the last
    # known-working state.
    original_config = copy.deepcopy(config)

    stream_settings = {"security": security}
    net_type = "tcp"

    if s_choice == "1":
        net_type = "ws"
        ws_settings = {"path": path}
        if custom_host:
            ws_settings["headers"] = {"Host": custom_host}
        stream_settings.update({"network": "ws", "wsSettings": ws_settings})
        if security == "tls":
            stream_settings["tlsSettings"] = build_tls_settings(net_type, manual_sni or custom_host)

    elif s_choice == "2":
        net_type = "grpc"
        grpc_settings = {"serviceName": path.strip("/")}
        if grpc_mode == "multi":
            grpc_settings["multiMode"] = True
        stream_settings.update({"network": "grpc", "grpcSettings": grpc_settings})
        if security == "tls":
            stream_settings["tlsSettings"] = build_tls_settings(net_type, manual_sni or custom_host)

    elif s_choice == "3":
        net_type = "httpupgrade"
        hu_settings = {"path": path}
        if custom_host:
            hu_settings["host"] = custom_host
        stream_settings.update({"network": "httpupgrade", "httpupgradeSettings": hu_settings})
        if security == "tls":
            stream_settings["tlsSettings"] = build_tls_settings(net_type, manual_sni or custom_host)

    elif s_choice == "4":
        net_type = "xhttp"
        xh_settings = {"path": path, "mode": xhttp_mode}
        if custom_host:
            xh_settings["host"] = custom_host
        stream_settings.update({"network": "xhttp", "xhttpSettings": xh_settings})
        if security == "tls":
            stream_settings["tlsSettings"] = build_tls_settings(net_type, manual_sni or custom_host)
        elif security == "reality":
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = {
                "show": False,
                "dest": f"{reality_sni}:443",
                "serverNames": [reality_sni],
                "privateKey": reality_keys["private_key"],
                "shortIds": [reality_keys["short_id"]]
            }

    elif s_choice == "5":
        net_type = "tcp"
        tcp_header = {"type": "none"}
        if custom_host:
            tcp_header = {
                "type": "http",
                "request": {
                    "version": "1.1",
                    "method": "GET",
                    "path": [path],
                    "headers": {"Host": [custom_host]}
                }
            }
        stream_settings.update({"network": "tcp", "tcpSettings": {"header": tcp_header}})
        if security == "tls":
            stream_settings["tlsSettings"] = build_tls_settings(net_type, manual_sni or custom_host)
        elif security == "reality":
            stream_settings["network"] = "tcp"
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = {
                "show": False,
                "dest": f"{reality_sni}:443",
                "serverNames": [reality_sni],
                "privateKey": reality_keys["private_key"],
                "shortIds": [reality_keys["short_id"]]
            }
            stream_settings.pop("tcpSettings", None)

    elif s_choice == "6":
        net_type = "kcp"
        # Xray-core removed kcpSettings.header/seed (build fails with "mkcp header &
        # seed has been removed and migrated to finalmask..."). The old header
        # obfuscation (wechat-video) and the seed-based encryption are now two
        # separate finalmask/udp layers: header-wechat for the packet-shape mask,
        # mkcp-aes128gcm for the seed's actual job (AES-128-GCM obfuscation keyed
        # off a password, which is what "seed" really did).
        stream_settings.update({
            "network": "kcp",
            "kcpSettings": {
                "mtu": 1350,
                "tti": 50,
                "uplinkCapacity": 5,
                "downlinkCapacity": 20,
                "congestion": False
            },
            "finalmask": {
                "udp": [
                    {"type": "header-wechat", "settings": {}},
                    {"type": "mkcp-aes128gcm", "settings": {"password": client_id[:8]}}
                ]
            }
        })

    vless_encryption = None
    if protocol == "vless":
        enc_choice = input(f"\n{C_GREEN}Enable VLESS Native Encryption (Post-Quantum ML-KEM-768, independent of TLS)? [y/N]: {C_RESET}").strip().lower()
        if enc_choice == 'y':
            vless_encryption = get_or_create_vless_enc_keys()
            if not vless_encryption:
                print(f"{C_YELLOW}Your installed Xray-core doesn't support 'xray vlessenc' (needs a recent build). Falling back to encryption=none.{C_RESET}")
            elif security == "tls":
                print(f"{C_YELLOW}Note: VLESS Native Encryption can't be combined with the port-443 fallback/decoy feature (menu option 3) on this inbound.{C_RESET}")

    if protocol == "shadowsocks":
        ss_method = "aes-256-gcm"
        client_entry = {"method": ss_method, "password": client_id, "email": remark}
    elif protocol == "trojan":
        client_entry = {"password": client_id, "email": remark}
    else:
        client_entry = {"id": client_id, "email": remark}
        if protocol == "vmess":
            client_entry["alterId"] = 0
        if protocol == "vless" and security == "reality" and s_choice == "5":
            client_entry["flow"] = "xtls-rprx-vision"

    settings_block = {"clients": [client_entry]}
    if protocol == "shadowsocks":
        settings_block["network"] = "tcp,udp"
    elif protocol == "vless":
        settings_block["decryption"] = vless_encryption["decryption"] if vless_encryption else "none"

    new_inbound = {
        "listen": "0.0.0.0",
        "port": port,
        "protocol": protocol,
        "settings": settings_block,
        "streamSettings": stream_settings
    }

    # PORT-CONFLICT PREVENTION & COMPATIBILITY CHECK
    def inbound_own_path(ib):
        net = ib.get("streamSettings", {}).get("network")
        ss = ib.get("streamSettings", {})
        if net == "ws":
            return ss.get("wsSettings", {}).get("path", "/")
        if net == "xhttp":
            return ss.get("xhttpSettings", {}).get("path", "/")
        if net == "httpupgrade":
            return ss.get("httpupgradeSettings", {}).get("path", "/")
        if net == "grpc":
            return "/" + ss.get("grpcSettings", {}).get("serviceName", "").lstrip("/")
        return None

    needed_protocols = protocols_for_transport(net_type, protocol)
    req_path = "/" + path.lstrip("/") if net_type != "grpc" else "/" + path.strip("/")

    existing_inbound = None
    conflicting_inbound = None
    for ib in config.get("inbounds", []):
        if ib.get("port") == port:
            ib_net = ib.get("streamSettings", {}).get("network", "tcp")
            ib_sec = ib.get("streamSettings", {}).get("security", "none")
            if ib.get("protocol") == protocol and ib_net == net_type and ib_sec == security:
                existing_inbound = ib
            else:
                conflicting_inbound = ib
            break

    is_multiplexed = False
    mux_kind = None  # "xray-fallback" or "nginx"

    if conflicting_inbound and not existing_inbound:
        can_xray_mux = (
            security == "tls"
            and net_type in PATH_ROUTABLE_TRANSPORTS
            and conflicting_inbound.get("streamSettings", {}).get("security") == "tls"
            and conflicting_inbound.get("streamSettings", {}).get("network") in PATH_ROUTABLE_TRANSPORTS
            and conflicting_inbound.get("protocol") in FALLBACK_CAPABLE_PROTOCOLS
        )
        can_nginx_mux = (
            security == "none"
            and net_type in PATH_ROUTABLE_TRANSPORTS - {"grpc"}
            and conflicting_inbound.get("streamSettings", {}).get("security", "none") == "none"
            and conflicting_inbound.get("streamSettings", {}).get("network") in (PATH_ROUTABLE_TRANSPORTS - {"grpc"})
        )

        if can_xray_mux:
            front_path = inbound_own_path(conflicting_inbound)
            front_fallback_paths = {fb.get("path") for fb in conflicting_inbound.get("settings", {}).get("fallbacks", [])}
            if req_path == front_path or req_path in front_fallback_paths:
                print(f"\n{C_RED}Path '{req_path}' on port {port} is already used by the existing {conflicting_inbound.get('protocol')} inbound or one of its fallback routes. Pick a different path.{C_RESET}")
                input("\nPress Enter to return...")
                return
            print(f"\n{C_YELLOW}Port {port} is already used by a {conflicting_inbound.get('protocol')}/{conflicting_inbound.get('streamSettings',{}).get('network')} TLS inbound, which supports fallbacks. "
                  f"This new {protocol}/{net_type} can share port {port} via native Xray path routing — the same technique used by 'all TLS on 443' multi-protocol setups (traffic to '{req_path}' gets routed to it internally, everything else keeps going to the existing inbound).{C_RESET}")
            mux_choice = input(f"{C_GREEN}Route it onto port {port} this way instead of picking a new port? [Y/n]: {C_RESET}").strip().lower()
            if mux_choice == 'n':
                print(f"{C_RED}Cancelled — choose a different port.{C_RESET}")
                input("\nPress Enter to return...")
                return
            is_multiplexed = True
            mux_kind = "xray-fallback"
        elif can_nginx_mux:
            if not nginx_installed():
                print(f"\n{C_RED}Port {port} is already used by another NTLS inbound. Sharing an NTLS port across protocols needs Nginx as a reverse proxy in front (Xray itself can't demux plaintext traffic), but Nginx isn't installed.{C_RESET}")
                input("\nPress Enter to return...")
                return
            print(f"\n{C_YELLOW}Port {port} is already used by a {conflicting_inbound.get('protocol')}/{conflicting_inbound.get('streamSettings',{}).get('network')} NTLS inbound. "
                  f"Since it's plaintext, sharing it needs Nginx in front doing path-based routing rather than a native Xray feature.{C_RESET}")
            mux_choice = input(f"{C_GREEN}Set up Nginx to route path '{req_path}' on port {port} to this new inbound? [Y/n]: {C_RESET}").strip().lower()
            if mux_choice == 'n':
                print(f"{C_RED}Cancelled — choose a different port.{C_RESET}")
                input("\nPress Enter to return...")
                return
            is_multiplexed = True
            mux_kind = "nginx"
        else:
            print(f"\n{C_RED}Error: Port {port} is already claimed by another inbound with a different protocol, transport, or security setting, and it isn't eligible for path multiplexing here.{C_RESET}")
            if security == "tls":
                print(f"{C_RED}(TLS multiplexing needs both inbounds on WS/gRPC/XHTTP/HTTPUpgrade, and the existing one must be VLESS or Trojan — VMess/Shadowsocks can't host fallbacks.){C_RESET}")
            input("\nPress Enter to return...")
            return

    if not existing_inbound and not is_multiplexed and check_system_port_in_use(port, needed_protocols):
        print(f"\n{C_RED}Error: Port {port} is already in use by another system service (such as Nginx, SSH, etc.).{C_RESET}")
        input("\nPress Enter to return...")
        return

    is_new_inbound = existing_inbound is None
    internal_port = None

    if existing_inbound:
        clients_list = existing_inbound.setdefault("settings", {}).setdefault("clients", [])
        if any(c.get("email") == remark for c in clients_list):
            print(f"\n{C_RED}Error: a client named '{remark}' already exists on this exact inbound "
                  f"(port {port}, {protocol}/{net_type}/{security}). Xray requires unique client emails "
                  f"per inbound. Choose a different username.{C_RESET}")
            input("\nPress Enter to return...")
            return
        clients_list.append(client_entry)
    elif is_multiplexed:
        internal_port = find_free_internal_port()
        if not internal_port:
            print(f"\n{C_RED}Couldn't find a free internal port to bind this inbound to. Try again.{C_RESET}")
            input("\nPress Enter to return...")
            return
        new_inbound["listen"] = "127.0.0.1"
        new_inbound["port"] = internal_port
        config["inbounds"].append(new_inbound)

        if mux_kind == "xray-fallback":
            fb_settings = conflicting_inbound.setdefault("settings", {})
            fb_settings.setdefault("fallbacks", []).append({"path": req_path, "dest": internal_port, "xver": 1})
        else:  # nginx
            mux = load_ntls_mux()
            port_key = str(port)
            routes = mux.setdefault(port_key, {})
            # First time multiplexing this port: move the existing inbound behind Nginx too.
            if conflicting_inbound.get("listen", "0.0.0.0") != "127.0.0.1":
                existing_internal_port = find_free_internal_port()
                if not existing_internal_port:
                    print(f"\n{C_RED}Couldn't find a free internal port for the existing inbound. Try again.{C_RESET}")
                    input("\nPress Enter to return...")
                    return
                existing_path = inbound_own_path(conflicting_inbound) or "/"
                conflicting_inbound["listen"] = "127.0.0.1"
                conflicting_inbound["port"] = existing_internal_port
                routes[existing_path] = existing_internal_port
            routes[req_path] = internal_port
            mux[port_key] = routes
            save_ntls_mux(mux)
    else:
        config["inbounds"].append(new_inbound)

    save_xray_config(config)

    xray_ok = restart_xray(verify_port=port, verify_proto=needed_protocols[0])
    nginx_ok = True
    if xray_ok and is_multiplexed and mux_kind == "nginx":
        mux = load_ntls_mux()
        write_nginx_mux_conf(port, mux.get(str(port), {}))
        nginx_ok = reload_nginx()

    if xray_ok and nginx_ok:
        # Only touch the firewall the first time this EXTERNAL port is actually bound;
        # a multiplexed inbound rides on the front's already-open port, and merging
        # another client onto an already-open port doesn't need a new rule either.
        if is_new_inbound and not is_multiplexed:
            open_firewall_port(port, needed_protocols)
        tracker = load_tracker()
        tracker[remark] = {
            "id": client_id,
            "protocol": protocol,
            "port": port,
            "transport": net_type,
            "security": security,
            "path": path,
            "host": custom_host,
            "expiry": expiry_date
        }
        save_tracker(tracker)

        if manual_domain:
            server_address = manual_domain
        elif security in ("tls", "reality"):
            server_address = get_domain()
        else:
            server_address = get_server_ip()

        link = ""

        def build_query_params():
            params = {"type": net_type}
            # Include on every protocol that shares this function — vless, trojan,
            # and shadowsocks alike — not just vless. Overridden below with the
            # real key if VLESS native encryption is actually turned on.
            params["encryption"] = "none"
            if net_type == "grpc":
                params["serviceName"] = path.strip("/")
                params["mode"] = grpc_mode
            elif net_type not in ("tcp", "kcp"):
                params["path"] = path
                if custom_host:
                    params["host"] = custom_host
            elif net_type == "tcp" and custom_host:
                params["host"] = custom_host

            if net_type == "xhttp":
                params["mode"] = xhttp_mode

            if net_type == "tcp" and custom_host and security != "reality":
                params["headerType"] = "http"

            if net_type == "kcp":
                params["seed"] = client_id[:8]
                params["headerType"] = "wechat-video"

            if security == "reality":
                params["security"] = "reality"
                params["pbk"] = reality_keys["public_key"]
                params["fp"] = reality_fp
                params["sni"] = reality_sni
                params["sid"] = reality_keys["short_id"]
                params["spx"] = "%2F"
            elif security == "tls":
                params["security"] = "tls"
                # Prefer the manually entered SNI; fall back to the bug-host Host
                # header, then the server's own domain, in that order. Shadowsocks
                # links conventionally omit sni entirely (vless/trojan carry it).
                if protocol != "shadowsocks":
                    params["sni"] = manual_sni or custom_host or get_domain()
                # Automatic: a bug-host SNI/domain essentially never matches the
                # real cert, so without this the client rejects the handshake
                # outright. Most clients (v2rayN/v2rayNG/NekoBox/sing-box based
                # apps) honor this as a share-link query param.
                params["allowInsecure"] = "1"
            else:
                params["security"] = "none"

            if protocol == "vless" and vless_encryption:
                params["encryption"] = urllib.parse.quote(vless_encryption["encryption"], safe="")

            return "&".join(f"{k}={v}" for k, v in params.items())

        if protocol == "vless":
            query = build_query_params()
            flow_part = "&flow=xtls-rprx-vision" if (security == "reality" and s_choice == "5") else ""
            link = f"vless://{client_id}@{server_address}:{port}?{query}{flow_part}#{remark}"
        elif protocol == "vmess":
            vmess_tls_field = "tls" if security == "tls" else ""
            vmess_net_type = net_type
            vmess_type_marker = "none"
            vmess_path = path

            if vmess_net_type == "grpc":
                vmess_path = path.strip("/")
            elif vmess_net_type == "tcp" and custom_host:
                vmess_type_marker = "http"
            elif vmess_net_type == "kcp":
                vmess_type_marker = "wechat-video"

            vmess_json = {
                "v": "2", "ps": remark, "add": server_address, "port": port, "id": client_id,
                "aid": 0, "net": vmess_net_type, "type": vmess_type_marker, "host": custom_host,
                "path": vmess_path, "tls": vmess_tls_field, "encryption": "none"
            }
            if vmess_tls_field == "tls":
                # Same preference order as vless/trojan/ss: manual SNI first, then
                # the bug-host Host header, then the server's own domain.
                vmess_json["sni"] = manual_sni or custom_host or get_domain()
                vmess_json["allowInsecure"] = True

            if vmess_net_type == "xhttp":
                vmess_json["mode"] = xhttp_mode
            elif vmess_net_type == "kcp":
                vmess_json["seed"] = client_id[:8]

            link = f"vmess://{base64.b64encode(json.dumps(vmess_json).encode()).decode()}"
        elif protocol == "trojan":
            query = build_query_params()
            link = f"trojan://{client_id}@{server_address}:{port}?{query}#{remark}"
        elif protocol == "shadowsocks":
            ss_raw = f"{ss_method}:{client_id}@{server_address}:{port}"
            if net_type == "tcp" and security == "none":
                link = f"ss://{base64.b64encode(ss_raw.encode()).decode()}#{remark}"
            else:
                query = build_query_params()
                link = f"ss://{base64.b64encode(ss_raw.encode()).decode()}@{server_address}:{port}?{query}#{remark}"

        print(f"\n{C_GREEN}Successfully created user '{remark}'!{C_RESET}\n")
        print(f"{C_YELLOW}--- CONNECTION LINK ---{C_RESET}")
        print(f"{C_CYAN}{link}{C_RESET}\n")

        full_choice = input(f"{C_GREEN}Also generate a full client app config (local socks/http proxy + outbound + routing) instead of just the share link — the shape bug-host apps often need? [y/N]: {C_RESET}").strip().lower()
        if full_choice == 'y':
            full_sni = manual_sni or custom_host or get_domain() if security == "tls" else ""
            full_cfg = build_full_client_config(
                protocol, server_address, port, client_id, stream_settings, security, full_sni,
                reality_keys=reality_keys, reality_fp=reality_fp, reality_sni=reality_sni,
                ss_method=ss_method if protocol == "shadowsocks" else None
            )
            print(f"\n{C_YELLOW}--- FULL CLIENT APP CONFIG ---{C_RESET}")
            print(f"{C_CYAN}{json.dumps(full_cfg, indent=2)}{C_RESET}\n")
            client_cfg_dir = "/usr/local/etc/xray/client-configs"
            os.makedirs(client_cfg_dir, exist_ok=True)
            client_cfg_path = f"{client_cfg_dir}/{remark}.json"
            with open(client_cfg_path, "w") as f:
                json.dump(full_cfg, f, indent=2)
            print(f"{C_GREEN}Saved to {client_cfg_path}{C_RESET}\n")

        if security == "tls":
            frag_choice = input(f"{C_GREEN}Include a recommended client-side TLS-fragment tip for restrictive networks? [y/N]: {C_RESET}").strip().lower()
            if frag_choice == 'y':
                print(f"\n{C_YELLOW}This is a CLIENT-side app setting (v2rayNG, NekoRay, etc.) — it doesn't go in the")
                print(f"server config, it fragments the outgoing TLS ClientHello on the client's own")
                print(f"'freedom' outbound to make SNI-based DPI harder to fingerprint:{C_RESET}")
                print(f"""{C_CYAN}{{
  "fragment": {{
    "packets": "tlshello",
    "length": "100-200",
    "interval": "10-20"
  }}
}}{C_RESET}\n""")
    else:
        if not xray_ok:
            # Roll back to the config that was actually working before this
            # attempt, rather than leaving the new (broken) inbound
            # permanently in place - see the comment where original_config
            # was captured for why this matters.
            save_xray_config(original_config)
            if restart_xray():
                print(f"\n{C_RED}Configuration applied but Xray failed to restart - reverted to the")
                print(f"previous working configuration and restarted successfully.{C_RESET}")
            else:
                print(f"\n{C_RED}Configuration applied but Xray failed to restart, and it also failed")
                print(f"to restart after reverting - check 'journalctl -u xray' directly.{C_RESET}")
        elif not nginx_ok:
            print(f"\n{C_RED}Xray config applied, but Nginx failed to reload — check its config before this route will work.{C_RESET}")

    input("Press Enter to return...")

def find_client_in_config(config, username):
    """Scan every inbound's actual client list for one whose email matches username,
    independent of the tracker. Returns (inbound, client) or (None, None).
    This is what lets delete operations find "ghost" users that exist in config.json
    but never made it into (or fell out of) users_tracker.json."""
    if not config:
        return None, None
    for inbound in config.get("inbounds", []):
        for client in inbound.get("settings", {}).get("clients", []):
            if client.get("email") == username:
                return inbound, client
    return None, None

def config_client_count(config):
    """Total number of clients actually present across all inbounds in config.json,
    regardless of whether the tracker knows about them."""
    if not config:
        return 0
    return sum(len(ib.get("settings", {}).get("clients", [])) for ib in config.get("inbounds", []))

def build_client_link_from_config(username, tracker_entry, inbound, client):
    """Reconstruct a client's connection URI purely from what's actually stored in
    config.json (+ the shared REALITY/VLESS-encryption keyfiles), so it always
    reflects the live server state rather than whatever was typed in at creation
    time. Used by 'view user details' and after 'edit user' saves a change."""
    protocol = inbound.get("protocol")
    stream = inbound.get("streamSettings", {})
    net_type = stream.get("network", "tcp")
    security = stream.get("security", "none")
    port = (tracker_entry or {}).get("port", inbound.get("port"))
    client_id = client.get("id") or client.get("password") or ""

    custom_host = ""
    path = "/"
    grpc_mode = "gun"
    xhttp_mode = "auto"

    if net_type == "ws":
        ws = stream.get("wsSettings", {})
        path = ws.get("path", "/")
        custom_host = ws.get("headers", {}).get("Host", "")
    elif net_type == "grpc":
        grpc = stream.get("grpcSettings", {})
        path = "/" + grpc.get("serviceName", "").lstrip("/")
        grpc_mode = "multi" if grpc.get("multiMode") else "gun"
    elif net_type == "httpupgrade":
        hu = stream.get("httpupgradeSettings", {})
        path = hu.get("path", "/")
        custom_host = hu.get("host", "")
    elif net_type == "xhttp":
        xh = stream.get("xhttpSettings", {})
        path = xh.get("path", "/")
        custom_host = xh.get("host", "")
        xhttp_mode = xh.get("mode", "auto")
    elif net_type == "tcp":
        tcp = stream.get("tcpSettings", {})
        header = tcp.get("header", {})
        if header.get("type") == "http":
            req = header.get("request", {})
            path = (req.get("path") or ["/"])[0]
            custom_host = (req.get("headers", {}).get("Host") or [""])[0]

    reality_sni = ""
    reality_pbk = ""
    reality_sid = ""
    if security == "reality":
        rs = stream.get("realitySettings", {})
        reality_sni = (rs.get("serverNames") or [""])[0]
        reality_sid = (rs.get("shortIds") or [""])[0]
        reality_keys_full = load_reality_keys() or {}
        reality_pbk = reality_keys_full.get("public_key", "")

    server_address = get_domain() if security in ("tls", "reality") else get_server_ip()

    def build_query_params(encryption_override=None):
        params = {"type": net_type}
        params["encryption"] = encryption_override or "none"
        if net_type == "grpc":
            params["serviceName"] = path.strip("/")
            params["mode"] = grpc_mode
        elif net_type not in ("tcp", "kcp"):
            params["path"] = path
            if custom_host:
                params["host"] = custom_host
        elif net_type == "tcp" and custom_host:
            params["host"] = custom_host

        if net_type == "xhttp":
            params["mode"] = xhttp_mode

        if net_type == "tcp" and custom_host and security != "reality":
            params["headerType"] = "http"

        if net_type == "kcp":
            params["seed"] = client_id[:8]
            params["headerType"] = "wechat-video"

        if security == "reality":
            params["security"] = "reality"
            params["pbk"] = reality_pbk
            params["fp"] = "chrome"  # client-side hint only; not stored server-side
            params["sni"] = reality_sni
            params["sid"] = reality_sid
            params["spx"] = "%2F"
        elif security == "tls":
            params["security"] = "tls"
            if protocol != "shadowsocks":
                params["sni"] = custom_host or get_domain()
            params["allowInsecure"] = "1"
        else:
            params["security"] = "none"

        return "&".join(f"{k}={v}" for k, v in params.items())

    link = ""
    if protocol == "vless":
        decryption = inbound.get("settings", {}).get("decryption", "none")
        flow_part = f"&flow={client['flow']}" if client.get("flow") else ""
        if decryption != "none":
            vless_enc = load_vless_enc_keys()
            enc_override = urllib.parse.quote(vless_enc["encryption"], safe="") if vless_enc else None
            query = build_query_params(enc_override)
        else:
            query = build_query_params()
        link = f"vless://{client_id}@{server_address}:{port}?{query}{flow_part}#{username}"
    elif protocol == "vmess":
        vmess_tls_field = "tls" if security == "tls" else ""
        vmess_type_marker = "none"
        vmess_path = path
        if net_type == "grpc":
            vmess_path = path.strip("/")
        elif net_type == "tcp" and custom_host:
            vmess_type_marker = "http"
        elif net_type == "kcp":
            vmess_type_marker = "wechat-video"

        vmess_json = {
            "v": "2", "ps": username, "add": server_address, "port": port, "id": client_id,
            "aid": client.get("alterId", 0), "net": net_type, "type": vmess_type_marker,
            "host": custom_host, "path": vmess_path, "tls": vmess_tls_field, "encryption": "none"
        }
        if vmess_tls_field == "tls":
            vmess_json["sni"] = custom_host or get_domain()
            vmess_json["allowInsecure"] = True
        if net_type == "xhttp":
            vmess_json["mode"] = xhttp_mode
        elif net_type == "kcp":
            vmess_json["seed"] = client_id[:8]
        link = f"vmess://{base64.b64encode(json.dumps(vmess_json).encode()).decode()}"
    elif protocol == "trojan":
        query = build_query_params()
        link = f"trojan://{client_id}@{server_address}:{port}?{query}#{username}"
    elif protocol == "shadowsocks":
        ss_method = client.get("method", "aes-256-gcm")
        ss_raw = f"{ss_method}:{client_id}@{server_address}:{port}"
        if net_type == "tcp" and security == "none":
            link = f"ss://{base64.b64encode(ss_raw.encode()).decode()}#{username}"
        else:
            query = build_query_params()
            link = f"ss://{base64.b64encode(ss_raw.encode()).decode()}@{server_address}:{port}?{query}#{username}"

    return link

def view_user_details(username):
    tracker = load_tracker()
    config = load_xray_config()
    tracker_entry = tracker.get(username)
    inbound, client = find_client_in_config(config, username)

    if not tracker_entry and not client:
        print(f"\n{C_RED}User '{username}' not found!{C_RESET}")
        input("\nPress Enter to return...")
        return

    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] USER DETAILS: {username}{C_RESET}\n")

    if tracker_entry:
        print(f"{C_CYAN}Protocol:{C_RESET}    {tracker_entry.get('protocol')}")
        print(f"{C_CYAN}Port:{C_RESET}        {tracker_entry.get('port')}")
        print(f"{C_CYAN}Transport:{C_RESET}   {tracker_entry.get('transport')}")
        print(f"{C_CYAN}Security:{C_RESET}    {tracker_entry.get('security')}")
        print(f"{C_CYAN}Path:{C_RESET}        {tracker_entry.get('path')}")
        print(f"{C_CYAN}Host header:{C_RESET} {tracker_entry.get('host') or '(none)'}")
        print(f"{C_CYAN}Expiry:{C_RESET}      {tracker_entry.get('expiry')}")
    else:
        print(f"{C_YELLOW}(No tracker record for this user — untracked config entry.){C_RESET}")

    if inbound and client:
        link = build_client_link_from_config(username, tracker_entry, inbound, client)
        if link:
            print(f"\n{C_YELLOW}--- CONNECTION LINK ---{C_RESET}")
            print(f"{C_CYAN}{link}{C_RESET}")

        print(f"\n{C_YELLOW}--- RAW CLIENT JSON (settings.clients entry) ---{C_RESET}")
        print(f"{C_CYAN}{json.dumps(client, indent=2)}{C_RESET}")

        print(f"\n{C_YELLOW}--- RAW STREAM SETTINGS (this inbound's transport/security block) ---{C_RESET}")
        print(f"{C_CYAN}{json.dumps(inbound.get('streamSettings', {}), indent=2)}{C_RESET}")
    else:
        print(f"\n{C_RED}No matching client entry found in config.json (config may be out of sync with the tracker).{C_RESET}")

    input("\nPress Enter to return...")

def update_mux_routes_for_path_change(config, inbound, old_path, new_path):
    """If this inbound is a path-multiplexed child (routed to via Xray-native
    fallback, or via the Nginx NTLS mux table), keep whichever routing rule points
    at it in sync when its own path/serviceName changes — otherwise the front keeps
    routing the OLD path here and the new path never gets reached."""
    if not old_path:
        return
    old_norm = "/" + old_path.lstrip("/")
    new_norm = "/" + new_path.lstrip("/")
    if old_norm == new_norm:
        return
    if inbound.get("listen", "0.0.0.0") != "127.0.0.1":
        return  # not a multiplexed internal-only inbound; nothing else references its path

    this_port = inbound.get("port")

    # Xray-native fallback front(s) pointing at this inbound's internal port.
    for other in config.get("inbounds", []):
        for fb in other.get("settings", {}).get("fallbacks", []):
            if fb.get("dest") == this_port and fb.get("path") == old_norm:
                fb["path"] = new_norm

    # Nginx NTLS mux table.
    mux = load_ntls_mux()
    changed_ports = []
    for port_key, routes in mux.items():
        if routes.get(old_norm) == this_port:
            del routes[old_norm]
            routes[new_norm] = this_port
            changed_ports.append(port_key)
    if changed_ports:
        save_ntls_mux(mux)
        for port_key in changed_ports:
            write_nginx_mux_conf(int(port_key), mux[port_key])
        reload_nginx()

def edit_user():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] EDIT USER{C_RESET}\n")
    username = input(f"{C_GREEN}Enter Username to edit: {C_RESET}").strip()

    tracker = load_tracker()
    config = load_xray_config()
    inbound, client = find_client_in_config(config, username)
    tracker_entry = tracker.get(username)

    if not inbound or not client:
        print(f"\n{C_RED}User not found in config.json!{C_RESET}")
        input("\nPress Enter to return...")
        return

    if not tracker_entry:
        print(f"{C_YELLOW}Note: no tracker record for this user (untracked) — editing the live config directly. "
              f"Expiry won't be available until it's tracked again.{C_RESET}")
        input("\nPress Enter to continue...")

    stream = inbound.get("streamSettings", {})
    net_type = stream.get("network", "tcp")
    protocol = inbound.get("protocol")
    dirty = False

    while True:
        clear_screen()
        print_header()
        print(f"{C_YELLOW}[*] EDITING USER: {username}{C_RESET}")
        print(f"{C_CYAN}Protocol: {protocol} | Port: {(tracker_entry or {}).get('port', inbound.get('port'))} | Transport: {net_type} | Security: {stream.get('security','none')}{C_RESET}\n")
        print(f"  {C_GREEN}[1]{C_RESET} Rename (username / remark)")
        print(f"  {C_GREEN}[2]{C_RESET} Set expiry date (days from now)")
        print(f"  {C_GREEN}[3]{C_RESET} Regenerate UUID/Password")
        if net_type in ("ws", "httpupgrade", "xhttp", "tcp"):
            print(f"  {C_GREEN}[4]{C_RESET} Change Host header")
        if net_type in ("ws", "httpupgrade", "xhttp", "grpc"):
            print(f"  {C_GREEN}[5]{C_RESET} Change Path / ServiceName")
        print(f"  {C_YELLOW}[6]{C_RESET} View current config (client + stream settings JSON)")
        print(f"  {C_RED}[0]{C_RESET} Save & Return")
        print(f"\n{C_YELLOW}Note: port, protocol, transport type, and TLS/REALITY security can't be edited here — "
              f"delete and re-add the user for those.{C_RESET}")

        sub = input(f"\n{C_BOLD}Select Option: {C_RESET}").strip()

        if sub == "0":
            break

        elif sub == "1":
            new_name = input(f"{C_GREEN}New username/remark: {C_RESET}").strip()
            if not new_name:
                print(f"{C_RED}Cannot be empty.{C_RESET}")
                input("\nPress Enter...")
                continue
            if new_name != username and (new_name in tracker or find_client_in_config(config, new_name)[0]):
                print(f"{C_RED}A user named '{new_name}' already exists.{C_RESET}")
                input("\nPress Enter...")
                continue
            client["email"] = new_name
            if tracker_entry:
                del tracker[username]
                tracker[new_name] = tracker_entry
            username = new_name
            dirty = True

        elif sub == "2":
            if not tracker_entry:
                print(f"{C_RED}No tracker record — can't set an expiry for an untracked user.{C_RESET}")
                input("\nPress Enter...")
                continue
            try:
                days = int(input(f"{C_GREEN}Set validity: how many days from now?: {C_RESET}").strip())
            except ValueError:
                print(f"{C_RED}Invalid number.{C_RESET}")
                input("\nPress Enter...")
                continue
            tracker_entry["expiry"] = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
            dirty = True

        elif sub == "3":
            confirm = input(f"{C_YELLOW}This invalidates the user's existing client link/QR code. Continue? [y/N]: {C_RESET}").strip().lower()
            if confirm != 'y':
                continue
            new_id = str(uuid.uuid4())
            if protocol in ("trojan", "shadowsocks"):
                client["password"] = new_id
            else:
                client["id"] = new_id
            if tracker_entry:
                tracker_entry["id"] = new_id
            dirty = True

        elif sub == "4" and net_type in ("ws", "httpupgrade", "xhttp", "tcp"):
            new_host = input(f"{C_GREEN}New Host header (blank to remove): {C_RESET}").strip()
            if net_type == "ws":
                ws = stream.setdefault("wsSettings", {})
                if new_host:
                    ws.setdefault("headers", {})["Host"] = new_host
                else:
                    ws.pop("headers", None)
            elif net_type == "httpupgrade":
                hu = stream.setdefault("httpupgradeSettings", {})
                if new_host:
                    hu["host"] = new_host
                else:
                    hu.pop("host", None)
            elif net_type == "xhttp":
                xh = stream.setdefault("xhttpSettings", {})
                if new_host:
                    xh["host"] = new_host
                else:
                    xh.pop("host", None)
            elif net_type == "tcp":
                tcp = stream.setdefault("tcpSettings", {})
                header = tcp.setdefault("header", {"type": "none"})
                if new_host:
                    header["type"] = "http"
                    req = header.setdefault("request", {"version": "1.1", "method": "GET", "path": ["/"]})
                    req.setdefault("headers", {})["Host"] = [new_host]
                else:
                    header["type"] = "none"
                    header.pop("request", None)
            if tracker_entry:
                tracker_entry["host"] = new_host
            dirty = True

        elif sub == "5" and net_type in ("ws", "httpupgrade", "xhttp", "grpc"):
            new_path = input(f"{C_GREEN}New Path / ServiceName: {C_RESET}").strip() or "/"
            old_path = (tracker_entry or {}).get("path")
            if net_type == "grpc":
                stream.setdefault("grpcSettings", {})["serviceName"] = new_path.strip("/")
                new_path_norm = "/" + new_path.strip("/")
            else:
                new_path_norm = "/" + new_path.lstrip("/")
                if net_type == "ws":
                    stream.setdefault("wsSettings", {})["path"] = new_path_norm
                elif net_type == "httpupgrade":
                    stream.setdefault("httpupgradeSettings", {})["path"] = new_path_norm
                elif net_type == "xhttp":
                    stream.setdefault("xhttpSettings", {})["path"] = new_path_norm

            update_mux_routes_for_path_change(config, inbound, old_path, new_path_norm)

            if tracker_entry:
                tracker_entry["path"] = new_path
            dirty = True

        elif sub == "6":
            print(f"\n{C_YELLOW}--- CLIENT ---{C_RESET}\n{json.dumps(client, indent=2)}")
            print(f"\n{C_YELLOW}--- STREAM SETTINGS ---{C_RESET}\n{json.dumps(stream, indent=2)}")
            input("\nPress Enter...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter...")

    if not dirty:
        print(f"\n{C_YELLOW}No changes made.{C_RESET}")
        input("\nPress Enter to return...")
        return

    if tracker_entry:
        save_tracker(tracker)
    save_xray_config(config)

    if restart_xray():
        print(f"\n{C_GREEN}User '{username}' updated and Xray restarted successfully.{C_RESET}")
        link = build_client_link_from_config(username, tracker_entry, inbound, client)
        if link:
            print(f"\n{C_YELLOW}--- UPDATED CONNECTION LINK ---{C_RESET}")
            print(f"{C_CYAN}{link}{C_RESET}")
    else:
        print(f"\n{C_RED}Changes saved, but Xray failed to restart — check the config.{C_RESET}")
    input("\nPress Enter to return...")

def delete_user():
    clear_screen()
    print_header()
    print(f"{C_RED}[-] DELETE USER{C_RESET}\n")
    username = input(f"{C_GREEN}Enter Username to delete: {C_RESET}").strip()

    tracker = load_tracker()
    config = load_xray_config()

    if username not in tracker:
        # Not in the tracker — but it might still be a real, live client in config.json
        # (e.g. added outside the tracker, or the tracker got reset/edited by hand).
        inbound, client = find_client_in_config(config, username)
        if not inbound:
            print(f"\n{C_RED}User not found!{C_RESET}")
            input("\nPress Enter to return...")
            return

        print(f"\n{C_YELLOW}No tracker record for '{username}', but a matching client was found directly "
              f"in config.json (untracked/orphaned user). Removing it from the live config now.{C_RESET}")
        inbound["settings"]["clients"] = [
            c for c in inbound["settings"].get("clients", []) if c.get("email") != username
        ]
        freed_ports = prune_empty_inbounds(config)
        save_xray_config(config)
        if restart_xray():
            for port, protos in freed_ports:
                close_firewall_port(port, protos)
        print(f"\n{C_GREEN}Untracked user '{username}' removed from config.{C_RESET}")
        input("\nPress Enter to return...")
        return

    user_id = tracker[username]["id"]
    freed_ports = []
    if config and "inbounds" in config:
        for inbound in config["inbounds"]:
            settings = inbound.get("settings", {})
            if "clients" in settings:
                settings["clients"] = [
                    c for c in settings["clients"]
                    if c.get("id") != user_id and c.get("password") != user_id and c.get("email") != username
                ]
        freed_ports = prune_empty_inbounds(config)
        save_xray_config(config)
        if restart_xray():
            for port, protos in freed_ports:
                close_firewall_port(port, protos)

    del tracker[username]
    save_tracker(tracker)
    if freed_ports:
        print(f"\n{C_GREEN}User '{username}' deleted, and port(s) {', '.join(str(p) for p, _ in freed_ports)} unbound (no users left on them).{C_RESET}")
    else:
        print(f"\n{C_GREEN}User '{username}' deleted successfully.{C_RESET}")
    input("\nPress Enter to return...")

def delete_all_users():
    clear_screen()
    print_header()
    print(f"{C_RED}[!] DELETE ALL USERS{C_RESET}\n")

    tracker = load_tracker()
    config = load_xray_config()
    live_client_count = config_client_count(config)

    if not tracker and live_client_count == 0:
        print(f"\n{C_RED}No users found.{C_RESET}")
        input("\nPress Enter to return...")
        return

    if not tracker and live_client_count > 0:
        print(f"{C_YELLOW}Note: users_tracker.json is empty, but {live_client_count} client(s) exist directly "
              f"in config.json (untracked). They will be wiped too.{C_RESET}")

    confirm = input(f"{C_YELLOW}Are you sure you want to delete ALL users? [y/N]: {C_RESET}").strip().lower()
    if confirm != 'y':
        return

    if config and "inbounds" in config:
        for inbound in config["inbounds"]:
            settings = inbound.get("settings", {})
            if "clients" in settings:
                settings["clients"] = []
        freed_ports = prune_empty_inbounds(config)
        save_xray_config(config)
        if restart_xray():
            for port, protos in freed_ports:
                close_firewall_port(port, protos)

    save_tracker({})
    print(f"\n{C_GREEN}All users deleted successfully, and their ports unbound from the firewall.{C_RESET}")
    input("\nPress Enter to return...")

def renew_user():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] RENEW USER{C_RESET}\n")
    username = input(f"{C_GREEN}Enter Username to renew: {C_RESET}").strip()

    tracker = load_tracker()
    if username not in tracker:
        print(f"\n{C_RED}User not found!{C_RESET}")
        input("\nPress Enter to return...")
        return

    try:
        add_days = int(input(f"{C_GREEN}Enter additional days to extend: {C_RESET}").strip())
    except ValueError:
        add_days = 30

    current_expiry = datetime.strptime(tracker[username]["expiry"], "%Y-%m-%d %H:%M:%S")
    if current_expiry < datetime.now():
        new_expiry = datetime.now() + timedelta(days=add_days)
    else:
        new_expiry = current_expiry + timedelta(days=add_days)

    tracker[username]["expiry"] = new_expiry.strftime("%Y-%m-%d %H:%M:%S")
    save_tracker(tracker)

    print(f"\n{C_GREEN}User '{username}' renewed until {tracker[username]['expiry']}!{C_RESET}")
    input("\nPress Enter to return...")

def delete_expired_users():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] CLEANING EXPIRED USERS{C_RESET}\n")

    tracker = load_tracker()
    if not tracker:
        print(f"{C_RED}No users found.{C_RESET}")
        input("\nPress Enter to return...")
        return

    now = datetime.now()
    config = load_xray_config()
    expired_count = 0
    freed_ports = []

    for username, data in list(tracker.items()):
        expiry_dt = datetime.strptime(data["expiry"], "%Y-%m-%d %H:%M:%S")
        if expiry_dt < now:
            user_id = data["id"]
            if config and "inbounds" in config:
                for inbound in config["inbounds"]:
                    settings = inbound.get("settings", {})
                    if "clients" in settings:
                        settings["clients"] = [
                            c for c in settings["clients"]
                            if c.get("id") != user_id and c.get("password") != user_id and c.get("email") != username
                        ]
            del tracker[username]
            expired_count += 1
            print(f"{C_RED}Removed expired user: {username}{C_RESET}")

    if expired_count > 0:
        freed_ports = prune_empty_inbounds(config)
        save_xray_config(config)
        if restart_xray():
            for port, protos in freed_ports:
                close_firewall_port(port, protos)
        save_tracker(tracker)
        print(f"\n{C_GREEN}Successfully cleaned {expired_count} expired user(s).{C_RESET}")
        if freed_ports:
            print(f"{C_GREEN}Unbound now-unused port(s): {', '.join(str(p) for p, _ in freed_ports)}{C_RESET}")
    else:
        print(f"\n{C_GREEN}No expired users found.{C_RESET}")
    input("\nPress Enter to return...")

def list_users():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] LIST OF ALL USERS{C_RESET}\n")
    tracker = load_tracker()
    config = load_xray_config()

    if tracker:
        for uname, data in tracker.items():
            print(f" - {C_CYAN}{uname}{C_RESET} | Protocol: {data['protocol']} | Port: {data['port']} | Expiry: {data['expiry']}")

    # Cross-check against what's actually in config.json — a client that's live there
    # but missing from the tracker (untracked/orphaned) is exactly what makes delete
    # operations report "not found" even though the user still exists and is working.
    orphans = []
    if config:
        for inbound in config.get("inbounds", []):
            for client in inbound.get("settings", {}).get("clients", []):
                email = client.get("email")
                if email and email not in tracker:
                    orphans.append((email, inbound.get("protocol"), inbound.get("port")))

    if orphans:
        print(f"\n{C_YELLOW}[!] Untracked users found in config.json (no tracker record — "
              f"no expiry, but Delete/Delete All/Edit can still act on them):{C_RESET}")
        for email, protocol, port in orphans:
            print(f" - {C_CYAN}{email}{C_RESET} | Protocol: {protocol} | Port: {port}")

    if not tracker and not orphans:
        print(f"{C_RED}No users found.{C_RESET}")
        input("\nPress Enter to return...")
        return

    choice = input(f"\n{C_GREEN}Enter a username to view its full config (link, raw JSON, etc.) — or press Enter to return: {C_RESET}").strip()
    if choice:
        view_user_details(choice)

def configure_fallbacks():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] CONFIGURE TLS FALLBACK / ANTI-PROBING DECOY{C_RESET}\n")
    print("Sets a catch-all decoy destination on your TLS front inbound(s): any connection")
    print("that doesn't match a known VLESS/Trojan path (active probes, browsers, scanners)")
    print("gets quietly handed to a real local web server instead of an obvious TLS error.\n")
    print(f"{C_CYAN}This only touches the catch-all — it will NOT disturb the per-protocol path")
    print(f"routes already wired up when you multiplexed protocols onto the same port.{C_RESET}\n")

    decoy_port = prompt_port(f"{C_GREEN}Enter local decoy web server port [default 80]: {C_RESET}", default=80)

    config = load_xray_config()
    if not config or "inbounds" not in config:
        print(f"\n{C_RED}No valid Xray configuration or inbounds found.{C_RESET}")
        input("\nPress Enter to return...")
        return

    # Fallbacks are only a valid field on VLESS/Trojan inbound settings — writing it into
    # every TLS inbound (including VMess/Shadowsocks, which don't have this field at all)
    # was the actual bug here. Only "front" inbounds (the ones capable of hosting a
    # fallbacks array) are eligible.
    front_inbounds = [
        ib for ib in config["inbounds"]
        if ib.get("streamSettings", {}).get("security") == "tls"
        and ib.get("protocol") in FALLBACK_CAPABLE_PROTOCOLS
        and ib.get("streamSettings", {}).get("network") in PATH_ROUTABLE_TRANSPORTS
    ]

    if not front_inbounds:
        print(f"\n{C_YELLOW}No eligible front inbound found. A decoy fallback needs a TLS VLESS or Trojan")
        print(f"inbound on WS/gRPC/XHTTP/HTTPUpgrade — create one first (menu option 1), then run this again.{C_RESET}")
        input("\nPress Enter to return...")
        return

    if not check_system_port_in_use(decoy_port, ("tcp",)):
        print(f"\n{C_YELLOW}Warning: nothing appears to be listening on port {decoy_port} yet. Until something")
        print(f"(e.g. Nginx serving a real site) is actually there, probes hitting the fallback will just")
        print(f"get a connection error instead of a convincing decoy — which defeats the point.{C_RESET}\n")

    updated_count = 0
    for inbound in front_inbounds:
        settings_block = inbound.setdefault("settings", {})
        existing_fallbacks = settings_block.get("fallbacks", [])
        # Keep every path-specific route (these came from multiplexing other protocols
        # onto this port); only replace the catch-all entry (the one with no "path").
        path_routes = [fb for fb in existing_fallbacks if "path" in fb]
        path_routes.append({"dest": decoy_port, "xver": 1})
        settings_block["fallbacks"] = path_routes
        updated_count += 1

    if updated_count > 0:
        save_xray_config(config)
        if restart_xray():
            print(f"\n{C_GREEN}Decoy fallback set to port {decoy_port} on {updated_count} front inbound(s).{C_RESET}")
        else:
            print(f"\n{C_RED}Fallback added, but Xray failed to restart. Check your configuration.{C_RESET}")
    else:
        print(f"\n{C_YELLOW}No eligible inbounds found to apply the fallback to.{C_RESET}")

    input("\nPress Enter to return...")

def online_users():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] ONLINE USERS & CONNECTIONS{C_RESET}\n")
    # -t alone misses mKCP/Shadowsocks-UDP sessions since they never show up as TCP
    # connections; -u catches those too.
    subprocess.run("ss -tunp | grep xray", shell=True)
    input("\nPress Enter to return...")

def shared_logins():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] USERS SHARING LOGINS{C_RESET}\n")
    print("Feature placeholder: All client UUIDs are currently unique.")
    input("\nPress Enter to return...")

# ==================== HYSTERIA2 (QUIC) — BONUS PROTOCOL ====================
# QUIC/UDP traffic isn't subject to the same TCP-based throttling/DPI heuristics ISPs
# apply to WS/gRPC/TLS, so it's a strong complement to the Xray protocols above rather
# than a replacement — most modern panels (Marzban, 3x-ui) ship it alongside Xray for
# exactly this reason. It runs as its own systemd service with its own config.

def load_hysteria_tracker():
    if not os.path.exists(HYSTERIA_TRACKER_PATH):
        return {}
    try:
        with open(HYSTERIA_TRACKER_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_hysteria_tracker(tracker):
    os.makedirs(os.path.dirname(HYSTERIA_TRACKER_PATH), exist_ok=True)
    with open(HYSTERIA_TRACKER_PATH, "w") as f:
        json.dump(tracker, f, indent=2)

def load_hysteria_config():
    if not os.path.exists(HYSTERIA_CONFIG_PATH):
        return None
    try:
        with open(HYSTERIA_CONFIG_PATH, "r") as f:
            return json.load(f)  # JSON is valid YAML; yaml.v3 (used by Hysteria) parses it fine
    except Exception:
        return None

def save_hysteria_config(config):
    os.makedirs(os.path.dirname(HYSTERIA_CONFIG_PATH), exist_ok=True)
    with open(HYSTERIA_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

def restart_hysteria():
    try:
        subprocess.run(["systemctl", "restart", "hysteria-server"], check=True)
        time.sleep(1)
        res = subprocess.run(["systemctl", "is-active", "hysteria-server"], capture_output=True, text=True)
        if res.returncode == 0 and "active" in res.stdout:
            return True
        print(f"{C_RED}Hysteria2 service failed to stay active after restart.{C_RESET}")
        return False
    except Exception as e:
        print(f"{C_RED}Failed to restart Hysteria2 service: {e}{C_RESET}")
        return False

def hysteria_install():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[+] INSTALL HYSTERIA2 (QUIC){C_RESET}\n")

    if not cert_files_exist():
        print(f"{C_RED}No TLS certificate found for {get_domain()}. Run Stage 1 SSL setup first.{C_RESET}")
        input("\nPress Enter to return...")
        return

    port = prompt_port(f"{C_GREEN}Enter port for Hysteria2 (UDP) [default 443]: {C_RESET}", default=443)

    if check_system_port_in_use(port, ("udp",)):
        print(f"\n{C_RED}Error: UDP port {port} is already in use.{C_RESET}")
        input("\nPress Enter to return...")
        return

    print(f"\n[+] Installing Hysteria2 core...")
    result = subprocess.run("bash <(curl -fsSL https://get.hy2.sh/)", shell=True, executable="/bin/bash")
    if result.returncode != 0:
        print(f"{C_RED}Hysteria2 installation failed.{C_RESET}")
        input("\nPress Enter to return...")
        return

    cert_file, key_file = get_cert_paths()
    config = {
        "listen": f":{port}",
        "tls": {"cert": cert_file, "key": key_file},
        "auth": {"type": "userpass", "userpass": {}},
        "masquerade": {"type": "proxy", "proxy": {"url": "https://www.bing.com", "rewriteHost": True}}
    }
    save_hysteria_config(config)
    save_hysteria_tracker({})

    subprocess.run(["systemctl", "enable", "hysteria-server"], capture_output=True, text=True)
    if restart_hysteria():
        open_firewall_port(port, ("udp",))
        os.makedirs(os.path.dirname(HYSTERIA_INSTALL_FLAG), exist_ok=True)
        with open(HYSTERIA_INSTALL_FLAG, "w") as f:
            json.dump({"port": port}, f)
        print(f"\n{C_GREEN}Hysteria2 installed and listening on UDP {port}!{C_RESET}")
    else:
        print(f"\n{C_RED}Hysteria2 installed but the service failed to start. Check its config.{C_RESET}")
    input("\nPress Enter to return...")

def hysteria_add_user():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[+] ADD HYSTERIA2 USER{C_RESET}\n")

    config = load_hysteria_config()
    if not config:
        print(f"{C_RED}Hysteria2 is not installed yet. Install it first.{C_RESET}")
        input("\nPress Enter to return...")
        return

    username = input(f"{C_GREEN}Enter Username: {C_RESET}").strip()
    if not username:
        print(f"{C_RED}Username cannot be empty!{C_RESET}")
        input("\nPress Enter...")
        return

    try:
        days = int(input(f"{C_GREEN}Enter Validity (Days): {C_RESET}").strip())
    except ValueError:
        days = 30

    password = secrets.token_urlsafe(16)
    config.setdefault("auth", {}).setdefault("userpass", {})[username] = password
    save_hysteria_config(config)

    if restart_hysteria():
        tracker = load_hysteria_tracker()
        tracker[username] = {
            "password": password,
            "expiry": (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        }
        save_hysteria_tracker(tracker)

        port = config["listen"].lstrip(":")
        domain = get_domain()
        link = f"hysteria2://{password}@{domain}:{port}/?sni={domain}#{username}"
        print(f"\n{C_GREEN}Successfully created Hysteria2 user '{username}'!{C_RESET}\n")
        print(f"{C_YELLOW}--- CONNECTION LINK ---{C_RESET}")
        print(f"{C_CYAN}{link}{C_RESET}\n")
    else:
        print(f"\n{C_RED}User added to config but Hysteria2 failed to restart.{C_RESET}")
    input("Press Enter to return...")

def hysteria_delete_user():
    clear_screen()
    print_header()
    print(f"{C_RED}[-] DELETE HYSTERIA2 USER{C_RESET}\n")
    username = input(f"{C_GREEN}Enter Username to delete: {C_RESET}").strip()

    tracker = load_hysteria_tracker()
    if username not in tracker:
        print(f"\n{C_RED}User not found!{C_RESET}")
        input("\nPress Enter to return...")
        return

    config = load_hysteria_config()
    if config:
        config.get("auth", {}).get("userpass", {}).pop(username, None)
        save_hysteria_config(config)
        restart_hysteria()

    del tracker[username]
    save_hysteria_tracker(tracker)
    print(f"\n{C_GREEN}Hysteria2 user '{username}' deleted successfully.{C_RESET}")
    input("\nPress Enter to return...")

def hysteria_list_users():
    clear_screen()
    print_header()
    print(f"{C_YELLOW}[*] LIST OF HYSTERIA2 USERS{C_RESET}\n")
    tracker = load_hysteria_tracker()
    if not tracker:
        print(f"{C_RED}No Hysteria2 users found.{C_RESET}")
    else:
        for uname, data in tracker.items():
            print(f" - {C_CYAN}{uname}{C_RESET} | Expiry: {data['expiry']}")
    input("\nPress Enter to return...")

def hysteria_menu():
    while True:
        clear_screen()
        print_header()
        print(f"{C_YELLOW}[*] HYSTERIA2 (QUIC) MANAGEMENT{C_RESET}\n")
        installed = os.path.exists(HYSTERIA_INSTALL_FLAG)
        print(f"  {C_GREEN}[1]{C_RESET} Install Hysteria2" + ("" if not installed else f" {C_YELLOW}(already installed){C_RESET}"))
        print(f"  {C_GREEN}[2]{C_RESET} Add User")
        print(f"  {C_GREEN}[3]{C_RESET} Delete User")
        print(f"  {C_GREEN}[4]{C_RESET} List Users")
        print(f"  {C_RED}[0]{C_RESET} Back")
        choice = input(f"\n{C_BOLD}Select Option [0-4]: {C_RESET}").strip()
        if choice == "1":
            hysteria_install()
        elif choice == "2":
            hysteria_add_user()
        elif choice == "3":
            hysteria_delete_user()
        elif choice == "4":
            hysteria_list_users()
        elif choice == "0":
            return
        else:
            print(f"{C_RED}Invalid option!{C_RESET}")
            input("Press Enter to continue...")

def uninstall_script():
    """Xray-core is normally installed via XTLS's own official install
    script (bash -c "$(curl -L .../install-release.sh)"), not apt - that
    script's own documented file list is exactly what's removed here.
    'xray' is not a real Ubuntu/Debian package (confirmed: the only actual
    apt package by a similar name is a third-party PPA's own "xray-server",
    a different name entirely) - apt-get purge -y xray silently fails
    against a nonexistent package, meaning the previous version of this
    function never actually removed anything beyond stopping the current
    process. The service stayed enabled and the config file (with every
    inbound's port still in it) stayed on disk, so a later reboot would
    bring Xray back up and silently rebind every "uninstalled" port."""
    clear_screen()
    print_header()
    print(f"{C_RED}[!] UNINSTALL V2RAY/XRAY{C_RESET}\n")
    confirm = input("Are you sure you want to completely remove Xray? [y/N]: ").strip().lower()
    if confirm == 'y':
        ports_to_close = []
        try:
            config = load_xray_config()
            for inbound in (config or {}).get("inbounds", []):
                port = inbound.get("port")
                if isinstance(port, int):
                    ports_to_close.append(port)
        except Exception:
            pass

        subprocess.run("systemctl stop xray", shell=True)
        subprocess.run("systemctl disable xray", shell=True)
        subprocess.run("rm -f /etc/systemd/system/xray.service /etc/systemd/system/xray@.service", shell=True)
        subprocess.run("systemctl daemon-reload", shell=True)
        subprocess.run("rm -f /usr/local/bin/xray", shell=True)
        subprocess.run("rm -rf /usr/local/etc/xray /usr/local/share/xray /var/log/xray /etc/xray", shell=True)

        for port in ports_to_close:
            close_firewall_port(port, ("tcp", "udp"))

        if os.path.exists(INSTALL_FLAG):
            os.remove(INSTALL_FLAG)
        print(f"{C_GREEN}Xray uninstalled successfully.{C_RESET}")
    input("\nPress Enter to exit...")

def main_menu():
    if not check_stage1_completed():
        if not stage_1_installer():
            return

    while True:
        clear_screen()
        print(f"{C_CYAN}{C_BOLD}╔════════════════════════════════════════════════════════════╗")
        print(f"║        XRAY ADVANCED MANAGER: MULTI-PROTOCOL PANEL         ║")
        print(f"╚════════════════════════════════════════════════════════════╝{C_RESET}")
        print(f"  {C_GREEN}[1]{C_RESET} Add User")
        print(f"  {C_GREEN}[2]{C_RESET} Edit User")
        print(f"  {C_GREEN}[3]{C_RESET} Delete User")
        print(f"  {C_GREEN}[4]{C_RESET} Configure Port 443 Fallbacks (Nginx Decoy)")
        print(f"  {C_GREEN}[5]{C_RESET} List Users")
        print(f"  {C_GREEN}[6]{C_RESET} Renew User")
        print(f"  {C_GREEN}[7]{C_RESET} Delete Expired Users")
        print(f"  {C_GREEN}[8]{C_RESET} Online Users & Connections")
        print(f"  {C_GREEN}[9]{C_RESET} View list of users that share their logins")
        print(f"  {C_GREEN}[10]{C_RESET} Delete All Users")
        print(f"  {C_GREEN}[11]{C_RESET} Hysteria2 (QUIC) Management [bonus protocol]")
        print(f"  {C_GREEN}[12]{C_RESET} Uninstall V2ray/Xray script")
        print(f"  {C_RED}[0]{C_RESET} Exit")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(f"{C_BOLD}Select Option [0-12]: {C_RESET}").strip()

        if choice == "1":
            add_user()
        elif choice == "2":
            edit_user()
        elif choice == "3":
            delete_user()
        elif choice == "4":
            configure_fallbacks()
        elif choice == "5":
            list_users()
        elif choice == "6":
            renew_user()
        elif choice == "7":
            delete_expired_users()
        elif choice == "8":
            online_users()
        elif choice == "9":
            shared_logins()
        elif choice == "10":
            delete_all_users()
        elif choice == "11":
            hysteria_menu()
        elif choice == "12":
            uninstall_script()
            break
        elif choice == "0":
            print("Exiting manager.")
            break
        else:
            print(f"{C_RED}Invalid option!{C_RESET}")
            input("Press Enter to continue...")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{C_RED}[-] Please run this script with sudo or as root!{C_RESET}")
        exit(1)
    main_menu()