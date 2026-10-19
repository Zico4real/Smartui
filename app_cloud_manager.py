"""
app_cloud_manager.py - "App Cloud" module for the SmartUI panel.

One small HTTP service on the VPS that the VPN app talks to for four things:
  1. Cloud configs   - the app uploads an exported config and gets a link;
                       any app can import it back by pasting that link.
  2. In-app messages - messages you post here show up in the app's inbox.
  3. Notifications   - a message can also raise an Android notification and/or
                       a pop-up the next time the app checks in.
  4. App updates     - publish a new version (APK hosted here, or any store
                       link) and the app offers to download/install it.

Security notes (the same plain-HTTP transport as the CheckUser API):
  - Uploading needs a secret token (set once in the app); reading a config
    needs its random 16-hex link. Nothing else is writable from the network.
  - Uploads are size-limited and failed-token attempts are rate limited.
  - Messages/update info are public to anyone who has the app (that is their job).
"""

import os
import re
import json
import time
import secrets
import shutil
import hashlib
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_live_port_from_service,
)

DATA_DIR = "/var/lib/app-cloud"
SCRIPT_PATH = "/usr/local/bin/app-cloud-api.py"
SERVICE_PATH = "/etc/systemd/system/app-cloud-api.service"
DEFAULT_PORT = 8890

API_SCRIPT = '''#!/usr/bin/env python3
"""App Cloud API (configs, messages, update info, APK download)."""
import os
import re
import json
import time
import hmac
import secrets
import threading
import http.server
import socketserver
import urllib.parse

PORT = int(os.environ.get("APP_CLOUD_PORT", "8890"))
DATA = os.environ.get("APP_CLOUD_DIR", "/var/lib/app-cloud")
CFG_DIR = os.path.join(DATA, "configs")
MAX_UPLOAD = 1024 * 1024
ID_RE = re.compile(r"^[a-f0-9]{16}$")
_fails = {}
_lock = threading.Lock()


def _read_json(name, default):
    try:
        with open(os.path.join(DATA, name)) as f:
            return json.load(f)
    except Exception:
        return default


def _write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def _token():
    return str(_read_json("settings.json", {}).get("token", ""))


def _limited(addr):
    now = time.time()
    arr = [t for t in _fails.get(addr, []) if now - t < 60]
    _fails[addr] = arr
    return len(arr) >= 10


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)
        if path == "/ping":
            return self._send(200, json.dumps({"ok": True, "t": int(time.time())}))
        m = re.match(r"^/c/([a-f0-9]{16})$", path)
        if m:
            return self._config(m.group(1))
        if path == "/api/app":
            return self._app(q)
        if path == "/app/latest.apk":
            return self._apk()
        return self._send(404, json.dumps({"ok": False}))

    def _config(self, cid):
        idx = _read_json("configs/index.json", {})
        meta = idx.get(cid)
        fp = os.path.join(CFG_DIR, cid + ".smp")
        if not meta or not os.path.exists(fp):
            return self._send(404, json.dumps({"ok": False, "error": "not_found"}))
        exp = meta.get("expires", 0)
        if exp and time.time() > exp:
            return self._send(410, json.dumps({"ok": False, "error": "expired"}))
        with open(fp, "rb") as f:
            data = f.read()
        return self._send(200, data, "text/plain; charset=utf-8", {"X-Config-Name": urllib.parse.quote(str(meta.get("name", "")))})

    def _app(self, q):
        user = (q.get("user", [""])[0] or "").strip()[:64]
        try:
            since = int(q.get("since", ["0"])[0])
        except Exception:
            since = 0
        now = time.time()
        out = []
        for msg in _read_json("messages.json", []):
            if msg.get("expires", 0) and now > msg["expires"]:
                continue
            to = msg.get("to", "all")
            if to != "all" and to != user:
                continue
            if msg.get("id", 0) <= since:
                continue
            out.append(msg)
        out = out[-50:]
        upd = _read_json("update.json", {})
        resp = {"ok": True, "time": int(now), "messages": out, "update": upd if upd.get("versionCode") else None}
        return self._send(200, json.dumps(resp))

    def _apk(self):
        fp = os.path.join(DATA, "app.apk")
        if not os.path.exists(fp):
            return self._send(404, json.dumps({"ok": False}))
        size = os.path.getsize(fp)
        start = 0
        rng = self.headers.get("Range", "")
        m = re.match(r"^bytes=(\\d+)-", rng)
        if m:
            start = min(int(m.group(1)), max(size - 1, 0))
        code = 206 if start > 0 else 200
        self.send_response(code)
        self.send_header("Content-Type", "application/vnd.android.package-archive")
        self.send_header("Content-Length", str(size - start))
        self.send_header("Accept-Ranges", "bytes")
        if code == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, size - 1, size))
        self.end_headers()
        if self.command == "HEAD":
            return
        with open(fp, "rb") as f:
            f.seek(start)
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                except Exception:
                    break

    def do_POST(self):
        addr = self.client_address[0]
        if urllib.parse.urlparse(self.path).path != "/cloud/upload":
            return self._send(404, json.dumps({"ok": False}))
        if _limited(addr):
            return self._send(429, json.dumps({"ok": False, "error": "slow_down"}))
        tok = self.headers.get("X-Token", "")
        real = _token()
        if not real or not hmac.compare_digest(tok.encode(), real.encode()):
            _fails.setdefault(addr, []).append(time.time())
            return self._send(403, json.dumps({"ok": False, "error": "bad_token"}))
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except Exception:
            n = 0
        if n <= 0 or n > MAX_UPLOAD:
            return self._send(413, json.dumps({"ok": False, "error": "size"}))
        body = self.rfile.read(n)
        try:
            days = max(0, min(3650, int(self.headers.get("X-Expire-Days", "0"))))
        except Exception:
            days = 0
        name = urllib.parse.unquote(self.headers.get("X-Name", ""))[:80]
        with _lock:
            os.makedirs(CFG_DIR, exist_ok=True)
            cid = secrets.token_hex(8)
            with open(os.path.join(CFG_DIR, cid + ".smp"), "wb") as f:
                f.write(body)
            idx = _read_json("configs/index.json", {})
            idx[cid] = {"name": name, "created": int(time.time()), "size": n,
                        "expires": int(time.time() + days * 86400) if days else 0}
            _write_json(os.path.join(CFG_DIR, "index.json"), idx)
        return self._send(200, json.dumps({"ok": True, "id": cid, "path": "/c/" + cid}))


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    os.makedirs(CFG_DIR, exist_ok=True)
    with Server(("0.0.0.0", PORT), Handler) as httpd:
        print("app-cloud listening on 0.0.0.0:%d" % PORT)
        httpd.serve_forever()
'''


# ---------------------------------------------------------------- helpers

def _jload(name, default):
    try:
        with open(os.path.join(DATA_DIR, name)) as f:
            return json.load(f)
    except Exception:
        return default


def _jsave(name, obj):
    os.makedirs(os.path.join(DATA_DIR, "configs"), exist_ok=True)
    path = os.path.join(DATA_DIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def _settings():
    return _jload("settings.json", {})


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "app-cloud-api"]).returncode == 0


def _restart():
    _run("systemctl reset-failed app-cloud-api")
    return _run("systemctl restart app-cloud-api").returncode == 0


def _write_service(port):
    unit = """[Unit]
Description=App Cloud API (configs, messages, updates)
After=network.target

[Service]
Type=simple
User=root
Environment=APP_CLOUD_PORT=%s
Environment=APP_CLOUD_DIR=%s
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (port, DATA_DIR, SCRIPT_PATH)
    with open(SERVICE_PATH, "w") as f:
        f.write(unit)
    _run("systemctl daemon-reload")


def _deploy_script():
    os.makedirs(os.path.join(DATA_DIR, "configs"), exist_ok=True)
    with open(SCRIPT_PATH, "w") as f:
        f.write(API_SCRIPT)
    os.chmod(SCRIPT_PATH, 0o755)
    check = _run(["python3", "-m", "py_compile", SCRIPT_PATH])
    if check.returncode != 0:
        print("%s[X] Service script failed its syntax check: %s%s" % (C_RED, check.stderr.strip(), C_RESET))
        return False
    return True


def _wait_listening(port, tries=6):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(1)
    return False


def _public_ip():
    r = _run("curl -4 -s --max-time 4 https://api.ipify.org")
    ip = (getattr(r, "stdout", "") or "").strip()
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return ip
    r = _run("hostname -I")
    parts = (getattr(r, "stdout", "") or "").split()
    return parts[0] if parts else "YOUR_SERVER_IP"


def _fmt_age(ts):
    d = int((time.time() - ts) / 86400)
    return "today" if d <= 0 else "%dd ago" % d


def _ask(prompt, default=""):
    v = input(prompt).strip()
    return v if v else default


def _next_msg_id(msgs):
    return max([m.get("id", 0) for m in msgs] + [0]) + 1


# ---------------------------------------------------------------- menu actions

def _install(ports_dict):
    clear_screen()
    print("%s== INSTALL / CHANGE PORT ==%s" % (C_BOLD, C_RESET))
    cur = int(ports_dict.get("APP_CLOUD_PORT", "0") or 0) or DEFAULT_PORT
    raw = _ask(" Port to listen on [%d]: " % cur, str(cur))
    if not raw.isdigit() or not (1 <= int(raw) <= 65535):
        print("%s[X] Invalid port.%s" % (C_RED, C_RESET))
        return
    port = int(raw)
    old = int(ports_dict.get("APP_CLOUD_PORT", "0") or 0)
    if port != old and check_system_port_in_use(port, ("tcp",)):
        print("%s[X] Port %d is already used by something else.%s" % (C_RED, port, C_RESET))
        return
    if not _deploy_script():
        return
    st = _settings()
    if not st.get("token"):
        st["token"] = secrets.token_urlsafe(18)
        _jsave("settings.json", st)
    os.chmod(os.path.join(DATA_DIR, "settings.json"), 0o600)
    open_firewall_port(port, ("tcp",))
    persist_firewall_rules()
    prev_unit = open(SERVICE_PATH).read() if os.path.exists(SERVICE_PATH) else None
    _write_service(port)
    _run("systemctl enable app-cloud-api")
    if _restart() and _wait_listening(port):
        if old and old != port:
            close_firewall_port(old, ("tcp",))
            persist_firewall_rules()
        ports_dict["APP_CLOUD_PORT"] = str(port)
        print("%s[OK] App Cloud is running on port %d.%s" % (C_GREEN, port, C_RESET))
        _show_connection(port)
    else:
        if prev_unit is not None:
            with open(SERVICE_PATH, "w") as f:
                f.write(prev_unit)
            _run("systemctl daemon-reload")
            _restart()
        print("%s[X] Service did not come up - reverted. Check: journalctl -u app-cloud-api%s" % (C_RED, C_RESET))


def _show_connection(port):
    st = _settings()
    print()
    print("%s Put these two values in the app (Export -> Cloud settings):%s" % (C_CYAN, C_RESET))
    print("   Cloud server : http://%s:%s" % (_public_ip(), port))
    print("   Upload token : %s" % st.get("token", "(not set)"))
    print(" Keep the token private: it lets an app upload configs.")


def _post_message():
    clear_screen()
    print("%s== POST A MESSAGE TO THE APP ==%s" % (C_BOLD, C_RESET))
    title = _ask(" Title: ")
    body = _ask(" Message: ")
    if not title or not body:
        print("%s[X] Title and message are required.%s" % (C_RED, C_RESET))
        return
    print(" How should it reach users?")
    print("  [1] Inbox only (they see it when they open the Messages screen)")
    print("  [2] Inbox + Android notification")
    print("  [3] Inbox + pop-up when the app is opened")
    print("  [4] Inbox + notification + pop-up")
    k = _ask(" Choice [2]: ", "2")
    kind = {"1": "message", "2": "notification", "3": "popup", "4": "both"}.get(k, "notification")
    to = _ask(" Send to (username, or Enter for everyone): ", "all")
    link = _ask(" Optional link (https://...): ")
    if link and not link.lower().startswith(("http://", "https://")):
        print("%s[!] Link ignored (must start with http:// or https://).%s" % (C_YELLOW, C_RESET))
        link = ""
    days = _ask(" Keep for how many days? [14]: ", "14")
    days = int(days) if days.isdigit() and int(days) > 0 else 14
    msgs = _jload("messages.json", [])
    mid = _next_msg_id(msgs)
    msgs.append({"id": mid, "title": title[:80], "body": body[:1000], "kind": kind, "to": to,
                 "link": link, "time": int(time.time()), "expires": int(time.time() + days * 86400)})
    msgs = msgs[-200:]
    _jsave("messages.json", msgs)
    print("%s[OK] Message #%d posted (%s, to %s). Apps pick it up on their next check.%s" % (C_GREEN, mid, kind, to, C_RESET))


def _list_messages():
    clear_screen()
    print("%s== MESSAGES ==%s" % (C_BOLD, C_RESET))
    msgs = _jload("messages.json", [])
    if not msgs:
        print(" No messages.")
        return
    now = time.time()
    for m in msgs[-30:]:
        live = "" if not m.get("expires") or m["expires"] > now else " (expired)"
        print(" #%-4d %-12s to %-10s %s%s" % (m["id"], m.get("kind", ""), m.get("to", "all"), m.get("title", ""), live))
    sel = _ask("\n Delete which # ? (number, 'all', or Enter to go back): ")
    if sel.lower() == "all":
        _jsave("messages.json", [])
        print("%s[OK] All messages deleted.%s" % (C_GREEN, C_RESET))
    elif sel.isdigit():
        left = [m for m in msgs if m.get("id") != int(sel)]
        _jsave("messages.json", left)
        print("%s[OK] %s.%s" % (C_GREEN, "Deleted" if len(left) != len(msgs) else "No such message", C_RESET))


def _publish_update():
    clear_screen()
    print("%s== PUBLISH APP UPDATE ==%s" % (C_BOLD, C_RESET))
    cur = _jload("update.json", {})
    if cur.get("versionCode"):
        print(" Current: %s (code %s)" % (cur.get("versionName", ""), cur.get("versionCode")))
    vc = _ask(" New versionCode (the number from build.gradle, e.g. 9): ")
    if not vc.isdigit():
        print("%s[X] versionCode must be a whole number.%s" % (C_RED, C_RESET))
        return
    vn = _ask(" versionName (e.g. 8.1.0): ")
    notes = _ask(" What's new (one line): ")
    force = _ask(" Force update (users cannot skip)? (y/N): ", "n").lower() == "y"
    print(" Where is the new version?")
    print("  [1] APK file on this server (the app downloads and installs it)")
    print("  [2] A store / web link (Play Store, any app store, your website)")
    src = _ask(" Choice [1]: ", "1")
    upd = {"versionCode": int(vc), "versionName": vn, "notes": notes[:500], "force": force,
           "published": int(time.time())}
    if src == "2":
        link = _ask(" Link: ")
        if not link.lower().startswith(("http://", "https://", "market://")):
            print("%s[X] Link must start with http://, https:// or market://%s" % (C_RED, C_RESET))
            return
        upd["store_url"] = link
    else:
        path = _ask(" Full path of the APK on this server: ")
        if not os.path.isfile(path):
            print("%s[X] File not found.%s" % (C_RED, C_RESET))
            return
        os.makedirs(DATA_DIR, exist_ok=True)
        dst = os.path.join(DATA_DIR, "app.apk")
        shutil.copyfile(path, dst)
        h = hashlib.sha256()
        with open(dst, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        upd["apk_path"] = "/app/latest.apk"
        upd["sha256"] = h.hexdigest()
        upd["size"] = os.path.getsize(dst)
        print(" APK stored (%.1f MB, sha256 %s...)" % (upd["size"] / 1048576.0, upd["sha256"][:12]))
    _jsave("update.json", upd)
    print("%s[OK] Update %s published. Apps offer it on their next check.%s" % (C_GREEN, vn or vc, C_RESET))
    print(" Reminder: the APK must be signed with the SAME key as the installed app, and have a higher versionCode.")


def _clear_update():
    _jsave("update.json", {})
    try:
        os.remove(os.path.join(DATA_DIR, "app.apk"))
    except OSError:
        pass
    print("%s[OK] Update withdrawn.%s" % (C_GREEN, C_RESET))


def _manage_configs():
    clear_screen()
    print("%s== CLOUD CONFIGS ==%s" % (C_BOLD, C_RESET))
    idx = _jload("configs/index.json", {})
    if not idx:
        print(" No uploaded configs.")
        return
    now = time.time()
    items = sorted(idx.items(), key=lambda kv: kv[1].get("created", 0), reverse=True)
    for cid, m in items[:40]:
        exp = m.get("expires", 0)
        state = "never expires" if not exp else ("EXPIRED" if exp < now else "expires in %dd" % int((exp - now) / 86400))
        print(" %s  %-24s %6.1f KB  %-9s %s" % (cid, (m.get("name") or "-")[:24], m.get("size", 0) / 1024.0, _fmt_age(m.get("created", 0)), state))
    sel = _ask("\n Delete which id? (id, 'expired', 'all', or Enter to go back): ")
    if sel in ("all", "expired"):
        for cid, m in list(idx.items()):
            if sel == "all" or (m.get("expires") and m["expires"] < now):
                try:
                    os.remove(os.path.join(DATA_DIR, "configs", cid + ".smp"))
                except OSError:
                    pass
                idx.pop(cid, None)
        _jsave("configs/index.json", idx)
        print("%s[OK] Done.%s" % (C_GREEN, C_RESET))
    elif sel in idx:
        try:
            os.remove(os.path.join(DATA_DIR, "configs", sel + ".smp"))
        except OSError:
            pass
        idx.pop(sel)
        _jsave("configs/index.json", idx)
        print("%s[OK] Deleted.%s" % (C_GREEN, C_RESET))


def _token_menu(port):
    st = _settings()
    print(" Current token: %s" % (st.get("token") or "(none)"))
    if _ask(" Generate a NEW token? Apps must be updated with it. (y/N): ", "n").lower() == "y":
        st["token"] = secrets.token_urlsafe(18)
        _jsave("settings.json", st)
        os.chmod(os.path.join(DATA_DIR, "settings.json"), 0o600)
        print("%s[OK] New token set.%s" % (C_GREEN, C_RESET))
    _show_connection(port)


def app_cloud_manager(ports_dict):
    """App Cloud administrator module (configs, messages, notifications, updates)."""
    while True:
        if os.path.exists(SERVICE_PATH):
            _run("systemctl enable app-cloud-api")
        live = get_live_port_from_service(SERVICE_PATH, r'Environment=APP_CLOUD_PORT=(\d+)')
        if live and live != ports_dict.get("APP_CLOUD_PORT", ""):
            ports_dict["APP_CLOUD_PORT"] = live
        port = int(ports_dict.get("APP_CLOUD_PORT", "0") or 0)
        upd = _jload("update.json", {})
        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                  APP CLOUD (CONFIGS / MESSAGES / UPDATES)       %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("  PORT: %s  |  SERVICE: %s  |  MESSAGES: %d  |  CONFIGS: %d" % (
            port or "not installed", "ON" if _service_active() else "OFF",
            len(_jload("messages.json", [])), len(_jload("configs/index.json", {}))))
        print("  PUBLISHED UPDATE: %s" % (("%s (code %s)" % (upd.get("versionName", ""), upd["versionCode"])) if upd.get("versionCode") else "none"))
        print("----------------------------------------------------------------")
        print(" [1]> INSTALL / CHANGE PORT")
        print(" [2]> POST MESSAGE / NOTIFICATION TO THE APP")
        print(" [3]> VIEW / DELETE MESSAGES")
        print(" [4]> PUBLISH APP UPDATE")
        print(" [5]> WITHDRAW APP UPDATE")
        print(" [6]> CLOUD CONFIGS (list / delete)")
        print(" [7]> SHOW SERVER LINK + UPLOAD TOKEN")
        print(" [8]> RESTART / START-STOP / LOGS")
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [9] UNINSTALL")
        choice = input(" Enter an Option: ").strip()
        if choice == "0":
            break
        elif choice == "1":
            _install(ports_dict)
        elif choice in ("2", "3", "4", "5", "6", "7") and not port:
            print("%s[X] Install first (option 1).%s" % (C_RED, C_RESET))
        elif choice == "2":
            _post_message()
        elif choice == "3":
            _list_messages()
        elif choice == "4":
            _publish_update()
        elif choice == "5":
            _clear_update()
        elif choice == "6":
            _manage_configs()
        elif choice == "7":
            _token_menu(port)
        elif choice == "8":
            sub = _ask(" [1] Restart  [2] Start/Stop  [3] Logs: ")
            if sub == "1":
                print("%s[OK] Restarted.%s" % (C_GREEN, C_RESET) if _restart() else "%s[X] Failed.%s" % (C_RED, C_RESET))
            elif sub == "2":
                if _service_active():
                    _run("systemctl stop app-cloud-api")
                    print("%s[!] Stopped.%s" % (C_YELLOW, C_RESET))
                else:
                    _run("systemctl start app-cloud-api")
                    print("%s[OK] Started.%s" % (C_GREEN, C_RESET) if _service_active() else "%s[X] Failed.%s" % (C_RED, C_RESET))
            elif sub == "3":
                os.system("journalctl -u app-cloud-api -n 50 --no-pager")
        elif choice == "9":
            if _ask(" Remove App Cloud AND all uploaded configs/messages? (y/N): ", "n").lower() == "y":
                _run("systemctl stop app-cloud-api")
                _run("systemctl disable app-cloud-api")
                _run("rm -f %s %s" % (SERVICE_PATH, SCRIPT_PATH))
                _run("systemctl daemon-reload")
                if port:
                    close_firewall_port(port, ("tcp",))
                    persist_firewall_rules()
                _run("rm -rf %s" % DATA_DIR)
                ports_dict.pop("APP_CLOUD_PORT", None)
                print("%s[OK] Removed.%s" % (C_GREEN, C_RESET))
        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
        input("\nPress Enter to continue...")
