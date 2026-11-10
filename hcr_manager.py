"""
hcr_manager.py - "HCR Custom" admin module for the SmartUI panel.

Design notes (read before changing the protocol):

There is no public reference implementation of "HCR" / "HCR Custom" - it was
seen only as a screenshot of a Spanish-language admin panel on someone else's
VPS script, with these fields: Puerto HCR, Puerto de Redireccion, Max
Download Frame, Download Poll Timeout, and a Modo SSL/TLS toggle. No source
code or binary was available anywhere, so rather than guess at an unknown
third party's wire format and risk producing something that looks plausible
but doesn't actually interoperate with anything, this is a self-consistent,
independent implementation: a plain Python3 HTTP long-polling tunnel, built
to the same standard the other 29 protocols in this panel already meet, with
both ends (this VPS service and its Android counterpart) under our control.
That shape was chosen specifically because it matches the only two
parameters the screenshot actually exposed:

  - "Max Download Frame"     -> the max number of bytes returned per
                                 long-poll GET response (a frame cap).
  - "Download Poll Timeout"  -> how long a long-poll GET blocks waiting for
                                 data before returning empty, so the client
                                 can retry. This is the client's "download"
                                 leg; "upload" is a plain POST since there's
                                 nothing to poll for on that side.

Why long-polling instead of a raw relay (unlike websocket_manager.py /
ws_epro_manager.py, which are both plain bidirectional TCP relays): the whole
point of an HTTP-polling tunnel is to look like ordinary request/response
HTTP traffic to anything inspecting it, at the cost of some latency - that
tradeoff is what the two timing knobs in the original screenshot exist to
tune, and a raw relay has no use for either of them.

Session model: each client is identified by a short random session id (sid)
it generates itself and includes in both the upload and download URLs. On
the first request for a new sid, the bridge opens one backend TCP connection
to 127.0.0.1:TARGET_PORT and starts a reader thread that drains it into a
per-session buffer; POSTs append bytes to send to the backend, long-polling
GETs drain bytes out of that buffer (up to MAX_DOWNLOAD_FRAME at a time,
waiting up to DOWNLOAD_POLL_TIMEOUT seconds for something to arrive). A
sweep thread closes/garbage-collects sessions that have gone idle, so a
client that vanishes without closing cleanly doesn't leak a backend
connection forever.

SSL/TLS toggle: reuses the exact same self-signed-certificate approach
already proven in stunnel_manager.py (a single combined cert+key .pem file,
auto-generated on first use if missing - verified there that `openssl req
-out FILE -keyout FILE` with an identical path for both does not lose either
half). When the toggle is on, the bridge wraps its listening socket with
Python's own ssl module instead of handing off to a separate daemon, since
the whole service is a single small Python script already.
"""

import os
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, get_public_ip, get_live_port_from_service,
)

HCR_DIR = "/etc/hcr-custom"
HCR_SCRIPT_PATH = "/etc/hcr-custom/bridge.py"
HCR_SERVICE_PATH = "/etc/systemd/system/hcr-custom.service"
HCR_PEM_PATH = "/etc/hcr-custom/hcr.pem"

BRIDGE_SCRIPT = '''#!/usr/bin/env python3
"""Standalone HCR Custom long-polling HTTP tunnel - plain Python3, stdlib
only. Independent design (see hcr_manager.py's module docstring) - not
byte-compatible with any third-party "HCR" implementation, by necessity:
no reference implementation was ever available to match against."""
import os
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_PORT = int(os.environ.get("HCR_LISTEN_PORT", "8090"))
TARGET_HOST = "127.0.0.1"
TARGET_PORT = int(os.environ.get("HCR_TARGET_PORT", "22"))
MAX_DOWNLOAD_FRAME = int(os.environ.get("HCR_MAX_FRAME", "32768"))
DOWNLOAD_POLL_TIMEOUT = float(os.environ.get("HCR_POLL_TIMEOUT", "25"))
USE_TLS = os.environ.get("HCR_USE_TLS", "0") == "1"
PEM_PATH = os.environ.get("HCR_PEM_PATH", "/etc/hcr-custom/hcr.pem")

SESSION_IDLE_LIMIT = 90  # seconds with no activity before a session is reaped

sessions = {}
sessions_lock = threading.Lock()


class Session:
    def __init__(self, sid):
        self.sid = sid
        self.lock = threading.Lock()
        self.cond = threading.Condition(self.lock)
        self.buf = bytearray()
        self.closed = False
        self.last_active = time.time()
        self.sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        try:
            while True:
                data = self.sock.recv(65536)
                if not data:
                    break
                with self.cond:
                    self.buf.extend(data)
                    self.last_active = time.time()
                    self.cond.notify_all()
        except Exception:
            pass
        finally:
            with self.cond:
                self.closed = True
                self.cond.notify_all()

    def send(self, data):
        self.sock.sendall(data)
        self.last_active = time.time()

    def read(self, max_bytes, timeout):
        deadline = time.time() + timeout
        with self.cond:
            while not self.buf and not self.closed and time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                self.cond.wait(timeout=remaining)
            chunk = bytes(self.buf[:max_bytes])
            del self.buf[:len(chunk)]
            self.last_active = time.time()
            return chunk, (self.closed and not self.buf)

    def destroy(self):
        try:
            self.sock.close()
        except Exception:
            pass


def _get_or_create_session(sid):
    with sessions_lock:
        sess = sessions.get(sid)
        if sess is None or sess.closed:
            sess = Session(sid)
            sessions[sid] = sess
        return sess


def _reap_idle_sessions():
    while True:
        time.sleep(15)
        now = time.time()
        with sessions_lock:
            dead = [sid for sid, s in sessions.items()
                    if s.closed or (now - s.last_active) > SESSION_IDLE_LIMIT]
            for sid in dead:
                sessions.pop(sid, None).destroy()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HCR/1.0"

    def log_message(self, fmt, *args):
        pass  # keep journalctl quiet - same convention as the other relays

    def _sid_from_path(self):
        parts = self.path.strip("/").split("/")
        return parts[1] if len(parts) > 1 else "default"

    def do_POST(self):
        sid = self._sid_from_path()
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        try:
            sess = _get_or_create_session(sid)
            if body:
                sess.send(body)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except Exception as e:
            sys.stderr.write("hcr-custom: upload error for sid=%s: %s\\n" % (sid, e))
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        sid = self._sid_from_path()
        try:
            sess = _get_or_create_session(sid)
            chunk, done = sess.read(MAX_DOWNLOAD_FRAME, DOWNLOAD_POLL_TIMEOUT)
            if not chunk and not done:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(chunk)))
            if done:
                self.send_header("X-HCR-Session-Closed", "1")
            self.end_headers()
            if chunk:
                self.wfile.write(chunk)
            if done:
                with sessions_lock:
                    s = sessions.pop(sid, None)
                if s:
                    s.destroy()
        except Exception as e:
            sys.stderr.write("hcr-custom: download error for sid=%s: %s\\n" % (sid, e))
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()


def main():
    threading.Thread(target=_reap_idle_sessions, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    if USE_TLS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=PEM_PATH, keyfile=PEM_PATH)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
'''


def _deploy_script():
    os.makedirs(HCR_DIR, exist_ok=True)
    with open(HCR_SCRIPT_PATH, "w") as f:
        f.write(BRIDGE_SCRIPT)
    os.chmod(HCR_SCRIPT_PATH, 0o755)


def _generate_self_signed_cert():
    # Identical pattern to stunnel_manager.py's own cert generation, including
    # the identical-out/keyout-path call that was independently verified
    # there to not lose either half in this environment.
    os.makedirs(HCR_DIR, exist_ok=True)
    result = _run(
        "openssl req -new -x509 -days 3650 -nodes -out %s -keyout %s "
        "-subj '/CN=hcr-custom' 2>/dev/null" % (HCR_PEM_PATH, HCR_PEM_PATH)
    )
    return result.returncode == 0 and os.path.exists(HCR_PEM_PATH)


def _service_active():
    return _run(["systemctl", "is-active", "--quiet", "hcr-custom"]).returncode == 0


def _restart_service():
    _run("systemctl reset-failed hcr-custom")
    return _run("systemctl restart hcr-custom").returncode == 0


def _wait_for_port_listening(port, tries=8, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _write_service(listen_port, target_port, max_frame, poll_timeout, use_tls):
    _deploy_script()
    if use_tls and not os.path.exists(HCR_PEM_PATH):
        _generate_self_signed_cert()
    service_content = """[Unit]
Description=HCR Custom Tunnel (long-polling HTTP relay)
After=network.target

[Service]
Type=simple
User=root
Environment="HCR_LISTEN_PORT=%s"
Environment="HCR_TARGET_PORT=%s"
Environment="HCR_MAX_FRAME=%s"
Environment="HCR_POLL_TIMEOUT=%s"
Environment="HCR_USE_TLS=%s"
Environment="HCR_PEM_PATH=%s"
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % (listen_port, target_port, max_frame, poll_timeout,
       "1" if use_tls else "0", HCR_PEM_PATH, HCR_SCRIPT_PATH)
    with open(HCR_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _apply_safely(listen_port, target_port, max_frame, poll_timeout, use_tls, description):
    original = None
    if os.path.exists(HCR_SERVICE_PATH):
        with open(HCR_SERVICE_PATH, "r") as f:
            original = f.read()

    _write_service(listen_port, target_port, max_frame, poll_timeout, use_tls)

    if not _restart_service():
        if original is not None:
            with open(HCR_SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_service()
        return False, "%s failed to restart - check 'journalctl -u hcr-custom'." % description

    if not _wait_for_port_listening(listen_port):
        if original is not None:
            with open(HCR_SERVICE_PATH, "w") as f:
                f.write(original)
            _run("systemctl daemon-reload")
            _restart_service()
        return False, "%s restarted, but port %s never came up - reverted. Nothing was left broken." % (description, listen_port)

    return True, "%s applied and verified on port %s." % (description, listen_port)


def hcr_admin_manager(ports_dict):
    """Standalone HCR Custom Tunnel Administrator Module."""
    while True:
        if os.path.exists(HCR_SERVICE_PATH):
            _run("systemctl enable hcr-custom")
        live_port = get_live_port_from_service(HCR_SERVICE_PATH, r'HCR_LISTEN_PORT=(\d+)')
        if live_port and str(ports_dict.get('HCR_PORT')) != str(live_port):
            print(f"{C_YELLOW}[!] The saved port didn't match what's actually running ({live_port}) -")
            print(f"    correcting the panel's records to match reality.{C_RESET}")
            ports_dict['HCR_PORT'] = live_port
            input("\nPress Enter to continue...")

        hcr_port = ports_dict.get('HCR_PORT', 'Not configured')
        hcr_target = ports_dict.get('HCR_TARGET_PORT', '22')
        max_frame = ports_dict.get('HCR_MAX_FRAME', '32768')
        poll_timeout = ports_dict.get('HCR_POLL_TIMEOUT', '25')
        use_tls = ports_dict.get('HCR_USE_TLS', '0') == '1'
        is_active = _service_active()
        status_label = "ON" if is_active else "OFF"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                  HCR CUSTOM ADMINISTRATOR                  %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("      PORT: %s  |  REDIRECTION TARGET: %s" % (hcr_port, hcr_target))
        print("      MAX DOWNLOAD FRAME: %s bytes  |  DOWNLOAD POLL TIMEOUT: %ss" % (max_frame, poll_timeout))
        print("      SSL/TLS MODE: %s" % ("ON" if use_tls else "OFF"))
        print("----------------------------------------------------------------")
        print(" [1]> CONFIGURE / INSTALL HCR CUSTOM")
        print(" [2]> MODIFY PORT & REDIRECTION")
        print(" [3]> MODIFY MAX DOWNLOAD FRAME / POLL TIMEOUT")
        print(" [4]> TOGGLE SSL/TLS MODE")
        print(" [5]> VIEW CONNECTION INFO")
        print(" [6]> VIEW SERVICE LOGS")
        print(" [7]> RESTART SERVICE")
        print(" [8]> START/STOP SERVICE [%s]" % status_label)
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" [0] RETURN  [9] UNINSTALL HCR CUSTOM")
        print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    SETUP WIZARD                            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

            listen_port = prompt_port(" Enter HCR port (e.g., 8090): ", default=8090)
            if str(listen_port) != str(hcr_port) and check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            target_port = prompt_port(" Enter redirect port (e.g., 22 for SSH, 143 for Dropbear): ", default=22)
            if not check_system_port_in_use(target_port, ("tcp",)):
                print("%s[!] Nothing seems to be listening on port %s yet.%s" % (C_YELLOW, target_port, C_RESET))

            new_max_frame = prompt_port(" Max Download Frame in bytes (e.g., 32768): ", default=32768)
            new_poll_timeout = prompt_port(" Download Poll Timeout in seconds (e.g., 25): ", default=25)
            tls_choice = input(" Enable SSL/TLS mode? (y/n) [n]: ").strip().lower()
            new_use_tls = tls_choice == 'y'

            open_firewall_port(listen_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable hcr-custom")

            ok, msg = _apply_safely(listen_port, target_port, new_max_frame, new_poll_timeout,
                                     new_use_tls, "HCR Custom tunnel")
            if ok:
                ports_dict['HCR_PORT'] = str(listen_port)
                ports_dict['HCR_TARGET_PORT'] = str(target_port)
                ports_dict['HCR_MAX_FRAME'] = str(new_max_frame)
                ports_dict['HCR_POLL_TIMEOUT'] = str(new_poll_timeout)
                ports_dict['HCR_USE_TLS'] = '1' if new_use_tls else '0'
                server_ip = get_public_ip()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
                print()
                print(" Client setup:")
                print("   Host:            %s" % server_ip)
                print("   Port:            %s" % listen_port)
                print("   Scheme:          %s" % ("https" if new_use_tls else "http"))
                print("   Upload path:     /up/<session-id>  (POST)")
                print("   Download path:   /down/<session-id>  (long-poll GET)")
                print("   Max frame:       %s bytes" % new_max_frame)
                print("   Poll timeout:    %s seconds" % new_poll_timeout)
                print()
                print(" Then authenticate at the backend with your normal SSH/Dropbear account.")
            else:
                close_firewall_port(listen_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            if not os.path.exists(HCR_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_port = prompt_port(" Enter new HCR port [Current: %s]: " % hcr_port,
                                    default=int(hcr_port) if str(hcr_port).isdigit() else 8090)
            if str(new_port) != str(hcr_port) and check_system_port_in_use(new_port, ("tcp",)):
                print("%s[X] Port %s is already in use.%s" % (C_RED, new_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_target = prompt_port(" Enter new redirect port [Current: %s]: " % hcr_target,
                                      default=int(hcr_target) if str(hcr_target).isdigit() else 22)

            open_firewall_port(new_port, ("tcp",))
            persist_firewall_rules()

            ok, msg = _apply_safely(new_port, new_target, max_frame, poll_timeout, use_tls, "Port/redirect change")
            if ok:
                old_port = hcr_port
                ports_dict['HCR_PORT'] = str(new_port)
                ports_dict['HCR_TARGET_PORT'] = str(new_target)
                if str(old_port).isdigit() and str(old_port) != str(new_port):
                    close_firewall_port(int(old_port), ("tcp",))
                    persist_firewall_rules()
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
            else:
                close_firewall_port(new_port, ("tcp",))
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            if not os.path.exists(HCR_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            new_max_frame = prompt_port(" Max Download Frame in bytes [Current: %s]: " % max_frame,
                                         default=int(max_frame) if str(max_frame).isdigit() else 32768)
            new_poll_timeout = prompt_port(" Download Poll Timeout in seconds [Current: %s]: " % poll_timeout,
                                            default=int(poll_timeout) if str(poll_timeout).isdigit() else 25)

            ok, msg = _apply_safely(hcr_port, hcr_target, new_max_frame, new_poll_timeout, use_tls,
                                     "Frame/timeout change")
            if ok:
                ports_dict['HCR_MAX_FRAME'] = str(new_max_frame)
                ports_dict['HCR_POLL_TIMEOUT'] = str(new_poll_timeout)
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            if not os.path.exists(HCR_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            new_use_tls = not use_tls
            if new_use_tls and not os.path.exists(HCR_PEM_PATH):
                print("%s[i] No certificate found - generating a self-signed one so this actually works.%s" % (C_CYAN, C_RESET))
                if not _generate_self_signed_cert():
                    print("%s[X] Certificate generation failed - leaving SSL/TLS mode off.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
            ok, msg = _apply_safely(hcr_port, hcr_target, max_frame, poll_timeout, new_use_tls, "SSL/TLS mode change")
            if ok:
                ports_dict['HCR_USE_TLS'] = '1' if new_use_tls else '0'
                print("%s[OK] SSL/TLS mode is now %s. %s%s" % (C_GREEN, "ON" if new_use_tls else "OFF", msg, C_RESET))
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            if not os.path.exists(HCR_SERVICE_PATH):
                print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue
            server_ip = get_public_ip()
            print(" Server IP: %s" % server_ip)
            print(" Port: %s  ->  127.0.0.1:%s" % (hcr_port, hcr_target))
            print(" Scheme: %s" % ("https" if use_tls else "http"))
            print(" Max Download Frame: %s bytes" % max_frame)
            print(" Download Poll Timeout: %s seconds" % poll_timeout)
            print()
            print(" %sUpload (client -> server):%s   POST /up/<session-id>   body = raw bytes" % (C_YELLOW, C_RESET))
            print(" %sDownload (server -> client):%s GET  /down/<session-id>  (long-poll, up to %ss)" %
                  (C_YELLOW, C_RESET, poll_timeout))
            print("   Each client picks its own random session-id and reuses it for the")
            print("   life of the connection; the backend session is created on first use.")
            print("   Then authenticate at the backend (127.0.0.1:%s) with your normal" % hcr_target)
            print("   SSH/Dropbear account.")
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            os.system("journalctl -u hcr-custom -n 50 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == '7':
            if _restart_service():
                print("%s[OK] HCR Custom tunnel restarted successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Failed to restart - check 'journalctl -u hcr-custom'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '8':
            if is_active:
                _run("systemctl stop hcr-custom")
                print("%s[!] HCR Custom tunnel stopped.%s" % (C_YELLOW, C_RESET))
            else:
                if not os.path.exists(HCR_SERVICE_PATH):
                    print("%s[X] Not installed yet - run option 1 first.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start hcr-custom")
                if _service_active():
                    print("%s[OK] HCR Custom tunnel started.%s" % (C_GREEN, C_RESET))
                else:
                    print("%s[X] Failed to start - check 'journalctl -u hcr-custom'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '9':
            clear_screen()
            confirm = input(" Are you sure you want to completely remove HCR Custom? (y/n): ").strip().lower()
            if confirm == 'y':
                _run("systemctl stop hcr-custom")
                _run("systemctl disable hcr-custom")
                _run("rm -f %s" % HCR_SERVICE_PATH)
                _run("rm -rf %s" % HCR_DIR)
                _run("systemctl daemon-reload")
                if str(hcr_port).isdigit():
                    close_firewall_port(int(hcr_port), ("tcp",))
                    persist_firewall_rules()
                ports_dict.pop('HCR_PORT', None)
                ports_dict.pop('HCR_TARGET_PORT', None)
                ports_dict.pop('HCR_MAX_FRAME', None)
                ports_dict.pop('HCR_POLL_TIMEOUT', None)
                ports_dict.pop('HCR_USE_TLS', None)
                print("%s[OK] HCR Custom removed and purged successfully.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Uninstallation cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
