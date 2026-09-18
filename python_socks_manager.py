"""
python_socks_manager.py - Python SOCKS (payload responder) admin module for
the SmartUI panel.

This implements the well-established "HTTP Injector payload" pattern used
throughout this ecosystem: a lightweight listener sends a canned response
(e.g. "101 Switching Protocols" or "200 Connection Established") on connect,
then relays raw bytes to a backend (SSH, Dropbear, etc.) for the rest of the
connection. Confirmed this is a real, established technique before building
it (tavgar/Custom-Internet implements the client side of the same handshake:
"On success (101 Switching Protocols or equivalent), the socket is left in
raw mode"). This module implements the SERVER side of that pattern.

Four variants, matching the requested layout:
  - SIMPLE PY2/PY3: fixed default port (109 / 8880, matching the ports shown
    in the SmartUI dashboard mockup), fixed default redirect target (SSH,
    port 22), no wizard - just an on/off toggle.
  - DIRECT PY2/PY3: full wizard (listen port, redirect target chosen from a
    live scan of what's actually listening on the box, response code,
    optional custom raw header, optional mini-banner).

Design notes:
  - Both interpreter variants read their config from environment variables
    set in each instance's systemd unit, not from text baked into the script
    - the same architecture used for WS-EPRO, specifically to avoid the
    fragile string-search-and-replace-on-deployed-source bug found and fixed
    there. The script itself is deployed once per interpreter and never
    needs to be rewritten to change a port.
  - Each running instance gets its own systemd unit named "python.<port>",
    matching the naming shown in the requested layout ("systemctl start
    python.81") - this also means multiple DIRECT instances on different
    ports can coexist, not just one at a time.
  - No python2 interpreter is available in the environment this was built in,
    so the py2 script's syntax was checked (kept to syntax valid under both
    python2 and python3 - no f-strings, no walrus, function-call print()
    only) but never actually executed under a real python2 interpreter.
    Flagging that honestly rather than implying full runtime verification.
"""

import os
import re
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run, list_known_targets as _known_targets, pick_redirect_target as _pick_target,
)

PYSOCKS_DIR = "/opt/pysocks"
PY3_SCRIPT_PATH = f"{PYSOCKS_DIR}/pysocks3.py"
PY2_SCRIPT_PATH = f"{PYSOCKS_DIR}/pysocks2.py"

RESPONSE_CHOICES = {"101": "101 Switching Protocols", "200": "200 Connection Established"}

PY3_SCRIPT = '''#!/usr/bin/env python3
"""Python3 SOCKS payload responder: sends a canned handshake response, then
relays raw bytes to a backend target."""
import socket
import threading
import os
import sys

LISTEN_PORT = int(os.environ.get("PYSOCKS_LISTEN_PORT", "8880"))
TARGET_HOST = os.environ.get("PYSOCKS_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("PYSOCKS_TARGET_PORT", "22"))
RESPONSE_CODE = os.environ.get("PYSOCKS_RESPONSE_CODE", "101")
CUSTOM_HEADER = os.environ.get("PYSOCKS_CUSTOM_HEADER", "")
MINIBANNER = os.environ.get("PYSOCKS_MINIBANNER", "")

RESPONSES = {
    "101": "HTTP/1.1 101 Switching Protocols\\r\\n\\r\\n",
    "200": "HTTP/1.1 200 Connection Established\\r\\n\\r\\n",
}


def build_response():
    if CUSTOM_HEADER:
        payload = CUSTOM_HEADER.replace("\\\\r\\\\n", "\\r\\n")
        if not payload.endswith("\\r\\n\\r\\n"):
            payload += "\\r\\n\\r\\n"
    else:
        payload = RESPONSES.get(RESPONSE_CODE, RESPONSES["101"])
    if MINIBANNER:
        payload += MINIBANNER + "\\r\\n"
    return payload.encode()


def relay(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        # Half-close only dst's write direction, rather than fully closing
        # both sockets - the OTHER relay direction (running in its own
        # thread) may still be actively delivering data (e.g. the backend's
        # own banner/greeting) and must be allowed to finish naturally.
        # Confirmed as a real bug: one direction ending first was killing
        # both sockets outright, causing "Connection lost: Broken pipe"
        # right as a backend's banner was still being delivered.
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(client_sock):
    try:
        # Drain whatever the client sends within a short window before
        # responding - long enough to catch a full payload-mode request
        # (confirmed as the actual cause of "works direct, fails with
        # payloads": the response was being sent immediately on connect,
        # racing ahead of the client's own request instead of replying to
        # it), short enough that a direct-mode client - which may send
        # nothing at all before expecting a response - doesn't get stuck
        # waiting and dropped.
        client_sock.settimeout(0.4)
        buf = b""
        try:
            while b"\\r\\n\\r\\n" not in buf and len(buf) < 8192:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        client_sock.settimeout(None)
        client_sock.sendall(build_response())
    except Exception:
        client_sock.close()
        return

    try:
        backend = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    except Exception as e:
        sys.stderr.write("pysocks3: cannot reach backend %s:%s: %s\\n" % (TARGET_HOST, TARGET_PORT, e))
        client_sock.close()
        return

    t1 = threading.Thread(target=relay, args=(client_sock, backend), daemon=True)
    t2 = threading.Thread(target=relay, args=(backend, client_sock), daemon=True)
    t1.start()
    t2.start()
    # Only fully close both sockets once BOTH directions have genuinely
    # finished - closing them earlier is exactly what caused the bug above.
    t1.join()
    t2.join()
    try:
        client_sock.close()
    except Exception:
        pass
    try:
        backend.close()
    except Exception:
        pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(128)
    print("pysocks3 listening on 0.0.0.0:%d -> %s:%d" % (LISTEN_PORT, TARGET_HOST, TARGET_PORT))
    while True:
        client_sock, _ = server.accept()
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()
'''

PY2_SCRIPT = '''#!/usr/bin/env python
"""Python2 SOCKS payload responder: sends a canned handshake response, then
relays raw bytes to a backend target."""
import socket
import threading
import os
import sys

LISTEN_PORT = int(os.environ.get("PYSOCKS_LISTEN_PORT", "109"))
TARGET_HOST = os.environ.get("PYSOCKS_TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.environ.get("PYSOCKS_TARGET_PORT", "22"))
RESPONSE_CODE = os.environ.get("PYSOCKS_RESPONSE_CODE", "101")
CUSTOM_HEADER = os.environ.get("PYSOCKS_CUSTOM_HEADER", "")
MINIBANNER = os.environ.get("PYSOCKS_MINIBANNER", "")

RESPONSES = {
    "101": "HTTP/1.1 101 Switching Protocols\\r\\n\\r\\n",
    "200": "HTTP/1.1 200 Connection Established\\r\\n\\r\\n",
}


def build_response():
    if CUSTOM_HEADER:
        payload = CUSTOM_HEADER.replace("\\\\r\\\\n", "\\r\\n")
        if not payload.endswith("\\r\\n\\r\\n"):
            payload += "\\r\\n\\r\\n"
    else:
        payload = RESPONSES.get(RESPONSE_CODE, RESPONSES["101"])
    if MINIBANNER:
        payload += MINIBANNER + "\\r\\n"
    return payload


def relay(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        # Half-close only dst's write direction, rather than fully closing
        # both sockets - the OTHER relay direction (running in its own
        # thread) may still be actively delivering data (e.g. the backend's
        # own banner/greeting) and must be allowed to finish naturally.
        # Confirmed as a real bug: one direction ending first was killing
        # both sockets outright, causing "Connection lost: Broken pipe"
        # right as a backend's banner was still being delivered.
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_client(client_sock):
    try:
        client_sock.settimeout(0.4)
        buf = b""
        try:
            while b"\\r\\n\\r\\n" not in buf and len(buf) < 8192:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        client_sock.settimeout(None)
        client_sock.sendall(build_response())
    except Exception:
        client_sock.close()
        return

    try:
        backend = socket.create_connection((TARGET_HOST, TARGET_PORT), 10)
    except Exception as e:
        sys.stderr.write("pysocks2: cannot reach backend %s:%s: %s\\n" % (TARGET_HOST, TARGET_PORT, e))
        client_sock.close()
        return

    t1 = threading.Thread(target=relay, args=(client_sock, backend))
    t2 = threading.Thread(target=relay, args=(backend, client_sock))
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    # Only fully close both sockets once BOTH directions have genuinely
    # finished - closing them earlier is exactly what caused the bug above.
    t1.join()
    t2.join()
    try:
        client_sock.close()
    except Exception:
        pass
    try:
        backend.close()
    except Exception:
        pass



def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(128)
    print("pysocks2 listening on 0.0.0.0:%d -> %s:%d" % (LISTEN_PORT, TARGET_HOST, TARGET_PORT))
    while True:
        client_sock, _ = server.accept()
        t = threading.Thread(target=handle_client, args=(client_sock,))
        t.daemon = True
        t.start()


if __name__ == "__main__":
    main()
'''



def _pysocks_instances(ports_dict):
    raw = ports_dict.get('PYSOCKS_INSTANCES', '')
    instances = []
    for entry in raw.split(','):
        if not entry:
            continue
        parts = entry.split(':')
        if len(parts) == 3:
            instances.append({'variant': parts[0], 'port': parts[1], 'target': parts[2]})
    return instances


def _save_instances(ports_dict, instances):
    ports_dict['PYSOCKS_INSTANCES'] = ",".join("%s:%s:%s" % (i['variant'], i['port'], i['target']) for i in instances)


def _service_name(port):
    return "python.%s" % port


def _service_active(port):
    return _run(["systemctl", "is-active", "--quiet", _service_name(port)]).returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _ensure_scripts_deployed():
    os.makedirs(PYSOCKS_DIR, exist_ok=True)
    ok = True
    for path, content in ((PY3_SCRIPT_PATH, PY3_SCRIPT), (PY2_SCRIPT_PATH, PY2_SCRIPT)):
        needs_write = True
        if os.path.exists(path):
            with open(path, "r") as f:
                needs_write = f.read() != content
        if needs_write:
            with open(path, "w") as f:
                f.write(content)
            os.chmod(path, 0o755)
            check = _run(["python3", "-m", "py_compile", path])
            if check.returncode != 0:
                print("%s[X] %s failed its own syntax check:\n%s%s" % (C_RED, os.path.basename(path), check.stderr.strip(), C_RESET))
                os.remove(path)
                ok = False
    return ok


def _ensure_python2_installed():
    if _run(["which", "python2"]).returncode == 0:
        return True
    print("%s[i] Installing python2 (not present by default on modern Ubuntu)...%s" % (C_CYAN, C_RESET))
    _run("apt-get update && apt-get install -y python2")
    ok = _run(["which", "python2"]).returncode == 0
    if not ok:
        print("%s[X] python2 isn't available from this system's repos. This Ubuntu release" % C_RED)
        print("    may no longer ship it at all - Python2 variants won't work without it.%s" % C_RESET)
    return ok


def _write_instance_service(port, script_path, interpreter, target_host, target_port,
                             response_code, custom_header, minibanner):
    service_path = "/etc/systemd/system/python.%s.service" % port
    service_content = """[Unit]
Description=Python SOCKS Payload Responder (port %s)
After=network.target

[Service]
Type=simple
User=root
Environment=PYSOCKS_LISTEN_PORT=%s
Environment=PYSOCKS_TARGET_HOST=%s
Environment=PYSOCKS_TARGET_PORT=%s
Environment=PYSOCKS_RESPONSE_CODE=%s
Environment=PYSOCKS_CUSTOM_HEADER=%s
Environment=PYSOCKS_MINIBANNER=%s
ExecStart=%s %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % (port, port, target_host, target_port, response_code, custom_header, minibanner, interpreter, script_path)
    with open(service_path, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")
    return service_path


def _apply_instance_safely(port, service_path, description):
    if not _run("systemctl restart %s" % _service_name(port)).returncode == 0:
        return False, "%s failed to start - check 'journalctl -u %s'." % (description, _service_name(port))
    if not _wait_for_port_listening(port):
        _run("systemctl stop %s" % _service_name(port))
        _run("systemctl disable %s" % _service_name(port))
        _run("rm -f %s" % service_path)
        _run("systemctl daemon-reload")
        return False, "%s started, but port %s never came up - rolled back and removed the unit." % (description, port)
    return True, "%s is up and listening on port %s." % (description, port)


def _configure_instance(ports_dict, variant, listen_port, default_target=22, quick=False):
    clear_screen()
    label = variant.replace('-', ' ').upper()
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("               CONFIGURE %s" % label)
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print(" PYTHON SOCKS PORT: %s" % listen_port)

    if quick:
        target_port = default_target
        response_code = "101"
        custom_header = ""
        minibanner = ""
    else:
        target_port = _pick_target(ports_dict)
        if target_port is None:
            return False

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("               CONFIGURE %s" % label)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" PYTHON SOCKS PORT: %s" % listen_port)
        print("----------------------------------------------------------------")
        print(" TRAFFIC REDIRECTED TO THE PORT: %s" % target_port)
        print("----------------------------------------------------------------")
        print("             Enter to apply default settings (200)")
        print("                     101 for websocket")
        print("----------------------------------------------------------------")
        response_code = input(" ENTER A STATE OF RESPONSE: ").strip() or "200"
        if response_code not in RESPONSE_CHOICES:
            print("%s[!] '%s' isn't a recognized status - using 101.%s" % (C_YELLOW, response_code, C_RESET))
            response_code = "101"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("               CONFIGURE %s" % label)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" PYTHON SOCKS PORT: %s" % listen_port)
        print("----------------------------------------------------------------")
        print(" TRAFFIC REDIRECTED TO THE PORT: %s" % target_port)
        print("----------------------------------------------------------------")
        print(" ANSWER: %s" % response_code)
        print("----------------------------------------------------------------")
        print(r" Ex: \r\nContent-length: 0\r\n\r\nHTTP/1.1 200 Connection Established\r\n\r\n")
        print("----------------------------------------------------------------")
        custom_header = input(" CUSTOM HEADER (blank for default): ").strip()

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("               CONFIGURE %s" % label)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" PYTHON SOCKS PORT: %s" % listen_port)
        print("----------------------------------------------------------------")
        print(" TRAFFIC REDIRECTED TO THE PORT: %s" % target_port)
        print("----------------------------------------------------------------")
        print(" ANSWER: %s" % response_code)
        print("----------------------------------------------------------------")
        print(" HEADER: %s" % (custom_header if custom_header else 'DEFAULT'))
        print("----------------------------------------------------------------")
        minibanner = input(" MINIBANNER (blank for default): ").strip()

    if not check_system_port_in_use(target_port, ("tcp",)):
        print("%s[!] Nothing seems to be listening on port %s yet.%s" % (C_YELLOW, target_port, C_RESET))

    if not _ensure_scripts_deployed():
        input("\nPress Enter to continue...")
        return False

    is_py2 = 'py2' in variant
    if is_py2 and not _ensure_python2_installed():
        input("\nPress Enter to continue...")
        return False

    interpreter = "/usr/bin/python2" if is_py2 else "/usr/bin/python3"
    script_path = PY2_SCRIPT_PATH if is_py2 else PY3_SCRIPT_PATH

    open_firewall_port(listen_port, ("tcp",))
    persist_firewall_rules()
    service_path = _write_instance_service(listen_port, script_path, interpreter,
                                            "127.0.0.1", target_port, response_code,
                                            custom_header, minibanner)
    _run("systemctl enable %s" % _service_name(listen_port))

    ok, msg = _apply_instance_safely(listen_port, service_path, "%s on port %s" % (label, listen_port))

    clear_screen()
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print("               CONFIGURE %s" % label)
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    print(" PYTHON SOCKS PORT: %s" % listen_port)
    print("----------------------------------------------------------------")
    print(" TRAFFIC REDIRECTED TO THE PORT: %s" % target_port)
    print("----------------------------------------------------------------")
    print(" ANSWER: %s" % response_code)
    print("----------------------------------------------------------------")
    print(" HEADER: %s" % (custom_header if custom_header else 'DEFAULT'))
    print("----------------------------------------------------------------")
    print(" MINIBANNER: %s" % (minibanner if minibanner else 'DEFAULT'))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
    if ok:
        print("           systemctl daemon-reload............OK")
        print("           systemctl start %s..........OK" % _service_name(listen_port))
        print("           systemctl enable %s.........OK" % _service_name(listen_port))
    else:
        print("%s           %s%s" % (C_RED, msg, C_RESET))
    print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

    if ok:
        instances = _pysocks_instances(ports_dict)
        instances = [i for i in instances if i['port'] != str(listen_port)]
        instances.append({'variant': variant, 'port': str(listen_port), 'target': str(target_port)})
        _save_instances(ports_dict, instances)
    else:
        close_firewall_port(listen_port, ("tcp",))

    input("            >> Presione enter para continuar <<")
    return ok


def _read_instance_env(port):
    """Reads an existing instance's current settings straight from its live
    service file - PYSOCKS_INSTANCES only tracks variant:port:target, not
    response code/header/banner, so redirecting a port's target without
    losing its other settings means reading them from the one place they
    actually live."""
    service_path = "/etc/systemd/system/python.%s.service" % port
    env = {}
    try:
        with open(service_path) as f:
            content = f.read()
        for key in ('PYSOCKS_TARGET_HOST', 'PYSOCKS_TARGET_PORT', 'PYSOCKS_RESPONSE_CODE',
                    'PYSOCKS_CUSTOM_HEADER', 'PYSOCKS_MINIBANNER'):
            m = re.search(r'^Environment=%s=(.*)$' % key, content, re.MULTILINE)
            env[key] = m.group(1) if m else ''
    except FileNotFoundError:
        pass
    return env


def python_socks_admin_manager(ports_dict):
    """PYTHON SOCKS MANAGER."""
    while True:
        instances = _pysocks_instances(ports_dict)
        ports_display = ", ".join(i['port'] for i in instances) if instances else "None"

        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                    PYTHON SOCKS MANAGER                    %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("                   PORTS: %s" % ports_display)
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("  %s[1]>%s ADD PORT" % (C_YELLOW, C_RESET))
        print("  %s[2]>%s VIEW PORTS" % (C_YELLOW, C_RESET))
        print("  %s[3]>%s REDIRECT PORT" % (C_YELLOW, C_RESET))
        print("  %s[4]>%s REMOVE PORT" % (C_YELLOW, C_RESET))
        print("----------------------------------------------------------------")
        print("  %s[5]>%s REINSTALL PYTHON MODULES" % (C_YELLOW, C_RESET))
        print("----------------------------------------------------------------")
        print("  %s[6]>%s STOP ALL PORTS AND SERVICES" % (C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("  %s[0]%s RETURN               %s[7]%s LOGS AND REGISTERS" % (C_YELLOW, C_RESET, C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                       ADD PORT                             %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print(" [1] SIMPLE PYTHON2 SOCKS   (quick setup, default settings)")
            print(" [2] SIMPLE PYTHON3 SOCKS   (quick setup, default settings)")
            print(" [3] SOCKS PYTHON2 DIRECT   (full customization)")
            print(" [4] SOCKS PYTHON3 DIRECT   (full customization)")
            print(" [0] CANCEL")
            variant_choice = input(" Select type: ").strip()

            variant_map = {
                '1': ('py2-simple', 109, True),
                '2': ('py3-simple', 8880, True),
                '3': ('py2-direct', 81, False),
                '4': ('py3-direct', 8080, False),
            }
            if variant_choice not in variant_map:
                if variant_choice != '0':
                    print("%s[X] Invalid selection.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                continue

            variant, default_port, quick = variant_map[variant_choice]
            used_ports = [i['port'] for i in instances]
            listen_port = prompt_port(" Enter listen port (any port not already used here): ", default=default_port)
            if str(listen_port) in used_ports:
                print("%s[X] Port %s already has a Python SOCKS instance - use REDIRECT PORT" % (C_RED, listen_port))
                print("    to change it, or REMOVE PORT first.%s" % C_RESET)
                input("\nPress Enter to continue...")
                continue
            if check_system_port_in_use(listen_port, ("tcp",)):
                print("%s[X] Port %s is already in use by another service.%s" % (C_RED, listen_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            _configure_instance(ports_dict, variant, listen_port, default_target=22, quick=quick)

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                      VIEW PORTS                            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not instances:
                print("%s No ports configured yet - use ADD PORT.%s" % (C_YELLOW, C_RESET))
            else:
                for i in instances:
                    status = "ON" if _service_active(i['port']) else "OFF"
                    color = C_GREEN if status == "ON" else C_RED
                    print(" %-12s port %-6s -> 127.0.0.1:%-6s [%s%s%s]" % (
                        i['variant'], i['port'], i['target'], color, status, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                    REDIRECT PORT                           %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not instances:
                print("%s No ports configured yet - use ADD PORT.%s" % (C_YELLOW, C_RESET))
                input("\nPress Enter to continue...")
                continue
            for idx, i in enumerate(instances, 1):
                print(" [%d] %-12s port %-6s -> 127.0.0.1:%s" % (idx, i['variant'], i['port'], i['target']))
            print(" [0] CANCEL")
            pick = input(" Which port do you want to redirect? ").strip()
            if not pick.isdigit() or not (1 <= int(pick) <= len(instances)):
                if pick != '0':
                    print("%s[X] Invalid selection.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                continue
            target_instance = instances[int(pick) - 1]
            listen_port = target_instance['port']

            new_target = _pick_target(ports_dict)
            if new_target is None:
                continue

            existing_env = _read_instance_env(listen_port)
            service_path = _write_instance_service(
                listen_port,
                PY2_SCRIPT_PATH if 'py2' in target_instance['variant'] else PY3_SCRIPT_PATH,
                "/usr/bin/python2" if 'py2' in target_instance['variant'] else "/usr/bin/python3",
                "127.0.0.1", new_target,
                existing_env.get('PYSOCKS_RESPONSE_CODE', '200'),
                existing_env.get('PYSOCKS_CUSTOM_HEADER', ''),
                existing_env.get('PYSOCKS_MINIBANNER', ''),
            )
            ok, msg = _apply_instance_safely(int(listen_port), service_path,
                                              "%s on port %s" % (target_instance['variant'], listen_port))
            if ok:
                target_instance['target'] = str(new_target)
                _save_instances(ports_dict, instances)
                print("%s[OK] %s%s" % (C_GREEN, msg, C_RESET))
            else:
                print("%s[X] %s%s" % (C_RED, msg, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '4':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     REMOVE PORT                            %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not instances:
                print("%s No ports configured yet.%s" % (C_YELLOW, C_RESET))
                input("\nPress Enter to continue...")
                continue
            for idx, i in enumerate(instances, 1):
                print(" [%d] %-12s port %-6s -> 127.0.0.1:%s" % (idx, i['variant'], i['port'], i['target']))
            print(" [0] CANCEL")
            pick = input(" Which port do you want to remove? ").strip()
            if not pick.isdigit() or not (1 <= int(pick) <= len(instances)):
                if pick != '0':
                    print("%s[X] Invalid selection.%s" % (C_RED, C_RESET))
                    input("\nPress Enter to continue...")
                continue
            target_instance = instances[int(pick) - 1]
            port = target_instance['port']
            confirm = input(" Remove %s on port %s? (y/n): " % (target_instance['variant'], port)).strip().lower()
            if confirm == 'y':
                _run("systemctl stop %s" % _service_name(port))
                _run("systemctl disable %s" % _service_name(port))
                _run("rm -f /etc/systemd/system/python.%s.service" % port)
                _run("systemctl daemon-reload")
                if port.isdigit():
                    close_firewall_port(int(port), ("tcp",))
                    persist_firewall_rules()
                instances = [i for i in instances if i['port'] != port]
                _save_instances(ports_dict, instances)
                print("%s[OK] Port %s removed.%s" % (C_GREEN, port, C_RESET))
            else:
                print("%s[i] Cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '5':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                REINSTALL PYTHON MODULES                    %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            _run("apt-get update && apt-get install -y python3 python2")
            deployed = _ensure_scripts_deployed()
            if deployed:
                print("%s[OK] Python modules reinstalled and payload scripts redeployed.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[X] Redeploy failed a syntax check - see above.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '6':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s               STOP ALL PORTS AND SERVICES                  %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            confirm = input(" Stop and disable ALL Python SOCKS instances? (y/n): ").strip().lower()
            if confirm == 'y':
                for i in instances:
                    port = i['port']
                    _run("systemctl stop %s" % _service_name(port))
                    _run("systemctl disable %s" % _service_name(port))
                    _run("rm -f /etc/systemd/system/python.%s.service" % port)
                    if port.isdigit():
                        close_firewall_port(int(port), ("tcp",))
                _run("systemctl daemon-reload")
                persist_firewall_rules()
                ports_dict.pop('PYSOCKS_INSTANCES', None)
                print("%s[OK] All Python SOCKS instances stopped and removed.%s" % (C_GREEN, C_RESET))
            else:
                print("%s[i] Cancelled.%s" % (C_YELLOW, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '7':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                  LOGS AND REGISTERS                        %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            if not instances:
                print("%s No instances configured.%s" % (C_YELLOW, C_RESET))
            else:
                for i in instances:
                    print("\n--- %s (port %s) ---" % (i['variant'], i['port']))
                    os.system("journalctl -u %s -n 15 --no-pager" % _service_name(i['port']))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
