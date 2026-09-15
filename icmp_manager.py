"""
icmp_manager.py - ICMP tunnel admin module for the SmartUI panel, wrapping a
custom Python ICMP-over-echo server matching a specific Android client's own
wire protocol (MAGIC=b"ICMPVPN2"). Replaces the earlier Hans-based approach
entirely - Hans and this custom protocol are mutually incompatible, and the
whole point here is matching an already-built client app, not choosing the
tunnel technology from scratch.

Two real issues were found and fixed while reviewing the client-provided
script before wrapping it, not assumed to be correct as-is:

1. No authentication of any kind. The wire protocol (data/ack/keepalive
   frames) has no login step - any client that knows the protocol gets a TUN
   IP and NAT'd internet access. Since ICMP has no companion TCP/HTTP port
   the way other tunnels in this panel do, gating happens the same way as
   the Psiphon/WebSocket gates: closed by default (dedicated iptables chain,
   DROP), and a small HTTP service grants a client's source IP temporary
   ICMP access after they authenticate - using the REAL system SSH accounts
   via PAM (python-pam, confirmed real/maintained, also packaged natively as
   python3-pampy on Debian/Ubuntu), not a separate credential store. This is
   what makes SSH the actual global credential here, as asked for.

2. The downlink routing picked whichever client was "most recently active"
   for every return packet, regardless of who it was actually addressed to
   (confirmed by reading the code directly: max(clients.items(),
   key=lambda x: x[1]['last'])). With more than one customer connected at
   once, one customer's return traffic could be delivered to a different
   customer entirely. Fixed by learning each client's real internal IP from
   their own uplink packets (already present in every IP packet's source
   address field) and matching downlink packets by actual destination IP -
   using information already in the protocol, no client-side change needed.
   Verified against the client's exact original file: the diff is two small,
   targeted blocks, everything else is untouched byte-for-byte.

No install step beyond writing the file: the tunnel server itself only uses
Python standard library (argparse, fcntl, os, select, socket, struct,
subprocess, time) - no compilation, no third-party download.
"""

import os
import re
import time
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, run_cmd as _run, get_public_ip,
    persist_firewall_rules, open_firewall_port, close_firewall_port,
)
from openvpn_manager import _default_interface

ICMP_DIR = "/etc/icmp-vpn"
SERVER_SCRIPT_PATH = "/usr/local/bin/icmp-vpn-server.py"
SERVICE_PATH = "/etc/systemd/system/icmp-vpn.service"
GATE_SCRIPT_PATH = "/usr/local/bin/icmp-vpn-gate.py"
GATE_SERVICE_PATH = "/etc/systemd/system/icmp-vpn-gate.service"
GATE_STATE_PATH = f"{ICMP_DIR}/gate_state.json"
CLEANUP_SCRIPT_PATH = "/usr/local/bin/icmp-vpn-gate-cleanup.py"
CLEANUP_CRON_PATH = "/etc/cron.d/icmp-vpn-gate-cleanup"
GATE_CHAIN = "icmpgate"
GATE_PORT_DEFAULT = 8602
TUN_DEVICE = "tun1"
TUNNEL_NETWORK = "10.8.0.0/24"  # hardcoded in the server script itself, matching the Android client

SERVER_SCRIPT = '#!/usr/bin/env python3\n"""ICMP-only VPN server for the matching Android client.\n\nCreates a TUN interface, NATs 10.8.0.0/24 to the Internet interface, and\ncarries framed IPv4 packets inside ICMP Echo Request/Reply messages.\n"""\nimport argparse, fcntl, os, select, socket, struct, subprocess, time\n\nMAGIC=b"ICMPVPN2"; VERSION=1\nTYPE_DATA=1; TYPE_ACK=2; TYPE_KEEPALIVE=3\n# TYPE_STATS is kept only for backward compatibility; v4.7+ carries stats in ACK/KEEPALIVE.\nTYPE_STATS=4\nHEADER_SIZE=32; MAX_PAYLOAD=1320; MAX_DATA=MAX_PAYLOAD-HEADER_SIZE\nTUNSETIFF=0x400454CA; IFF_TUN=0x0001; IFF_NO_PI=0x1000\n\ndef checksum(data):\n    if len(data)%2: data+=b"\\0"\n    s=sum((data[i]<<8)+data[i+1] for i in range(0,len(data),2))\n    while s>>16: s=(s&0xffff)+(s>>16)\n    return (~s)&0xffff\n\ndef create_tun(name):\n    fd=os.open(\'/dev/net/tun\',os.O_RDWR)\n    res=fcntl.ioctl(fd,TUNSETIFF,struct.pack(\'16sH\',name.encode(),IFF_TUN|IFF_NO_PI))\n    actual=struct.unpack(\'16sH\',res)[0].split(b\'\\0\',1)[0].decode()\n    return fd,actual\n\ndef sh(*args): subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n\ndef setup_network(tun,external):\n    try: sh(\'ip\',\'addr\',\'add\',\'10.8.0.1/24\',\'dev\',tun)\n    except subprocess.CalledProcessError: pass\n    sh(\'ip\',\'link\',\'set\',\'dev\',tun,\'up\')\n    sh(\'sysctl\',\'-w\',\'net.ipv4.ip_forward=1\')\n    for rule in [\n        (\'iptables\',\'-A\',\'FORWARD\',\'-i\',tun,\'-j\',\'ACCEPT\'),\n        (\'iptables\',\'-A\',\'FORWARD\',\'-o\',tun,\'-m\',\'state\',\'--state\',\'ESTABLISHED,RELATED\',\'-j\',\'ACCEPT\'),\n        (\'iptables\',\'-t\',\'nat\',\'-A\',\'POSTROUTING\',\'-s\',\'10.8.0.0/24\',\'-o\',external,\'-j\',\'MASQUERADE\')]:\n        try: sh(*rule)\n        except subprocess.CalledProcessError: pass\n\ndef build_icmp(typ,payload,ident,seq):\n    msg=struct.pack(\'!BBHHH\',typ,0,0,ident,seq)+payload\n    c=checksum(msg)\n    return struct.pack(\'!BBHHH\',typ,0,c,ident,seq)+payload\n\ndef build_frame(typ,session,pid,seq,fi,fc,data):\n    return MAGIC+bytes((VERSION,typ))+struct.pack(\'!IIQHHH\',session,pid,seq,fi,fc,len(data))+data\n\ndef parse_frame(p):\n    if len(p)<HEADER_SIZE or p[:8]!=MAGIC or p[8]!=VERSION: return None\n    typ=p[9]; session,pid,seq,fi,fc,n=struct.unpack(\'!IIQHHH\',p[10:32])\n    if fc<1 or fc>64 or fi>=fc or n!=len(p)-HEADER_SIZE or n>MAX_DATA: return None\n    return typ,session,pid,seq,fi,fc,p[HEADER_SIZE:]\n\ndef valid_ipv4(p):\n    if len(p)<20 or p[0]>>4!=4: return False\n    ihl=(p[0]&15)*4\n    if ihl<20 or ihl>len(p): return False\n    total=(p[2]<<8)|p[3]\n    return ihl<=total<=len(p) and total<=1400\n\ndef iptables_packet_counters():\n    forward=0; nat=0\n    try:\n        out=subprocess.check_output([\'iptables\',\'-nvx\',\'-L\',\'FORWARD\'],stderr=subprocess.DEVNULL,text=True)\n        for line in out.splitlines():\n            parts=line.split()\n            if len(parts)>=8 and parts[0].isdigit() and parts[1].isdigit():\n                if \'tun1\' in line or \'tun\' in line:\n                    forward += int(parts[0])\n    except Exception:\n        pass\n    try:\n        out=subprocess.check_output([\'iptables\',\'-t\',\'nat\',\'-nvx\',\'-L\',\'POSTROUTING\'],stderr=subprocess.DEVNULL,text=True)\n        for line in out.splitlines():\n            parts=line.split()\n            if len(parts)>=8 and parts[0].isdigit() and parts[1].isdigit() and \'MASQUERADE\' in line:\n                nat += int(parts[0])\n    except Exception:\n        pass\n    try:\n        with open(\'/proc/sys/net/ipv4/ip_forward\',\'r\') as f:\n            ip_forward=int(f.read().strip() or \'0\')\n    except Exception:\n        ip_forward=-1\n    return ip_forward, forward, nat\n\ndef build_stats_payload(rx_frames,rx_bytes,tx_frames,tx_bytes,tun_out,tun_in,drops,last_rx,last_tx,ip_forward,forward_pkts,nat_pkts):\n    return struct.pack(\'!QQQQQQQQQIII\', rx_frames,rx_bytes,tx_frames,tx_bytes,tun_out,tun_in,drops,last_rx,last_tx,ip_forward & 0xffffffff,forward_pkts & 0xffffffff,nat_pkts & 0xffffffff)\n\ndef run(args):\n    if os.geteuid()!=0: raise SystemExit(\'Run as root.\')\n    tun_fd,tun_name=create_tun(args.tun); setup_network(tun_name,args.interface)\n    print(f\'[+] TUN ready: {tun_name}\'); print(f\'[+] NAT interface: {args.interface}\')\n    ipfwd, fwd_pkts, nat_pkts = iptables_packet_counters()\n    print(f\'[+] ip_forward={ipfwd} FORWARD_pkts={fwd_pkts} NAT_pkts={nat_pkts}\')\n    try:\n        print(\'[+] FORWARD rules:\')\n        print(subprocess.check_output([\'iptables\',\'-nvx\',\'-L\',\'FORWARD\'], text=True, stderr=subprocess.STDOUT).strip())\n    except Exception as e:\n        print(f\'[!] Could not read FORWARD rules: {e}\')\n    try:\n        print(\'[+] POSTROUTING NAT rules:\')\n        print(subprocess.check_output([\'iptables\',\'-t\',\'nat\',\'-nvx\',\'-L\',\'POSTROUTING\'], text=True, stderr=subprocess.STDOUT).strip())\n    except Exception as e:\n        print(f\'[!] Could not read NAT rules: {e}\')\n    icmp=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); icmp.setblocking(False)\n    clients={}; assemblies={}\n    server_rx_frames=0; server_rx_bytes=0; server_tx_frames=0; server_tx_bytes=0\n    server_tun_out=0; server_tun_in=0; server_drops=0\n    server_last_rx_seq=0; server_last_tx_seq=0\n    server_ip_forward=0; server_forward_pkts=0; server_nat_pkts=0; next_stats=0.0\n    print(\'[+] Waiting for ICMP VPN clients...\'); print(\'[+] ICMP raw socket ready\')\n    try:\n        while True:\n            readable,_,_=select.select([icmp,tun_fd],[],[],0.5); now=time.monotonic()\n            for key,a in list(assemblies.items()):\n                if now-a[0]>15:\n                    assemblies.pop(key,None); server_drops+=1\n            if now >= next_stats:\n                server_ip_forward, server_forward_pkts, server_nat_pkts = iptables_packet_counters()\n                next_stats=now+1.0\n            if icmp in readable:\n                packet,addr=icmp.recvfrom(65535)\n                if len(packet)<28: continue\n                typ,code,_checksum,ident,iseq=struct.unpack(\'!BBHHH\',packet[20:28])\n                if typ not in (8,0) or code!=0: continue\n                parsed=parse_frame(packet[28:])\n                if not parsed: continue\n                ftyp,session,pid,seq,fi,fc,data=parsed; client_key=(addr[0],session)\n                # Remember the ICMP Echo identifier from the real client request.\n                # Downlink Echo Replies must use the same identifier on the target Android ping socket.\n                clients[client_key]={\'last\':now,\'ident\':ident}\n                if ftyp==TYPE_DATA:\n                    server_rx_frames+=1; server_rx_bytes+=len(data); server_last_rx_seq=seq\n                    key=(addr[0],session,pid)\n                    a=assemblies.get(key)\n                    if fc==1:\n                        full=data\n                    else:\n                        if a is None or a[1]!=pid or a[2]!=fc: a=(now,pid,fc,[None]*fc); assemblies[key]=a\n                        parts=a[3]; parts[fi]=data\n                        if any(x is None for x in parts):\n                            full=None\n                        else:\n                            full=b\'\'.join(parts); assemblies.pop(key,None)\n                    if full is not None and valid_ipv4(full):\n                        # Learn this client\'s actual internal IP from their own\n                        # packet\'s source address - the app never tells us this\n                        # directly, but it\'s already sitting in every packet it\n                        # sends. Used below to route downlink replies correctly\n                        # when more than one client is connected at once.\n                        clients[client_key][\'internal_ip\']=socket.inet_ntoa(full[12:16])\n                        os.write(tun_fd,full)\n                        server_tun_out+=1\n                        print(f\'[RX] {addr[0]} session={session} pid={pid} seq={seq} packet={len(full)}\')\n                    elif full is not None:\n                        server_drops+=1\n                        print(f\'[DROP] invalid IPv4 session={session} pid={pid} size={len(full)}\')\n                    stats=build_stats_payload(server_rx_frames,server_rx_bytes,server_tx_frames,server_tx_bytes,\n                                              server_tun_out,server_tun_in,server_drops,server_last_rx_seq,\n                                              server_last_tx_seq,server_ip_forward,server_forward_pkts,server_nat_pkts)\n                    ack=build_frame(TYPE_ACK,session,pid,seq,0,1,stats)\n                    icmp.sendto(build_icmp(0,ack,ident,iseq),(addr[0],0))\n                elif ftyp==TYPE_KEEPALIVE:\n                    stats=build_stats_payload(server_rx_frames,server_rx_bytes,server_tx_frames,server_tx_bytes,\n                                              server_tun_out,server_tun_in,server_drops,server_last_rx_seq,\n                                              server_last_tx_seq,server_ip_forward,server_forward_pkts,server_nat_pkts)\n                    reply=build_frame(TYPE_KEEPALIVE,session,pid,seq,0,1,stats)\n                    icmp.sendto(build_icmp(0,reply,ident,iseq),(addr[0],0))\n                elif ftyp==TYPE_ACK:\n                    pass\n            if tun_fd in readable:\n                data=os.read(tun_fd,65535)\n                if not data or not clients: continue\n                server_tun_in+=1\n                # Route by the packet\'s actual destination IP (learned from each\n                # client\'s own uplink traffic above), not by guessing which\n                # client was most recently active - with more than one client\n                # connected, the old approach could deliver one customer\'s\n                # return traffic to a different customer entirely.\n                match=None\n                if valid_ipv4(data):\n                    dest_ip=socket.inet_ntoa(data[16:20])\n                    for ck,info in clients.items():\n                        if info.get(\'internal_ip\')==dest_ip:\n                            match=(ck,info); break\n                if match is None:\n                    match=max(clients.items(),key=lambda x:x[1][\'last\'])\n                (client_ip,session), client_info=match\n                client_ident=client_info[\'ident\']\n                pid=int(time.monotonic()*1000000)&0xffffffff\n                fc=(len(data)+MAX_DATA-1)//MAX_DATA\n                for fi,off in enumerate(range(0,len(data),MAX_DATA)):\n                    chunk=data[off:off+MAX_DATA]; seq=int(time.monotonic_ns())&0xffffffffffffffff\n                    frame=build_frame(TYPE_DATA,session,pid,seq,fi,fc,chunk)\n                    server_tx_frames+=1; server_tx_bytes+=len(chunk); server_last_tx_seq=seq\n                    icmp.sendto(build_icmp(0,frame,client_ident,seq&0xffff),(client_ip,0))\n                print(f\'[TX] {client_ip} session={session} pid={pid} packet={len(data)} frags={fc}\')\n    finally:\n        icmp.close(); os.close(tun_fd)\n\nif __name__==\'__main__\':\n    p=argparse.ArgumentParser(); p.add_argument(\'-i\',\'--interface\',\'--iface\',dest=\'interface\',required=True); p.add_argument(\'-t\',\'--tun\',dest=\'tun\',default=\'tun1\')\n    run(p.parse_args())\n'

GATE_SCRIPT = '#!/usr/bin/env python3\n"""ICMP tunnel access gate. GET /unlock?user=X&pass=Y -> verifies the\ncredentials against the REAL system SSH accounts via PAM (the same accounts\nssh_user_manager.py already manages - no separate credential store), and on\nsuccess inserts a time-limited iptables ACCEPT rule for that client\'s source\nIP ahead of the default DROP rule for ICMP echo traffic. Exists because the\nICMP VPN protocol itself (matching a specific Android client) has no\nauthentication of its own - without this, anyone who discovers the server\nresponds to this protocol gets free, unauthenticated NAT\'d internet access."""\nimport os\nimport sys\nimport json\nimport time\nimport subprocess\nimport http.server\nimport socketserver\nimport urllib.parse\n\ntry:\n    import pam\nexcept ImportError:\n    pam = None\n\nGATE_STATE_PATH = "/etc/icmp-vpn/gate_state.json"\nGATE_CHAIN = "icmpgate"\nACCEPT_WINDOW_MINUTES = 15\nPORT = int(os.environ.get("ICMP_GATE_PORT", "8602"))\n\n_fail_counts = {}\n_fail_window = 60\n_fail_limit = 10\n\n\ndef run(cmd):\n    return subprocess.run(cmd, capture_output=True, text=True)\n\n\ndef load_gate_state():\n    try:\n        with open(GATE_STATE_PATH) as f:\n            return json.load(f)\n    except Exception:\n        return {}\n\n\ndef save_gate_state(state):\n    os.makedirs(os.path.dirname(GATE_STATE_PATH), exist_ok=True)\n    with open(GATE_STATE_PATH, "w") as f:\n        json.dump(state, f, indent=2)\n\n\ndef grant_access(source_ip):\n    check = run(["iptables", "-C", GATE_CHAIN, "-s", source_ip, "-j", "ACCEPT"])\n    if check.returncode != 0:\n        run(["iptables", "-I", GATE_CHAIN, "1", "-s", source_ip, "-j", "ACCEPT"])\n    state = load_gate_state()\n    state[source_ip] = time.time() + ACCEPT_WINDOW_MINUTES * 60\n    save_gate_state(state)\n\n\ndef _rate_limited(addr):\n    now = time.time()\n    entry = [t for t in _fail_counts.get(addr, []) if now - t < _fail_window]\n    _fail_counts[addr] = entry\n    return len(entry) >= _fail_limit\n\n\ndef _record_failure(addr):\n    _fail_counts.setdefault(addr, []).append(time.time())\n\n\nclass GateHandler(http.server.BaseHTTPRequestHandler):\n    def log_message(self, fmt, *args):\n        pass  # the query string carries the password - never let it reach a log file\n\n    def do_GET(self):\n        client_addr = self.client_address[0]\n        if _rate_limited(client_addr):\n            self.send_response(429)\n            self.end_headers()\n            return\n\n        if pam is None:\n            self.send_response(500)\n            self.end_headers()\n            self.wfile.write(b\'{"error":"pam module not installed on server"}\')\n            return\n\n        parsed = urllib.parse.urlparse(self.path)\n        params = urllib.parse.parse_qs(parsed.query)\n        user = params.get("user", [""])[0]\n        password = params.get("pass", [""])[0]\n\n        valid = False\n        if user and password:\n            try:\n                valid = pam.pam().authenticate(user, password, service="login")\n            except Exception:\n                valid = False\n\n        if not valid:\n            _record_failure(client_addr)\n            self.send_response(401)\n            self.end_headers()\n            return\n\n        grant_access(client_addr)\n        body = json.dumps({"status": "granted", "valid_for_minutes": ACCEPT_WINDOW_MINUTES}).encode()\n        self.send_response(200)\n        self.send_header("Content-type", "application/json")\n        self.send_header("Content-length", str(len(body)))\n        self.end_headers()\n        self.wfile.write(body)\n\n\nclass ReusableTCPServer(socketserver.ThreadingTCPServer):\n    allow_reuse_address = True\n    daemon_threads = True\n\n\nif __name__ == "__main__":\n    with ReusableTCPServer(("0.0.0.0", PORT), GateHandler) as httpd:\n        print("icmp-vpn-gate listening on 0.0.0.0:%d" % PORT)\n        httpd.serve_forever()\n'

CLEANUP_SCRIPT = '#!/usr/bin/env python3\n"""Expires temporary per-IP ICMP ACCEPT rules once their window has passed -\nsame cadence pattern as the Psiphon/WebSocket gate cleanups elsewhere in\nthis panel, run periodically via cron."""\nimport json\nimport time\nimport subprocess\n\nGATE_STATE_PATH = "/etc/icmp-vpn/gate_state.json"\nGATE_CHAIN = "icmpgate"\n\n\ndef run(cmd):\n    return subprocess.run(cmd, capture_output=True, text=True)\n\n\ndef main():\n    try:\n        with open(GATE_STATE_PATH) as f:\n            state = json.load(f)\n    except Exception:\n        return\n\n    now = time.time()\n    changed = False\n    for ip, expiry in list(state.items()):\n        if now >= expiry:\n            run(["iptables", "-D", GATE_CHAIN, "-s", ip, "-j", "ACCEPT"])\n            del state[ip]\n            changed = True\n\n    if changed:\n        with open(GATE_STATE_PATH, "w") as f:\n            json.dump(state, f, indent=2)\n\n\nif __name__ == "__main__":\n    main()\n'


def _service_active(name):
    return _run(["systemctl", "is-active", "--quiet", name]).returncode == 0


def _deploy_script(path, content):
    needs_write = True
    if os.path.exists(path):
        with open(path) as f:
            needs_write = f.read() != content
    if needs_write:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o755)
        check = _run(["python3", "-m", "py_compile", path])
        if check.returncode != 0:
            print(f"{C_RED}[X] {os.path.basename(path)} failed its own syntax check:\n{check.stderr.strip()}{C_RESET}")
            os.remove(path)
            return False
    return True


def _ensure_pam_installed():
    check = _run(["python3", "-c", "import pam"])
    if check.returncode == 0:
        return True
    print(f"{C_CYAN}[i] Installing python3-pampy (real SSH/system-account auth, no separate{C_RESET}")
    print(f"{C_CYAN}    credential store)...{C_RESET}")
    _run("apt-get update && apt-get install -y python3-pampy")
    check2 = _run(["python3", "-c", "import pam"])
    if check2.returncode != 0:
        print(f"{C_YELLOW}[!] apt package unavailable - trying pip instead...{C_RESET}")
        _run("pip3 install python-pam --break-system-packages")
        check2 = _run(["python3", "-c", "import pam"])
    return check2.returncode == 0


def _write_server_service(interface):
    service_content = f"""[Unit]
Description=ICMP VPN Server (custom protocol)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 {SERVER_SCRIPT_PATH} -i {interface} -t {TUN_DEVICE}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    with open(SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _write_gate_service(gate_port):
    service_content = f"""[Unit]
Description=ICMP VPN Access Gate
After=network.target

[Service]
Type=simple
User=root
Environment=ICMP_GATE_PORT={gate_port}
ExecStart=/usr/bin/python3 {GATE_SCRIPT_PATH}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    with open(GATE_SERVICE_PATH, "w") as f:
        f.write(service_content)
    _run("systemctl daemon-reload")


def _ensure_gate_chain():
    """Default-DROP chain for ICMP echo traffic - only source IPs the gate has
    explicitly granted (via a temporary ACCEPT inserted ahead of this) get
    through. This is the opposite default from panel_common's own
    open_firewall_icmp() (which assumes you WANT icmp open broadly) -
    deliberately not reused here since a gated deployment needs the reverse."""
    _run(["iptables", "-N", GATE_CHAIN])
    check_jump = _run(["iptables", "-C", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", GATE_CHAIN])
    if check_jump.returncode != 0:
        _run(["iptables", "-I", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", GATE_CHAIN])
    check_drop = _run(["iptables", "-C", GATE_CHAIN, "-j", "DROP"])
    if check_drop.returncode != 0:
        _run(["iptables", "-A", GATE_CHAIN, "-j", "DROP"])


def _remove_gate_chain():
    _run(["iptables", "-D", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-j", GATE_CHAIN])
    _run(["iptables", "-F", GATE_CHAIN])
    _run(["iptables", "-X", GATE_CHAIN])


def _wait_for_tun_up(tries=8, delay=1):
    for _ in range(tries):
        result = _run(["ip", "addr", "show", "dev", TUN_DEVICE])
        if result.returncode == 0 and re.search(r"inet \d+\.\d+\.\d+\.\d+", result.stdout):
            return True
        time.sleep(delay)
    return False


def icmp_admin_manager(ports_dict):
    """ICMP VPN (custom protocol) Administrator Module."""
    while True:
        gate_port = ports_dict.get("ICMP_GATE_PORT", "Not configured")
        is_active = _service_active("icmp-vpn")
        gate_active = _service_active("icmp-vpn-gate")

        clear_screen()
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print("%s                   ICMP TUNNEL ADMINISTRATOR                %s" % (C_BOLD, C_RESET))
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print(f"      NETWORK: {TUNNEL_NETWORK} (fixed - matches the Android client)")
        print(f"      GATE PORT: {gate_port}")
        print(f"{C_YELLOW}      This protocol has no login of its own - clients must unlock their")
        print(f"      IP via the gate (using their real SSH username/password) before the")
        print(f"      tunnel will respond to them at all.{C_RESET}")
        print("----------------------------------------------------------------")
        print(" %s[1]>%s CONFIGURE / INSTALL ICMP TUNNEL" % (C_YELLOW, C_RESET))
        print(" %s[2]>%s VIEW CONNECTION INFO" % (C_YELLOW, C_RESET))
        print(" %s[3]>%s VIEW SERVICE LOGS" % (C_YELLOW, C_RESET))
        print(" %s[4]>%s RESTART SERVICES" % (C_YELLOW, C_RESET))
        print(f" {C_YELLOW}[5]>{C_RESET} START/STOP SERVICES [{'ON' if is_active else 'OFF'}]")
        print("%s================================================================%s" % (C_CYAN, C_RESET))
        print(" %s[0]%s RETURN  %s[6]%s UNINSTALL ICMP TUNNEL" % (C_YELLOW, C_RESET, C_YELLOW, C_RESET))
        print("%s================================================================%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == "0":
            break

        elif choice == "1":
            clear_screen()
            print("%s================================================================%s" % (C_CYAN, C_RESET))
            print("%s            ICMP TUNNEL INSTALLATION                        %s" % (C_BOLD, C_RESET))
            print("%s================================================================%s" % (C_CYAN, C_RESET))
            print(f"{C_CYAN}[i] Nothing to configure - network interface and tunnel subnet are")
            print(f"    auto-detected/fixed. Installing...{C_RESET}\n")

            interface = _default_interface()
            gate_port = int(ports_dict.get("ICMP_GATE_PORT", GATE_PORT_DEFAULT))

            if not _deploy_script(SERVER_SCRIPT_PATH, SERVER_SCRIPT):
                input("\nPress Enter to continue...")
                continue
            if not _ensure_pam_installed():
                print(f"{C_RED}[X] Could not install PAM support - the gate needs this to check")
                print(f"    SSH credentials. Aborting.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            if not _deploy_script(GATE_SCRIPT_PATH, GATE_SCRIPT):
                input("\nPress Enter to continue...")
                continue
            if not _deploy_script(CLEANUP_SCRIPT_PATH, CLEANUP_SCRIPT):
                input("\nPress Enter to continue...")
                continue
            if not os.path.exists(CLEANUP_CRON_PATH):
                with open(CLEANUP_CRON_PATH, "w") as f:
                    f.write("* * * * * root /usr/bin/python3 %s\n" % CLEANUP_SCRIPT_PATH)
                os.chmod(CLEANUP_CRON_PATH, 0o644)

            _write_server_service(interface)
            _write_gate_service(gate_port)
            _ensure_gate_chain()
            open_firewall_port(gate_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable icmp-vpn")
            _run("systemctl enable icmp-vpn-gate")

            server_ok = _run("systemctl restart icmp-vpn").returncode == 0
            gate_ok = _run("systemctl restart icmp-vpn-gate").returncode == 0

            if server_ok and _wait_for_tun_up() and gate_ok:
                ports_dict["ICMP_GATE_PORT"] = str(gate_port)
                server_ip = get_public_ip()
                print(f"{C_GREEN}[OK] ICMP tunnel and gate installed and verified.{C_RESET}\n")
                print(f" Server IP: {server_ip}")
                print(f" Gate URL: http://{server_ip}:{gate_port}/unlock?user=SSH_USERNAME&pass=SSH_PASSWORD")
                print(f"\n Customers hit that URL once (from the same network they'll tunnel from)")
                print(f" using their real SSH username/password, then connect via the Android app.")
            else:
                _remove_gate_chain()
                close_firewall_port(gate_port, ("tcp",))
                print(f"{C_RED}[X] Install did not complete successfully - check")
                print(f"    'journalctl -u icmp-vpn' and 'journalctl -u icmp-vpn-gate'.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == "2":
            clear_screen()
            if not os.path.exists(SERVER_SCRIPT_PATH):
                print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                input("\nPress Enter to continue...")
                continue
            server_ip = get_public_ip()
            print(f" Server IP: {server_ip}")
            print(f" Gate URL: http://{server_ip}:{gate_port}/unlock?user=SSH_USERNAME&pass=SSH_PASSWORD")
            print(f"\n Customers authenticate with their real SSH username/password - the same")
            print(f" accounts already used for SSH/Dropbear, nothing separate to manage.")
            input("\nPress Enter to continue...")

        elif choice == "3":
            clear_screen()
            os.system("journalctl -u icmp-vpn -n 30 --no-pager")
            print()
            os.system("journalctl -u icmp-vpn-gate -n 20 --no-pager")
            input("\nPress Enter to continue...")

        elif choice == "4":
            ok1 = _run("systemctl restart icmp-vpn").returncode == 0
            ok2 = _run("systemctl restart icmp-vpn-gate").returncode == 0
            if ok1 and ok2:
                print(f"{C_GREEN}[OK] Both services restarted successfully.{C_RESET}")
            else:
                print(f"{C_RED}[X] One or both failed to restart - check the logs.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == "5":
            if is_active:
                _run("systemctl stop icmp-vpn")
                _run("systemctl stop icmp-vpn-gate")
                print(f"{C_YELLOW}[!] ICMP tunnel and gate stopped.{C_RESET}")
            else:
                if not os.path.exists(SERVER_SCRIPT_PATH):
                    print(f"{C_RED}[X] Not installed yet - run option 1 first.{C_RESET}")
                    input("\nPress Enter to continue...")
                    continue
                _run("systemctl start icmp-vpn")
                _run("systemctl start icmp-vpn-gate")
                print(f"{C_GREEN}[OK] ICMP tunnel and gate started.{C_RESET}" if _service_active("icmp-vpn")
                      else f"{C_RED}[X] Failed to start - check the logs.{C_RESET}")
            input("\nPress Enter to continue...")

        elif choice == "6":
            clear_screen()
            confirm = input(" Are you sure you want to completely remove the ICMP tunnel? (y/n): ").strip().lower()
            if confirm == "y":
                _run("systemctl stop icmp-vpn")
                _run("systemctl stop icmp-vpn-gate")
                _run("systemctl disable icmp-vpn")
                _run("systemctl disable icmp-vpn-gate")
                _run(f"rm -f {SERVICE_PATH} {GATE_SERVICE_PATH} {CLEANUP_CRON_PATH}")
                _run("systemctl daemon-reload")
                _remove_gate_chain()
                if str(gate_port).isdigit():
                    close_firewall_port(int(gate_port), ("tcp",))
                persist_firewall_rules()
                _run(f"rm -rf {ICMP_DIR} {SERVER_SCRIPT_PATH} {GATE_SCRIPT_PATH} {CLEANUP_SCRIPT_PATH}")
                ports_dict.pop("ICMP_GATE_PORT", None)
                print(f"{C_GREEN}[OK] ICMP tunnel removed and purged successfully.{C_RESET}")
            else:
                print(f"{C_YELLOW}[i] Uninstallation cancelled.{C_RESET}")
            input("\nPress Enter to continue...")

        else:
            print(f"{C_RED}Invalid option.{C_RESET}")
            input("\nPress Enter to continue...")
