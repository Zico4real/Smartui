# SmartUI

A multi-protocol VPN/tunnel administration panel for Linux VPS servers — SSH-based menu, no web UI, root-only. Built to consolidate SSH/Dropbear, Xray/V2Ray, WireGuard, OpenVPN, and a wide range of censorship-circumvention tunnels (DNS-based, ICMP, WebSocket, Obfuscated-SSH) behind one consistent interface, with real per-user quota/connection-limit enforcement and a shared port-multiplexing layer.

## Quick install

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Zico4real/Smartui/main/install.sh)

```bash
smartui
```

Requires Ubuntu or Debian, run as root. Individual protocols are installed on-demand from inside the panel itself — the installer only sets up the panel program and its own dependencies (`git`, `curl`, `python3`, `python3-pip`).

## What's included

**Core account/protocol management**
- SSH & Dropbear — server config, banners, port changes with automatic rollback if a change would break access
- SSH User Administrator — per-customer accounts with expiry, connection-limit enforcement, and real data-quota enforcement (iptables byte-accounting), plus online-user and shared-account visibility
- Xray/V2Ray — VLESS / VMess / Trojan / Shadowsocks over TCP, WS, gRPC, XHTTP, HTTPUpgrade, mKCP; REALITY, TLS, and plaintext security; path-based multiplexing so several protocols can share one external port
- WireGuard — real per-peer IP allocation, generated client profiles
- OpenVPN — full PKI, NAT, generated `.ovpn` client profiles

**Tunnel protocols**
- Stunnel, Shadowsocks (SIP002), Hysteria (v1 + v2), Squid
- WS-EPRO — real WebSocket bridge
- Standalone WebSocket (wstunnel) — gated per-customer with username/password + optional Atken token
- BadVPN-UDPGW, ZIVPN/UDP-Custom, SSHGO (SSH-over-WebSocket/TCP)
- ICMP tunnel (Hans) — IP-over-ICMP, unique per-deployment key
- Psiphon (Obfuscated SSH) — standalone, gated the same way as the WebSocket module
- DNSTT / SLOWDNS family — dnstt, Slipstream, MasterDnsVPN, VayDNS, StormDNS, CottenDNS, with a **Multi-Engine Mode** that lets several of these run simultaneously on the same port 53 via subdomain-based DNS routing
- Port 443/80 multiplexing (sslh) — SSH, a TLS-based service, OpenVPN-TCP, and an HTTP-based tunnel can share one public port

**Auth & access control**
- CheckUser API — hashed username/password/expiry lookup for client apps
- Atken/Hash — salted-hash token auth with optional per-device (HWID) binding

**Admin tooling**
- Extra Tools — SSL certs, TCP BBR, Fail2ban, DDoS mitigation, timezone, speedtest, a gated (never automatic) firewall-activation flow, and a sandboxed plugin-script runner
- API & Bots — REST API (bearer-token, hashed), Telegram bot (read-only status commands), WhatsApp Business Cloud API webhook receiver
- Central dashboard with live stats pulled from the real user registry

## Requirements

- Ubuntu or Debian VPS, root access
- Python 3.8+
- Individual modules apt-get their own dependencies (Go, Rust/Cargo, Docker, etc.) as needed the first time you install that protocol

## Usage

```
smartui
```

opens the main dashboard:

```
[1] Manage Accounts (SSH/Dropbear)      [5] Extra Tools
[2] Manage Accounts (V2Ray/Xray)        [6] Configure API & Bots
[3] Manage Accounts (WireGuard)         [7] Panel Info / Check for Updates
[4] Protocol Configuration              [8] Uninstall Panel
```

Panel state (which protocols are installed, on which ports) persists in `/etc/smartui/panel_state.json` between runs.

## Architecture

Every module is a single flat `.py` file, importing shared helpers from `panel_common.py` (firewall management, port checking, guarded firewall activation) rather than duplicating that logic. `smartui_main.py` is the entrypoint; `protocol_configuration_manager.py` is the dispatcher for everything under "Protocol Configuration." Modules that create per-customer instances (Psiphon, standalone WebSocket, DNSTT Multi-Engine) each keep their own JSON registry under `/etc/`.

| File | Covers |
|---|---|
| `smartui_main.py` | Top-level entrypoint, dashboard, state persistence |
| `panel_common.py` | Shared firewall/port/networking helpers |
| `protocol_configuration_manager.py` | Dispatcher for all tunnel protocols |
| `ssh_dropbear_manager.py` | SSH/Dropbear server configuration |
| `ssh_user_manager.py` | Per-customer SSH accounts, quotas, connection limits |
| `xray_manager.py` | Xray/V2Ray (VLESS/VMess/Trojan/Shadowsocks) |
| `wireguard_manager.py` | WireGuard server + peers |
| `openvpn_manager.py` | OpenVPN server + PKI + client profiles |
| `stunnel_manager.py`, `shadowsocks_manager.py`, `hysteria_manager.py`, `squid_manager.py` | Individual tunnel protocols |
| `ws_epro_manager.py`, `websocket_manager.py` | WebSocket-based tunnels (own bridge, and wstunnel-based) |
| `badvpn_manager.py`, `zivpn_manager.py`, `sshgo_manager.py` | UDP gateway, ZIVPN, SSH-over-WS/TCP |
| `icmp_manager.py` | ICMP tunnel (Hans) |
| `psiphon_manager.py` | Psiphon / Obfuscated SSH |
| `dnstt_manager.py` | DNSTT family + Multi-Engine DNS router |
| `port_broker_manager.py` | Port 443/80 multiplexing (sslh) |
| `checkuser_api_manager.py`, `atken_hash_manager.py` | Auth/lookup APIs |
| `filebrowser_manager.py` | Web file browser |
| `extra_tools_manager.py` | System hardening/utilities |
| `api_and_bots_manager.py` | REST API, Telegram bot, WhatsApp webhook |
| `python_socks_manager.py` | Lightweight SOCKS/HTTP responder instances |

## Known limitations / testing status

Every module has been tested at the logic level (unit-style tests against the actual functions) and, wherever the underlying protocol allowed it, with real running processes and real sockets in a sandboxed environment — the DNS router, the WebSocket/Psiphon gates, and the quota/connection-limit enforcement were all run end-to-end this way. What hasn't happened: a full install-and-run pass on a live production VPS. Things worth a real dry run before you rely on them in production:

- The `sslh` config generation (port_broker_manager.py) was verified against the documented syntax but not against a running `sslh` binary.
- The firewall-activation guard in Extra Tools (option 11) was tested for its logic (port enumeration, timed auto-revert) but not against a real `ufw` install.
- CottenDNS's dual UDP+TCP port reconfiguration in DNSTT Multi-Engine Mode has an unconfirmed TCP config key name — the module warns if it can't find one to rewrite.
- Whether MasterDNS/StormDNS/CottenDNS's own binaries support running multiple simultaneous instances from different config files (as Multi-Engine Mode does) hasn't been independently verified — the dnstt/VayDNS/Slipstream instances are self-contained processes and confirmed safe; the vendor-binary engines should be, but weren't built from scratch the same way.

## Credits

This panel installs and wraps a number of other people's open-source work. All credit for the underlying protocols/tools goes to their original authors:

- [dnstt](https://www.bamsoftware.com/software/dnstt/) — David Fifield / bamsoftware
- [Xray-core](https://github.com/XTLS/Xray-core) — XTLS project
- [Hysteria](https://github.com/apernet/hysteria) — Apernet
- [WireGuard](https://www.wireguard.com/) — Jason A. Donenfeld
- [OpenVPN](https://openvpn.net/)
- [Hans](https://github.com/friedrich/hans) — friedrich (IP-over-ICMP)
- [wstunnel](https://github.com/erebe/wstunnel) — erebe
- [sslh](https://github.com/yrutschle/sslh) — yrutschle
- [Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core) — Psiphon Inc.
- [Slipstream](https://github.com/Mygod/slipstream-rust) — Mygod
- [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) — masterking32
- [VayDNS](https://github.com/net2share/vaydns) — net2share
- [StormDNS](https://github.com/nullroute1970/StormDNS) — nullroute1970
- [CottenDNS](https://github.com/TaJirax/cottenDNS) — TaJirax

## License

This project's own code (everything in this repository) is licensed under [LICENSE](LICENSE).

**This license covers only the panel's own code.** Every third-party project listed above under Credits is installed by this panel at runtime and remains under its own separate license (a mix of MIT, GPL-3.0, and BSD-3-Clause among them) — this repository doesn't redistribute their code and doesn't relicense it. Check each project's own repository for its exact terms before redistributing anything this panel installs.
