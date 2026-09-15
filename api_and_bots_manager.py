"""
api_and_bots_manager.py - API & Bots module for the SmartUI panel.

Real bugs found across all three sub-installers:

1. API Installer stored the bearer token as a PLAINTEXT string baked directly
   into the deployed server.py source. For a shared-secret comparison like a
   bearer token, the same hash-and-compare principle used everywhere else in
   this panel (CheckUser API, Atken) applies: anyone who can read that file
   gets the token outright. Fixed with salted PBKDF2 storage in a separate
   credentials file (also means changing the token later doesn't require
   redeploying the server script itself), and a timing-safe comparison
   instead of a plain == string check.

2. Telegram bot token was written to a world-readable file with no
   permission restriction - same category of exposure. Fixed with 0o600.

3. Neither installer verified its dependency actually installed (pip3
   install flask / pip3 install python-telegram-bot) before writing and
   starting a systemd unit that imports it - a failed pip install would
   crash-loop the service while the code claimed "[OK] successfully
   installed and running" regardless.

4. WhatsApp Bot Installer was a complete fake. The "bot" it deployed did
   nothing but print a startup message and sleep forever - no webhook
   receiver, no WhatsApp Business API client, no session handling of any
   kind - while claiming "[OK] WhatsApp bot daemon successfully installed
   and configured!" A real, session-based WhatsApp automation bot is out of
   reasonable scope here: the official path requires Meta business
   verification this panel can't script around, and unofficial automation
   libraries risk WhatsApp ToS enforcement (account bans) - not something to
   build or encourage. What IS honest and buildable: a real webhook
   RECEIVER for Meta's WhatsApp Business Cloud API, including the actual
   verify-token GET handshake and HMAC-SHA256 payload signature validation,
   for an admin who already has their own approved Meta app. Replaced the
   fake sleep-loop with that, clearly labeled as a receiver only, not a
   sender/automation bot.

Both the API and Telegram bot were also extended with real, READ-ONLY
commands/endpoints wired into data this panel already tracks (registered SSH
users and their expiry, currently active sessions - reading directly from
ssh_user_manager.py's registry.json and `who`) rather than a single inert
"status: online" placeholder. Kept deliberately read-only: a compromised bot
token or a stolen phone with Telegram logged in would otherwise translate
directly into remote account creation/deletion capability, a meaningfully
bigger attack surface than a status query.
"""

import os
import re
import time
import json
import hashlib
import hmac
import secrets
from panel_common import (
    C_RESET, C_BOLD, C_RED, C_GREEN, C_YELLOW, C_CYAN,
    clear_screen, check_system_port_in_use, prompt_port,
    open_firewall_port, close_firewall_port, persist_firewall_rules,
    run_cmd as _run,
)

API_DIR = "/etc/atken/api"
BOT_DIR = "/etc/atken/bots"
API_SCRIPT_PATH = os.path.join(API_DIR, "server.py")
API_CREDS_PATH = os.path.join(API_DIR, "credentials.json")
API_SERVICE_PATH = "/etc/systemd/system/vps-api.service"

TELEGRAM_SCRIPT_PATH = os.path.join(BOT_DIR, "telegram_bot.py")
TELEGRAM_SERVICE_PATH = "/etc/systemd/system/vps-telegram-bot.service"

WHATSAPP_SCRIPT_PATH = os.path.join(BOT_DIR, "whatsapp_webhook.py")
WHATSAPP_SERVICE_PATH = "/etc/systemd/system/vps-whatsapp-webhook.service"

SSH_REGISTRY_PATH = "/etc/ssh_users/registry.json"

API_SCRIPT = '''#!/usr/bin/env python3
"""Panel REST API. Reads its port/credentials path from the environment.
Bearer token is verified against a salted hash, never stored/compared as
plaintext."""
import os
import json
import hmac
import hashlib
import subprocess
from flask import Flask, jsonify, request

app = Flask(__name__)
CREDS_PATH = os.environ.get("PANEL_API_CREDS", "/etc/atken/api/credentials.json")
SSH_REGISTRY_PATH = "/etc/ssh_users/registry.json"


def _hash(value, salt):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 100000).hex()


def verify_token():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return False
    submitted = auth[len('Bearer '):]
    try:
        with open(CREDS_PATH) as f:
            creds = json.load(f)
    except Exception:
        return False
    computed = _hash(submitted, creds["salt"])
    return hmac.compare_digest(computed, creds["hash"])


@app.route('/api/status', methods=['GET'])
def status():
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"status": "online", "service": "VPS Panel API"})


@app.route('/api/users', methods=['GET'])
def users():
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        with open(SSH_REGISTRY_PATH) as f:
            registry = json.load(f)
    except Exception:
        registry = {}
    result = {u: {"expiry": r.get("expiry"), "locked": r.get("locked", False)} for u, r in registry.items()}
    return jsonify(result)


@app.route('/api/online', methods=['GET'])
def online():
    if not verify_token():
        return jsonify({"error": "Unauthorized"}), 401
    res = subprocess.run(["who"], capture_output=True, text=True)
    sessions = []
    for line in res.stdout.splitlines():
        parts = line.split(None, 3)
        if parts:
            sessions.append(parts[0])
    return jsonify({"online_sessions": sessions})


if __name__ == '__main__':
    port = int(os.environ.get("PANEL_API_PORT", "5000"))
    app.run(host='0.0.0.0', port=port)
'''

TELEGRAM_SCRIPT = '''#!/usr/bin/env python3
"""Panel Telegram bot - read-only status commands. Reads its token/admin ID
from the environment, never baked into this file's own source."""
import os
import json
import subprocess
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
ADMIN_ID = os.environ.get("TELEGRAM_ADMIN_ID", "")
SSH_REGISTRY_PATH = "/etc/ssh_users/registry.json"


def _is_admin(update):
    return str(update.effective_user.id) == ADMIN_ID


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        await update.message.reply_text("Unauthorized access.")
        return
    await update.message.reply_text("VPS Bot is active. Commands: /status /users /online")


async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        return
    load = os.getloadavg()
    await update.message.reply_text("System Load: %.2f, %.2f, %.2f" % load)


async def users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        return
    try:
        with open(SSH_REGISTRY_PATH) as f:
            registry = json.load(f)
    except Exception:
        registry = {}
    if not registry:
        await update.message.reply_text("No registered SSH users.")
        return
    lines = []
    for uname, rec in registry.items():
        lock_tag = " [LOCKED]" if rec.get("locked") else ""
        lines.append("%s - expires %s%s" % (uname, rec.get("expiry", "?"), lock_tag))
    await update.message.reply_text("\\n".join(lines))


async def online(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not _is_admin(update):
        return
    res = subprocess.run(["who"], capture_output=True, text=True)
    if not res.stdout.strip():
        await update.message.reply_text("No active sessions.")
        return
    await update.message.reply_text(res.stdout.strip())


def main():
    if not TOKEN:
        raise SystemExit("TELEGRAM_BOT_TOKEN not set")
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("users", users))
    app.add_handler(CommandHandler("online", online))
    app.run_polling()


if __name__ == '__main__':
    main()
'''

WHATSAPP_SCRIPT = '''#!/usr/bin/env python3
"""WhatsApp Business Cloud API webhook RECEIVER only - not a sender/session
bot. Requires the admin's own Meta-approved WhatsApp Business app. Implements
the real Meta verify-token GET handshake and HMAC-SHA256 payload signature
validation on incoming POST webhooks - received events are logged, not acted
on, since what to do with them is specific to each admin's own use case."""
import os
import hmac
import hashlib
import json
from flask import Flask, request, abort

app = Flask(__name__)
VERIFY_TOKEN = os.environ.get("WHATSAPP_VERIFY_TOKEN", "")
APP_SECRET = os.environ.get("WHATSAPP_APP_SECRET", "")
LOG_PATH = "/etc/atken/bots/whatsapp_events.log"


@app.route('/webhook', methods=['GET'])
def verify():
    mode = request.args.get('hub.mode')
    token = request.args.get('hub.verify_token')
    challenge = request.args.get('hub.challenge')
    if mode == 'subscribe' and token == VERIFY_TOKEN:
        return challenge, 200
    abort(403)


@app.route('/webhook', methods=['POST'])
def receive():
    signature = request.headers.get('X-Hub-Signature-256', '')
    if not signature.startswith('sha256='):
        abort(401)
    expected = 'sha256=' + hmac.new(APP_SECRET.encode(), request.data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        abort(401)

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(request.get_json(silent=True) or {}) + "\\n")
    return "", 200


if __name__ == '__main__':
    port = int(os.environ.get("WHATSAPP_WEBHOOK_PORT", "5001"))
    app.run(host='0.0.0.0', port=port)
'''


def _hash_value(value, salt):
    return hashlib.pbkdf2_hmac("sha256", value.encode(), salt.encode(), 100000).hex()


def _deploy_script(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    needs_write = True
    if os.path.exists(path):
        with open(path) as f:
            needs_write = f.read() != content
    if needs_write:
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o700)
        check = _run(["python3", "-m", "py_compile", path])
        if check.returncode != 0:
            print("%s[X] %s failed its own syntax check:\n%s%s" % (C_RED, os.path.basename(path), check.stderr.strip(), C_RESET))
            os.remove(path)
            return False
    return True


def _pip_module_available(module_name):
    return _run(["python3", "-c", "import %s" % module_name]).returncode == 0


def _wait_for_port_listening(port, tries=6, delay=1):
    for _ in range(tries):
        if check_system_port_in_use(port, ("tcp",)):
            return True
        time.sleep(delay)
    return False


def _write_service(service_path, description, env_vars, script_path):
    env_lines = "\n".join("Environment=%s=%s" % (k, v) for k, v in env_vars.items())
    content = """[Unit]
Description=%s
After=network.target

[Service]
Type=simple
User=root
%s
ExecStart=/usr/bin/python3 %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""" % (description, env_lines, script_path)
    with open(service_path, "w") as f:
        f.write(content)
    _run("systemctl daemon-reload")


def api_and_bots_manager():
    """API & Bots Administrator Module."""
    os.makedirs(API_DIR, exist_ok=True)
    os.makedirs(BOT_DIR, exist_ok=True)

    while True:
        clear_screen()
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print("%s                  API & BOTS ADMINISTRATOR                  %s" % (C_BOLD, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" %s[1]>%s API INSTALLER" % (C_YELLOW, C_RESET))
        print(" %s[2]>%s TELEGRAM BOT INSTALLER" % (C_YELLOW, C_RESET))
        print(" %s[3]>%s WHATSAPP WEBHOOK RECEIVER" % (C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
        print(" %s[0]%s Back" % (C_YELLOW, C_RESET))
        print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))

        choice = input(" Enter an Option: ").strip()

        if choice == '0':
            break

        elif choice == '1':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s                     API INSTALLER WIZARD                   %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            api_port = prompt_port(" Enter desired port for REST API service (e.g., 5000): ", default=5000)
            if check_system_port_in_use(api_port, ("tcp",)):
                print("%s[X] Port %d is already in use by another service.%s" % (C_RED, api_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            api_token = input(" Enter secure API bearer token (blank to auto-generate): ").strip()
            if not api_token:
                api_token = secrets.token_urlsafe(24)
                print("%s[i] Generated token: %s%s" % (C_CYAN, api_token, C_RESET))

            print("\n[i] Installing dependencies (Flask)...")
            _run("apt-get update && apt-get install -y python3-pip")
            _run("pip3 install --break-system-packages flask")
            if not _pip_module_available("flask"):
                print("%s[X] Flask failed to install - check network access / pip output.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            salt = secrets.token_hex(16)
            with open(API_CREDS_PATH, "w") as f:
                json.dump({"salt": salt, "hash": _hash_value(api_token, salt)}, f)
            os.chmod(API_CREDS_PATH, 0o600)

            if not _deploy_script(API_SCRIPT_PATH, API_SCRIPT):
                input("\nPress Enter to continue...")
                continue

            _write_service(API_SERVICE_PATH, "VPS Management REST API",
                            {"PANEL_API_PORT": api_port, "PANEL_API_CREDS": API_CREDS_PATH}, API_SCRIPT_PATH)

            open_firewall_port(api_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable vps-api")
            restart_ok = _run("systemctl restart vps-api").returncode == 0

            if restart_ok and _wait_for_port_listening(api_port):
                print("%s[OK] REST API installed and verified on port %d.%s" % (C_GREEN, api_port, C_RESET))
                print("     Endpoints: /api/status /api/users /api/online (all require the Bearer token)")
            else:
                close_firewall_port(api_port, ("tcp",))
                print("%s[X] Service failed to come up - check 'journalctl -u vps-api'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s               TELEGRAM BOT INSTALLER WIZARD                %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            bot_token = input(" Enter Telegram Bot Token (from @BotFather): ").strip()
            admin_id = input(" Enter your Telegram Admin numeric User ID: ").strip()

            if not (bot_token and admin_id):
                print("%s[X] Bot token and admin ID cannot be empty.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            print("\n[i] Installing python-telegram-bot (pinned to a known-compatible")
            print("    major version range, since this library has broken API")
            print("    compatibility at major version boundaries before)...")
            _run("pip3 install --break-system-packages 'python-telegram-bot>=20,<23'")
            if not _pip_module_available("telegram"):
                print("%s[X] python-telegram-bot failed to install - check network access.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            if not _deploy_script(TELEGRAM_SCRIPT_PATH, TELEGRAM_SCRIPT):
                input("\nPress Enter to continue...")
                continue

            _write_service(TELEGRAM_SERVICE_PATH, "VPS Management Telegram Bot",
                            {"TELEGRAM_BOT_TOKEN": bot_token, "TELEGRAM_ADMIN_ID": admin_id}, TELEGRAM_SCRIPT_PATH)
            os.chmod(TELEGRAM_SERVICE_PATH, 0o600)

            _run("systemctl enable vps-telegram-bot")
            restart_ok = _run("systemctl restart vps-telegram-bot").returncode == 0
            time.sleep(2)
            active = _run(["systemctl", "is-active", "--quiet", "vps-telegram-bot"]).returncode == 0

            if restart_ok and active:
                print("%s[OK] Telegram bot installed and running.%s" % (C_GREEN, C_RESET))
                print("     Commands: /start /status /users /online")
            else:
                print("%s[X] Bot failed to start - check 'journalctl -u vps-telegram-bot' (often" % C_RED)
                print("    an invalid token).%s" % C_RESET)
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s            WHATSAPP WEBHOOK RECEIVER (Meta Cloud API)      %s" % (C_BOLD, C_RESET))
            print("%s════════════════════════════════════════════════════════════════%s" % (C_CYAN, C_RESET))
            print("%s[i] This is a webhook RECEIVER for an already-approved Meta WhatsApp" % C_CYAN)
            print("    Business Cloud API app - not a standalone automation bot. You need")
            print("    your own Meta app's verify token and app secret from the Meta")
            print("    developer dashboard for this to do anything.%s\n" % C_RESET)

            webhook_port = prompt_port(" Enter desired webhook listen port (e.g., 5001): ", default=5001)
            if check_system_port_in_use(webhook_port, ("tcp",)):
                print("%s[X] Port %d is already in use by another service.%s" % (C_RED, webhook_port, C_RESET))
                input("\nPress Enter to continue...")
                continue

            verify_token = input(" Enter your Meta webhook Verify Token: ").strip()
            app_secret = input(" Enter your Meta App Secret (for signature validation): ").strip()
            if not (verify_token and app_secret):
                print("%s[X] Both values are required for Meta's verification handshake and" % C_RED)
                print("    signature validation to actually work.%s" % C_RESET)
                input("\nPress Enter to continue...")
                continue

            _run("pip3 install --break-system-packages flask")
            if not _pip_module_available("flask"):
                print("%s[X] Flask failed to install.%s" % (C_RED, C_RESET))
                input("\nPress Enter to continue...")
                continue

            if not _deploy_script(WHATSAPP_SCRIPT_PATH, WHATSAPP_SCRIPT):
                input("\nPress Enter to continue...")
                continue

            _write_service(WHATSAPP_SERVICE_PATH, "WhatsApp Webhook Receiver",
                            {"WHATSAPP_WEBHOOK_PORT": webhook_port, "WHATSAPP_VERIFY_TOKEN": verify_token,
                             "WHATSAPP_APP_SECRET": app_secret}, WHATSAPP_SCRIPT_PATH)
            os.chmod(WHATSAPP_SERVICE_PATH, 0o600)

            open_firewall_port(webhook_port, ("tcp",))
            persist_firewall_rules()
            _run("systemctl enable vps-whatsapp-webhook")
            restart_ok = _run("systemctl restart vps-whatsapp-webhook").returncode == 0

            if restart_ok and _wait_for_port_listening(webhook_port):
                print("%s[OK] Webhook receiver running on port %d.%s" % (C_GREEN, webhook_port, C_RESET))
                print("     Point your Meta app's webhook URL at: http://<server-ip>:%d/webhook" % webhook_port)
                print("     Incoming events are logged to /etc/atken/bots/whatsapp_events.log -")
                print("     acting on them is specific to your own use case, not built in here.")
            else:
                close_firewall_port(webhook_port, ("tcp",))
                print("%s[X] Service failed to come up - check 'journalctl -u vps-whatsapp-webhook'.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")

        else:
            print("%sInvalid option.%s" % (C_RED, C_RESET))
            input("\nPress Enter to continue...")
