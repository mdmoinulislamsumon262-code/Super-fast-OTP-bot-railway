import sqlite3
import threading
import time
import re
import os
import asyncio
import base64
import json
import html as _html
import io
import tempfile
import logging
import hashlib
import math
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlsplit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests
import temp_mail_engine
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import date, datetime
import telebot
from telebot.types import (
    InlineKeyboardMarkup, InlineKeyboardButton,
    ReplyKeyboardMarkup, KeyboardButton,
)
try:
    from telebot.types import CopyTextButton
except ImportError:
    CopyTextButton = None


_TelegramInlineKeyboardButton = InlineKeyboardButton
_TelegramKeyboardButton = KeyboardButton


def _button_style(text: str) -> str:
    label = str(text or "").lower()
    style_map = str.maketrans(
        "𝚊𝚋𝚌𝚍𝚎𝚏𝚐𝚑𝚒𝚓𝚔𝚕𝚖𝚗𝚘𝚙𝚚𝚛𝚜𝚝𝚞𝚟𝚠𝚡𝚢𝚣𝙰𝙱𝙲𝙳𝙴𝙵𝙶𝙷𝙸𝙹𝙺𝙻𝙼𝙽𝙾𝙿𝚀𝚁𝚂𝚃𝚄𝚅𝚆𝚇𝚈𝚉",
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    )
    label = label.translate(style_map)

    success_words = (
        "submit", "confirm", "save", "add", "approve", "yes", "enable",
        "unban", "get number", "backup file", "set", "import", "input",
        "buy", "purchase", "claim", "retry", "try again", "send",
        "force join: on",
    )
    danger_words = (
        "back", "cancel", "close", "delete", "reject", "no", "remove",
        "clear", "disable", "ban", "reset", "del", "stock out",
        "force join: off",
    )

    if any(re.search(rf"\b{re.escape(word)}\b", label) for word in success_words):
        return "success"
    if any(re.search(rf"\b{re.escape(word)}\b", label) for word in danger_words):
        return "danger"
    if any(symbol in label for symbol in ("✔️", "➕")):
        return "success"
    if any(symbol in label for symbol in ("🧹", "⛔", "🛑", "↩")):
        return "danger"
    return "primary"


def _with_button_style(button, style: str):
    try:
        button.style = style
    except Exception:
        pass
    return button


def _number_values(number=None, numbers=None):
    values = list(numbers or ([] if number is None else [number]))
    return [str(value).strip().lstrip("+") for value in values if str(value).strip()]


def _number_from_api_data(num_data):
    return (
        num_data.get("no_plus_number")
        or normalize_number(num_data.get("full_number", ""))
        or num_data.get("national_number")
        or ""
    )


def fetch_api_numbers(rid: str, count: int = 1):
    numbers = []
    for _ in range(count):
        num_data = fetch_api_number(rid)
        if not num_data:
            return []
        full_number = _number_from_api_data(num_data)
        if not full_number or full_number in numbers:
            return []
        numbers.append(full_number)
    return numbers


def InlineKeyboardButton(*args, **kwargs):
    text = args[0] if args else kwargs.get("text", "")
    style = kwargs.pop("style", None) or _button_style(text)
    try:
        return _TelegramInlineKeyboardButton(*args, style=style, **kwargs)
    except TypeError:
        return _with_button_style(_TelegramInlineKeyboardButton(*args, **kwargs), style)


def KeyboardButton(*args, **kwargs):
    text = args[0] if args else kwargs.get("text", "")
    style = kwargs.pop("style", None) or _button_style(text)
    try:
        return _TelegramKeyboardButton(*args, style=style, **kwargs)
    except TypeError:
        return _with_button_style(_TelegramKeyboardButton(*args, **kwargs), style)


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─── CREDENTIALS ───────────────────────────────────────────────────────────────

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID_RAW = os.getenv("ADMIN_ID", "").strip()
if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN is required. Add it to the service environment.")
if not ADMIN_ID_RAW or not ADMIN_ID_RAW.isdigit():
    raise SystemExit("ADMIN_ID must be a numeric Telegram user ID. Add it to the service environment.")
ADMIN_ID = int(ADMIN_ID_RAW)

# API keys, temporary-mail credentials, and provider tokens are encrypted at
# rest. Set BOT_DATA_ENCRYPTION_KEY to a stable deployment secret; BOT_TOKEN
# is the compatibility fallback for installations that have not set one yet.
_DATA_ENCRYPTION_SECRET = (
    os.getenv("BOT_DATA_ENCRYPTION_KEY", "").strip()
    or os.getenv("IMAP_DATA_ENCRYPTION_KEY", "").strip()
    or BOT_TOKEN
)
_DATA_ENCRYPTION_KEY = hashlib.scrypt(
    _DATA_ENCRYPTION_SECRET.encode("utf-8"),
    salt=b"otp-telegram-bot-data-v1",
    n=2**14,
    r=8,
    p=1,
    dklen=32,
    maxmem=64 * 1024 * 1024,
)
_DATA_CIPHER = AESGCM(_DATA_ENCRYPTION_KEY)
_ENCRYPTED_VALUE_PREFIX = "enc:v1:"
_DATA_CIPHER_AAD = b"otp-telegram-bot-data-v1"


def _encrypt_data_secret(value: str) -> str:
    value = str(value or "")
    if not value or value.startswith(_ENCRYPTED_VALUE_PREFIX):
        return value
    nonce = secrets.token_bytes(12)
    ciphertext = _DATA_CIPHER.encrypt(nonce, value.encode("utf-8"), _DATA_CIPHER_AAD)
    encoded = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
    return _ENCRYPTED_VALUE_PREFIX + encoded


def _decrypt_data_secret(value: str) -> str:
    value = str(value or "")
    if not value.startswith(_ENCRYPTED_VALUE_PREFIX):
        return value
    try:
        payload = base64.urlsafe_b64decode(value[len(_ENCRYPTED_VALUE_PREFIX):])
        nonce, ciphertext = payload[:12], payload[12:]
        return _DATA_CIPHER.decrypt(nonce, ciphertext, _DATA_CIPHER_AAD).decode("utf-8")
    except Exception as exc:
        raise RuntimeError(
            "Stored encrypted data could not be decrypted. Restore the original "
            "BOT_DATA_ENCRYPTION_KEY (or legacy key source) before starting the bot."
        ) from exc


def _transform_temp_mail_state_secrets(state: dict, transform) -> dict:
    result = dict(state)
    for key in ("password", "token"):
        if result.get(key):
            result[key] = transform(result[key])
    imap = result.get("imap")
    if isinstance(imap, dict):
        imap = dict(imap)
        if imap.get("imap_pass"):
            imap["imap_pass"] = transform(imap["imap_pass"])
        result["imap"] = imap
    return result


# Railway exposes the mounted volume path automatically. DATA_DIR can
# override it; the local fallback is useful for development and Docker.
DATA_DIR = (
    os.getenv("DATA_DIR", "").strip()
    or os.getenv("RAILWAY_VOLUME_MOUNT_PATH", "").strip()
    or os.path.join(os.getcwd(), "data")
)
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "Developer By SUMON VAI.db")
LEGACY_DB_PATH = os.path.join(DATA_DIR, "voltx.db")

# Keep existing installations' data when switching the database filename.
# SQLite's backup API includes committed data that may still be in the WAL.
if not os.path.exists(DB_PATH) and os.path.isfile(LEGACY_DB_PATH):
    legacy_conn = sqlite3.connect(LEGACY_DB_PATH, timeout=30)
    new_conn = None
    try:
        new_conn = sqlite3.connect(DB_PATH, timeout=30)
        legacy_conn.backup(new_conn)
        new_conn.commit()
    except Exception:
        if new_conn is not None:
            new_conn.close()
        legacy_conn.close()
        try:
            os.remove(DB_PATH)
        except OSError:
            pass
        raise
    else:
        new_conn.close()
        legacy_conn.close()
        logger.info(
            "Copied existing SQLite data from %s to %s",
            LEGACY_DB_PATH,
            DB_PATH,
        )

# ─── TEMP MAIL ────────────────────────────────────────────────────────────────
TEMP_MAIL_DOMAINS_API = "https://api.mail.gw/domains"
TEMP_MAIL_ACCOUNTS_API = "https://api.mail.gw/accounts"
TEMP_MAIL_TOKEN_API = "https://api.mail.gw/token"
TEMP_MAIL_MESSAGES_API = "https://api.mail.gw/messages"
TEMP_MAIL_MESSAGE_DETAILS_API = "https://api.mail.gw/messages/{message_id}"
TEMP_MAIL_DATA_PATH = os.path.join(DATA_DIR, "temp_mail_users.json")
# Hard maximum lifetime of a temporary mailbox: 1 hour.
TEMP_MAIL_TTL_SECONDS = 60 * 60
TEMP_MAIL_CHECK_INTERVAL_SECONDS = 10
TEMP_MAIL_FAST_POLL_SECONDS = 5
TEMP_MAIL_FAST_POLL_WINDOW = 180
# Bound task creation and simultaneous provider requests under heavy use.
TEMP_MAIL_MAX_CONCURRENT_CHECKS = 5
TEMP_MAIL_CHECK_BATCH_SIZE = 10
# Nothing active -> the checker idles instead of hammering the providers.
TEMP_MAIL_IDLE_SLEEP_SECONDS = 15
# Keep per-mailbox "already delivered" memory bounded.
TEMP_MAIL_MAX_SEEN_IDS = 60
# Safe backoff so a broken provider cannot burn CPU/RAM.
TEMP_MAIL_MAX_FETCH_ERRORS = 5
TEMP_MAIL_ERROR_COOLDOWN_SECONDS = 120
TEMP_MAIL_MAX_ERROR_ENTRIES = 500
# Keep persisted mailbox state and per-cycle response processing bounded.
TEMP_MAIL_MAX_ACTIVE_USERS = 500

# ─── EXTERNAL API (YesMS) ─────────────────────────────────────────────────────
YESMS_BASE = os.getenv("YESMS_BASE_URL", "https://yesms.online/api").rstrip("/")

# ─── PANEL BASE URLS ──────────────────────────────────────────────────────────
STEXSMS_BASE   = os.getenv("STEXSMS_BASE_URL", "https://api.2oo9.cloud/MXS47FLFX0U/tness/@public/api").rstrip("/")
FASTXOTPS_BASE = os.getenv("FASTXOTPS_BASE_URL", "https://2eee7.com/@Access/@Bot/2eee7/@public").rstrip("/")
VOLTXSMS_BASE  = os.getenv("VOLTXSMS_BASE_URL", "https://api.2oo9.cloud/MXS47FLFX0U/tnevs/@public/api").rstrip("/")
ZEBRASMS_BASE  = os.getenv("ZEBRASMS_BASE_URL", "https://api.zebrasms.com/api/v1").rstrip("/")

# ─── API CREDENTIALS (URLs only; keys managed entirely via admin panel) ────────
SMSHADI_URL = os.getenv("SMSHADI_URL", "").strip()
LAMIX_URL   = os.getenv("LAMIX_URL", "").strip()

# ─── API NAME DEFINITIONS ──────────────────────────────────────────────────────
API_DEFINITIONS = {
    "smshadi":   {"name": "SMShadi",    "url": SMSHADI_URL,    "default_key": ""},
    "lamix":     {"name": "Lamix",      "url": LAMIX_URL,      "default_key": ""},
    "yesms":     {"name": "YesMS API",  "url": YESMS_BASE,     "default_key": ""},
    "stexsms":   {"name": "StexSMS",    "url": STEXSMS_BASE,   "default_key": ""},
    "fastxotps": {"name": "FastXOTPs",  "url": FASTXOTPS_BASE, "default_key": ""},
    "voltxsms":  {"name": "VoltXSMS",   "url": VOLTXSMS_BASE,  "default_key": ""},
    "zebrasms":  {"name": "ZebraSMS",   "url": ZEBRASMS_BASE,  "default_key": ""},
}

# ─── PANEL ROTATION GLOBALS ────────────────────────────────────────────────────
_panel_alloc_idx       = 0
_panel_alloc_lock      = threading.Lock()
_traffic_panel_idx     = 0
_traffic_panel_last_sw = 0.0
_traffic_panel_lock    = threading.Lock()

# ─── SERVICE ABBREVIATION MAP ─────────────────────────────────────────────────
SERVICE_SHORT_MAP = {
    "facebook": "fb", "instagram": "ig", "whatsapp": "wa", "telegram": "tg",
    "twitter": "tw", "google": "gg", "gmail": "gm", "microsoft": "ms",
    "amazon": "amz", "netflix": "nf", "snapchat": "sc", "tiktok": "tt",
    "uber": "ub", "lyft": "lf", "paypal": "pp", "discord": "dc",
    "linkedin": "li", "reddit": "rd", "pinterest": "pt", "youtube": "yt",
    "apple": "ap", "yahoo": "yh", "ebay": "eb", "airbnb": "ab",
    "wechat": "wc", "viber": "vb", "line": "ln", "signal": "sg",
}


def get_service_short(sid: str) -> str:
    """Return short 2-letter abbreviation for a service name."""
    low = sid.lower()
    for key, short in SERVICE_SHORT_MAP.items():
        if key in low:
            return short
    return sid[:2].lower() if sid else "??"

def stylish(text: str) -> str:
    """Convert ASCII letters and digits to mathematical monospace typewriter font."""
    result = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            result.append(chr(0x1D670 + ord(ch) - ord('A')))
        elif 'a' <= ch <= 'z':
            result.append(chr(0x1D68A + ord(ch) - ord('a')))
        elif '0' <= ch <= '9':
            result.append(chr(0x1D7F6 + ord(ch) - ord('0')))
        else:
            result.append(ch)
    return ''.join(result)


def _bot_name() -> str:
    saved = get_setting("bot_name", "")
    if saved:
        return saved
    try:
        me = bot.get_me()
        return me.username or me.first_name or "BOT"
    except Exception:
        return "BOT"

def _powered_by() -> str:
    return get_setting("powered_by", "SUMON VAI")

def _join_prompt_text() -> str:
    bn = stylish(_bot_name())
    pw = stylish(_powered_by())
    sep = "━" * 32
    return (
        f"❗️ {sep}\n"
        f"🔐 {stylish('JOIN REQUIRED')}\n"
        f"{sep}\n\n"
        f"🦾 {bn} ব্যবহার করতে হলে\n"
        f"নিচের চ্যানেল/গ্রুপে জয়েন করুন!\n\n"
        f"👇 Join করে <b>{stylish('CHECK JOIN')}</b> বাটনে চাপুন\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔷 {stylish('Developer_By')} <b>{pw}</b>"
    )


bot = telebot.TeleBot(BOT_TOKEN, parse_mode="HTML", threaded=True, num_threads=2)

# Populated after the Shop integration module is loaded near the end of this
# file.  Keeping these as optional hooks lets Main remain the primary router.
shop_handle_text = None
shop_handle_media = None
shop_cleanup_runtime_state = None


# ─── IN-MEMORY STATE ───────────────────────────────────────────────────────────
class ExpiringStateDict(dict):
    """Activity-based cache for conversational state, never business data."""

    def __init__(self, ttl_seconds=60 * 60):
        super().__init__()
        self.ttl_seconds = int(ttl_seconds)
        self._touched = {}
        self._state_lock = threading.RLock()
        self._last_prune = 0.0

    def _expire_key_locked(self, key, now):
        touched = self._touched.get(key)
        if touched is not None and now - touched >= self.ttl_seconds:
            dict.pop(self, key, None)
            self._touched.pop(key, None)
            return True
        return False

    def __getitem__(self, key):
        now = time.time()
        with self._state_lock:
            self._expire_key_locked(key, now)
            value = dict.__getitem__(self, key)
            self._touched[key] = now
            return value

    def __setitem__(self, key, value):
        with self._state_lock:
            dict.__setitem__(self, key, value)
            self._touched[key] = time.time()

    def __contains__(self, key):
        now = time.time()
        with self._state_lock:
            if self._expire_key_locked(key, now):
                return False
            exists = dict.__contains__(self, key)
            if exists:
                self._touched[key] = now
            return exists

    def get(self, key, default=None):
        now = time.time()
        with self._state_lock:
            if self._expire_key_locked(key, now):
                return default
            if not dict.__contains__(self, key):
                return default
            self._touched[key] = now
            return dict.__getitem__(self, key)

    def pop(self, key, default=...):
        with self._state_lock:
            self._touched.pop(key, None)
            if default is ...:
                return dict.pop(self, key)
            return dict.pop(self, key, default)

    def setdefault(self, key, default=None):
        now = time.time()
        with self._state_lock:
            self._expire_key_locked(key, now)
            if dict.__contains__(self, key):
                self._touched[key] = now
                return dict.__getitem__(self, key)
            dict.__setitem__(self, key, default)
            self._touched[key] = now
            return default

    def update(self, *args, **kwargs):
        values = dict(*args, **kwargs)
        now = time.time()
        with self._state_lock:
            for key, value in values.items():
                dict.__setitem__(self, key, value)
                self._touched[key] = now

    def clear(self):
        with self._state_lock:
            dict.clear(self)
            self._touched.clear()

    def prune_if_due(self, interval_seconds=300):
        now = time.time()
        with self._state_lock:
            if now - self._last_prune < interval_seconds:
                return 0
            self._last_prune = now
            expired = [
                key for key, touched in self._touched.items()
                if now - touched >= self.ttl_seconds
            ]
            for key in expired:
                dict.pop(self, key, None)
                self._touched.pop(key, None)
            return len(expired)


admin_states: dict = ExpiringStateDict(ttl_seconds=60 * 60)
user_states: dict = ExpiringStateDict(ttl_seconds=60 * 60)
admin_live_mode: set = set()   # admins who see live number notifications (/start)
admin_user_mode: set = set()   # admins currently acting as plain user (/user)
admin_live_msg_ids: dict = {}  # number -> {admin_id: msg_id}  (live panel tracking)


# ─── TEMP MAIL STATE ──────────────────────────────────────────────────────────
temp_mail_users: dict = {}
temp_mail_lock = threading.RLock()
_temp_mail_loop = None
_temp_mail_loop_thread = None
_temp_mail_loop_ready = threading.Event()
_temp_mail_loop_lock = threading.Lock()
_temp_mail_user_locks = {}
_temp_mail_errors = {}
_temp_mail_pending_creations = set()


class TempMailCapacityError(RuntimeError):
    pass


def _load_temp_mail_users():
    global temp_mail_users
    try:
        with open(TEMP_MAIL_DATA_PATH, "r", encoding="utf-8") as state_file:
            loaded = json.load(state_file)
        if isinstance(loaded, dict):
            migrated = False
            restored = {}
            for user_id, state in loaded.items():
                if not isinstance(state, dict):
                    restored[user_id] = state
                    continue
                secret_values = [state.get("password"), state.get("token")]
                imap = state.get("imap")
                if isinstance(imap, dict):
                    secret_values.append(imap.get("imap_pass"))
                migrated = migrated or any(
                    value and not str(value).startswith(_ENCRYPTED_VALUE_PREFIX)
                    for value in secret_values
                )
                restored[user_id] = _transform_temp_mail_state_secrets(
                    state, _decrypt_data_secret
                )
            temp_mail_users = restored
            now = time.time()
            active = [
                (user_id, state)
                for user_id, state in temp_mail_users.items()
                if _temp_mail_is_active(state, now)
            ]
            active.sort(
                key=lambda item: _temp_mail_created_at(item[1]),
                reverse=True,
            )
            excess = max(0, len(active) - TEMP_MAIL_MAX_ACTIVE_USERS)
            temp_mail_users = dict(active[:TEMP_MAIL_MAX_ACTIVE_USERS])
            if migrated or excess or len(temp_mail_users) != len(loaded):
                with temp_mail_lock:
                    _save_temp_mail_users_locked()
            if excess:
                logger.warning(
                    "Expired %s excess temporary inbox state entries to enforce the active-mailbox limit",
                    excess,
                )
    except FileNotFoundError:
        temp_mail_users = {}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not load Temp Mail state: %s", exc)
        temp_mail_users = {}


def _save_temp_mail_users_locked():
    temporary_path = f"{TEMP_MAIL_DATA_PATH}.tmp"
    try:
        fd = os.open(
            temporary_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        with os.fdopen(fd, "w", encoding="utf-8") as state_file:
            protected = {
                user_id: _transform_temp_mail_state_secrets(
                    state, _encrypt_data_secret
                ) if isinstance(state, dict) else state
                for user_id, state in temp_mail_users.items()
            }
            json.dump(protected, state_file, ensure_ascii=False, separators=(",", ":"))
        os.replace(temporary_path, TEMP_MAIL_DATA_PATH)
        try:
            os.chmod(TEMP_MAIL_DATA_PATH, 0o600)
        except OSError:
            pass
    except OSError as exc:
        logger.warning("Could not save Temp Mail state: %s", exc)
        try:
            if os.path.exists(temporary_path):
                os.remove(temporary_path)
        except OSError:
            pass


def _temp_mail_created_at(state) -> float:
    if not isinstance(state, dict):
        return 0.0
    try:
        return float(state.get("created_at") or 0)
    except (TypeError, ValueError):
        return 0.0


def _temp_mail_expiry(state) -> float:
    """Expiry of a mailbox, always clamped to the 1 hour maximum lifetime."""
    created = _temp_mail_created_at(state)
    if created <= 0:
        return 0.0
    return created + TEMP_MAIL_TTL_SECONDS


def _temp_mail_is_active(state, now=None) -> bool:
    """A mailbox is usable only while it exists AND is inside its lifetime."""
    if not isinstance(state, dict) or not state.get("email"):
        return False
    now = time.time() if now is None else now
    return now < _temp_mail_expiry(state)


def _temp_mail_same_mailbox(current, expected) -> bool:
    """True only for the exact mailbox a check started with (not a replacement)."""
    if not isinstance(current, dict) or not isinstance(expected, dict):
        return False
    if current.get("email") != expected.get("email"):
        return False
    return str(current.get("mail_uid") or "") == str(expected.get("mail_uid") or "")


def _temp_mail_forget_locked(user_key) -> None:
    """Drop a mailbox plus every piece of state that belongs to it."""
    user_key = str(user_key)
    temp_mail_users.pop(user_key, None)
    _temp_mail_errors.pop(user_key, None)
    try:
        _temp_mail_user_locks.pop(int(user_key), None)
    except (TypeError, ValueError):
        pass


def _temp_mail_note_error(user_key, exc) -> None:
    """Count consecutive fetch failures and cool the mailbox down."""
    user_key = str(user_key)
    with temp_mail_lock:
        if len(_temp_mail_errors) > TEMP_MAIL_MAX_ERROR_ENTRIES:
            _temp_mail_errors.clear()
        entry = _temp_mail_errors.setdefault(user_key, {"count": 0, "until": 0.0})
        entry["count"] = int(entry.get("count") or 0) + 1
        if entry["count"] >= TEMP_MAIL_MAX_FETCH_ERRORS:
            entry["count"] = 0
            entry["until"] = time.time() + TEMP_MAIL_ERROR_COOLDOWN_SECONDS
            logger.warning(
                "Temp Mail cooling down user=%s for %ss after repeated failures",
                user_key, TEMP_MAIL_ERROR_COOLDOWN_SECONDS,
            )
    logger.warning(
        "Temp Mail inbox fetch failed (user=%s, error=%s)",
        user_key,
        type(exc).__name__,
    )


def _temp_mail_clear_error(user_key) -> None:
    with temp_mail_lock:
        _temp_mail_errors.pop(str(user_key), None)


def _cleanup_expired_temp_mail_users():
    """Remove expired mailboxes and any leftover locks / error counters."""
    now = time.time()
    changed = False
    with temp_mail_lock:
        for user_id, state in list(temp_mail_users.items()):
            if not _temp_mail_is_active(state, now):
                _temp_mail_forget_locked(user_id)
                changed = True
        live_ids = set()
        for key in temp_mail_users:
            try:
                live_ids.add(int(key))
            except (TypeError, ValueError):
                continue
        for user_id in [uid for uid in _temp_mail_user_locks if uid not in live_ids]:
            _temp_mail_user_locks.pop(user_id, None)
        for key in [k for k in _temp_mail_errors if k not in temp_mail_users]:
            _temp_mail_errors.pop(key, None)
        if changed:
            _save_temp_mail_users_locked()


def _get_temp_mail_user(user_id: int):
    _cleanup_expired_temp_mail_users()
    with temp_mail_lock:
        state = temp_mail_users.get(str(user_id))
        return dict(state) if isinstance(state, dict) else None


def _temp_mail_extract_members(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("hydra:member", "messages", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def _temp_mail_sender_email(sender):
    if isinstance(sender, dict):
        return str(sender.get("address") or sender.get("email") or "").strip()
    return str(sender or "").strip()


def _temp_mail_clean_body(message_text: str) -> str:
    try:
        return temp_mail_engine.html_to_text(message_text)
    except Exception:
        return str(message_text or "")


def _temp_mail_extract_otp(subject: str, message_text: str) -> str:
    """Pull the verification code out of a mail (digits or alphanumeric)."""
    body = _temp_mail_clean_body(message_text)
    searchable_text = "\n".join(
        part for part in (str(subject or ""), body) if part
    )
    patterns = (
        r"(?i)\b(?:otp|one[-\s]?time\s+(?:password|code|pin)|verification|verify|security|"
        r"confirm(?:ation)?|activation|access|login|auth(?:entication)?)"
        r"[^0-9A-Za-z]{0,20}(?:code|pin|number|is|:)?[^0-9A-Za-z]{0,10}([0-9]{4,8})\b",
        r"(?i)\b([0-9]{4,8})\b[^0-9A-Za-z]{0,20}(?:is\s+your\s+)?"
        r"(?:otp|one[-\s]?time\s+(?:password|code)|verification\s+code|security\s+code|code)",
        r"(?i)\b(?:code|pin|token)\s*[:#\-=]?\s*([0-9]{4,8})\b",
        r"(?i)\b(?:code|otp)\s*[:#\-=]?\s*([A-Z0-9]{4,8})\b",
        r"(?<![0-9])([0-9]{6})(?![0-9])",
        r"(?<![0-9])([0-9]{4,8})(?![0-9])",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, searchable_text):
            candidate = match.group(1).strip()
            # skip obvious years / prices
            if candidate.isdigit() and len(candidate) == 4 and candidate.startswith(("19", "20")):
                continue
            return candidate
    return "Not found"


def _temp_mail_preview(message_text: str, limit: int = 600) -> str:
    body = _temp_mail_clean_body(message_text)
    if len(body) > limit:
        body = body[:limit].rstrip() + "…"
    return body or "(empty message)"


def _temp_mail_copy_button(label: str, value: str, callback_prefix: str):
    if CopyTextButton is not None:
        try:
            return InlineKeyboardButton(label, copy_text=CopyTextButton(text=value))
        except Exception as exc:
            logger.debug("Native copy button unavailable: %s", exc)
    callback_data = f"{callback_prefix}{value}"
    if len(callback_data.encode("utf-8")) <= 64:
        return InlineKeyboardButton(label, callback_data=callback_data)
    return InlineKeyboardButton(label, callback_data=f"{callback_prefix}unavailable")


def _temp_mail_email_keyboard(email: str):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(_temp_mail_copy_button("🧾 Copy Email", email, "temp_mail_copy_email:"))
    kb.add(
        InlineKeyboardButton("♻ Refresh Inbox", callback_data="temp_mail_check"),
        InlineKeyboardButton("➕ New Email", callback_data="temp_mail_new"),
    )
    return kb


def _temp_mail_message_keyboard(otp: str):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(_temp_mail_copy_button("🧾 Copy OTP", otp, "temp_mail_copy_otp:"))
    kb.add(InlineKeyboardButton("➕ New Email", callback_data="temp_mail_new"))
    return kb


def _temp_mail_random_credentials(domain: str):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    local_part = "".join(secrets.choice(alphabet) for _ in range(12))
    email = f"{local_part}@{domain}"
    password = secrets.token_urlsafe(18)
    return email, password


_temp_mail_provider_cursor = 0


async def _create_temp_mail_account():
    """Create a mailbox.

    Priority order:
      1. Admin-added domains (Admin Panel -> Settings -> Temp Mail -> Add Domain)
      2. Public free providers, in fallback order, so one provider being down
         never breaks the Get Mail button.
    """
    attempts = []
    for row in get_temp_mail_domains(enabled_only=True):
        attempts.append(
            (
                row["provider"],
                row["domain"],
                {
                    "imap_host": row["imap_host"],
                    "imap_port": row["imap_port"],
                    "imap_user": row["imap_user"],
                    "imap_pass": row["imap_pass"],
                    "imap_folder": row["imap_folder"],
                },
            )
        )
    # Round-robin across every public provider so no single service hits its
    # per-IP / per-day limit, then always finish with the "never-ending" ones.
    global _temp_mail_provider_cursor
    providers = list(temp_mail_engine.PUBLIC_PROVIDERS)
    if providers:
        start = _temp_mail_provider_cursor % len(providers)
        _temp_mail_provider_cursor = (start + 1) % len(providers)
        providers = providers[start:] + providers[:start]
    for provider in providers:
        attempts.append((provider, None, None))
    for provider in temp_mail_engine.UNLIMITED_PROVIDERS:
        attempts.append((provider, None, None))

    last_error = None
    for provider, domain, imap_config in attempts:
        try:
            state = await temp_mail_engine.create_account(
                provider, domain=domain, imap_config=imap_config
            )
            state["expires_at"] = state["created_at"] + TEMP_MAIL_TTL_SECONDS
            logger.info("Temp Mail created via %s", provider)
            return state
        except Exception as exc:
            last_error = exc
            logger.warning(
                "Temp Mail provider %s failed (%s)",
                provider,
                type(exc).__name__,
            )
    raise last_error or RuntimeError("Temp Mail account creation failed")


async def _generate_temp_mail_for_user(user_id: int):
    """Give the user exactly ONE active mailbox; the old one dies immediately."""
    user_key = str(user_id)
    with temp_mail_lock:
        previous = temp_mail_users.get(user_key)
        if user_key in _temp_mail_pending_creations:
            raise TempMailCapacityError("TEMP_MAIL_USER_BUSY")
        now = time.time()
        has_active_mailbox = _temp_mail_is_active(previous, now)
        active_count = sum(
            1 for item in temp_mail_users.values()
            if _temp_mail_is_active(item, now)
        )
        projected_count = active_count - int(has_active_mailbox)
        if projected_count + len(_temp_mail_pending_creations) >= TEMP_MAIL_MAX_ACTIVE_USERS:
            raise TempMailCapacityError("TEMP_MAIL_CAPACITY")
        _temp_mail_pending_creations.add(user_key)

    try:
        state = await _create_temp_mail_account()
        state["mail_uid"] = secrets.token_hex(8)
        state["seen_messages"] = []
        state["expires_at"] = (
            _temp_mail_expiry(state) or (time.time() + TEMP_MAIL_TTL_SECONDS)
        )
        with temp_mail_lock:
            previous = temp_mail_users.get(user_key)
            if isinstance(previous, dict) and previous.get("email"):
                logger.info(
                    "Temp Mail replaced for user=%s",
                    user_id,
                )
            # Invalidate the old mailbox only after the replacement succeeds.
            _temp_mail_forget_locked(user_key)
            temp_mail_users[user_key] = state
            _save_temp_mail_users_locked()
        return state
    finally:
        with temp_mail_lock:
            _temp_mail_pending_creations.discard(user_key)


async def _check_temp_mail_for_user(user_id: int):
    user_key = str(user_id)
    now = time.time()
    with temp_mail_lock:
        stored = temp_mail_users.get(user_key)
        if not _temp_mail_is_active(stored, now):
            return 0
        state = dict(stored)
        cooldown_until = float(
            (_temp_mail_errors.get(user_key) or {}).get("until") or 0
        )
        user_lock = _temp_mail_user_locks.get(user_id)
        if user_lock is None:
            user_lock = asyncio.Lock()
            _temp_mail_user_locks[user_id] = user_lock
    if cooldown_until > now:
        return 0
    if user_lock.locked():
        # A check for this mailbox is already running: never queue a duplicate.
        return 0
    async with user_lock:
        with temp_mail_lock:
            stored = temp_mail_users.get(user_key)
            if not _temp_mail_is_active(stored) or not _temp_mail_same_mailbox(stored, state):
                return 0
            state = dict(stored)

        delivered_count = 0
        try:
            messages = await temp_mail_engine.fetch_messages(state)
        except Exception as exc:
            _temp_mail_note_error(user_key, exc)
            return 0
        _temp_mail_clear_error(user_key)
        seen_messages = {str(value) for value in state.get("seen_messages", [])}

        for message in messages:
            message_id = str(message.get("id") or "")
            if not message_id or message_id in seen_messages:
                continue

            subject = str(message.get("subject") or "No subject")
            message_text = str(message.get("text") or "")
            otp = _temp_mail_extract_otp(subject, message_text)
            # Keep mail alerts privacy-friendly and useful: users only need the
            # verification code, not the sender, subject, or the entire mail.
            notification = (
                "╭━━━ ✉️ <b>MAIL OTP RECEIVED</b> ━━━╮\n"
                "┃\n"
                f"┃ 🔐 <b>OTP CODE</b>\n"
                f"┃ <code>{_html.escape(otp)}</code>\n"
                "┃\n"
                "╰━━━━━━━━━━━━━━━━━━━━╯\n"
                "✅ এই কোডটি আপনার verification-এর জন্য ব্যবহার করুন।"
            )
            with temp_mail_lock:
                current_state = temp_mail_users.get(user_key)
                if not _temp_mail_is_active(current_state) or not _temp_mail_same_mailbox(
                    current_state, state
                ):
                    # Mailbox was replaced or expired mid-check: deliver nothing.
                    return delivered_count

            await asyncio.to_thread(
                bot.send_message,
                user_id,
                notification,
                reply_markup=_temp_mail_message_keyboard(otp),
            )

            with temp_mail_lock:
                current_state = temp_mail_users.get(user_key)
                if not isinstance(current_state, dict) or not _temp_mail_same_mailbox(
                    current_state, state
                ):
                    return delivered_count
                current_seen = [
                    str(value) for value in current_state.get("seen_messages", [])
                ]
                if message_id not in current_seen:
                    current_seen.append(message_id)
                # Bounded: only the newest ids are needed for de-duplication.
                current_state["seen_messages"] = current_seen[-TEMP_MAIL_MAX_SEEN_IDS:]
                _save_temp_mail_users_locked()
            seen_messages.add(message_id)
            delivered_count += 1
        return delivered_count


async def _check_temp_mail_batch(user_ids):
    """Check a small batch while limiting concurrent provider requests."""
    semaphore = asyncio.Semaphore(TEMP_MAIL_MAX_CONCURRENT_CHECKS)

    async def bounded_check(user_id):
        async with semaphore:
            return await _check_temp_mail_for_user(user_id)

    return await asyncio.gather(
        *(bounded_check(user_id) for user_id in user_ids),
        return_exceptions=True,
    )


async def _temp_mail_background_loop():
    logger.info("Temp Mail background checker started.")
    loop_errors = 0
    while True:
        # Nothing active -> stay idle instead of polling provider APIs.
        sleep_for = TEMP_MAIL_IDLE_SLEEP_SECONDS
        try:
            _cleanup_expired_temp_mail_users()
            now = time.time()
            user_ids = []
            fresh = False
            with temp_mail_lock:
                for user_id, state in temp_mail_users.items():
                    if not str(user_id).isdigit() or not _temp_mail_is_active(state, now):
                        continue
                    user_ids.append(int(user_id))
                    if now - _temp_mail_created_at(state) <= TEMP_MAIL_FAST_POLL_WINDOW:
                        fresh = True
            if user_ids:
                for batch_start in range(0, len(user_ids), TEMP_MAIL_CHECK_BATCH_SIZE):
                    batch = user_ids[batch_start:batch_start + TEMP_MAIL_CHECK_BATCH_SIZE]
                    results = await _check_temp_mail_batch(batch)
                    for result in results:
                        if isinstance(result, Exception):
                            logger.warning(
                                "Temp Mail check failed (%s)",
                                type(result).__name__,
                            )
                sleep_for = (
                    TEMP_MAIL_FAST_POLL_SECONDS if fresh
                    else TEMP_MAIL_CHECK_INTERVAL_SECONDS
                )
            loop_errors = 0
        except Exception as exc:
            loop_errors = min(loop_errors + 1, 8)
            sleep_for = min(TEMP_MAIL_IDLE_SLEEP_SECONDS * loop_errors, 120)
            logger.warning(
                "Temp Mail background loop error (%s)",
                type(exc).__name__,
            )
        await asyncio.sleep(sleep_for)


def _run_temp_mail_coroutine(coroutine, timeout=45):
    try:
        _start_temp_mail_background_loop()
    except Exception:
        if hasattr(coroutine, "close"):
            coroutine.close()
        raise
    if _temp_mail_loop is None:
        if hasattr(coroutine, "close"):
            coroutine.close()
        raise RuntimeError("Temp Mail background loop is unavailable")
    bounded = asyncio.wait_for(coroutine, timeout=max(1, timeout - 1))
    future = asyncio.run_coroutine_threadsafe(bounded, _temp_mail_loop)
    try:
        return future.result(timeout=timeout)
    except TimeoutError:
        future.cancel()
        raise


def _start_temp_mail_background_loop():
    global _temp_mail_loop_thread
    with _temp_mail_loop_lock:
        if _temp_mail_loop_thread and _temp_mail_loop_thread.is_alive():
            return
        _temp_mail_loop_ready.clear()

        def run_loop():
            global _temp_mail_loop
            _temp_mail_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(_temp_mail_loop)
            _temp_mail_loop.create_task(_temp_mail_background_loop())
            _temp_mail_loop_ready.set()
            _temp_mail_loop.run_forever()

        _temp_mail_loop_thread = threading.Thread(
            target=run_loop,
            daemon=True,
            name="temp-mail-checker",
        )
        _temp_mail_loop_thread.start()
    if not _temp_mail_loop_ready.wait(timeout=5):
        raise RuntimeError("Temp Mail background loop did not start")


def _send_generated_temp_mail(chat_id, user_id):
    try:
        state = _run_temp_mail_coroutine(_generate_temp_mail_for_user(user_id))
        email = _html.escape(state["email"])
        bot.send_message(
            chat_id,
            "╭━━━ 📬 <b>TEMP MAIL READY</b> ━━━╮\n"
            "┃\n"
            f"┃ ✉️ <b>Your temporary email</b>\n"
            f"┃ <code>{email}</code>\n"
            "┃\n"
            f"┃ ⏳ Valid for <b>{TEMP_MAIL_TTL_SECONDS // 60} minutes</b>\n"
            "┃ ♻ একজন ইউজারের একসাথে একটাই mail থাকবে\n"
            "╰━━━━━━━━━━━━━━━━━━━━╯\n\n"
            "💡 এই inbox-এ verification mail এলে পুরো mail নয়—"
            "শুধু দরকারি OTP code দেখানো হবে।",
            reply_markup=_temp_mail_email_keyboard(state["email"]),
        )
    except TempMailCapacityError as exc:
        if "BUSY" in str(exc):
            message_text = (
                "⌛ আপনার জন্য নতুন inbox তৈরির কাজ চলছে। "
                "একটু অপেক্ষা করে আবার চেষ্টা করুন।"
            )
        else:
            message_text = (
                "⌛ Temporary inbox-গুলোর বর্তমান সীমা পূর্ণ। "
                "কিছু inbox মেয়াদ শেষ হলে আবার চেষ্টা করুন।"
            )
        bot.send_message(chat_id, message_text)
    except Exception as exc:
        logger.warning(
            "Temp Mail generation failed for user=%s (%s)",
            user_id,
            type(exc).__name__,
        )
        bot.send_message(
            chat_id,
            "⚠️ <b>TEMP MAIL UNAVAILABLE</b>\n\n"
            "এখন নতুন temporary email তৈরি করা যাচ্ছে না। "
            "কিছুক্ষণ পর আবার চেষ্টা করুন।",
        )


def _send_temp_mail_check_result(chat_id, user_id):
    if not _get_temp_mail_user(user_id):
        new_kb = InlineKeyboardMarkup(row_width=1)
        new_kb.add(InlineKeyboardButton("➕ New Email", callback_data="temp_mail_new"))
        bot.send_message(
            chat_id,
            "⚠️ <b>NO ACTIVE TEMP MAIL</b>\n\n"
            "আপনার temporary email-এর মেয়াদ শেষ হয়ে থাকতে পারে। "
            "নতুন email তৈরি করুন।",
            reply_markup=new_kb,
        )
        return
    try:
        delivered_count = _run_temp_mail_coroutine(
            _check_temp_mail_for_user(user_id)
        )
    except Exception as exc:
        logger.warning(
            "Manual Temp Mail check failed for user=%s (%s)",
            user_id,
            type(exc).__name__,
        )
        delivered_count = 0
    if not delivered_count:
        retry_kb = InlineKeyboardMarkup(row_width=2)
        retry_kb.add(
            InlineKeyboardButton("♻ Refresh Inbox", callback_data="temp_mail_check"),
            InlineKeyboardButton("➕ New Email", callback_data="temp_mail_new"),
        )
        bot.send_message(
            chat_id,
            "⌛ এখনো কোনো mail OTP পাওয়া যায়নি।\n"
            "নতুন mail এলে শুধু OTP code-টাই এখানে দেখানো হবে।",
            reply_markup=retry_kb,
        )


_load_temp_mail_users()



# ─── DATABASE ──────────────────────────────────────────────────────────────────
class _ClosingSQLiteConnection(sqlite3.Connection):
    """Commit/rollback on context exit and always release the file handle."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def get_conn():
    conn = sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
        timeout=30,
        factory=_ClosingSQLiteConnection,
    )
    conn.row_factory = sqlite3.Row
    # WAL mode is set once during init_db. Re-setting journal_mode on every
    # connection can contend with active readers/writers in background threads.
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    # Smaller bounded page cache and file-backed scratch space limit aggregate
    # RAM use when several handlers/pollers run concurrently.
    conn.execute("PRAGMA cache_size = -1000")
    conn.execute("PRAGMA temp_store = FILE")
    conn.execute("PRAGMA journal_size_limit = 16777216")
    return conn


def init_db():
    # journal_mode is persistent for the database file; configure it once
    # before the app starts its concurrent polling/background threads.
    bootstrap_conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    try:
        bootstrap_conn.execute("PRAGMA journal_mode=WAL")
        bootstrap_conn.execute("PRAGMA journal_size_limit=16777216")
    finally:
        bootstrap_conn.close()

    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            is_banned INTEGER DEFAULT 0,
            numbers_generated INTEGER DEFAULT 0,
            otps_received INTEGER DEFAULT 0,
            referred_by INTEGER DEFAULT NULL,
            referral_bonus_paid INTEGER DEFAULT 0,
            joined_at INTEGER DEFAULT (strftime('%s','now')),
            last_active_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS countries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            flag TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            code TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s','now')),
            FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS numbers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            country_id INTEGER NOT NULL,
            number TEXT NOT NULL,
            assigned INTEGER DEFAULT 0,
            assigned_to INTEGER DEFAULT NULL,
            assigned_at INTEGER DEFAULT NULL,
            created_at INTEGER DEFAULT (strftime('%s','now')),
            FOREIGN KEY (country_id) REFERENCES countries(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS allocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            number_id INTEGER,
            number TEXT NOT NULL,
            service_name TEXT DEFAULT '',
            country_name TEXT DEFAULT '',
            country_flag TEXT DEFAULT '',
            country_code TEXT DEFAULT '',
            message_id INTEGER,
            otp_received INTEGER DEFAULT 0,
            otp_text TEXT DEFAULT '',
            timed_out INTEGER DEFAULT 0,
            allocated_at INTEGER DEFAULT (strftime('%s','now')),
            rid TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_hash TEXT UNIQUE,
            user_id INTEGER,
            number TEXT,
            message TEXT,
            otp_code TEXT,
            cli TEXT DEFAULT '',
            received_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS wallet (
            user_id INTEGER PRIMARY KEY,
            balance REAL DEFAULT 0.0,
            pending_balance REAL DEFAULT 0.0,
            total_income REAL DEFAULT 0.0,
            total_otp INTEGER DEFAULT 0,
            today_otp INTEGER DEFAULT 0,
            today_income REAL DEFAULT 0.0,
            referral_income REAL DEFAULT 0.0,
            last_reset_date TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS withdraw_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            method TEXT,
            number TEXT,
            amount REAL,
            status TEXT DEFAULT 'pending',
            group_msg_id INTEGER,
            created_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS delivered_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_hash TEXT UNIQUE NOT NULL,
            number TEXT,
            message TEXT,
            user_id INTEGER,
            delivered_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS admins (
            user_id INTEGER PRIMARY KEY,
            added_by INTEGER,
            added_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS withdraw_methods (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            is_enabled INTEGER DEFAULT 1,
            created_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS join_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id TEXT NOT NULL,
            channel_name TEXT NOT NULL,
            channel_url TEXT NOT NULL,
            channel_type TEXT DEFAULT 'channel',
            created_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS api_configs (
            api_id TEXT PRIMARY KEY,
            api_key TEXT NOT NULL DEFAULT '',
            is_enabled INTEGER DEFAULT 1,
            updated_at INTEGER DEFAULT (strftime('%s','now'))
        );

        -- Durable de-duplication for Auto SMS.  The old implementation kept
        -- this only in RAM, so a restart resent old messages and a failed
        -- Telegram send was permanently lost.
        CREATE TABLE IF NOT EXISTS auto_sms_deliveries (
            delivery_key TEXT PRIMARY KEY,
            panel_name TEXT NOT NULL DEFAULT '',
            number TEXT NOT NULL DEFAULT '',
            message TEXT NOT NULL DEFAULT '',
            created_at INTEGER DEFAULT (strftime('%s','now'))
        );

        -- Admin-managed Temp Mail domains.  Mail addresses are created on
        -- these domains first; public free providers are only a fallback.
        CREATE TABLE IF NOT EXISTS temp_mail_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            provider TEXT NOT NULL DEFAULT 'mailtm',
            imap_host TEXT DEFAULT '',
            imap_port INTEGER DEFAULT 993,
            imap_user TEXT DEFAULT '',
            imap_pass TEXT DEFAULT '',
            imap_folder TEXT DEFAULT 'INBOX',
            is_enabled INTEGER DEFAULT 1,
            created_at INTEGER DEFAULT (strftime('%s','now'))
        );

        CREATE INDEX IF NOT EXISTS idx_allocations_active
            ON allocations(otp_received, timed_out, allocated_at);
        CREATE INDEX IF NOT EXISTS idx_numbers_available
            ON numbers(country_id, assigned);
        CREATE INDEX IF NOT EXISTS idx_otps_number_time
            ON otps(number, received_at);
        """)

init_db()


def create_database_backup() -> str:
    """Create a consistent SQLite snapshot, including any pending WAL data."""
    backup_path = os.path.join(
        DATA_DIR,
        f"voltx_backup_{int(time.time())}_{secrets.token_hex(3)}.db",
    )
    source = None
    destination = None
    try:
        source = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
        source.execute("PRAGMA busy_timeout = 30000")
        destination = sqlite3.connect(backup_path)
        source.backup(destination)
        destination.commit()
        return backup_path
    except Exception:
        if destination is not None:
            destination.close()
        try:
            os.remove(backup_path)
        except OSError:
            pass
        raise
    finally:
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()


# ─── TEMP MAIL DOMAIN STORE ───────────────────────────────────────────────────
def get_temp_mail_domains(enabled_only: bool = False):
    query = "SELECT * FROM temp_mail_domains"
    if enabled_only:
        query += " WHERE is_enabled=1"
    query += " ORDER BY id"
    try:
        with get_conn() as conn:
            rows = [dict(row) for row in conn.execute(query).fetchall()]
    except Exception as exc:
        logger.warning("Could not read temp mail domains: %s", exc)
        return []
    for row in rows:
        row["imap_pass"] = _decrypt_data_secret(row.get("imap_pass", ""))
    return rows


def add_temp_mail_domain(
    domain: str,
    provider: str = "mailtm",
    imap_host: str = "",
    imap_port: int = 993,
    imap_user: str = "",
    imap_pass: str = "",
    imap_folder: str = "INBOX",
):
    domain = str(domain or "").strip().lstrip("@").lower()
    if not domain:
        return False
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO temp_mail_domains
               (domain, provider, imap_host, imap_port, imap_user, imap_pass, imap_folder)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(domain) DO UPDATE SET
                 provider=excluded.provider,
                 imap_host=excluded.imap_host,
                 imap_port=excluded.imap_port,
                 imap_user=excluded.imap_user,
                 imap_pass=excluded.imap_pass,
                 imap_folder=excluded.imap_folder,
                 is_enabled=1""",
            (
                domain, provider, imap_host, int(imap_port or 993), imap_user,
                _encrypt_data_secret(imap_pass), imap_folder,
            ),
        )
    return True


def delete_temp_mail_domain(domain: str):
    domain = str(domain or "").strip().lstrip("@").lower()
    with get_conn() as conn:
        cursor = conn.execute("DELETE FROM temp_mail_domains WHERE domain=?", (domain,))
    return cursor.rowcount > 0


def toggle_temp_mail_domain(domain: str):
    domain = str(domain or "").strip().lstrip("@").lower()
    with get_conn() as conn:
        conn.execute(
            "UPDATE temp_mail_domains SET is_enabled = 1 - is_enabled WHERE domain=?",
            (domain,),
        )


def migrate_db():
    with get_conn() as conn:
        for col, typedef in [
            ("balance", "REAL DEFAULT 0.0"),
            ("pending_balance", "REAL DEFAULT 0.0"),
            ("total_income", "REAL DEFAULT 0.0"),
            ("total_otp", "INTEGER DEFAULT 0"),
            ("today_otp", "INTEGER DEFAULT 0"),
            ("today_income", "REAL DEFAULT 0.0"),
            ("referral_income", "REAL DEFAULT 0.0"),
            ("last_reset_date", "TEXT DEFAULT ''"),
        ]:
            try:
                conn.execute(f"ALTER TABLE wallet ADD COLUMN {col} {typedef}")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
        conn.execute("INSERT OR IGNORE INTO wallet (user_id) SELECT id FROM users")
        for col, typedef in [
            ("number_id", "INTEGER"),
            ("service_name", "TEXT DEFAULT ''"),
            ("country_name", "TEXT DEFAULT ''"),
            ("country_flag", "TEXT DEFAULT ''"),
            ("country_code", "TEXT DEFAULT ''"),
            ("otp_text", "TEXT DEFAULT ''"),
            ("rid", "TEXT DEFAULT ''"),
        ]:
            try:
                conn.execute(f"ALTER TABLE allocations ADD COLUMN {col} {typedef}")
            except sqlite3.OperationalError as exc:
                if "duplicate column name" not in str(exc).lower():
                    raise
        try:
            conn.execute("ALTER TABLE join_channels ADD COLUMN channel_type TEXT DEFAULT 'channel'")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
        try:
            conn.execute("ALTER TABLE countries ADD COLUMN range_id TEXT DEFAULT ''")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
        # referral support
        try:
            conn.execute("ALTER TABLE users ADD COLUMN referred_by INTEGER DEFAULT NULL")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise
        try:
            conn.execute("ALTER TABLE users ADD COLUMN referral_bonus_paid INTEGER DEFAULT 0")
        except sqlite3.OperationalError as exc:
            if "duplicate column name" not in str(exc).lower():
                raise

migrate_db()


def _migrate_stored_data_secrets():
    """Encrypt existing API keys and IMAP passwords; validate encrypted values."""
    with get_conn() as conn:
        api_rows = conn.execute(
            "SELECT api_id, api_key FROM api_configs WHERE api_key <> ''"
        ).fetchall()
        for row in api_rows:
            value = str(row["api_key"] or "")
            if value.startswith(_ENCRYPTED_VALUE_PREFIX):
                _decrypt_data_secret(value)
            else:
                conn.execute(
                    "UPDATE api_configs SET api_key=? WHERE api_id=?",
                    (_encrypt_data_secret(value), row["api_id"]),
                )

        domain_rows = conn.execute(
            "SELECT id, imap_pass FROM temp_mail_domains WHERE imap_pass <> ''"
        ).fetchall()
        for row in domain_rows:
            value = str(row["imap_pass"] or "")
            if value.startswith(_ENCRYPTED_VALUE_PREFIX):
                _decrypt_data_secret(value)
            else:
                conn.execute(
                    "UPDATE temp_mail_domains SET imap_pass=? WHERE id=?",
                    (_encrypt_data_secret(value), row["id"]),
                )


_migrate_stored_data_secrets()


# ─── API CONFIG HELPERS ────────────────────────────────────────────────────────
def get_api_config(api_id: str) -> dict:
    """Return config for an API (key + enabled). Falls back to code defaults."""
    defn = API_DEFINITIONS.get(api_id, {})
    with get_conn() as conn:
        row = conn.execute(
            "SELECT api_key, is_enabled FROM api_configs WHERE api_id=?", (api_id,)
        ).fetchone()
    if row:
        key = (
            _decrypt_data_secret(row["api_key"])
            if row["api_key"]
            else defn.get("default_key", "")
        )
        return {"key": key, "enabled": bool(row["is_enabled"]), "url": defn.get("url", "")}
    return {"key": defn.get("default_key", ""), "enabled": True, "url": defn.get("url", "")}


def set_api_key(api_id: str, key: str):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO api_configs (api_id, api_key, is_enabled, updated_at)
               VALUES (?, ?, 1, strftime('%s','now'))
               ON CONFLICT(api_id) DO UPDATE SET api_key=excluded.api_key, updated_at=strftime('%s','now')""",
            (api_id, _encrypt_data_secret(key)),
        )


def toggle_api_enabled(api_id: str):
    cfg = get_api_config(api_id)
    new_val = 0 if cfg["enabled"] else 1
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO api_configs (api_id, api_key, is_enabled, updated_at)
               VALUES (?, '', ?, strftime('%s','now'))
               ON CONFLICT(api_id) DO UPDATE SET is_enabled=excluded.is_enabled, updated_at=strftime('%s','now')""",
            (api_id, new_val),
        )
    return bool(new_val)


def remove_api_key(api_id: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM api_configs WHERE api_id=?", (api_id,))


# ─── ADMIN HELPERS ─────────────────────────────────────────────────────────────
def is_admin(user_id: int) -> bool:
    if user_id == ADMIN_ID:
        return True
    with get_conn() as conn:
        row = conn.execute("SELECT user_id FROM admins WHERE user_id=?", (user_id,)).fetchone()
    return row is not None


def get_sub_admins() -> list:
    with get_conn() as conn:
        return conn.execute("SELECT user_id FROM admins ORDER BY added_at").fetchall()


# ─── SETTINGS HELPERS ──────────────────────────────────────────────────────────
def get_setting(key: str, default=None):
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value):
    with get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, str(value)))


def _safe_float_setting(key: str, default: float, minimum: float = 0.0,
                        maximum: float = 1_000_000.0) -> float:
    try:
        value = float(str(get_setting(key, default)).strip())
    except (TypeError, ValueError):
        value = default
    if not math.isfinite(value):
        value = default
    return max(minimum, min(maximum, value))


def get_otp_earn() -> float:
    return _safe_float_setting("otp_earn_bdt", 0.30, minimum=0.0)


def get_referral_bonus() -> float:
    return _safe_float_setting("referral_bonus_bdt", 0.0, minimum=0.0)


def is_leaderboard_enabled() -> bool:
    return str(get_setting("leaderboard_enabled", "1")) == "1"


def is_auto_sms_enabled() -> bool:
    return str(get_setting("auto_sms_enabled", "0")) == "1"


def get_min_withdraw() -> float:
    return _safe_float_setting("min_withdraw_bdt", 100.0, minimum=0.01)


def get_positive_int_setting(key: str, default: int, minimum: int = 1,
                            maximum: int = 86400) -> int:
    try:
        value = int(str(get_setting(key, default)).strip())
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def delete_setting(key: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM settings WHERE key=?", (key,))


def get_active_withdraw_methods() -> list:
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM withdraw_methods WHERE is_enabled=1 ORDER BY name"
        ).fetchall()


def get_all_withdraw_methods() -> list:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM withdraw_methods ORDER BY name").fetchall()


def get_join_channels() -> list:
    with get_conn() as conn:
        return conn.execute("SELECT * FROM join_channels ORDER BY id").fetchall()


def is_force_join_enabled() -> bool:
    return get_setting("force_join_enabled", "0") == "1"


# ─── WALLET HELPERS ────────────────────────────────────────────────────────────
def get_wallet(user_id: int) -> sqlite3.Row:
    with get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO wallet (user_id) VALUES (?)", (user_id,))
        return conn.execute("SELECT * FROM wallet WHERE user_id=?", (user_id,)).fetchone()


def _today_str() -> str:
    return str(date.today())


def credit_otp_earn(user_id: int):
    with get_conn() as conn:
        _credit_otp_earn_in_conn(conn, user_id)


def _credit_otp_earn_in_conn(conn, user_id: int):
    """Credit one OTP while already inside the delivery transaction."""
    today = _today_str()
    conn.execute("INSERT OR IGNORE INTO wallet (user_id) VALUES (?)", (user_id,))
    w = conn.execute("SELECT * FROM wallet WHERE user_id=?", (user_id,)).fetchone()
    if w["last_reset_date"] != today:
        conn.execute(
            "UPDATE wallet SET today_otp=0, today_income=0.0, last_reset_date=? WHERE user_id=?",
            (today, user_id),
        )
    earn = get_otp_earn()
    conn.execute("""
        UPDATE wallet SET
            balance=balance+?, total_income=total_income+?,
            today_income=today_income+?, total_otp=total_otp+1,
            today_otp=today_otp+1, last_reset_date=?
        WHERE user_id=?
    """, (earn, earn, earn, today, user_id))


def apply_referral(user_id: int, referrer_id: int) -> tuple[bool, float]:
    """Attach a valid first-time referral and credit its configured bonus once."""
    if user_id == referrer_id:
        return False, 0.0
    bonus = get_referral_bonus()
    with get_conn() as conn:
        referrer = conn.execute("SELECT id FROM users WHERE id=?", (referrer_id,)).fetchone()
        referred = conn.execute(
            "SELECT referred_by, referral_bonus_paid FROM users WHERE id=?", (user_id,)
        ).fetchone()
        if not referrer or not referred or referred["referred_by"] is not None:
            return False, 0.0
        updated = conn.execute(
            "UPDATE users SET referred_by=?, referral_bonus_paid=1 "
            "WHERE id=? AND referred_by IS NULL AND referral_bonus_paid=0",
            (referrer_id, user_id),
        )
        if updated.rowcount != 1:
            return False, 0.0
        conn.execute("INSERT OR IGNORE INTO wallet (user_id) VALUES (?)", (referrer_id,))
        if bonus > 0:
            conn.execute(
                "UPDATE wallet SET balance=balance+?, total_income=total_income+?, "
                "referral_income=referral_income+? WHERE user_id=?",
                (bonus, bonus, bonus, referrer_id),
            )
    return True, bonus


def get_wallet_stats(user_id: int) -> dict:
    today = _today_str()
    with get_conn() as conn:
        conn.execute("INSERT OR IGNORE INTO wallet (user_id) VALUES (?)", (user_id,))
        w = conn.execute("SELECT * FROM wallet WHERE user_id=?", (user_id,)).fetchone()
    if w["last_reset_date"] != today:
        return dict(
            balance=w["balance"], pending_balance=w["pending_balance"],
            total_income=w["total_income"], total_otp=w["total_otp"],
            today_otp=0, today_income=0.0,
        )
    return dict(
        balance=w["balance"], pending_balance=w["pending_balance"],
        total_income=w["total_income"], total_otp=w["total_otp"],
        today_otp=w["today_otp"], today_income=w["today_income"],
    )


def has_pending_withdraw(user_id: int) -> bool:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM withdraw_requests WHERE user_id=? AND status='pending'",
            (user_id,),
        ).fetchone()
    return row is not None


# ─── GENERAL HELPERS ───────────────────────────────────────────────────────────
def upsert_user(user):
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO users (id, username, first_name, last_active_at)
            VALUES (?, ?, ?, strftime('%s','now'))
            ON CONFLICT(id) DO UPDATE SET
                username=excluded.username,
                first_name=excluded.first_name,
                last_active_at=strftime('%s','now')
        """, (user.id, user.username, user.first_name))
        conn.execute("INSERT OR IGNORE INTO wallet (user_id) VALUES (?)", (user.id,))


def get_user(user_id):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def extract_otp(message_text):
    # Instagram-style spaced codes: "123 456" or "1234 5678"
    spaced = re.findall(r'(?<!\d)(\d{3,4}[ \-]\d{3,4})(?!\d)', message_text)
    if spaced:
        return re.sub(r'[ \-]', '', spaced[0])
    # Standard 4-8 digit OTP code
    matches = re.findall(r'(?<!\d)(\d{4,8})(?!\d)', message_text)
    return matches[0] if matches else ""


def msg_hash(num, dt, message):
    raw = f"{num}|{dt}|{message}"
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_country_info(text):
    text = text.strip()
    parts = text.split()
    if len(parts) < 3:
        return None
    flag = parts[0]
    code_raw = parts[-1].lstrip("+")
    if not code_raw.isdigit():
        return None
    name = " ".join(parts[1:-1])
    return {"flag": flag, "name": name, "code": code_raw}


def normalize_number(num: str) -> str:
    return num.strip().lstrip("+")


def parse_channel_link(link: str):
    """
    Parse a Telegram channel/group link and return (channel_id, channel_name, channel_url).
    Supports:
      https://t.me/username  → @username
      https://t.me/+invite   → invite hash (can't resolve ID without bot join)
      @username              → @username
    """
    link = link.strip()
    # Already a username
    if link.startswith("@"):
        username = link.lstrip("@")
        return f"@{username}", username, f"https://t.me/{username}"
    # t.me link
    match = re.search(r't\.me/([^/\s?]+)', link)
    if match:
        slug = match.group(1)
        if slug.startswith("+"):
            return slug, slug.lstrip("+")[:12], link
        return f"@{slug}", slug, f"https://t.me/{slug}"
    # Raw ID
    if re.match(r'^-?\d+$', link):
        return link, f"Chat_{link}", link
    return None, None, None


# ─── USER KEYBOARDS ────────────────────────────────────────────────────────────
def welcome_keyboard(is_admin_user=False):
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    # Row 1 — primary action + Temp Mail
    kb.add(
        KeyboardButton(f"📲 {stylish('Get Number')}"),
        KeyboardButton(f"📬 {stylish('Temp Mail')}"),
    )
    # Row 2 — Balance + custom range
    kb.add(
        KeyboardButton(f"🪪 {stylish('Balance')}"),
        KeyboardButton(f"🧿 {stylish('CUSTOM RANGE')}"),
    )
    # Row 3 — Support + profile (Withdraw now lives inside Balance)
    kb.add(
        KeyboardButton(f"🎧 {stylish('Support')}"),
        KeyboardButton(f"🧑 {stylish('Profile')}"),
    )
    # Row 4 — Traffic is half-width beside the integrated Shop entry point.
    kb.add(
        KeyboardButton(f"📊 {stylish('Traffic')}"),
        KeyboardButton(f"🛍️ {stylish('Shop')}"),
    )
    # Row 5 — Leaderboard (admin controlled)
    if is_leaderboard_enabled():
        kb.add(KeyboardButton(f"🏆 {stylish('Leaderboard')}"))
    if is_admin_user:
        kb.add(KeyboardButton(f"🎛️ {stylish('Admin Panel')}"))
    return kb


def balance_inline_keyboard():
    """Withdraw is reachable from the Balance card only."""
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton(f"🪙 {stylish('Withdraw')}", callback_data="bal_withdraw"))
    return kb


def profile_inline_keyboard():
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton(f"🎁 {stylish('Refer & Earn')}", callback_data="profile_referral"))
    return kb


def referral_inline_keyboard(ref_link: str):
    kb = InlineKeyboardMarkup(row_width=1)
    share_url = f"https://t.me/share/url?url={quote(ref_link, safe='')}&text={quote('Join this bot and earn rewards!', safe='')}"
    kb.add(InlineKeyboardButton(f"⛓ {stylish('Share Referral Link')}", url=share_url))
    label = f"🧾 {stylish('Copy Link')}"
    if CopyTextButton is not None:
        try:
            kb.add(InlineKeyboardButton(label, copy_text=CopyTextButton(text=ref_link)))
            return kb
        except Exception as exc:
            logger.warning("Referral CopyTextButton unsupported, falling back: %s", exc)
    kb.add(InlineKeyboardButton(label, callback_data="referral_copy"))
    return kb


def withdraw_methods_inline_keyboard():
    methods = get_active_withdraw_methods()
    if not methods:
        return None
    kb = InlineKeyboardMarkup(row_width=2)
    for m in methods:
        kb.add(InlineKeyboardButton(m["name"], callback_data=f"wd_method:{m['name']}"))
    kb.add(InlineKeyboardButton("❎️ Cancel", callback_data="wd_cancel"))
    return kb


def withdraw_confirm_inline_keyboard():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("✔️ Confirm", callback_data="wd_confirm"),
        InlineKeyboardButton("❎️ Cancel", callback_data="wd_cancel"),
    )
    return kb


def join_keyboard():
    channels = get_join_channels()
    kb = InlineKeyboardMarkup(row_width=2)
    channel_buttons = []
    if channels:
        for ch in channels:
            sname = stylish(ch["channel_name"].upper())
            if ch["channel_type"] == "group":
                label = f"👥 {sname}"
            else:
                label = f"📣 {sname}"
            channel_buttons.append(InlineKeyboardButton(label, url=ch["channel_url"]))
    else:
        fallback_url = get_setting("otp_group_link", "https://t.me/")
        channel_buttons.append(InlineKeyboardButton(f"👥 {stylish('JOIN GROUP')}", url=fallback_url))
    # Add channel buttons in rows of 2
    for i in range(0, len(channel_buttons), 2):
        kb.add(*channel_buttons[i:i+2])
    kb.add(InlineKeyboardButton(f"♻ {stylish('CHECK JOIN')}", callback_data="usr_check_join"))
    return kb


def number_card_inline_keyboard(number: str = "", numbers=None):
    """Inline buttons shown below the number card.
    Row 1: COPY NUMBER (full width, native copy button)
    Row 2: CHANGE (full width)
    Row 3: COUNTRY | OTP GROUP (50/50) or CHANGE COUNTRY (full width)
    """
    otp_link = get_setting("otp_group_link", "")
    kb = InlineKeyboardMarkup(row_width=2)
    # Row 1: COPY NUMBER — native copy button if available
    number_values = list(numbers or ([] if not number else [number]))
    for index, number_value in enumerate(number_values, 1):
        safe_num = str(number_value).strip().lstrip("+")
        display = f"+{safe_num}"
        label = f"🧾 {stylish('COPY NUMBER')} {index} • {display}"
        if CopyTextButton is not None:
            try:
                kb.row(InlineKeyboardButton(label, copy_text=CopyTextButton(text=display)))
            except Exception:
                cb = f"num_copy:{safe_num}"
                if len(cb.encode()) <= 64:
                    kb.row(InlineKeyboardButton(label, callback_data=cb))
        else:
            cb = f"num_copy:{safe_num}"
            if len(cb.encode()) <= 64:
                kb.row(InlineKeyboardButton(label, callback_data=cb))
    # Row 2: CHANGE — full width always
    kb.row(InlineKeyboardButton(f"♻ {stylish('CHANGE')}", callback_data="num_change"))
    if otp_link:
        kb.row(
            InlineKeyboardButton(f"🗺 {stylish('COUNTRY')}", callback_data="num_change_country"),
            InlineKeyboardButton(f"👥 {stylish('OTP GROUP')}", url=otp_link),
        )
    else:
        kb.row(InlineKeyboardButton(f"🗺 {stylish('CHANGE COUNTRY')}", callback_data="num_change_country"))
    return kb


def user_services_inline_keyboard():
    """Services shown as InlineKeyboard (admin services on top, Other Service at bottom)."""
    with get_conn() as conn:
        services = conn.execute("""
            SELECT DISTINCT s.id, s.name FROM services s
            WHERE EXISTS (
                SELECT 1 FROM countries c
                WHERE c.service_id = s.id
                AND (
                    (c.range_id IS NOT NULL AND c.range_id != '')
                    OR c.id IN (SELECT n.country_id FROM numbers n WHERE n.assigned = 0)
                )
            )
            ORDER BY s.name
        """).fetchall()
    kb = InlineKeyboardMarkup(row_width=2)
    for svc in services:
        kb.add(InlineKeyboardButton(f"📟 {svc['name']}", callback_data=f"sel_service:{svc['id']}"))
    kb.add(InlineKeyboardButton("◀️ Back", callback_data="sel_service_back"))
    return kb


def user_services_keyboard():
    with get_conn() as conn:
        services = conn.execute("""
            SELECT DISTINCT s.id, s.name FROM services s
            WHERE EXISTS (
                SELECT 1 FROM countries c
                WHERE c.service_id = s.id
                AND (
                    (c.range_id IS NOT NULL AND c.range_id != '')
                    OR c.id IN (SELECT n.country_id FROM numbers n WHERE n.assigned = 0)
                )
            )
            ORDER BY s.name
        """).fetchall()
    if not services:
        return None
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    for svc in services:
        kb.add(KeyboardButton(f"📟 {svc['name']}"))
    kb.add(KeyboardButton("◀️ Back"))
    return kb


def user_countries_inline_keyboard(service_id):
    """Countries shown as InlineKeyboard — 3 per row."""
    with get_conn() as conn:
        countries = conn.execute("""
            SELECT c.*,
                   (SELECT COUNT(*) FROM numbers n WHERE n.country_id = c.id AND n.assigned = 0) as avail
            FROM countries c
            WHERE c.service_id = ?
            AND (
                (c.range_id IS NOT NULL AND c.range_id != '')
                OR c.id IN (SELECT n.country_id FROM numbers n WHERE n.assigned = 0)
            )
            ORDER BY c.name
        """, (service_id,)).fetchall()
    kb = InlineKeyboardMarkup(row_width=3)
    buttons = [
        InlineKeyboardButton(
            f"{c['flag']} {c['name']}",
            callback_data=f"sel_country:{c['id']}",
        )
        for c in countries
    ]
    kb.add(*buttons)
    kb.add(InlineKeyboardButton("◀️ Back", callback_data="sel_country_back"))
    return kb


# ─── ADMIN KEYBOARDS ───────────────────────────────────────────────────────────
def admin_keyboard(is_main_admin=False):
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"🛠️ {stylish('Manage Services')}"),
        KeyboardButton(f"📊 {stylish('Dashboard')}"),
    )
    kb.add(
        KeyboardButton(f"🛡️ {stylish('Ban Unban')}"),
        KeyboardButton(f"📣 {stylish('Broadcast')}"),
    )
    kb.add(
        KeyboardButton(f"👥 {stylish('Users')}"),
        KeyboardButton(f"💎 {stylish('Balance Mgmt')}"),
    )
    kb.add(
        KeyboardButton(f"🪙 {stylish('Withdraw Mgmt')}"),
        KeyboardButton(f"🔧 {stylish('Settings')}"),
    )
    kb.add(KeyboardButton(f"◀️ {stylish('Back to User Panel')}"))
    if is_main_admin:
        kb.add(KeyboardButton(f"👑 {stylish('Admin Management')}"))
    return kb


def admin_management_keyboard():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"➕ {stylish('Add Admin')}"),
        KeyboardButton(f"👥 {stylish('View Admins')}"),
    )
    kb.add(
        KeyboardButton(f"🧹 {stylish('Remove Admin')}"),
        KeyboardButton(f"◀️ {stylish('Back to Admin')}"),
    )
    return kb


def balance_management_keyboard():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"🎛️ {stylish('Set OTP Earn')}"),
        KeyboardButton(f"💲 {stylish('Add Balance')}"),
    )
    kb.add(
        KeyboardButton(f"➖ {stylish('Remove Balance')}"),
        KeyboardButton(f"🎁 {stylish('Set Referral Bonus')}"),
    )
    kb.add(KeyboardButton(f"◀️ {stylish('Back to Admin')}"))
    return kb


def withdraw_management_keyboard():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"➕ {stylish('Add Method')}"),
        KeyboardButton(f"🧹 {stylish('Delete Method')}"),
    )
    kb.add(
        KeyboardButton(f"🧾 {stylish('List Methods')}"),
        KeyboardButton(f"🎛️ {stylish('Set Min Withdraw')}"),
    )
    kb.add(KeyboardButton(f"◀️ {stylish('Back to Admin')}"))
    return kb


def settings_keyboard(is_main_admin=False):
    """Main Settings keyboard (Task 2)."""
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"🔏 {stylish('Force Join')}"),
        KeyboardButton(f"⛓ {stylish('Others Link')}"),
    )
    kb.add(KeyboardButton(f"🗝 {stylish('API Management')}"))
    lb = "ON" if is_leaderboard_enabled() else "OFF"
    kb.add(KeyboardButton(f"🏆 {stylish('Leaderboard')}: {lb}"))
    kb.add(KeyboardButton(f"🚀 {stylish('Auto SMS')}"))
    kb.add(KeyboardButton(f"📬 {stylish('Temp Mail Domains')}"))
    kb.add(KeyboardButton(f"🗄 {stylish('Backup')}"))
    kb.add(KeyboardButton(f"◀️ {stylish('Back to Admin')}"))
    return kb


def temp_mail_admin_keyboard():
    """Temp Mail domain management sub-menu (admin)."""
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"➕ {stylish('Add Mail Domain')}"),
        KeyboardButton(f"🧾 {stylish('List Mail Domains')}"),
    )
    kb.add(
        KeyboardButton(f"🔁 {stylish('Toggle Mail Domain')}"),
        KeyboardButton(f"🧹 {stylish('Del Mail Domain')}"),
    )
    kb.add(KeyboardButton(f"🧪 {stylish('Mail Provider Status')}"))
    kb.add(KeyboardButton(f"↩ {stylish('Back to Settings')}"))
    return kb


def temp_mail_provider_keyboard():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    kb.add(KeyboardButton("🛰 Own Domain (IMAP)"))
    kb.add(KeyboardButton("📪 Mail.tm"))
    kb.add(KeyboardButton("📪 Mail.gw"))
    kb.add(KeyboardButton("📪 Temp-Mail.io"))
    kb.add(KeyboardButton("📪 GuerrillaMail"))
    kb.add(KeyboardButton("❎️ Cancel"))
    return kb


TEMP_MAIL_PROVIDER_CHOICES = {
    "🛰 Own Domain (IMAP)": "imap",
    "📪 Mail.tm": "mailtm",
    "📪 Mail.gw": "mailgw",
    "📪 Temp-Mail.io": "tempmailio",
    "📪 GuerrillaMail": "guerrilla",
}


def _temp_mail_domains_text():
    rows = get_temp_mail_domains()
    if not rows:
        return (
            "📬 <b>Mail Domains</b>\n\n"
            "⛔ কোনো domain যোগ করা নেই।\n"
            "এখন Get Mail free public provider থেকে address দিচ্ছে।"
        )
    lines = ["📬 <b>Mail Domains</b>\n"]
    for row in rows:
        status = "🟩" if row["is_enabled"] else "🟥"
        label = temp_mail_engine.PROVIDER_LABELS.get(row["provider"], row["provider"])
        lines.append(f"{status} <code>{_html.escape(row['domain'])}</code> — {label}")
        if row["provider"] == "imap":
            lines.append(
                f"    📥 {_html.escape(str(row['imap_host']))}:{row['imap_port']} "
                f"({_html.escape(str(row['imap_user']))})"
            )
    return "\n".join(lines)


def _temp_mail_admin_status_text():
    return (
        "📬 <b>Temp Mail Settings</b>\n\n"
        f"{_temp_mail_domains_text()}\n\n"
        "ℹ️ যোগ করা domain গুলো আগে ব্যবহার হবে; কাজ না করলে free provider fallback হবে।"
    )


def auto_sms_keyboard():
    """Auto SMS sub-menu (admin) — forwards REAL panel SMS to a group/channel."""
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    state = "ON" if is_auto_sms_enabled() else "OFF"
    kb.add(KeyboardButton(f"🚀 {stylish('Auto SMS')}: {state}"))
    kb.add(KeyboardButton(f"🗨 {stylish('Set Auto SMS Group ID')}"))
    kb.add(KeyboardButton(f"🧹 {stylish('Del Auto SMS Group')}"))
    demo_state = "ON" if is_demo_sms_enabled() else "OFF"
    kb.add(KeyboardButton(f"🧪 {stylish('Demo SMS')}: {demo_state}"))
    kb.add(KeyboardButton(f"⏱ {stylish('Set Demo Delay')}"))
    kb.add(KeyboardButton(f"📨 {stylish('Send Demo SMS Now')}"))
    kb.add(KeyboardButton(f"↩ {stylish('Back to Settings')}"))
    return kb


def backup_keyboard():
    """Backup sub-menu — take a backup file, or restore from an uploaded file."""
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"📤 {stylish('Backup File')}"),
        KeyboardButton(f"📥 {stylish('Input File')}"),
    )
    kb.add(KeyboardButton(f"↩ {stylish('Back to Settings')}"))
    return kb


def api_management_keyboard():
    """API Management sub-menu."""
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    for api_id, defn in API_DEFINITIONS.items():
        cfg = get_api_config(api_id)
        status = "🟩" if cfg["enabled"] else "🟥"
        kb.add(KeyboardButton(f"{status} {stylish(defn['name'])}"))
    kb.add(KeyboardButton(f"↩ {stylish('Back to Settings')}"))
    return kb


def api_detail_keyboard(api_id: str):
    """Detail buttons for a specific API."""
    cfg = get_api_config(api_id)
    toggle_label = f"🟥 {stylish('Disable')}" if cfg["enabled"] else f"🟩 {stylish('Enable')}"
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"🗝 {stylish('Set Key')} [{api_id}]"),
        KeyboardButton(f"🧹 {stylish('Remove Key')} [{api_id}]"),
    )
    kb.add(KeyboardButton(f"{toggle_label} [{api_id}]"))
    if api_id == "zebrasms":
        kb.add(KeyboardButton(f"📡 {stylish('Live Access')} [{api_id}]"))
    kb.add(KeyboardButton(f"↩ {stylish('API Management')}"))
    return kb


def developer_keyboard():
    """Developer Info sub-menu (main admin only)."""
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"✏️ {stylish('Set Dev Info')}"),
        KeyboardButton(f"🧹 {stylish('Clear Dev Info')}"),
    )
    kb.add(KeyboardButton(f"↩ {stylish('Back to Settings')}"))
    return kb


def force_join_keyboard():
    """Force Join sub-menu (Task 3)."""
    fj_status = get_setting("force_join_enabled", "0")
    fj_label = f"🟩 {stylish('Force Join: ON')}" if fj_status == "1" else f"🟥 {stylish('Force Join: OFF')}"
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"➕ {stylish('Add Channel')}"),
        KeyboardButton(f"➕ {stylish('Add Group')}"),
    )
    kb.add(
        KeyboardButton(f"🧹 {stylish('Delete Channel')}"),
        KeyboardButton(f"🧹 {stylish('Delete Group')}"),
    )
    kb.add(KeyboardButton(fj_label))
    kb.add(KeyboardButton(f"↩ {stylish('Back to Settings')}"))
    return kb


def others_link_keyboard():
    """Others Link sub-menu."""
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"☎ {stylish('Support Btn')}"),
        KeyboardButton(f"🧹 {stylish('Del Support')}"),
    )
    kb.add(
        KeyboardButton(f"🗨 {stylish('OTP Group Btn')}"),
        KeyboardButton(f"🧹 {stylish('Del OTP Group')}"),
    )
    kb.add(
        KeyboardButton(f"👑 {stylish('Panel Link')}"),
        KeyboardButton(f"🧹 {stylish('Del Panel Link')}"),
    )
    kb.add(
        KeyboardButton(f"⚡ {stylish('Dev Link')}"),
        KeyboardButton(f"🧹 {stylish('Del Dev Link')}"),
    )
    kb.add(
        KeyboardButton(f"📣 {stylish('Main Channel')}"),
        KeyboardButton(f"🧹 {stylish('Del Main Channel')}"),
    )
    kb.add(
        KeyboardButton(f"🤖 {stylish('Auto SMS Bot Link')}"),
        KeyboardButton(f"🧹 {stylish('Del Auto Bot Link')}"),
    )
    kb.add(
        KeyboardButton(f"📢 {stylish('Auto SMS Channel Link')}"),
        KeyboardButton(f"🧹 {stylish('Del Auto Channel Link')}"),
    )
    kb.add(
        KeyboardButton(f"🪪 {stylish('Payment Request ID')}"),
        KeyboardButton(f"🧹 {stylish('Del Payment ID')}"),
    )
    kb.add(
        KeyboardButton(f"📨 {stylish('OTP Forward ID')}"),
        KeyboardButton(f"🧹 {stylish('Del OTP Fwd')}"),
    )
    kb.add(
        KeyboardButton(f"🦾 {stylish('Bot Name')}"),
        KeyboardButton(f"🧹 {stylish('Del Bot Name')}"),
    )
    kb.add(
        KeyboardButton(f"🕷 {stylish('Powered By')}"),
        KeyboardButton(f"🧹 {stylish('Del Powered By')}"),
    )
    kb.add(KeyboardButton(f"↩ {stylish('Back to Settings')}"))
    return kb


def ban_unban_keyboard():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"🛑 {stylish('Ban User')}"),
        KeyboardButton(f"✔️ {stylish('Unban User')}"),
    )
    kb.add(KeyboardButton(f"◀️ {stylish('Back to Admin')}"))
    return kb


def manage_services_keyboard():
    """Simplified Manage Services keyboard (Task 1)."""
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(
        KeyboardButton(f"➕ {stylish('Add Service')}"),
        KeyboardButton(f"🧹 {stylish('Delete Service')}"),
    )
    kb.add(
        KeyboardButton(f"🧾 {stylish('View Services')}"),
        KeyboardButton(f"📊 {stylish('Service Statistics')}"),
    )
    kb.add(
        KeyboardButton(f"📥 {stylish('Import Numbers')}"),
        KeyboardButton(f"🧩 {stylish('Input Range')}"),
    )
    kb.add(KeyboardButton(f"♻ {stylish('Reset Numbers')}"))
    kb.add(KeyboardButton(f"◀️ {stylish('Back to Admin')}"))
    return kb


def cancel_keyboard():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    kb.add(KeyboardButton(f"⛔ {stylish('Cancel')}"))
    return kb


def _services_buttons_keyboard(back_label="◀️ Back"):
    """Shared: list all services, two per row, with a back button."""
    with get_conn() as conn:
        services = conn.execute("SELECT * FROM services ORDER BY name").fetchall()
    if not services:
        return None
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    buttons = [KeyboardButton(f"📟 {svc['name']}") for svc in services]
    for i in range(0, len(buttons), 2):
        kb.add(*buttons[i:i + 2])
    kb.add(KeyboardButton(back_label))
    return kb


def services_list_keyboard():
    """List all services as reply buttons."""
    return _services_buttons_keyboard()


def delete_service_options_keyboard():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    kb.add(KeyboardButton(f"🧹 {stylish('Delete Entire Service')}"))
    kb.add(KeyboardButton(f"🗂 {stylish('Show Countries')}"))
    kb.add(KeyboardButton("◀️ Back"))
    return kb


def delete_country_list_keyboard(service_id):
    with get_conn() as conn:
        countries = conn.execute(
            "SELECT * FROM countries WHERE service_id=? ORDER BY name", (service_id,)
        ).fetchall()
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    for c in countries:
        kb.add(KeyboardButton(f"{c['flag']} {c['name']} +{c['code']}"))
    kb.add(KeyboardButton("◀️ Back"))
    return kb


def delete_country_options_keyboard():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    kb.add(KeyboardButton(f"🧹 {stylish('Delete Country + Numbers')}"))
    kb.add(KeyboardButton(f"🧹 {stylish('Delete Numbers Only')}"))
    kb.add(KeyboardButton("◀️ Back"))
    return kb


def confirm_keyboard_reply():
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(KeyboardButton(f"✔️ {stylish('Yes, Confirm')}"), KeyboardButton(f"⛔ {stylish('No, Cancel')}"))
    return kb


def reset_services_keyboard():
    return _services_buttons_keyboard()


def reset_countries_keyboard(service_id):
    with get_conn() as conn:
        countries = conn.execute(
            "SELECT * FROM countries WHERE service_id=? ORDER BY name", (service_id,)
        ).fetchall()
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    for c in countries:
        kb.add(KeyboardButton(f"{c['flag']} {c['name']} +{c['code']}"))
    kb.add(KeyboardButton("◀️ Back"))
    return kb


def import_service_keyboard():
    """Services keyboard for number import."""
    return _services_buttons_keyboard()


def join_channels_list_keyboard(channel_type=None):
    """List channels/groups for deletion."""
    with get_conn() as conn:
        if channel_type:
            rows = conn.execute(
                "SELECT * FROM join_channels WHERE channel_type=? ORDER BY id", (channel_type,)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM join_channels ORDER BY id").fetchall()
    if not rows:
        return None
    kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
    for ch in rows:
        kb.add(KeyboardButton(ch["channel_name"]))
    kb.add(KeyboardButton(f"⛔ {stylish('Cancel')}"))
    return kb


def withdraw_action_keyboard(request_id: int):
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("✔️ Approve", callback_data=f"awd_approve:{request_id}"),
        InlineKeyboardButton("⛔ Reject", callback_data=f"awd_reject:{request_id}"),
    )
    return kb


# ─── MEMBERSHIP CHECK ──────────────────────────────────────────────────────────
def _check_chat_member(chat_id, user_id) -> bool:
    try:
        member = bot.get_chat_member(chat_id, user_id)
        return member.status not in ("left", "kicked", "banned")
    except Exception as e:
        err = str(e).lower()
        # User is explicitly not a participant — they haven't joined
        if "user_not_participant" in err or "participant" in err or "not found" in err:
            return False
        # Do not bypass force-join on an API/configuration error.  Failing open
        # made the feature ineffective whenever Telegram returned an error.
        logger.warning(
            "Force-join membership check failed for chat=%s user=%s: %s",
            chat_id, user_id, e,
        )
        return False


def is_member(user_id):
    """Check if user has joined all required channels (if force join is enabled)."""
    if not is_force_join_enabled():
        return True
    channels = get_join_channels()
    if channels:
        return all(_check_chat_member(ch["channel_id"], user_id) for ch in channels)
    gid = get_setting("group_id", "")
    if gid:
        return _check_chat_member(gid, user_id)
    logger.error("Force join is enabled but no channel/group is configured")
    return False


# ─── MESSAGE BUILDERS ──────────────────────────────────────────────────────────
def _limit_telegram_text(value, limit: int = 2500) -> str:
    """Keep dynamic panel/email text below Telegram's message limit."""
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "…"


def build_number_card(flag, code, name, number, service, numbers=None):
    pw = stylish(_powered_by())
    safe_name = _html.escape(str(name or ""))
    safe_service = _html.escape(str(service or ""))
    sep = "━" * 32
    number_values = _number_values(number, numbers)
    number_boxes = []
    for index, num_str in enumerate(number_values, 1):
        number_boxes.append(
            f"☎ {stylish('YOUR NUMBER')} {index}\n"
            f"┌{'─'*30}┐\n"
            f"│  <code>+{num_str}</code>\n"
            f"└{'─'*30}┘"
        )
    number_section = "\n\n".join(number_boxes)
    return (
        f"🟩 {sep}\n"
        f"  🎯  {stylish('NUMBER READY')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"❖ 📱 {stylish('SERVICE')}  ➤  <b>{safe_service}</b>\n"
        f"❖ 🌍 {stylish('COUNTRY')}  ➤  {flag} <b>{safe_name}</b>\n"
        f"❖ ⏳ {stylish('STATUS')}   ➤  🟢 {stylish('WAITING FOR OTP...')}"
        f"</blockquote>\n\n"
        f"{number_section}\n"
        f"💡 এই নম্বরে {safe_service}-এর verification SMS আসবে।\n"
        f"<i>👆 নম্বরে tap করে দ্রুত copy করুন • OTP এলে সঙ্গে সঙ্গে দেখানো হবে</i>\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔷 {stylish('POWERED BY')} <b>{pw}</b>"
    )


def build_otp_card(flag, code, name, number, service, otp_msg, otp_code):
    safe_otp = _html.escape(str(otp_code)) if otp_code else "N/A"
    safe_msg = _html.escape(_limit_telegram_text(otp_msg)) if otp_msg else "N/A"
    safe_name = _html.escape(str(name or "Unknown"))
    safe_service = _html.escape(str(service or "Unknown"))
    pw = stylish(_powered_by())
    sep = "━" * 32
    return (
        f"🔔 {sep}\n"
        f"  🔐  {stylish('OTP ARRIVED')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"❖ 📱 {stylish('SERVICE')}  ➤  <b>{safe_service}</b>\n"
        f"❖ 🌍 {stylish('COUNTRY')}  ➤  {flag} <b>{safe_name}</b>\n"
        f"❖ ☎ {stylish('NUMBER')}   ➤  <code>+{number}</code>\n"
        f"❖ 🔑 {stylish('OTP CODE')} ➤  <code>{safe_otp}</code>"
        f"</blockquote>\n\n"
        f"🧾 {stylish('SMS DETAILS')}\n"
        f"<blockquote>{safe_msg}</blockquote>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔷 {stylish('POWERED BY')} <b>{pw}</b>"
    )


def build_otp_card_with_balance(flag, code, name, number, service, otp_msg, otp_code, balance: float):
    safe_otp = _html.escape(str(otp_code)) if otp_code else "N/A"
    safe_msg = _html.escape(_limit_telegram_text(otp_msg)) if otp_msg else "N/A"
    safe_name = _html.escape(str(name or "Unknown"))
    safe_service = _html.escape(str(service or "Unknown"))
    pw = stylish(_powered_by())
    earn = get_otp_earn()
    sep = "━" * 32
    return (
        f"🔔 {sep}\n"
        f"  🔐  {stylish('OTP ARRIVED')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"❖ 📱 {stylish('SERVICE')}   ➤  <b>{safe_service}</b>\n"
        f"❖ 🌍 {stylish('COUNTRY')}   ➤  {flag} <b>{safe_name}</b>\n"
        f"❖ ☎ {stylish('NUMBER')}     ➤  <code>+{number}</code>\n"
        f"❖ 🔑 {stylish('OTP CODE')}   ➤  <code>{safe_otp}</code>\n"
        f"❖ 💎 {stylish('OTP EARNED')} ➤  +{earn:.2f} BDT\n"
        f"❖ 💰 {stylish('BALANCE')}    ➤  {balance:.2f} BDT"
        f"</blockquote>\n\n"
        f"🧾 {stylish('SMS DETAILS')}\n"
        f"<blockquote>{safe_msg}</blockquote>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔷 {stylish('POWERED BY')} <b>{pw}</b>"
    )


def build_timeout_card(flag, code, name, number, service, numbers=None):
    """Same visual design as build_number_card, but shows the NO OTP RECEIVED / timed-out state."""
    pw = stylish(_powered_by())
    safe_name = _html.escape(str(name or ""))
    safe_service = _html.escape(str(service or ""))
    sep = "━" * 32
    number_values = _number_values(number, numbers)
    number_boxes = []
    for index, num_str in enumerate(number_values, 1):
        number_boxes.append(
            f"❖ ☎ {stylish('NUMBER')} {index} ➤ <code>+{num_str}</code>"
        )
    number_section = "\n".join(number_boxes)
    return (
        f"🟥 {sep}\n"
        f"  ⛔  {stylish('NO OTP RECEIVED')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"❖ 📟 {stylish('SERVICE')}  ➤  <b>{safe_service}</b>\n"
        f"❖ 🗺 {stylish('COUNTRY')}  ➤  {flag} <b>{safe_name}</b>\n"
        f"{number_section}\n"
        f"❖ ⌛ {stylish('STATUS')}   ➤  ❗️ {stylish('TIMED OUT')}"
        f"</blockquote>\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔷 {stylish('POWERED BY')} <b>{pw}</b>"
    )


def otp_card_keyboard(otp_code):
    """Inline keyboard below an OTP card sent to the USER — COPY OTP button."""
    kb = InlineKeyboardMarkup(row_width=1)
    safe = str(otp_code).strip() if otp_code else ""
    if safe and safe.isdigit() and len(safe) <= 8:
        label = f"🧾 {stylish('COPY OTP')} : {safe}"
        if CopyTextButton is not None:
            try:
                kb.add(InlineKeyboardButton(label, copy_text=CopyTextButton(text=safe)))
                return kb
            except Exception as e:
                logger.warning(
                    "CopyTextButton unavailable; using fallback (%s)",
                    type(e).__name__,
                )
        cb = f"otp_copy:{safe}"
        if len(cb.encode()) <= 64:
            kb.add(InlineKeyboardButton(label, callback_data=cb))
            return kb
    return None


def normalize_link(raw: str) -> str:
    """Turn any admin-entered contact value into a valid Telegram-safe https URL."""
    link = str(raw or "").strip()
    if not link:
        return ""
    if link.startswith("@"):
        return "https://t.me/" + link[1:].strip()
    if link.startswith(("http://", "https://", "tg://")):
        return link
    if re.fullmatch(r"[A-Za-z0-9_]{4,64}", link):
        return "https://t.me/" + link
    return "https://" + link.lstrip("/")


def _send_support_message(chat_id):
    """Send the Support card. Always answers the user, even if no link is set."""
    link = normalize_link(get_setting("support_link", ""))
    admin_uname = str(get_setting("support_username", "") or "").strip()
    if not link and admin_uname:
        link = normalize_link(admin_uname)
    text_body = (
        f"☎ <b>{stylish('Support')}</b>\n\n"
        f"<blockquote>{stylish('Need help? Tap the button below to contact our support team.')}</blockquote>"
    )
    if not link:
        bot.send_message(
            chat_id,
            f"☎ <b>{stylish('Support')}</b>\n\n"
            f"<blockquote>{stylish('Support link is not configured yet. Please try again later.')}</blockquote>",
        )
        return
    kb = InlineKeyboardMarkup()
    try:
        kb.add(InlineKeyboardButton(f"🔵 🛡️ {stylish('Contact Support')}", url=link))
        bot.send_message(chat_id, text_body, reply_markup=kb)
    except Exception as e:
        logger.warning("Support button setup failed (%s)", type(e).__name__)
        bot.send_message(chat_id, f"☎ <b>{stylish('Support')}:</b> {_html.escape(link)}")


def otp_group_keyboard():
    """Buttons shown on forwarded OTP cards."""
    panel_link = normalize_link(get_setting("panel_link", ""))
    dev_link = get_setting("dev_link", "")
    channel_link = normalize_link(get_setting("main_channel_link", ""))
    kb = InlineKeyboardMarkup(row_width=1)
    has_btn = False
    if panel_link:
        kb.add(InlineKeyboardButton(f"👑 {stylish('GO TO PANEL')} 👑", url=panel_link))
        has_btn = True
    if channel_link:
        kb.add(InlineKeyboardButton(f"📣 {stylish('GO TO CHANNEL')} 📣", url=channel_link))
        has_btn = True
    if dev_link:
        kb.add(InlineKeyboardButton(f"⚡ {stylish('BOT DEVELOPER')} ⚡", url=dev_link))
        has_btn = True
    return kb if has_btn else None


def build_balance_text(stats: dict) -> str:
    earn = get_otp_earn()
    min_wd = get_min_withdraw()
    sep = "━" * 28
    return (
        f"💲 {sep}\n"
        f"   💎  {stylish('MY WALLET')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"❖ 📊 {stylish('Today OTP')}     ➤  <b>{stats['today_otp']}</b>\n"
        f"❖ 📈 {stylish('Total OTP')}     ➤  <b>{stats['total_otp']}</b>\n"
        f"❖ 💵 {stylish('Per OTP Earn')}  ➤  <b>{earn:.2f} BDT</b>\n\n"
        f"❖ 💲 {stylish('Today Income')}  ➤  <b>{stats['today_income']:.2f} BDT</b>\n"
        f"❖ 🏦 {stylish('Total Income')}  ➤  <b>{stats['total_income']:.2f} BDT</b>\n\n"
        f"❖ 🪪 {stylish('Balance')}       ➤  <b>{stats['balance']:.2f} BDT</b>\n"
        f"❖ 🔏 {stylish('Min Withdraw')}  ➤  <b>{min_wd:.0f} BDT</b>"
        f"</blockquote>\n"
        f"━━━━━━━━━━━━━━━━━━"
    )


def _row_value(row, key, default=None):
    """Safely read a column from a sqlite3.Row / dict / None."""
    if row is None:
        return default
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def build_profile_text(user, db_user, stats):
    sep = "━" * 28
    joined_ts = _row_value(db_user, "joined_at", 0)
    try:
        joined = datetime.fromtimestamp(float(joined_ts)).strftime("%d %b %Y") if joined_ts else "N/A"
    except (ValueError, OSError, OverflowError, TypeError):
        joined = "N/A"
    return (
        f"🧑 {sep}\n"
        f"   🌟  {stylish('MY PROFILE')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"❖ 🏷 {stylish('Name')}       ➤  <b>{user.first_name or 'N/A'}</b>\n"
        f"❖ 🆔 {stylish('User ID')}    ➤  <code>{user.id}</code>\n"
        f"❖ 📛 {stylish('Username')}   ➤  @{user.username or 'N/A'}\n"
        f"❖ 📅 {stylish('Joined')}     ➤  {joined}\n\n"
        f"❖ ☎ {stylish('Numbers')}    ➤  <b>{_row_value(db_user, 'numbers_generated', 0)}</b>\n"
        f"❖ 🔢 {stylish('OTPs Got')}   ➤  <b>{_row_value(db_user, 'otps_received', 0)}</b>\n\n"
        f"❖ 🪪 {stylish('Balance')}    ➤  <b>{stats['balance']:.2f} BDT</b>\n"
        f"❖ 🏦 {stylish('Income')}     ➤  <b>{stats['total_income']:.2f} BDT</b>"
        f"</blockquote>\n"
        f"━━━━━━━━━━━━━━━━━━"
    )


def _referral_details(user_id: int) -> tuple[str, int, float, float]:
    bot_info = bot.get_me()
    ref_link = f"https://t.me/{bot_info.username}?start=ref_{user_id}"
    with get_conn() as conn:
        ref_count = conn.execute(
            "SELECT COUNT(*) AS c FROM users WHERE referred_by=?", (user_id,)
        ).fetchone()
        wallet = conn.execute(
            "SELECT referral_income FROM wallet WHERE user_id=?", (user_id,)
        ).fetchone()
    count = int(ref_count["c"] if ref_count else 0)
    earned = float(wallet["referral_income"] if wallet else 0.0)
    return ref_link, count, get_referral_bonus(), earned


def _send_referral_panel(chat_id: int, user_id: int):
    ref_link, count, bonus, earned = _referral_details(user_id)
    sep = "━" * 30
    bonus_text = f"{bonus:.2f} BDT" if bonus > 0 else "Admin সেট করেনি"
    bot.send_message(
        chat_id,
        f"🎁 {sep}\n"
        f"   🤝  {stylish('REFER & EARN')}\n"
        f"{sep}\n\n"
        f"🌟 বন্ধুদের এই bot-এ invite করুন এবং valid referral হলে bonus পান!\n\n"
        f"<blockquote>"
        f"❖ 💎 <b>প্রতি valid referral</b> ➤ <b>{bonus_text}</b>\n"
        f"❖ 👥 {stylish('Your Referrals')}    ➤  <b>{count}</b>\n"
        f"❖ 💰 {stylish('Referral Earned')}   ➤  <b>{earned:.2f} BDT</b>\n"
        f"❖ 🔗 {stylish('Your Link')}         ➤\n"
        f"<code>{ref_link}</code>"
        f"</blockquote>\n\n"
        f"🪄 <b>যেভাবে bonus পাবেন:</b>\n"
        f"① নিচের Share button দিয়ে link পাঠান\n"
        f"② বন্ধু আপনার link দিয়ে bot-এ Start করবে\n"
        f"③ referral valid হলে bonus আপনার wallet-এ যোগ হবে\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔷 {stylish('POWERED BY')} <b>{stylish(_powered_by())}</b>",
        reply_markup=referral_inline_keyboard(ref_link),
    )


# ─── SHARED ACTION HELPERS ─────────────────────────────────────────────────────
def _show_api_detail(chat_id, api_id: str):
    """Show detail info for one API with manage buttons."""
    defn = API_DEFINITIONS.get(api_id, {})
    cfg = get_api_config(api_id)
    status = "🟩 ON" if cfg["enabled"] else "🟥 OFF"
    key_preview = cfg["key"][:12] + "..." if len(cfg["key"]) > 12 else (cfg["key"] or "Using default key from code")
    bot.send_message(
        chat_id,
        f"🗝 <b>{defn.get('name', api_id)}</b>\n\nStatus: <b>{status}</b>\n"
        f"🗝 Key: <code>{key_preview}</code>",
        reply_markup=api_detail_keyboard(api_id),
    )


def _show_dashboard(chat_id, is_main_admin=False):
    with get_conn() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_nums = conn.execute("SELECT SUM(numbers_generated) FROM users").fetchone()[0] or 0
        total_otps = conn.execute("SELECT COUNT(*) FROM otps").fetchone()[0] or 0
        active_24h = conn.execute(
            "SELECT COUNT(*) FROM users WHERE last_active_at >= strftime('%s','now') - 86400"
        ).fetchone()[0]
        top_users = conn.execute(
            "SELECT u.first_name, w.total_otp FROM users u "
            "LEFT JOIN wallet w ON u.id=w.user_id ORDER BY w.total_otp DESC LIMIT 3"
        ).fetchall()
        pending_wd = conn.execute(
            "SELECT COUNT(*) FROM withdraw_requests WHERE status='pending'"
        ).fetchone()[0]
    medals = ["🥇", "🥈", "🥉"]
    top_str = ""
    for i, u in enumerate(top_users):
        top_str += f"\n{medals[i]} {u['first_name'] or 'User'} — {u['total_otp'] or 0} OTPs"
    sep = "━" * 30
    bot.send_message(
        chat_id,
        f"📊 {sep}\n"
        f"   👑  {stylish('ADMIN DASHBOARD')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"❖ 👥 {stylish('Total Users')}    ➤  <b>{total_users}</b>\n"
        f"❖ ☎ {stylish('Numbers Given')}  ➤  <b>{total_nums}</b>\n"
        f"❖ 🔢 {stylish('OTPs Received')}  ➤  <b>{total_otps}</b>\n"
        f"❖ 🟩 {stylish('Active 24h')}     ➤  <b>{active_24h}</b>\n"
        f"❖ 🪙 {stylish('Pending WD')}     ➤  <b>{pending_wd}</b>"
        f"</blockquote>\n\n"
        f"🏆 <b>{stylish('TOP OTP EARNERS')}</b>{top_str}\n\n"
        f"━━━━━━━━━━━━━━━━━━",
        reply_markup=admin_keyboard(is_main_admin=is_main_admin),
    )


def _show_service_stats(chat_id):
    with get_conn() as conn:
        total_services = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
        total_countries = conn.execute("SELECT COUNT(*) FROM countries").fetchone()[0]
        total_numbers = conn.execute("SELECT COUNT(*) FROM numbers").fetchone()[0]
        used_numbers = conn.execute("SELECT COUNT(*) FROM numbers WHERE assigned=1").fetchone()[0]
        avail_numbers = total_numbers - used_numbers
        active_alloc = conn.execute(
            "SELECT COUNT(*) FROM allocations WHERE otp_received=0 AND timed_out=0"
        ).fetchone()[0]
        total_otps = conn.execute("SELECT COUNT(*) FROM otps").fetchone()[0]
        services = conn.execute("SELECT * FROM services ORDER BY name").fetchall()
        breakdown = ""
        for svc in services:
            s_countries = conn.execute(
                "SELECT COUNT(*) FROM countries WHERE service_id=?", (svc["id"],)
            ).fetchone()[0]
            s_total = conn.execute(
                "SELECT COUNT(*) FROM numbers WHERE country_id IN (SELECT id FROM countries WHERE service_id=?)",
                (svc["id"],),
            ).fetchone()[0]
            s_used = conn.execute(
                "SELECT COUNT(*) FROM numbers WHERE assigned=1 AND country_id IN (SELECT id FROM countries WHERE service_id=?)",
                (svc["id"],),
            ).fetchone()[0]
            s_avail = s_total - s_used
            breakdown += (
                f"\n<b>{svc['name']}</b>: {s_countries} countries | "
                f"{s_avail} avail / {s_used} used / {s_total} total"
            )
    bot.send_message(
        chat_id,
        "<blockquote>📊 SERVICE STATISTICS</blockquote>\n\n"
        f"📟 <b>Total Services:</b> {total_services}\n"
        f"🗺 <b>Total Countries:</b> {total_countries}\n\n"
        f"☎ <b>Total Numbers:</b> {total_numbers}\n"
        f"✔️ <b>Used Numbers:</b> {used_numbers}\n"
        f"🟩 <b>Available Numbers:</b> {avail_numbers}\n\n"
        f"⌛ <b>Active Allocations:</b> {active_alloc}\n"
        f"🔐 <b>Total OTPs Delivered:</b> {total_otps}"
        f"\n\n{'─'*30}{breakdown}",
        reply_markup=manage_services_keyboard(),
    )


def _send_admin_live_panel(chat_id):
    """Send the live active-allocations panel to admin when they do /start."""
    sep = "━" * 30
    with get_conn() as conn:
        active = conn.execute("""
            SELECT a.number, a.service_name, a.country_flag, a.country_name,
                   a.allocated_at, a.otp_received, a.otp_text,
                   u.first_name, u.username, u.id as uid
            FROM allocations a
            LEFT JOIN users u ON u.id = a.user_id
            WHERE a.otp_received = 0 AND (a.timed_out IS NULL OR a.timed_out = 0)
            ORDER BY a.allocated_at DESC
            LIMIT 15
        """).fetchall()
    lines = [
        f"📡 {sep}",
        f"   🟥 {stylish('LIVE ACTIVE NUMBERS · latest 15')}",
        f"{sep}\n",
    ]
    if active:
        for a in active:
            fname = _html.escape((a["first_name"] or "User")[:40])
            uname = ("@" + a["username"][:40]) if a["username"] else f"ID:{a['uid']}"
            flag = a["country_flag"] or "🛰"
            t = datetime.fromtimestamp(a["allocated_at"]).strftime("%d/%m %H:%M") if a["allocated_at"] else "N/A"
            num = str(a["number"])
            lines.append(
                f"🧑 <b>{fname}</b>  <i>({uname})</i>\n"
                f"   ☎ <code>+{num[:32]}</code>  {flag} {_html.escape((a['country_name'] or '')[:40])}\n"
                f"   📟 {_html.escape((a['service_name'] or 'N/A')[:40])}  🕰 {t}\n"
                f"   ⌛ <i>Waiting for OTP...</i>"
            )
    else:
        lines.append("   <i>এখন কোনো active number নেই।</i>")
    lines += [
        f"\n{sep}",
        f"🔷 {stylish('POWERED BY')} <b>{stylish(_powered_by())}</b>",
        "\n<i>⚡ যখনই কেউ number নেবে, instant notification আসবে।</i>",
    ]
    try:
        bot.send_message(chat_id, "\n".join(lines))
    except Exception as e:
        logger.warning("Live panel send failed (%s)", type(e).__name__)


def _notify_admin_live(user_id, fname, uname, number, service, flag, country):
    """Instant live notification to all admins in admin_live_mode when a number is taken."""
    if not admin_live_mode:
        return
    sep = "━" * 28
    num_str = str(number)
    uname_display = ("@" + uname) if uname else f"ID:{user_id}"
    text = (
        f"🚨 {sep}\n"
        f"   📲 {stylish('NUMBER TAKEN — LIVE')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"🧑 {stylish('USER')}     ➤  <b>{_html.escape(fname)}</b>  <i>({_html.escape(uname_display)})</i>\n"
        f"📟 {stylish('SERVICE')}  ➤  {_html.escape(service)}\n"
        f"🗺 {stylish('COUNTRY')} ➤  {flag} {_html.escape(country)}\n"
        f"⌛ {stylish('STATUS')}  ➤  🕰 Waiting for OTP..."
        f"</blockquote>\n\n"
        f"☎ {stylish('NUMBER')}\n"
        f"┌{'─'*26}┐\n"
        f"│  <code>+{num_str}</code>\n"
        f"└{'─'*26}┘\n"
        f"━━━━━━━━━━━━━━━━━━"
    )
    for admin_id in list(admin_live_mode):
        try:
            sent = bot.send_message(admin_id, text)
            # Track msg_id per number per admin for later OTP update
            if num_str not in admin_live_msg_ids:
                # Keep this tracking map bounded (oldest entries drop first).
                while len(admin_live_msg_ids) >= 500:
                    try:
                        admin_live_msg_ids.pop(next(iter(admin_live_msg_ids)))
                    except (StopIteration, KeyError):
                        break
                admin_live_msg_ids[num_str] = {}
            admin_live_msg_ids[num_str][admin_id] = sent.message_id
        except Exception as e:
            logger.warning("Admin live number notification failed (%s)", type(e).__name__)


def _notify_admin_live_otp(number, otp_code, msg_text, fname, uname, user_id, service, flag, country):
    """When OTP arrives: delete old 'number taken' admin message, send new OTP notification."""
    if not admin_live_mode:
        return
    num_str = str(number).lstrip("+")
    sep = "━" * 28
    safe_otp = _html.escape(str(otp_code)) if otp_code else "N/A"
    safe_msg = _html.escape(str(msg_text)) if msg_text else "N/A"
    uname_display = ("@" + uname) if uname else f"ID:{user_id}"
    otp_text = (
        f"✨ {sep}\n"
        f"   🔐 {stylish('LIVE OTP ALERT')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"🧑 {stylish('USER')}     ➤  <b>{_html.escape(fname)}</b>  <i>({_html.escape(uname_display)})</i>\n"
        f"📱 {stylish('SERVICE')}  ➤  {_html.escape(service)}\n"
        f"🌍 {stylish('COUNTRY')} ➤  {flag} {_html.escape(country)}\n"
        f"☎️ {stylish('NUMBER')}  ➤  <code>+{num_str}</code>"
        f"</blockquote>\n\n"
        f"🔑 {stylish('OTP CODE')}\n"
        f"┌{'─'*26}┐\n"
        f"│  <code>{safe_otp}</code>\n"
        f"└{'─'*26}┘\n\n"
        f"🧾 {stylish('SMS DETAILS')}\n"
        f"<blockquote>{safe_msg}</blockquote>\n"
        f"━━━━━━━━━━━━━━━━━━"
    )
    prev_msgs = admin_live_msg_ids.pop(num_str, {})
    for admin_id in list(admin_live_mode):
        # Delete old "number taken" message for this admin
        old_msg_id = prev_msgs.get(admin_id)
        if old_msg_id:
            try:
                bot.delete_message(admin_id, old_msg_id)
            except Exception:
                pass
        # Send fresh OTP notification
        try:
            bot.send_message(admin_id, otp_text)
        except Exception as e:
            logger.warning("Admin live OTP notification failed (%s)", type(e).__name__)


def _send_welcome(chat_id, first_name, user_id):
    """Send welcome message with reply keyboard."""
    bn = stylish(_bot_name())
    pw = stylish(_powered_by())
    safe_first_name = _html.escape(str(first_name or "User"))
    sep = "━" * 32
    earn = get_otp_earn()
    bot.send_message(
        chat_id,
        f"🌟 {sep}\n"
        f"   👋  {stylish('WELCOME')} {safe_first_name}\n"
        f"{sep}\n\n"
        f"✨ আপনার প্রয়োজনীয় verification service এক জায়গায়।\n\n"
        f"<blockquote>"
        f"🤖 {stylish('BOT')}       ➤  {bn}\n"
        f"💎 {stylish('PER OTP')}  ➤  {earn:.2f} BDT\n"
        f"📲 {stylish('GET NUMBER')} ➤  service-এর নম্বর নিন\n"
        f"🔐 {stylish('OTP DELIVERY')} ➤  OTP auto deliver হবে\n"
        f"📬 {stylish('TEMP MAIL')} ➤  mail-এর শুধু OTP দেখুন\n"
        f"🎁 {stylish('REFER & EARN')} ➤  Profile থেকে bonus নিন"
        f"</blockquote>\n\n"
        f"💡 নিচের menu থেকে কাজ বেছে নিন—সবকিছু সহজ ও দ্রুত।\n\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🔷 {stylish('POWERED BY')} <b>{pw}</b>",
        reply_markup=welcome_keyboard(is_admin_user=is_admin(user_id)),
    )


# ─── NUMBER ASSIGNMENT ────────────────────────────────────────────────────────
def assign_number_to_user(user_id, chat_id, country_id):
    if not is_member(user_id):
        bot.send_message(
            chat_id,
            _join_prompt_text(),
            reply_markup=join_keyboard(),
        )
        return

    with get_conn() as conn:
        country = conn.execute("SELECT * FROM countries WHERE id=?", (country_id,)).fetchone()
        if not country:
            bot.send_message(
                chat_id, f"⛔ {stylish('Country not found.')}",
                reply_markup=welcome_keyboard(is_admin_user=is_admin(user_id)),
            )
            return
        service = conn.execute("SELECT * FROM services WHERE id=?", (country["service_id"],)).fetchone()

    range_id = (country["range_id"] or "").strip()
    if range_id:
        _assign_range_number_to_user(user_id, chat_id, country, service, range_id)
        return

    # Reserve exactly one row atomically.  SELECT followed by an unconditional
    # UPDATE allowed two concurrent users to receive the same number.
    with get_conn() as conn:
        number_row = conn.execute(
            "SELECT * FROM numbers WHERE country_id=? AND assigned=0 ORDER BY id LIMIT 1",
            (country_id,),
        ).fetchone()
        if not number_row:
            bot.send_message(
                chat_id, f"⛔ {stylish('No number is available for this country.')}",
                reply_markup=welcome_keyboard(is_admin_user=is_admin(user_id)),
            )
            return
        claimed = conn.execute(
            """
            UPDATE numbers
            SET assigned=1, assigned_to=?, assigned_at=strftime('%s','now')
            WHERE id=? AND assigned=0
            """,
            (user_id, number_row["id"]),
        )
        if claimed.rowcount != 1:
            bot.send_message(
                chat_id, f"⛔ {stylish('Number was just taken. Please try again.')}",
                reply_markup=welcome_keyboard(is_admin_user=is_admin(user_id)),
            )
            return

    number_rows = [number_row]
    try:
        text = build_number_card(
            country["flag"], country["code"], country["name"],
            number_row["number"], service["name"],
            numbers=[number_row["number"]],
        )
        msg = bot.send_message(
            chat_id,
            text,
            reply_markup=number_card_inline_keyboard(
                numbers=[number_row["number"]]
            ),
        )
    except Exception:
        with get_conn() as conn:
            conn.execute(
                "UPDATE numbers SET assigned=0, assigned_to=NULL, assigned_at=NULL "
                "WHERE id=? AND assigned_to=?",
                (number_row["id"], user_id),
            )
        raise

    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO allocations
                (user_id, number_id, number, service_name, country_name,
                 country_flag, country_code, message_id)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                user_id, number_row["id"], number_row["number"],
                service["name"], country["name"], country["flag"],
                country["code"], msg.message_id,
            ))
            conn.execute(
                "UPDATE users SET numbers_generated=numbers_generated+1 WHERE id=?",
                (user_id,),
            )
            _u = conn.execute(
                "SELECT first_name, username FROM users WHERE id=?",
                (user_id,),
            ).fetchone()
            _fn = (_u["first_name"] if _u else None) or "User"
            _un = (_u["username"] if _u else None)
    except Exception as exc:
        logger.error("Could not persist allocation (%s)", type(exc).__name__)
        with get_conn() as conn:
            conn.execute(
                "UPDATE numbers SET assigned=0, assigned_to=NULL, assigned_at=NULL "
                "WHERE id=? AND assigned_to=?",
                (number_row["id"], user_id),
            )
        raise
    for number_row in number_rows:
        _notify_admin_live(
            user_id, _fn, _un,
            number_row["number"], service["name"],
            country["flag"], country["name"],
        )


def _assign_range_number_to_user(user_id, chat_id, country, service, range_id):
    """Allocate a number dynamically via YesMS for an admin-configured range-based country."""
    loading_msg = bot.send_message(
        chat_id, f"⌛ {stylish('Getting number for')} <b>{_html.escape(country['name'])}</b>...",
    )
    full_numbers = fetch_api_numbers(range_id)
    if len(full_numbers) < 1:
        retry_kb = InlineKeyboardMarkup()
        retry_kb.add(InlineKeyboardButton(f"♻ {stylish('Try Again')}", callback_data=f"custom_range_retry:{range_id}"))
        try:
            bot.edit_message_text(
                f"⛔ {stylish('No number is available for')} {_html.escape(country['name'])}. {stylish('Please try again later.')}",
                chat_id=chat_id,
                message_id=loading_msg.message_id,
                reply_markup=retry_kb,
            )
        except Exception:
            pass
        return

    full_number = full_numbers[0]
    text_card = build_number_card(
        country["flag"], country["code"], country["name"], full_number,
        service["name"], numbers=full_numbers,
    )
    final_message_id = loading_msg.message_id
    try:
        bot.edit_message_text(
            text_card, chat_id=chat_id, message_id=loading_msg.message_id,
            reply_markup=number_card_inline_keyboard(numbers=full_numbers),
        )
    except Exception:
        sent = bot.send_message(chat_id, text_card, reply_markup=number_card_inline_keyboard(numbers=full_numbers))
        final_message_id = sent.message_id

    with get_conn() as conn:
        for full_number in full_numbers:
            conn.execute(
                """INSERT INTO allocations
                   (user_id, number_id, number, service_name, country_name,
                    country_flag, country_code, message_id, rid)
                   VALUES (?,NULL,?,?,?,?,?,?,?)""",
                (
                    user_id, full_number, service["name"], country["name"],
                    country["flag"], country["code"], final_message_id, range_id,
                ),
            )
        conn.execute(
            "UPDATE users SET numbers_generated=numbers_generated+1 WHERE id=?",
            (user_id,),
        )
        _u2 = conn.execute("SELECT first_name, username FROM users WHERE id=?", (user_id,)).fetchone()
        _fn2 = (_u2["first_name"] if _u2 else None) or "User"
        _un2 = (_u2["username"] if _u2 else None)
    _notify_admin_live(
        user_id, _fn2, _un2,
        full_numbers[0], service["name"],
        country["flag"], country["name"],
    )


# ─── OTP DELIVERY ─────────────────────────────────────────────────────────────
_otp_delivery_lock = threading.Lock()


def _deliver_otp(alloc, msg_text: str, msg_id: int):
    """Deliver a group OTP through the same idempotent path as API OTPs."""
    number = normalize_number(alloc["number"])
    return _deliver_otp_api(
        alloc, msg_text, str(msg_id),
        msg_hash(number, str(msg_id), msg_text),
        source="group",
    )


def _deliver_otp_api(alloc, msg_text: str, dt: str, mhash_val: str,
                     source: str = "api"):
    """Deliver one OTP exactly once and credit it exactly once.

    The previous implementation credited before checking/recording a
    delivery, so repeated panel polling could pay the same OTP repeatedly.
    A process lock plus a provisional unique ledger row makes the operation
    idempotent for all panels and the source group.
    """
    number = normalize_number(alloc["number"])
    msg_text = _limit_telegram_text(msg_text)
    with _otp_delivery_lock:
        with get_conn() as conn:
            current = conn.execute(
                "SELECT otp_received FROM allocations WHERE id=?",
                (alloc["id"],),
            ).fetchone()
            if not current or current["otp_received"]:
                return False
            # `otps` is the durable history and has a unique msg_hash. Consult
            # it before claiming the short-lived ledger row so an old panel
            # response cannot re-deliver or re-credit the same OTP later.
            already_recorded = conn.execute(
                "SELECT 1 FROM otps WHERE msg_hash=?",
                (mhash_val,),
            ).fetchone()
            if already_recorded:
                return False
            claimed = conn.execute(
                """
                INSERT OR IGNORE INTO delivered_messages
                (msg_hash, user_id)
                VALUES (?, ?)
                """,
                (mhash_val, alloc["user_id"]),
            )
            if claimed.rowcount != 1:
                return False

        otp_code = extract_otp(msg_text)
        # Show the post-credit balance without crediting until Telegram send
        # succeeds.
        stats = get_wallet_stats(alloc["user_id"])
        display_balance = stats["balance"] + get_otp_earn()
        otp_card = build_otp_card_with_balance(
            alloc["country_flag"], alloc["country_code"], alloc["country_name"],
            alloc["number"], alloc["service_name"], msg_text, otp_code,
            display_balance,
        )
        try:
            bot.send_message(alloc["user_id"], otp_card)
        except Exception as exc:
            logger.warning("OTP delivery error (%s): %s", source, exc)
            with get_conn() as conn:
                conn.execute(
                    "DELETE FROM delivered_messages WHERE msg_hash=?",
                    (mhash_val,),
                )
            return False

        try:
            with get_conn() as conn:
                updated = conn.execute(
                    """
                    UPDATE allocations
                    SET otp_received=1, otp_text=?
                    WHERE id=? AND otp_received=0
                    """,
                    (msg_text, alloc["id"]),
                )
                if updated.rowcount != 1:
                    return False
                _credit_otp_earn_in_conn(conn, alloc["user_id"])
                conn.execute(
                    """
                    INSERT OR IGNORE INTO otps
                    (msg_hash, user_id, number, message, otp_code, cli)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (mhash_val, alloc["user_id"], number, msg_text,
                     otp_code, source),
                )
                conn.execute(
                    "UPDATE users SET otps_received=otps_received+1 WHERE id=?",
                    (alloc["user_id"],),
                )
                _u = conn.execute(
                    "SELECT first_name, username FROM users WHERE id=?",
                    (alloc["user_id"],),
                ).fetchone()
                fn = (_u["first_name"] if _u else None) or "User"
                un = (_u["username"] if _u else None)
        except Exception as exc:
            logger.error("OTP ledger transaction failed (%s)", type(exc).__name__)
            return False

        _forward_otp(msg_text, alloc["number"], dict(alloc))
        _notify_admin_live_otp(
            number, otp_code, msg_text, fn, un, alloc["user_id"],
            alloc.get("service_name", ""), alloc.get("country_flag", ""),
            alloc.get("country_name", ""),
        )
        return True


_auto_sms_seen = set()
_auto_sms_lock = threading.Lock()


def _auto_sms_status_text() -> str:
    state = "🟩 ON" if is_auto_sms_enabled() else "🟥 OFF"
    chat = get_setting("auto_sms_chat_id", "Not set")
    demo = "🟩 ON" if is_demo_sms_enabled() else "🟥 OFF"
    delay = fmt_delay(get_demo_sms_delay())
    return (
        f"🚀 <b>{stylish('Auto SMS')}</b>\n\n"
        f"Status: <b>{state}</b>\n"
        f"🗨 Group/Channel ID: <code>{chat}</code>\n"
        f"🧪 Demo SMS: <b>{demo}</b>\n"
        f"⏱ Demo Delay: <b>{delay}</b>  (min 3 sec, max 60 min)\n\n"
        f"<i>Every real SMS/OTP from the connected panels "
        f"(ZebraSMS, YesMS, StexSMS, FastXOTPs, VoltXSMS) that belongs to the "
        f"panel's TOP ranges/countries is forwarded here automatically, with "
        f"GO TO BOT and GO TO CHANNEL buttons.</i>"
    )


def auto_sms_inline_keyboard():
    """Buttons under an Auto SMS card: GO TO BOT + GO TO CHANNEL (admin links)."""
    bot_link = normalize_link(get_setting("auto_sms_bot_link", "") or get_setting("bot_link", ""))
    channel_link = normalize_link(
        get_setting("auto_sms_channel_link", "") or get_setting("main_channel_link", "")
    )
    panel_link = normalize_link(get_setting("panel_link", ""))
    kb = InlineKeyboardMarkup(row_width=2)
    row = []
    if bot_link:
        row.append(InlineKeyboardButton(f"🤖 {stylish('GO TO BOT')}", url=bot_link))
    if channel_link:
        row.append(InlineKeyboardButton(f"📣 {stylish('GO TO CHANNEL')}", url=channel_link))
    has = bool(row)
    if row:
        kb.add(*row)
    if panel_link:
        kb.add(InlineKeyboardButton(f"👑 {stylish('NUMBER PANEL')} 👑", url=panel_link))
        has = True
    return kb if has else None


# ─── AUTO SMS ENGINE (top range / top country of the connected panel) ─────────
_auto_sms_targets = {"ranges": [], "countries": set(), "ts": 0.0}
_auto_sms_targets_lock = threading.Lock()
AUTO_SMS_TARGET_TTL = 180          # refresh top range/country every 3 min
AUTO_SMS_ENGINE_INTERVAL = 45      # allocate on a top range this often


def _auto_sms_panel_ids() -> list:
    """Every SMS panel the admin actually added (key saved + enabled)."""
    return [
        pid for pid in ("zebrasms", "yesms", "stexsms", "fastxotps", "voltxsms")
        if get_api_config(pid)["enabled"] and get_api_config(pid)["key"]
    ]


def _refresh_auto_sms_targets(force: bool = False):
    """Work out the TOP ranges + TOP countries of the connected panels."""
    now = time.time()
    with _auto_sms_targets_lock:
        if not force and now - _auto_sms_targets["ts"] < AUTO_SMS_TARGET_TTL:
            return _auto_sms_targets["ranges"], _auto_sms_targets["countries"]
    range_counts, country_counts = {}, {}
    for panel_id in _auto_sms_panel_ids():
        try:
            for rng, country_raw in _build_traffic_rows_from_panel(panel_id):
                rng_digits = re.sub(r"[Xx\s]+$", "", str(rng or ""))
                if rng_digits:
                    range_counts[rng_digits] = range_counts.get(rng_digits, 0) + 1
                _flag, cname = extract_flag_from_name(str(country_raw or ""))
                if cname:
                    country_counts[cname] = country_counts.get(cname, 0) + 1
        except Exception as e:
            logger.warning("Auto SMS target scan failed (%s): %s", panel_id, e)
    top_ranges = [r for r, _c in sorted(range_counts.items(), key=lambda x: -x[1])[:12]]
    top_countries = {c for c, _n in sorted(country_counts.items(), key=lambda x: -x[1])[:6]}
    with _auto_sms_targets_lock:
        _auto_sms_targets["ranges"] = top_ranges
        _auto_sms_targets["countries"] = top_countries
        _auto_sms_targets["ts"] = now
    logger.info("Auto SMS targets → ranges=%s countries=%s", top_ranges[:5], list(top_countries)[:5])
    return top_ranges, top_countries


def _auto_sms_matches_top(number: str) -> bool:
    """True when the SMS belongs to a top range / top country of the panel."""
    ranges, countries = _refresh_auto_sms_targets()
    if not ranges and not countries:
        return True                      # nothing learned yet → forward everything
    num = normalize_number(number)
    for rng in ranges:
        if num.startswith(rng):
            return True
    try:
        _flag, cname = extract_flag_from_name(range_to_country_name(num))
        if cname and cname in countries:
            return True
    except Exception:
        pass
    return False


def _auto_sms_engine_loop():
    """Keep the Auto SMS group alive with REAL panel traffic.

    Every cycle the bot picks the currently hottest range of the connected
    panel and allocates a number on it through the normal allocation path, so
    genuine OTPs keep arriving and get forwarded to the group automatically.
    """
    logger.info("Auto SMS engine started.")
    idx = 0
    while True:
        try:
            if is_auto_sms_enabled() and str(get_setting("auto_sms_chat_id", "") or "").strip():
                ranges, _countries = _refresh_auto_sms_targets()
                if ranges:
                    rid = ranges[idx % len(ranges)]
                    idx += 1
                    try:
                        data = fetch_api_number(rid)
                        if data:
                            logger.info("Auto SMS engine holding %s on top range %s",
                                        _number_from_api_data(data), rid)
                    except Exception as e:
                        logger.warning("Auto SMS engine allocation error (%s): %s", rid, e)
        except Exception as e:
            logger.warning("Auto SMS engine loop error: %s", e)
        time.sleep(AUTO_SMS_ENGINE_INTERVAL)


def _build_auto_sms_card(number: str, msg_text: str, panel_name: str = "") -> str:
    raw_num = str(number).strip().lstrip("+")
    masked = (raw_num[:-3] + "XXX") if len(raw_num) >= 4 else raw_num
    country_full = range_to_country_name(raw_num)
    flag, cname = extract_flag_from_name(country_full)
    otp_code = extract_otp(msg_text) or "N/A"
    service = detect_service_from_message(msg_text)
    sep = "━" * 30
    return (
        f"✨ {sep}\n"
        f"   🔐  {stylish('LIVE OTP ALERT')}\n"
        f"{sep}\n\n"
        f"<blockquote>"
        f"❖ 🌍 {stylish('COUNTRY')}  ➤  {flag} {cname}\n"
        f"❖ 📱 {stylish('SERVICE')}  ➤  {service}\n"
        f"❖ 🧭 {stylish('RANGE')}    ➤  <code>{masked}</code>\n"
        f"❖ 🔑 {stylish('OTP CODE')} ➤  <code>{otp_code}</code>"
        f"</blockquote>\n\n"
        f"🧾 {stylish('SMS DETAILS')}\n"
        f"<blockquote>{_html.escape(str(msg_text))}</blockquote>\n"
        f"━━━━━━━━━━━━━━━━━\n"
        f"🔷 {stylish('POWERED BY')} <b>{stylish(_powered_by())}</b>"
    )


def detect_service_from_message(msg_text: str) -> str:
    """Best-effort service name detection from the SMS body."""
    low = str(msg_text or "").lower()
    known = (
        ("whatsapp", "WhatsApp"), ("facebook", "Facebook"), ("instagram", "Instagram"),
        ("telegram", "Telegram"), ("tiktok", "TikTok"), ("google", "Google"),
        ("imo", "IMO"), ("viber", "Viber"), ("signal", "Signal"), ("twitter", "Twitter"),
        ("x.com", "X"), ("openai", "OpenAI"), ("chatgpt", "ChatGPT"), ("amazon", "Amazon"),
        ("paypal", "PayPal"), ("netflix", "Netflix"), ("uber", "Uber"), ("binance", "Binance"),
        ("microsoft", "Microsoft"), ("apple", "Apple"), ("snapchat", "Snapchat"),
        ("linkedin", "LinkedIn"), ("discord", "Discord"), ("yalla", "Yalla"),
    )
    for key, label in known:
        if key in low:
            return label
    return "OTHERS"


def _auto_forward_panel_sms(panel_name: str, number: str, msg_text: str, otp_id: str = ""):
    """Forward EVERY real SMS captured from a panel to the Auto SMS group."""
    if not is_auto_sms_enabled():
        return
    target = str(get_setting("auto_sms_chat_id", "") or "").strip()
    if not target or not number or not msg_text:
        return
    try:
        if not _auto_sms_matches_top(number):
            logger.info("Auto SMS skip: number is outside configured ranges")
            return
    except Exception as e:
        logger.warning("Auto SMS top-range check failed (%s)", type(e).__name__)
    key = hashlib.sha256(f"{normalize_number(number)}|{otp_id}|{msg_text}".encode()).hexdigest()
    with _auto_sms_lock:
        if key in _auto_sms_seen:
            return
        # Check the durable ledger too. This prevents duplicate forwards after
        # a Railway restart, while still allowing a retry after a send failure.
        with get_conn() as conn:
            if conn.execute(
                "SELECT 1 FROM auto_sms_deliveries WHERE delivery_key=?", (key,)
            ).fetchone():
                _auto_sms_seen.add(key)
                return
    try:
        kb = auto_sms_inline_keyboard()
        card = _build_auto_sms_card(number, msg_text, panel_name)
        if kb:
            bot.send_message(int(target), card, reply_markup=kb)
        else:
            bot.send_message(int(target), card)
        # Only mark delivered after Telegram accepted the message.
        with _auto_sms_lock:
            with get_conn() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO auto_sms_deliveries (delivery_key)
                       VALUES (?)""",
                    (key,),
                )
            _auto_sms_seen.add(key)
            if len(_auto_sms_seen) > 5000:
                # Bounded cache; the durable ledger still prevents duplicates.
                _auto_sms_seen.clear()
    except Exception as e:
        logger.warning("Auto SMS forward failed for %s (%s)", panel_name, type(e).__name__)


# ─── DEMO SMS (admin-timed, looks exactly like a real panel OTP) ──────────────
DEMO_SMS_MIN_DELAY = 3          # seconds (hard minimum)
DEMO_SMS_MAX_DELAY = 3600       # seconds (max 60 minutes)
DEMO_SMS_DEFAULT_DELAY = 180    # 3 minutes


def is_demo_sms_enabled() -> bool:
    return str(get_setting("auto_sms_demo_enabled", "0")) == "1"


def get_demo_sms_delay() -> int:
    try:
        val = int(str(get_setting("auto_sms_demo_delay", DEMO_SMS_DEFAULT_DELAY)).strip())
    except Exception:
        val = DEMO_SMS_DEFAULT_DELAY
    return max(DEMO_SMS_MIN_DELAY, min(DEMO_SMS_MAX_DELAY, val))


def fmt_delay(sec) -> str:
    sec = int(sec)
    if sec >= 60 and sec % 60 == 0:
        return f"{sec // 60} min"
    if sec > 60:
        return f"{sec // 60} min {sec % 60} sec"
    return f"{sec} sec"


_DEMO_TEMPLATES = (
    "{code} is your WhatsApp code. Don't share this code with others",
    "<#> {code} is your WhatsApp code",
    "Login code: {code}. Do not give this code to anyone, even if they say they are from Telegram!",
    "{code} is your Facebook confirmation code",
    "{code} is your Instagram code. Don't share it.",
    "[TikTok] {code} is your verification code",
    "G-{code} is your Google verification code.",
    "<#> imo verification code: {code}",
    "Your Signal verification code: {code}",
    "Your Viber code is {code}. It expires in 10 minutes.",
    "{code} is your Snapchat code. Snapchat will never call or text you for this code.",
    "Your Discord verification code is {code}",
    "[Binance] Verification code: {code}. Never share this code.",
    "Your ChatGPT code is {code}",
    "Your Uber code is {code}. Reply STOP to unsubscribe.",
    "PayPal: {code} is your security code. Don't share it.",
    "Microsoft account security code: {code}",
    "{code} is your Amazon OTP. Do not share it with anyone.",
)


def _demo_number_from_targets() -> str:
    """Build a realistic number from the panels' own TOP ranges."""
    base = ""
    try:
        ranges, _countries = _refresh_auto_sms_targets()
        if ranges:
            base = re.sub(r"\D", "", secrets.choice(ranges))
    except Exception:
        base = ""
    if not base:
        try:
            with get_conn() as conn:
                row = conn.execute(
                    "SELECT number FROM numbers ORDER BY RANDOM() LIMIT 1"
                ).fetchone()
            if row:
                base = re.sub(r"\D", "", str(row[0]))[:7]
        except Exception:
            base = ""
    if not base:
        base = secrets.choice(("8801712", "2613880", "212612", "96650", "234701", "639171"))
    need = max(4, 12 - len(base))
    tail = "".join(secrets.choice("0123456789") for _ in range(need))
    return (base + tail)[:15]


def _build_demo_sms():
    """Return (number, message) that looks exactly like a real panel OTP."""
    number = _demo_number_from_targets()
    template = secrets.choice(_DEMO_TEMPLATES)
    digits = secrets.choice((4, 5, 6, 6, 6))
    code = "".join(secrets.choice("0123456789") for _ in range(digits))
    if digits == 6 and secrets.choice((0, 1)):
        code = f"{code[:3]}-{code[3:]}"
    return number, template.format(code=code)


def _send_demo_sms() -> bool:
    target = str(get_setting("auto_sms_chat_id", "") or "").strip()
    if not target:
        return False
    number, msg_text = _build_demo_sms()
    try:
        kb = auto_sms_inline_keyboard()
        card = _build_auto_sms_card(number, msg_text, "")
        if kb:
            bot.send_message(int(target), card, reply_markup=kb)
        else:
            bot.send_message(int(target), card)
        return True
    except Exception as e:
        logger.warning("Demo SMS send error: %s", e)
        return False


def _demo_sms_loop():
    """Send one demo OTP to the Auto SMS group every <admin delay> seconds."""
    logger.info("Demo SMS engine started.")
    next_at = 0.0
    while True:
        try:
            if is_auto_sms_enabled() and is_demo_sms_enabled():
                if time.time() >= next_at:
                    if _send_demo_sms():
                        logger.info("Demo SMS sent (next in %ss).", get_demo_sms_delay())
                    next_at = time.time() + get_demo_sms_delay()
                time.sleep(1)
            else:
                next_at = 0.0
                time.sleep(5)          # feature off: idle instead of spinning
        except Exception as e:
            logger.warning("Demo SMS loop error: %s", e)
            time.sleep(5)


def _forward_otp(msg_text: str, number: str, alloc: dict = None):
    """Forward OTP to the configured otp_forward_chat_id in stylish format."""
    fwd_id = get_setting("otp_forward_chat_id")
    if not fwd_id:
        return
    try:
        otp_code = extract_otp(msg_text) if msg_text else ""
        if alloc:
            country_flag = alloc.get("country_flag", "")
            country_name = alloc.get("country_name", "")
            service_name = alloc.get("service_name", "")
            raw_num = str(alloc.get("number", number)).lstrip("+")
        else:
            country_flag = ""
            country_name = ""
            service_name = ""
            raw_num = str(number).lstrip("+")
        # Build masked range: show first digits then XXX for last 3
        if len(raw_num) >= 4:
            masked = raw_num[:-3] + "XXX"
        else:
            masked = raw_num
        country_display = f"{country_flag} {country_name}".strip() if country_name else raw_num
        sep = "━" * 30
        fwd_msg = (
            f"✨ {sep}\n"
            f"   🔐  {stylish('OTP RECEIVED')}\n"
            f"{sep}\n\n"
            f"<blockquote>"
            f"❖ 🌍 {stylish('COUNTRY')}  ➤  {country_display}\n"
            f"❖ 📱 {stylish('SERVICE')}  ➤  {service_name.upper() if service_name else 'N/A'}\n"
            f"❖ 🧭 {stylish('RANGE')}    ➤  <code>{masked}</code>\n"
            f"❖ 🔑 {stylish('OTP CODE')} ➤  <code>{otp_code if otp_code else 'N/A'}</code>"
            f"</blockquote>\n\n"
            f"🧾 {stylish('SMS DETAILS')}\n"
            f"<blockquote>{_html.escape(str(msg_text))}</blockquote>\n"
            f"━━━━━━━━━━━━━━━━━"
        )
        grp_kb = otp_group_keyboard()
        if grp_kb:
            bot.send_message(int(fwd_id), fwd_msg, reply_markup=grp_kb)
        else:
            bot.send_message(int(fwd_id), fwd_msg)
    except Exception as e:
        logger.warning("OTP forward failed (%s)", type(e).__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# COMMANDS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@bot.message_handler(commands=["start"])
def cmd_start(message):
    # Only respond in private chats — prevents welcome message from going to groups
    if message.chat.type != "private":
        return
    user = message.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.send_message(message.chat.id, f"🛑 {stylish('You are banned from using this bot.')}")
        return
    # ── Handle referral link (/start ref_USERID) ─────────────────────
    args = message.text.split()[1] if len(message.text.split()) > 1 else ""
    if args.startswith("ref_"):
        try:
            referrer_id = int(args[4:])
            applied, bonus = apply_referral(user.id, referrer_id)
            if applied:
                try:
                    bot.send_message(
                        referrer_id,
                        "╭━━━ 🎊 <b>REFERRAL BONUS</b> ━━━╮\n"
                        "┃\n"
                        "┃ ✅ আপনার referral link দিয়ে নতুন একজন user joined করেছে!\n"
                        f"┃ 💎 Bonus credited: <b>+{bonus:.2f} BDT</b>\n"
                        "┃\n"
                        "╰━━━━━━━━━━━━━━━━━━━━╯\n"
                        "💰 Bonus আপনার wallet-এ যোগ হয়েছে।",
                    )
                except Exception as exc:
                    logger.info("Referral notification skipped for %s: %s", referrer_id, exc)
                bot.send_message(
                    user.id,
                    "╭━━━ ✅ <b>REFERRAL CONFIRMED</b> ━━━╮\n"
                    "┃\n"
                    "┃ আপনি referral link দিয়ে সফলভাবে joined করেছেন।\n"
                    "┃ এখন bot-এর সব service ব্যবহার করতে পারবেন।\n"
                    "┃\n"
                    "╰━━━━━━━━━━━━━━━━━━━━╯",
                )
        except (TypeError, ValueError):
            logger.info("Ignored an invalid referral payload")
    if not is_member(user.id):
        bot.send_message(
            message.chat.id,
            _join_prompt_text(),
            reply_markup=join_keyboard(),
        )
        return
    first_name = user.first_name or "User"
    if is_admin(user.id) and user.id not in admin_user_mode:
        admin_user_mode.discard(user.id)   # exit user mode if active
        admin_live_mode.add(user.id)        # enable live notifications
        _send_welcome(message.chat.id, first_name, user.id)
        _send_admin_live_panel(message.chat.id)
    else:
        _send_welcome(message.chat.id, first_name, user.id)


@bot.message_handler(commands=["tempmail", "checkmail"])
def cmd_temp_mail(message):
    if message.chat.type != "private":
        return
    user = message.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        return
    if message.text.split()[0].lower().startswith("/checkmail"):
        _send_temp_mail_check_result(message.chat.id, user.id)
        return
    _send_generated_temp_mail(message.chat.id, user.id)


@bot.message_handler(commands=["searchotp"])
def cmd_searchotp(message):
    """Search own OTP history; administrators can search all numbers."""
    if message.chat.type != "private":
        return
    user = message.from_user
    if not user:
        return
    upsert_user(user)
    if not is_admin(user.id):
        db_user = get_user(user.id)
        if db_user and db_user["is_banned"]:
            return

    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.send_message(message.chat.id, "🔍 <b>Usage:</b> <code>/searchotp 8801XXXXXXXX</code>")
        return
    query = re.sub(r"\D", "", parts[1])
    if not query:
        bot.send_message(message.chat.id, "⛔ Please enter a phone number using digits only.")
        return
    with get_conn() as conn:
        if is_admin(user.id):
            rows = conn.execute(
                """SELECT number, otp_code, message, received_at FROM otps
                   WHERE number LIKE ? ORDER BY received_at DESC LIMIT 5""",
                (f"%{query}%",),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT number, otp_code, message, received_at FROM otps
                   WHERE user_id=? AND number LIKE ?
                   ORDER BY received_at DESC LIMIT 5""",
                (user.id, f"%{query}%"),
            ).fetchall()
    sep = "━" * 30
    if not rows:
        bot.send_message(message.chat.id,
            f"🔍 {sep}\n   {stylish('SEARCH OTP')}\n{sep}\n\n"
            f"⛔ <b>{query}</b> এর জন্য কোনো OTP পাওয়া যায়নি।")
        return
    result_lines = ""
    for r in rows:
        t = datetime.fromtimestamp(r["received_at"]).strftime("%d/%m %H:%M") if r["received_at"] else "N/A"
        otp = _html.escape(str(r["otp_code"])) if r["otp_code"] else "N/A"
        result_lines += f"\n❖ 🔢 OTP: <code>{otp}</code>  🕰 {t}"
    bot.send_message(
        message.chat.id,
        f"🔍 {sep}\n"
        f"   {stylish('SEARCH OTP')}\n"
        f"{sep}\n\n"
        f"☎ Number: <code>+{query}</code>\n"
        f"<blockquote>{result_lines}</blockquote>\n"
        f"━━━━━━━━━━━━━━━━━━",
    )


@bot.message_handler(commands=["user"])
def cmd_user(message):
    """Admin enters user mode: no live feed, no admin panel."""
    if message.chat.type != "private":
        return
    user = message.from_user
    if not is_admin(user.id):
        cmd_start(message)
        return
    admin_live_mode.discard(user.id)
    admin_states.pop(user.id, None)
    admin_user_mode.add(user.id)
    first_name = user.first_name or "User"
    # Send exact same welcome panel as a normal user (no admin notice at all)
    _send_welcome(message.chat.id, first_name, user.id)


@bot.message_handler(commands=["ban"])
def cmd_ban(message):
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, f"🛡️ {stylish('Admin access required.')}")
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id, f"ℹ️ {stylish('Usage: /ban <user_id>')}")
        return
    try:
        uid = int(parts[1])
    except (TypeError, ValueError):
        bot.send_message(message.chat.id, f"❎️ {stylish('Invalid user ID. Use numbers only.')}")
        return
    with get_conn() as conn:
        conn.execute("UPDATE users SET is_banned=1 WHERE id=?", (uid,))
    bot.send_message(message.chat.id, f"✔️ User {uid} banned.")


@bot.message_handler(commands=["unban"])
def cmd_unban(message):
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, f"🛡️ {stylish('Admin access required.')}")
        return
    parts = message.text.split()
    if len(parts) < 2:
        bot.send_message(message.chat.id, f"ℹ️ {stylish('Usage: /unban <user_id>')}")
        return
    try:
        uid = int(parts[1])
    except (TypeError, ValueError):
        bot.send_message(message.chat.id, f"❎️ {stylish('Invalid user ID. Use numbers only.')}")
        return
    with get_conn() as conn:
        conn.execute("UPDATE users SET is_banned=0 WHERE id=?", (uid,))
    bot.send_message(message.chat.id, f"✔️ User {uid} unbanned.")


@bot.message_handler(commands=["broadcast"])
def cmd_broadcast(message):
    if not is_admin(message.from_user.id):
        bot.send_message(message.chat.id, f"🛡️ {stylish('Admin access required.')}")
        return
    text = message.text[len("/broadcast"):].strip()
    sent = 0
    for user_ids in _iter_unbanned_user_id_batches():
        for user_id in user_ids:
            try:
                if message.reply_to_message:
                    bot.forward_message(
                        user_id, message.chat.id, message.reply_to_message.message_id
                    )
                else:
                    bot.send_message(user_id, text or "📣 Broadcast message.")
                sent += 1
            except Exception:
                pass
    bot.send_message(message.chat.id, f"✔️ Broadcast sent to {sent} users.")


def _iter_unbanned_user_id_batches(batch_size: int = 250):
    """Yield a bounded number of unbanned user IDs at a time."""
    batch_size = max(1, min(int(batch_size), 1000))
    with get_conn() as conn:
        max_id = conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM users"
        ).fetchone()[0]
    last_id = 0
    while last_id < max_id:
        with get_conn() as conn:
            rows = conn.execute(
                """SELECT id FROM users
                   WHERE id>? AND id<=? AND is_banned=0
                   ORDER BY id LIMIT ?""",
                (last_id, max_id, batch_size),
            ).fetchall()
        if not rows:
            break
        last_id = rows[-1]["id"]
        yield [row["id"] for row in rows]


@bot.message_handler(commands=["admin"])
def cmd_admin(message):
    if not is_admin(message.from_user.id):
        return
    _show_admin_monitor(message.chat.id, message.from_user.id)


def _show_admin_monitor(chat_id, admin_user_id):
    """Show admin monitoring panel: recent numbers taken + OTPs received."""
    now = int(time.time())
    with get_conn() as conn:
        recent_allocs = conn.execute("""
            SELECT a.id, a.number, a.service_name, a.country_flag, a.country_name,
                   a.allocated_at, a.otp_received, a.otp_text,
                   u.first_name, u.username, u.id as uid
            FROM allocations a
            LEFT JOIN users u ON u.id = a.user_id
            ORDER BY a.allocated_at DESC LIMIT 10
        """).fetchall()
        recent_otps = conn.execute("""
            SELECT o.number, o.otp_code, o.message, o.received_at,
                   u.first_name, u.username, u.id as uid
            FROM otps o
            LEFT JOIN users u ON u.id = o.user_id
            ORDER BY o.received_at DESC LIMIT 8
        """).fetchall()
        stats_row = conn.execute("""
            SELECT COUNT(*) as total_allocs,
                   SUM(CASE WHEN otp_received=1 THEN 1 ELSE 0 END) as got_otp,
                   SUM(CASE WHEN timed_out=1 AND otp_received=0 THEN 1 ELSE 0 END) as timed_out
            FROM allocations WHERE allocated_at > ? - 86400
        """, (now,)).fetchone()
    sep = "━" * 28
    lines = [
        "🔐 " + sep,
        "   👁️  " + stylish("ADMIN MONITOR"),
        sep + "\n",
        "📊 <b>" + stylish("LAST 24H STATS") + "</b>",
        "<blockquote>",
        "❖ ☎ " + stylish("Numbers Taken") + "  ➤  <b>" + str(stats_row["total_allocs"] or 0) + "</b>",
        "❖ ✔️ " + stylish("Got OTP") + "         ➤  <b>" + str(stats_row["got_otp"] or 0) + "</b>",
        "❖ ⏰ " + stylish("Timed Out") + "       ➤  <b>" + str(stats_row["timed_out"] or 0) + "</b>",
        "</blockquote>\n",
        "📟 <b>" + stylish("RECENT NUMBERS TAKEN") + "</b>",
        "<blockquote>",
    ]
    if recent_allocs:
        for a in recent_allocs[:8]:
            fname = _html.escape(a["first_name"] or "User")
            uname = ("@" + a["username"]) if a["username"] else ("ID:" + str(a["uid"]))
            t = datetime.fromtimestamp(a["allocated_at"]).strftime("%d/%m %H:%M") if a["allocated_at"] else "N/A"
            flag = a["country_flag"] or "🛰"
            otp_status = "✔️" if a["otp_received"] else "⌛"
            lines.append(
                otp_status + " <b>" + fname + "</b> (" + uname + ")\n"
                "   ☎ <code>+" + str(a["number"]) + "</code>  " + flag + "  📟 " + (a["service_name"] or "N/A") + "\n"
                "   🕰 " + t
            )
    else:
        lines.append("   <i>এখনো কোনো number নেওয়া হয়নি।</i>")
    lines += ["</blockquote>\n", "🔢 <b>" + stylish("RECENT OTPs RECEIVED") + "</b>", "<blockquote>"]
    if recent_otps:
        for o in recent_otps:
            fname = _html.escape(o["first_name"] or "User")
            uname = ("@" + o["username"]) if o["username"] else ("ID:" + str(o["uid"]))
            t = datetime.fromtimestamp(o["received_at"]).strftime("%d/%m %H:%M") if o["received_at"] else "N/A"
            otp_code = _html.escape(str(o["otp_code"])) if o["otp_code"] else "N/A"
            lines.append(
                "🧑 <b>" + fname + "</b> (" + uname + ")\n"
                "   ☎ <code>+" + str(o["number"]) + "</code>  🔢 <code>" + otp_code + "</code>\n"
                "   🕰 " + t
            )
    else:
        lines.append("   <i>এখনো কোনো OTP পাওয়া যায়নি।</i>")
    lines += [
        "</blockquote>",
        "\n" + "━" * 28,
        "🔷 " + stylish("POWERED BY") + " <b>" + stylish(_powered_by()) + "</b>",
    ]
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("☎ সব Numbers", callback_data="monitor_all_numbers"),
        InlineKeyboardButton("🔢 সব OTPs", callback_data="monitor_all_otps"),
    )
    kb.add(InlineKeyboardButton("🔐 Admin Panel খুলুন", callback_data="monitor_open_admin"))
    try:
        bot.send_message(chat_id, "\n".join(lines), reply_markup=kb)
    except Exception as e:
        logger.warning("Monitor send error: " + str(e))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CALLBACK HANDLERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _send_monitor_rows(chat_id, title, rows):
    header = f"🧾 <b>{stylish(title)}</b>\n━━━━━━━━━━━━━━━━━━━━"
    if not rows:
        bot.send_message(chat_id, header + "\n\n<i>No records found.</i>")
        return
    blocks = []
    for row in rows:
        blocks.append(row)
    message = header
    for block in blocks:
        candidate = message + "\n\n" + block
        if len(candidate) > 3900:
            bot.send_message(chat_id, message)
            message = header + "\n\n" + block
        else:
            message = candidate
    bot.send_message(chat_id, message)


@bot.callback_query_handler(func=lambda c: c.data in ("monitor_all_numbers", "monitor_all_otps", "monitor_open_admin"))
def cb_admin_monitor_actions(call):
    if not is_admin(call.from_user.id):
        bot.answer_callback_query(call.id, "Admin access required.", show_alert=True)
        return
    bot.answer_callback_query(call.id)
    if call.data == "monitor_open_admin":
        admin_live_mode.discard(call.from_user.id)
        admin_states.pop(call.from_user.id, None)
        bot.send_message(
            call.message.chat.id,
            f"🎛️ <b>{stylish('ADMIN PANEL')}</b>",
            reply_markup=admin_keyboard(call.from_user.id == ADMIN_ID),
        )
        return
    with get_conn() as conn:
        if call.data == "monitor_all_numbers":
            rows = conn.execute("""
                SELECT a.number, a.service_name, a.country_flag, a.country_name,
                       a.allocated_at, a.otp_received, u.first_name, u.username, u.id AS uid
                FROM allocations a
                LEFT JOIN users u ON u.id = a.user_id
                ORDER BY a.allocated_at DESC LIMIT 100
            """).fetchall()
            items = []
            for row in rows:
                user_name = _html.escape(row["first_name"] or row["username"] or str(row["uid"]) or "User")
                number = _html.escape(str(row["number"] or "N/A"))
                service = _html.escape(str(row["service_name"] or "N/A"))
                country = _html.escape(str(row["country_name"] or "N/A"))
                when = datetime.fromtimestamp(row["allocated_at"]).strftime("%d/%m/%Y %H:%M") if row["allocated_at"] else "N/A"
                status = "✔️" if row["otp_received"] else "⌛"
                items.append(f"{status} <b>{user_name}</b> · <code>+{number}</code>\n{row['country_flag'] or '🛰'} {country} · {service} · 🕰 {when}")
            title = "LATEST 100 NUMBERS"
        else:
            rows = conn.execute("""
                SELECT o.number, o.otp_code, o.message, o.received_at,
                       u.first_name, u.username, u.id AS uid
                FROM otps o
                LEFT JOIN users u ON u.id = o.user_id
                ORDER BY o.received_at DESC LIMIT 100
            """).fetchall()
            items = []
            for row in rows:
                user_name = _html.escape(row["first_name"] or row["username"] or str(row["uid"]) or "User")
                number = _html.escape(str(row["number"] or "N/A"))
                otp = _html.escape(str(row["otp_code"] or "N/A"))
                when = datetime.fromtimestamp(row["received_at"]).strftime("%d/%m/%Y %H:%M") if row["received_at"] else "N/A"
                items.append(f"🔐 <b>{user_name}</b> · <code>+{number}</code>\n🔢 <code>{otp}</code> · 🕰 {when}")
            title = "LATEST 100 OTPs"
    _send_monitor_rows(call.message.chat.id, title, items)


@bot.callback_query_handler(func=lambda c: c.data == "usr_check_join")
def cb_check_join(call):
    user = call.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.answer_callback_query(call.id)
        bot.send_message(call.message.chat.id, f"🛑 {stylish('You are banned.')}")
        return
    if not is_member(user.id):
        bot.answer_callback_query(call.id, f"❗️ {stylish('You have not joined yet!')}", show_alert=True)
        return
    bot.answer_callback_query(call.id)
    # Delete the join prompt message immediately after successful join
    try:
        bot.delete_message(call.message.chat.id, call.message.message_id)
    except Exception:
        pass
    first_name = user.first_name or "User"
    _send_welcome(call.message.chat.id, first_name, user.id)


@bot.callback_query_handler(func=lambda c: c.data.startswith("sel_service:") or c.data == "sel_service_back")
def cb_select_service(call):
    """Handle inline service selection."""
    user = call.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.answer_callback_query(call.id)
        return

    if call.data == "sel_service_back":
        bot.answer_callback_query(call.id)
        user_states.pop(user.id, None)
        try:
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
        except Exception:
            pass
        return

    svc_id = int(call.data.split(":")[1])
    with get_conn() as conn:
        svc = conn.execute("SELECT * FROM services WHERE id=?", (svc_id,)).fetchone()
    if not svc:
        bot.answer_callback_query(call.id, stylish("Service not found."), show_alert=True)
        return

    ustate = user_states.get(user.id, {})
    ustate["service_id"] = svc["id"]
    ustate["service_name"] = svc["name"]
    ustate["step"] = "selecting_country"
    user_states[user.id] = ustate

    bot.answer_callback_query(call.id)
    kb = user_countries_inline_keyboard(svc["id"])
    try:
        bot.edit_message_text(
            f"🗺 <b>{stylish('Select a Country')}:</b>",
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=kb,
        )
    except Exception:
        pass


@bot.callback_query_handler(func=lambda c: c.data.startswith("sel_country:") or c.data == "sel_country_back")
def cb_select_country(call):
    """Handle inline country selection."""
    user = call.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.answer_callback_query(call.id)
        return

    if call.data == "sel_country_back":
        ustate = user_states.get(user.id, {})
        ustate["step"] = "selecting_service"
        user_states[user.id] = ustate
        bot.answer_callback_query(call.id)
        kb = user_services_inline_keyboard()
        if not kb:
            user_states.pop(user.id, None)
            try:
                bot.edit_message_text(
                    f"⛔ {stylish('No services available.')}",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=None,
                )
            except Exception:
                pass
            return
        try:
            bot.edit_message_text(
                f"📟 <b>{stylish('Select a Service')}:</b>",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=kb,
            )
        except Exception:
            pass
        return

    ustate = user_states.get(user.id)
    if not ustate or ustate.get("step") != "selecting_country":
        bot.answer_callback_query(call.id, stylish("Session expired. Please start again."), show_alert=True)
        return

    country_id = int(call.data.split(":")[1])
    bot.answer_callback_query(call.id)
    user_states.pop(user.id, None)
    # Delete the "Select a Country" message entirely
    try:
        bot.delete_message(call.message.chat.id, call.message.message_id)
    except Exception:
        pass
    assign_number_to_user(user.id, call.message.chat.id, country_id)


@bot.callback_query_handler(func=lambda c: c.data.startswith("otp_copy:"))
def cb_otp_copy(call):
    """Fallback COPY OTP handler (used only if native copy_text buttons aren't supported).
    Shows the OTP in an alert popup so the user can select and copy it manually."""
    try:
        otp_val = call.data.split(":", 1)[1]
        bot.answer_callback_query(call.id, text=f"OTP: {otp_val}", show_alert=True)
    except Exception as e:
        logger.error("OTP copy failed (%s)", type(e).__name__)


@bot.callback_query_handler(func=lambda c: c.data.startswith("num_copy:"))
def cb_num_copy(call):
    """Fallback COPY NUMBER handler — shows number in alert popup for manual copy."""
    try:
        num_val = call.data.split(":", 1)[1]
        bot.answer_callback_query(call.id, text=f"+{num_val}", show_alert=True)
    except Exception as e:
        logger.error("Number copy failed (%s)", type(e).__name__)


@bot.callback_query_handler(func=lambda c: c.data in ("profile_referral", "referral_copy"))
def cb_profile_referral(call):
    user = call.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.answer_callback_query(call.id, stylish("You are banned."), show_alert=True)
        return
    if call.data == "profile_referral":
        bot.answer_callback_query(call.id)
        _send_referral_panel(call.message.chat.id, user.id)
        return
    ref_link, _, _, _ = _referral_details(user.id)
    bot.answer_callback_query(call.id, "Referral link sent below.")
    bot.send_message(
        call.message.chat.id,
        "🔗 <b>YOUR REFERRAL LINK</b>\n\n"
        "এই link share করে valid referral হলে bonus পাবেন।\n\n"
        f"<code>{ref_link}</code>",
    )


@bot.callback_query_handler(func=lambda c: c.data == "num_change")
def cb_number_card_actions(call):
    """Handle CHANGE — delete old card and assign new number from same country/range."""
    user = call.from_user
    bot.answer_callback_query(call.id)

    with get_conn() as conn:
        alloc = conn.execute(
            "SELECT * FROM allocations WHERE user_id=? AND message_id=? ORDER BY id LIMIT 1",
            (user.id, call.message.message_id),
        ).fetchone()

    # Delete old number card message
    try:
        bot.delete_message(call.message.chat.id, call.message.message_id)
    except Exception:
        pass

    if not alloc:
        kb = user_services_inline_keyboard()
        user_states[user.id] = {"step": "selecting_service"}
        bot.send_message(call.message.chat.id, f"📟 <b>{stylish('Select a Service')}:</b>", reply_markup=kb)
        return

    # Cancel old allocation — DB number stays assigned=1 permanently (never re-used)
    with get_conn() as conn:
        conn.execute(
            "UPDATE allocations SET timed_out=1 WHERE user_id=? AND message_id=?",
            (user.id, call.message.message_id),
        )

    # OTP Work number (rid stored) → re-fetch from same range, send as NEW message
    stored_rid = alloc["rid"] if alloc["rid"] else ""
    if not alloc["number_id"] and stored_rid:
        flag_prefix = alloc["country_flag"] or ""
        country_with_flag = f"{flag_prefix} {alloc['country_name']}".strip() if flag_prefix else alloc["country_name"]
        entry = {
            "country": country_with_flag,
            "service_sid": alloc["service_name"],
        }
        _otpwork_fetch_number(call, entry, stored_rid, send_new=True)
        return

    # DB number → same country
    with get_conn() as conn:
        country_row = conn.execute(
            """SELECT c.id FROM countries c
               JOIN services s ON s.id = c.service_id
               WHERE s.name=? AND c.name=? AND c.code=?
               LIMIT 1""",
            (alloc["service_name"], alloc["country_name"], alloc["country_code"]),
        ).fetchone()

    if country_row:
        assign_number_to_user(user.id, call.message.chat.id, country_row["id"])
    else:
        kb = user_services_inline_keyboard()
        user_states[user.id] = {"step": "selecting_service"}
        bot.send_message(call.message.chat.id, f"📟 <b>{stylish('Select a Service')}:</b>", reply_markup=kb)


@bot.callback_query_handler(func=lambda c: c.data == "num_change_range")
def cb_num_change_range(call):
    """Change Range — no longer available (live country/range browsing was removed)."""
    bot.answer_callback_query(call.id, f"❗️ {stylish('Change Range is no longer available.')}", show_alert=True)


def _submit_withdraw_request(user, chat_id, method, phone, amount):
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        bot.send_message(chat_id, "⛔ Invalid withdrawal amount.")
        return False
    if not math.isfinite(amount) or amount <= 0:
        bot.send_message(chat_id, "⛔ Withdrawal amount must be positive.")
        return False
    if amount < get_min_withdraw():
        bot.send_message(chat_id, "⛔ Amount is below the current minimum withdrawal.")
        return False
    phone = str(phone or "").strip()
    method = str(method or "").strip()
    if not phone or len(phone) > 80:
        bot.send_message(chat_id, "⛔ Invalid payment number.")
        return False
    with get_conn() as conn:
        valid_method = conn.execute(
            "SELECT 1 FROM withdraw_methods WHERE name=? AND is_enabled=1",
            (method,),
        ).fetchone()
        pending = conn.execute(
            "SELECT 1 FROM withdraw_requests WHERE user_id=? AND status='pending'",
            (user.id,),
        ).fetchone()
        if not valid_method or pending:
            bot.send_message(chat_id, "⛔ This withdrawal session is no longer valid.")
            return False
        updated = conn.execute(
            """
            UPDATE wallet
            SET balance=balance-?, pending_balance=pending_balance+?
            WHERE user_id=? AND balance>=?
            """,
            (amount, amount, user.id, amount),
        )
        if updated.rowcount != 1:
            bot.send_message(chat_id, "⛔ Insufficient balance or withdrawal already submitted.")
            return False
        conn.execute(
            "INSERT INTO withdraw_requests (user_id, method, number, amount) VALUES (?,?,?,?)",
            (user.id, method, phone, amount),
        )
        req_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    new_stats = get_wallet_stats(user.id)
    bot.send_message(
        chat_id,
        f"✔️ <b>{stylish('Withdraw Request Submitted')}</b>\n\n{stylish('Method')}: <b>{method}</b>\n"
        f"{stylish('Number')}: <b>{phone}</b>\n{stylish('Amount')}: <b>{amount:.2f} BDT</b>\n\n⌛ {stylish('Waiting for admin approval...')}",
        reply_markup=balance_inline_keyboard(),
    )
    uname = f"@{user.username}" if user.username else "N/A"
    group_text = (
        "🔔 <b>NEW WITHDRAW REQUEST</b>\n\n"
        f"🧑 User ID: <code>{user.id}</code>\n"
        f"🧑 Name: {user.first_name or 'N/A'}\n"
        f"🧑 Username: {uname}\n\n"
        f"🪪 Method: <b>{method}</b>\n"
        f"📟 Number: <code>{phone}</code>\n\n"
        f"💲 Requested: <b>{amount:.2f} BDT</b>\n"
        f"🏦 Remaining Balance: <b>{new_stats['balance']:.2f} BDT</b>"
    )
    pmt_fwd = get_setting("payment_forward_chat_id")
    if pmt_fwd:
        try:
            g_msg = bot.send_message(
                int(pmt_fwd), group_text, reply_markup=withdraw_action_keyboard(req_id)
            )
            with get_conn() as conn:
                conn.execute(
                    "UPDATE withdraw_requests SET group_msg_id=? WHERE id=?",
                    (g_msg.message_id, req_id),
                )
        except Exception as e:
            logger.warning("Payment forward failed (%s)", type(e).__name__)
    return True


@bot.callback_query_handler(func=lambda c: c.data in ("bal_withdraw", "bal_home"))
def cb_balance_actions(call):
    user = call.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.answer_callback_query(call.id)
        return
    if call.data == "bal_home":
        bot.answer_callback_query(call.id)
        user_states.pop(user.id, None)
        first_name = user.first_name or "User"
        _send_welcome(call.message.chat.id, first_name, user.id)
        return
    stats = get_wallet_stats(user.id)
    balance = stats["balance"]
    min_wd = get_min_withdraw()
    if balance < min_wd:
        bot.answer_callback_query(
            call.id,
            f"⛔ {stylish('Insufficient balance!')}\n{stylish('Minimum')}: {min_wd:.0f} BDT\n{stylish('Yours')}: {balance:.2f} BDT",
            show_alert=True,
        )
        return
    if has_pending_withdraw(user.id):
        bot.answer_callback_query(call.id, f"❗️ {stylish('You already have a pending withdrawal.')}", show_alert=True)
        return
    methods_kb = withdraw_methods_inline_keyboard()
    if not methods_kb:
        bot.answer_callback_query(call.id, f"⛔ {stylish('No payment methods configured. Contact admin.')}", show_alert=True)
        return
    bot.answer_callback_query(call.id)
    bot.send_message(
        call.message.chat.id,
        f"🪙 <b>{stylish('Select Payment Method')}</b>\n\n{stylish('Balance')}: <b>{balance:.2f} BDT</b>",
        reply_markup=methods_kb,
    )


@bot.callback_query_handler(func=lambda c: c.data.startswith("wd_method:"))
def cb_wd_method(call):
    user = call.from_user
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.answer_callback_query(call.id)
        return
    method = call.data.split(":", 1)[1].strip()
    with get_conn() as conn:
        valid_method = conn.execute(
            "SELECT 1 FROM withdraw_methods WHERE name=? AND is_enabled=1",
            (method,),
        ).fetchone()
    if not valid_method:
        bot.answer_callback_query(call.id, "Invalid payment method.", show_alert=True)
        return
    user_states[user.id] = {"step": "wd_enter_phone", "method": method}
    bot.answer_callback_query(call.id)
    try:
        bot.edit_message_text(
            f"✔️ <b>{method}</b> {stylish('selected.')}",
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=None,
        )
    except Exception:
        pass
    bot.send_message(call.message.chat.id, f"📟 <b>{method}</b>\n\n{stylish('Enter your')} <b>{stylish('phone number')}:</b>")


@bot.callback_query_handler(func=lambda c: c.data in ("wd_confirm", "wd_cancel"))
def cb_wd_confirm(call):
    user = call.from_user
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.answer_callback_query(call.id)
        return
    if call.data == "wd_cancel":
        user_states.pop(user.id, None)
        bot.answer_callback_query(call.id)
        try:
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
        except Exception:
            pass
        stats = get_wallet_stats(user.id)
        bot.send_message(
            call.message.chat.id,
            f"⛔ {stylish('Withdraw cancelled.')}\n\n" + build_balance_text(stats),
            reply_markup=balance_inline_keyboard(),
        )
        return
    wstate = user_states.get(user.id)
    if not wstate or wstate.get("step") != "wd_confirm":
        bot.answer_callback_query(call.id, stylish("Session expired. Please try again."), show_alert=True)
        return
    bot.answer_callback_query(call.id)
    user_states.pop(user.id, None)
    try:
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
    except Exception:
        pass
    _submit_withdraw_request(user, call.message.chat.id, wstate["method"], wstate["phone"], wstate["amount"])


@bot.callback_query_handler(func=lambda c: c.data.startswith("awd_approve:") or c.data.startswith("awd_reject:"))
def cb_withdraw_action(call):
    if not is_admin(call.from_user.id):
        bot.answer_callback_query(call.id, stylish("Unauthorized"), show_alert=True)
        return
    action, req_id_str = call.data.split(":", 1)
    req_id = int(req_id_str)
    with get_conn() as conn:
        req = conn.execute("SELECT * FROM withdraw_requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        bot.answer_callback_query(call.id, stylish("Request not found."), show_alert=True)
        return
    if req["status"] != "pending":
        bot.answer_callback_query(call.id, stylish("Already processed."), show_alert=True)
        try:
            bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id, reply_markup=None)
        except Exception:
            pass
        return
    bot.answer_callback_query(call.id)
    if action == "awd_approve":
        with get_conn() as conn:
            changed = conn.execute(
                "UPDATE withdraw_requests SET status='approved' "
                "WHERE id=? AND status='pending'",
                (req_id,),
            )
            if changed.rowcount != 1:
                bot.answer_callback_query(call.id, "Already processed.", show_alert=True)
                return
            conn.execute(
                "UPDATE wallet SET pending_balance=MAX(0, pending_balance-?) WHERE user_id=?",
                (req["amount"], req["user_id"]),
            )
        try:
            bot.send_message(
                req["user_id"],
                f"✔️ <b>{stylish('Withdraw Successful')}</b>\n\n{stylish('Amount')}: <b>{req['amount']:.2f} BDT</b>\n"
                f"{stylish('Method')}: <b>{req['method']}</b>\n{stylish('Number')}: <b>{req['number']}</b>",
            )
        except Exception:
            pass
        try:
            bot.edit_message_text(
                call.message.text + "\n\n✔️ <b>APPROVED</b>",
                chat_id=call.message.chat.id, message_id=call.message.message_id, reply_markup=None,
            )
        except Exception:
            pass
    else:
        with get_conn() as conn:
            changed = conn.execute(
                "UPDATE withdraw_requests SET status='rejected' "
                "WHERE id=? AND status='pending'",
                (req_id,),
            )
            if changed.rowcount != 1:
                bot.answer_callback_query(call.id, "Already processed.", show_alert=True)
                return
            conn.execute(
                "UPDATE wallet SET balance=balance+?, pending_balance=MAX(0, pending_balance-?) WHERE user_id=?",
                (req["amount"], req["amount"], req["user_id"]),
            )
        try:
            bot.send_message(
                req["user_id"],
                f"⛔ <b>Withdraw Failed</b>\n\nAmount <b>{req['amount']:.2f} BDT</b> returned.",
            )
        except Exception:
            pass
        try:
            bot.edit_message_text(
                call.message.text + "\n\n⛔ <b>REJECTED — Balance Returned</b>",
                chat_id=call.message.chat.id, message_id=call.message.message_id, reply_markup=None,
            )
        except Exception:
            pass





# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN TEXT HANDLER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@bot.message_handler(content_types=["text"])
def handle_text(message):
    if message.chat.type != "private":
        return
    user = message.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        return

    if shop_handle_text and shop_handle_text(message):
        return

    text = message.text.strip()
    chat_id = message.chat.id
    _is_main_admin = (user.id == ADMIN_ID)
    logger.info(
        "[MSG] uid=%s is_admin=%s state=%s",
        user.id,
        is_admin(user.id),
        admin_states.get(user.id, {}).get("step", "NONE"),
    )

    # ══════════════════════════════════════════════════════════════════════════
    # ADMIN PANEL
    # ══════════════════════════════════════════════════════════════════════════
    if is_admin(user.id):

        if user.id in admin_states:
            state = admin_states[user.id]
            step = state.get("step")

            # ── Cancel from anywhere ─────────────────────────────────────────
            if text == f"⛔ {stylish('Cancel')}":
                admin_states.pop(user.id, None)
                _bal_kb_steps = ("aset_otp_earn", "aset_referral_bonus", "aadd_balance", "arem_balance")
                _wd_kb_steps = ("awm_add", "awm_del", "awm_set_min")
                _fj_kb_steps = (
                    "aset_fj_add_channel", "aset_fj_add_group",
                    "aset_fj_del_ch", "aset_fj_del_gr",
                )
                _ol_kb_steps = ("aset_ol_support", "aset_ol_otpgroup", "aset_ol_main_channel", "aset_ol_payment_id", "aset_ol_otp_fwd")
                _ban_kb_steps = ("aban_uid", "aunban_uid")
                if step in _bal_kb_steps:
                    kb = balance_management_keyboard()
                elif step in _wd_kb_steps:
                    kb = withdraw_management_keyboard()
                elif step in _fj_kb_steps:
                    kb = force_join_keyboard()
                elif step in _ol_kb_steps:
                    kb = others_link_keyboard()
                elif step in _ban_kb_steps:
                    kb = ban_unban_keyboard()
                elif step in ("amgmt_add_uid", "amgmt_remove_uid"):
                    kb = admin_management_keyboard()
                elif step == "abroadcast_wait":
                    kb = admin_keyboard(is_main_admin=_is_main_admin)
                elif step in ("asvc_add_name", "arange_country_info", "arange_range_input"):
                    kb = manage_services_keyboard()
                elif step == "adev_set_info":
                    kb = developer_keyboard()
                elif step in ("aapi_setkey_smshadi", "aapi_setkey_lamix", "aapi_setkey_yesms",
                              "aapi_setkey_stexsms", "aapi_setkey_fastxotps", "aapi_setkey_voltxsms",
                              "aapi_setkey_zebrasms"):
                    kb = api_management_keyboard()
                elif step == "aauto_chat_id":
                    kb = auto_sms_keyboard()
                elif step.startswith("atm_"):
                    kb = temp_mail_admin_keyboard()
                elif step == "abackup_restore_wait":
                    kb = backup_keyboard()
                else:
                    kb = manage_services_keyboard()
                bot.send_message(chat_id, "⛔ Cancelled.", reply_markup=kb)
                return

            # ── API KEY INPUT ──────────────────────────────────────────────────
            if step == "aapi_setkey_smshadi":
                new_key = text.strip()
                if not new_key:
                    bot.send_message(chat_id, "⛔ Key cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_api_key("smshadi", new_key)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ {stylish('SMShadi API key saved!')}", reply_markup=api_management_keyboard())
                return
            elif step == "aapi_setkey_lamix":
                new_key = text.strip()
                if not new_key:
                    bot.send_message(chat_id, "⛔ Key cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_api_key("lamix", new_key)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ {stylish('Lamix API key saved!')}", reply_markup=api_management_keyboard())
                return
            elif step == "aapi_setkey_yesms":
                new_key = text.strip()
                if not new_key:
                    bot.send_message(chat_id, "⛔ Key cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_api_key("yesms", new_key)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ {stylish('YesMS API key saved!')}", reply_markup=api_management_keyboard())
                return
            elif step == "aapi_setkey_stexsms":
                new_key = text.strip()
                if not new_key:
                    bot.send_message(chat_id, "⛔ Key cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_api_key("stexsms", new_key)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ {stylish('StexSMS API key saved!')}", reply_markup=api_management_keyboard())
                return
            elif step == "aapi_setkey_fastxotps":
                new_key = text.strip()
                if not new_key:
                    bot.send_message(chat_id, "⛔ Key cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_api_key("fastxotps", new_key)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ {stylish('FastXOTPs API key saved!')}", reply_markup=api_management_keyboard())
                return
            elif step == "aapi_setkey_voltxsms":
                new_key = text.strip()
                if not new_key:
                    bot.send_message(chat_id, "⛔ Key cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_api_key("voltxsms", new_key)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ {stylish('VoltXSMS API key saved!')}", reply_markup=api_management_keyboard())
                return
            elif step == "aapi_setkey_zebrasms":
                new_key = text.strip()
                if not new_key:
                    bot.send_message(chat_id, "⛔ Key cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_api_key("zebrasms", new_key)
                admin_states.pop(user.id, None)
                live = _zebrasms_live_access()
                live_txt = "🟩 Live access OK" if live["ok"] else "🟥 Live access check failed"
                bot.send_message(chat_id, f"✔️ {stylish('ZebraSMS API key saved!')}\n{live_txt}", reply_markup=api_management_keyboard())
                return

            # ── ADMIN MANAGEMENT ──────────────────────────────────────────────
            if step == "amgmt_add_uid":
                if not _is_main_admin:
                    admin_states.pop(user.id, None)
                    return
                try:
                    new_admin_id = int(text.strip())
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid ID. Enter a numeric User ID.", reply_markup=cancel_keyboard())
                    return
                if new_admin_id == ADMIN_ID:
                    bot.send_message(chat_id, "ℹ️ This is already the main admin.", reply_markup=admin_management_keyboard())
                    admin_states.pop(user.id, None)
                    return
                with get_conn() as conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO admins (user_id, added_by) VALUES (?,?)",
                        (new_admin_id, user.id),
                    )
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ User <code>{new_admin_id}</code> added as admin.", reply_markup=admin_management_keyboard())
                try:
                    bot.send_message(new_admin_id, "✔️ You have been granted admin access.")
                except Exception:
                    pass
                return

            elif step == "amgmt_remove_uid":
                if not _is_main_admin:
                    admin_states.pop(user.id, None)
                    return
                try:
                    rem_id = int(text.strip())
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid ID.", reply_markup=cancel_keyboard())
                    return
                with get_conn() as conn:
                    conn.execute("DELETE FROM admins WHERE user_id=?", (rem_id,))
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ User <code>{rem_id}</code> removed from admins.", reply_markup=admin_management_keyboard())
                try:
                    bot.send_message(rem_id, f"ℹ️ {stylish('Your admin access has been revoked.')}")
                except Exception:
                    pass
                return

            # ── BAN / UNBAN ───────────────────────────────────────────────────
            if step == "aban_uid":
                try:
                    uid = int(text.strip())
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid User ID.", reply_markup=cancel_keyboard())
                    return
                with get_conn() as conn:
                    conn.execute("UPDATE users SET is_banned=1 WHERE id=?", (uid,))
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"🛑 User <code>{uid}</code> has been <b>banned</b>.", reply_markup=ban_unban_keyboard())
                try:
                    bot.send_message(uid, "🛑 You have been banned by admin.")
                except Exception:
                    pass
                return

            elif step == "aunban_uid":
                try:
                    uid = int(text.strip())
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid User ID.", reply_markup=cancel_keyboard())
                    return
                with get_conn() as conn:
                    conn.execute("UPDATE users SET is_banned=0 WHERE id=?", (uid,))
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ User <code>{uid}</code> has been <b>unbanned</b>.", reply_markup=ban_unban_keyboard())
                try:
                    bot.send_message(uid, f"✔️ {stylish('You have been unbanned.')}")
                except Exception:
                    pass
                return

            # ── BALANCE ───────────────────────────────────────────────────────
            elif step == "aset_otp_earn":
                try:
                    val = float(text.strip())
                    if val < 0:
                        raise ValueError()
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid amount.", reply_markup=cancel_keyboard())
                    return
                set_setting("otp_earn_bdt", val)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ OTP earn rate set to <b>{val:.2f} BDT</b>.", reply_markup=balance_management_keyboard())
                return

            elif step == "aset_referral_bonus":
                try:
                    val = float(text.strip())
                    if val < 0:
                        raise ValueError()
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid amount.", reply_markup=cancel_keyboard())
                    return
                set_setting("referral_bonus_bdt", val)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Referral bonus set to <b>{val:.2f} BDT</b>.", reply_markup=balance_management_keyboard())
                return

            elif step == "aadd_balance":
                parts = text.strip().split()
                if len(parts) < 2:
                    bot.send_message(chat_id, "⛔ Format: <code>user_id amount</code>", reply_markup=cancel_keyboard())
                    return
                try:
                    uid = int(parts[0])
                    amt = float(parts[1])
                    if amt <= 0:
                        raise ValueError()
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid input.", reply_markup=cancel_keyboard())
                    return
                with get_conn() as conn:
                    conn.execute("INSERT OR IGNORE INTO wallet (user_id) VALUES (?)", (uid,))
                    conn.execute(
                        "UPDATE wallet SET balance=balance+?, total_income=total_income+? WHERE user_id=?",
                        (amt, amt, uid),
                    )
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Added <b>{amt:.2f} BDT</b> to user <code>{uid}</code>.", reply_markup=balance_management_keyboard())
                try:
                    bot.send_message(uid, f"💲 Admin added <b>{amt:.2f} BDT</b> to your wallet.")
                except Exception:
                    pass
                return

            elif step == "arem_balance":
                parts = text.strip().split()
                if len(parts) < 2:
                    bot.send_message(chat_id, "⛔ Format: <code>user_id amount</code>", reply_markup=cancel_keyboard())
                    return
                try:
                    uid = int(parts[0])
                    amt = float(parts[1])
                    if amt <= 0:
                        raise ValueError()
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid input.", reply_markup=cancel_keyboard())
                    return
                with get_conn() as conn:
                    conn.execute("INSERT OR IGNORE INTO wallet (user_id) VALUES (?)", (uid,))
                    conn.execute(
                        "UPDATE wallet SET balance=MAX(0, balance-?) WHERE user_id=?",
                        (amt, uid),
                    )
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Removed <b>{amt:.2f} BDT</b> from user <code>{uid}</code>.", reply_markup=balance_management_keyboard())
                try:
                    bot.send_message(uid, f"🪙 Admin deducted <b>{amt:.2f} BDT</b> from your wallet.")
                except Exception:
                    pass
                return

            # ── WITHDRAW METHODS ──────────────────────────────────────────────
            # ── TEMP MAIL DOMAIN FLOWS ────────────────────────────────────
            elif step.startswith("atm_"):
                if text.strip() in ("❎️ Cancel", "⛔ Cancel"):
                    admin_states.pop(user.id, None)
                    bot.send_message(
                        chat_id, "⛔ Cancelled.", reply_markup=temp_mail_admin_keyboard()
                    )
                    return

                data = state.setdefault("data", {})

                if step == "atm_add_domain":
                    domain = text.strip().lstrip("@").lower()
                    if not domain or "." not in domain or " " in domain:
                        bot.send_message(
                            chat_id,
                            "⛔ সঠিক domain লিখুন (যেমন <code>mydomain.com</code>).",
                            reply_markup=cancel_keyboard(),
                        )
                        return
                    data["domain"] = domain
                    state["step"] = "atm_add_provider"
                    bot.send_message(
                        chat_id,
                        f"🛰 Domain: <code>{_html.escape(domain)}</code>\n\n"
                        "এই domain এর mail কোথা থেকে আসবে?\n\n"
                        "• <b>Own Domain (IMAP)</b> — আপনার নিজের domain, catch-all mailbox "
                        "(IMAP login লাগবে)\n"
                        "• বাকিগুলো — ওই free service এর domain হলে সেটা ব্যবহার হবে",
                        reply_markup=temp_mail_provider_keyboard(),
                    )
                    return

                if step == "atm_add_provider":
                    provider = TEMP_MAIL_PROVIDER_CHOICES.get(text.strip())
                    if not provider:
                        bot.send_message(
                            chat_id,
                            "⛔ নিচের যেকোনো একটি বেছে নিন।",
                            reply_markup=temp_mail_provider_keyboard(),
                        )
                        return
                    data["provider"] = provider
                    if provider != "imap":
                        add_temp_mail_domain(data["domain"], provider)
                        admin_states.pop(user.id, None)
                        bot.send_message(
                            chat_id,
                            f"✔️ Domain <code>{_html.escape(data['domain'])}</code> যোগ হয়েছে।\n\n"
                            f"{_temp_mail_domains_text()}",
                            reply_markup=temp_mail_admin_keyboard(),
                        )
                        return
                    state["step"] = "atm_add_imap_host"
                    bot.send_message(
                        chat_id,
                        "📥 IMAP server host লিখুন (যেমন <code>imap.hostinger.com</code>):",
                        reply_markup=cancel_keyboard(),
                    )
                    return

                if step == "atm_add_imap_host":
                    data["imap_host"] = text.strip()
                    state["step"] = "atm_add_imap_port"
                    bot.send_message(
                        chat_id,
                        "🔢 IMAP port লিখুন (SSL হলে <code>993</code>):",
                        reply_markup=cancel_keyboard(),
                    )
                    return

                if step == "atm_add_imap_port":
                    raw_port = text.strip()
                    if not raw_port.isdigit():
                        bot.send_message(
                            chat_id, "⛔ শুধু সংখ্যা লিখুন (993).", reply_markup=cancel_keyboard()
                        )
                        return
                    data["imap_port"] = int(raw_port)
                    state["step"] = "atm_add_imap_user"
                    bot.send_message(
                        chat_id,
                        "🧑 Catch-all mailbox এর email/username লিখুন\n"
                        f"(যেমন <code>catchall@{_html.escape(data['domain'])}</code>):",
                        reply_markup=cancel_keyboard(),
                    )
                    return

                if step == "atm_add_imap_user":
                    data["imap_user"] = text.strip()
                    state["step"] = "atm_add_imap_pass"
                    bot.send_message(
                        chat_id,
                        "🗝 ওই mailbox এর password লিখুন:",
                        reply_markup=cancel_keyboard(),
                    )
                    return

                if step == "atm_add_imap_pass":
                    data["imap_pass"] = text
                    try:
                        bot.delete_message(chat_id, message.message_id)
                    except Exception:
                        pass
                    config = {
                        "imap_host": data.get("imap_host"),
                        "imap_port": data.get("imap_port", 993),
                        "imap_user": data.get("imap_user"),
                        "imap_pass": data.get("imap_pass"),
                        "imap_folder": "INBOX",
                    }
                    try:
                        temp_mail_engine.imap_test_sync(config)
                    except Exception as exc:
                        admin_states.pop(user.id, None)
                        bot.send_message(
                            chat_id,
                            "⛔ IMAP connection failed:\n"
                            f"<code>{_html.escape(str(exc))}</code>\n\n"
                            "Host/port/username/password আবার দেখে try করুন।",
                            reply_markup=temp_mail_admin_keyboard(),
                        )
                        return
                    add_temp_mail_domain(
                        data["domain"],
                        "imap",
                        imap_host=config["imap_host"],
                        imap_port=config["imap_port"],
                        imap_user=config["imap_user"],
                        imap_pass=config["imap_pass"],
                        imap_folder="INBOX",
                    )
                    admin_states.pop(user.id, None)
                    bot.send_message(
                        chat_id,
                        "✔️ IMAP connection OK!\n"
                        f"Domain <code>{_html.escape(data['domain'])}</code> যোগ হয়েছে।\n"
                        "এখন Get Mail এই domain এ address বানাবে।\n\n"
                        f"{_temp_mail_domains_text()}",
                        reply_markup=temp_mail_admin_keyboard(),
                    )
                    return

                if step == "atm_del_domain":
                    removed = delete_temp_mail_domain(text.strip())
                    admin_states.pop(user.id, None)
                    bot.send_message(
                        chat_id,
                        ("✔️ Domain deleted." if removed else "⛔ Domain not found.")
                        + f"\n\n{_temp_mail_domains_text()}",
                        reply_markup=temp_mail_admin_keyboard(),
                    )
                    return

                if step == "atm_toggle_domain":
                    toggle_temp_mail_domain(text.strip())
                    admin_states.pop(user.id, None)
                    bot.send_message(
                        chat_id,
                        f"🔁 Updated.\n\n{_temp_mail_domains_text()}",
                        reply_markup=temp_mail_admin_keyboard(),
                    )
                    return

                admin_states.pop(user.id, None)
                bot.send_message(
                    chat_id, _temp_mail_admin_status_text(), reply_markup=temp_mail_admin_keyboard()
                )
                return

            elif step == "awm_add":
                method_name = text.strip().capitalize()
                if not method_name:
                    bot.send_message(chat_id, "⛔ Name cannot be empty.", reply_markup=cancel_keyboard())
                    return
                with get_conn() as conn:
                    try:
                        conn.execute("INSERT INTO withdraw_methods (name) VALUES (?)", (method_name,))
                        added = True
                    except Exception:
                        added = False
                admin_states.pop(user.id, None)
                if added:
                    bot.send_message(chat_id, f"✔️ Method <b>{method_name}</b> added.", reply_markup=withdraw_management_keyboard())
                else:
                    bot.send_message(chat_id, f"❗️ Method <b>{method_name}</b> already exists.", reply_markup=withdraw_management_keyboard())
                return

            elif step == "awm_del":
                method_name = text.strip()
                with get_conn() as conn:
                    conn.execute("DELETE FROM withdraw_methods WHERE name=?", (method_name,))
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Method <b>{method_name}</b> removed.", reply_markup=withdraw_management_keyboard())
                return

            elif step == "awm_set_min":
                try:
                    val = float(text.strip())
                    if val < 0:
                        raise ValueError()
                except ValueError:
                    bot.send_message(chat_id, "⛔ Invalid amount.", reply_markup=cancel_keyboard())
                    return
                set_setting("min_withdraw_bdt", val)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Minimum withdraw set to <b>{val:.0f} BDT</b>.", reply_markup=withdraw_management_keyboard())
                return

            # ── AUTO SMS SETTINGS ─────────────────────────────────────────────
            if step == "aauto_chat_id":
                raw = text.strip()
                if not re.fullmatch(r"-?\d{5,20}", raw):
                    bot.send_message(chat_id, "⛔ Invalid chat ID.", reply_markup=cancel_keyboard())
                    return
                set_setting("auto_sms_chat_id", raw)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, _auto_sms_status_text(), reply_markup=auto_sms_keyboard())
                return

            if step == "aauto_demo_delay":
                raw = text.strip().lower().replace(" ", "")
                m = re.fullmatch(r"(\d+)(s|sec|secs|second|seconds|m|min|mins|minute|minutes)?", raw)
                if not m:
                    bot.send_message(chat_id, "⛔ Invalid delay. Example: 30s or 5m",
                                     reply_markup=cancel_keyboard())
                    return
                val = int(m.group(1))
                unit = m.group(2) or "s"
                if unit.startswith("m"):
                    val *= 60
                if val < DEMO_SMS_MIN_DELAY or val > DEMO_SMS_MAX_DELAY:
                    bot.send_message(
                        chat_id,
                        f"⛔ Delay must be between <b>{DEMO_SMS_MIN_DELAY} sec</b> and "
                        f"<b>{DEMO_SMS_MAX_DELAY // 60} min</b>.",
                        reply_markup=cancel_keyboard(),
                    )
                    return
                set_setting("auto_sms_demo_delay", val)
                admin_states.pop(user.id, None)
                bot.send_message(
                    chat_id,
                    f"✔️ Demo delay set to <b>{fmt_delay(val)}</b>.",
                )
                bot.send_message(chat_id, _auto_sms_status_text(), reply_markup=auto_sms_keyboard())
                return

            # ── BROADCAST ─────────────────────────────────────────────────────
            if step == "abroadcast_wait":
                sent = 0
                for user_ids in _iter_unbanned_user_id_batches():
                    for user_id in user_ids:
                        try:
                            bot.copy_message(user_id, chat_id, message.message_id)
                            sent += 1
                        except Exception:
                            pass
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Broadcast sent to <b>{sent}</b> users.", reply_markup=admin_keyboard(is_main_admin=_is_main_admin))
                return

            # ── FORCE JOIN: Add Channel (Task 3) ──────────────────────────────
            elif step == "aset_fj_add_channel":
                link = text.strip()
                ch_id, ch_name, ch_url = parse_channel_link(link)
                if not ch_id:
                    bot.send_message(
                        chat_id,
                        "⛔ Invalid link. Send a valid Telegram link like:\n<code>https://t.me/yourchannel</code>",
                        reply_markup=cancel_keyboard(),
                    )
                    return
                with get_conn() as conn:
                    conn.execute(
                        "INSERT INTO join_channels (channel_id, channel_name, channel_url, channel_type) VALUES (?,?,?,?)",
                        (ch_id, ch_name, ch_url, "channel"),
                    )
                admin_states.pop(user.id, None)
                bot.send_message(
                    chat_id,
                    f"✔️ Channel <b>{ch_name}</b> added successfully!\n\n"
                    f"❗️ Make sure the bot is an <b>admin</b> in that channel for membership checks to work.",
                    reply_markup=force_join_keyboard(),
                )
                return

            # ── FORCE JOIN: Add Group (Task 3) ────────────────────────────────
            elif step == "aset_fj_add_group":
                link = text.strip()
                ch_id, ch_name, ch_url = parse_channel_link(link)
                if not ch_id:
                    bot.send_message(
                        chat_id,
                        "⛔ Invalid link. Send a valid Telegram link like:\n<code>https://t.me/yourgroup</code>",
                        reply_markup=cancel_keyboard(),
                    )
                    return
                with get_conn() as conn:
                    conn.execute(
                        "INSERT INTO join_channels (channel_id, channel_name, channel_url, channel_type) VALUES (?,?,?,?)",
                        (ch_id, ch_name, ch_url, "group"),
                    )
                admin_states.pop(user.id, None)
                bot.send_message(
                    chat_id,
                    f"✔️ Group <b>{ch_name}</b> added successfully!\n\n"
                    f"❗️ Make sure the bot is an <b>admin</b> in that group for membership checks to work.",
                    reply_markup=force_join_keyboard(),
                )
                return

            # ── FORCE JOIN: Delete Channel ────────────────────────────────────
            elif step == "aset_fj_del_ch":
                ch_name = text.strip()
                with get_conn() as conn:
                    conn.execute("DELETE FROM join_channels WHERE channel_name=?", (ch_name,))
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Channel <b>{ch_name}</b> removed.", reply_markup=force_join_keyboard())
                return

            # ── FORCE JOIN: Delete Group ──────────────────────────────────────
            elif step == "aset_fj_del_gr":
                gr_name = text.strip()
                with get_conn() as conn:
                    conn.execute("DELETE FROM join_channels WHERE channel_name=?", (gr_name,))
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Group <b>{gr_name}</b> removed.", reply_markup=force_join_keyboard())
                return

            # ── OTHERS LINK: Support Btn (Task 4) ────────────────────────────
            elif step == "aset_ol_support":
                link = text.strip()
                if not link.startswith("http"):
                    bot.send_message(chat_id, "⛔ Please send a valid URL (starting with http/https).", reply_markup=cancel_keyboard())
                    return
                set_setting("support_link", normalize_link(link))
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Support link saved:\n{link}", reply_markup=others_link_keyboard())
                return

            # ── OTHERS LINK: OTP Group Btn (Task 4) ──────────────────────────
            elif step == "aset_ol_otpgroup":
                link = text.strip()
                if not link.startswith("http"):
                    bot.send_message(chat_id, "⛔ Please send a valid URL (starting with http/https).", reply_markup=cancel_keyboard())
                    return
                set_setting("otp_group_link", link)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ OTP Group link saved:\n{link}", reply_markup=others_link_keyboard())
                return

            # ── OTHERS LINK: Number Panel Link ───────────────────────────────
            elif step == "aset_ol_panel_link":
                link = text.strip()
                if not link.startswith("http"):
                    bot.send_message(chat_id, "⛔ Please send a valid URL (starting with http/https).", reply_markup=cancel_keyboard())
                    return
                set_setting("panel_link", link)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Number Panel link saved:\n{link}", reply_markup=others_link_keyboard())
                return

            # ── OTHERS LINK: Bot Developer Link ──────────────────────────────
            elif step == "aset_ol_auto_bot_link":
                link = normalize_link(text)
                if not link:
                    bot.send_message(chat_id, "❗️ Send a valid https:// link.", reply_markup=cancel_keyboard())
                    return
                set_setting("auto_sms_bot_link", link)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Auto SMS bot link saved:\n{link}", reply_markup=others_link_keyboard())
                return

            elif step == "aset_ol_auto_channel_link":
                link = normalize_link(text)
                if not link:
                    bot.send_message(chat_id, "❗️ Send a valid https:// link.", reply_markup=cancel_keyboard())
                    return
                set_setting("auto_sms_channel_link", link)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Auto SMS channel link saved:\n{link}", reply_markup=others_link_keyboard())
                return

            elif step == "aset_ol_dev_link":
                link = text.strip()
                if not link.startswith("http"):
                    bot.send_message(chat_id, "⛔ Please send a valid URL (starting with http/https).", reply_markup=cancel_keyboard())
                    return
                set_setting("dev_link", link)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Bot Developer link saved:\n{link}", reply_markup=others_link_keyboard())
                return

            # ── OTHERS LINK: Main Channel ───────────────────────────────────
            elif step == "aset_ol_main_channel":
                link = text.strip()
                if not link.startswith(("http://", "https://", "tg://")):
                    bot.send_message(
                        chat_id,
                        "⛔ Please send a valid Telegram URL (https://t.me/...).",
                        reply_markup=cancel_keyboard(),
                    )
                    return
                link = normalize_link(link)
                set_setting("main_channel_link", link)
                admin_states.pop(user.id, None)
                bot.send_message(
                    chat_id,
                    f"✔️ Main channel link saved:\n{_html.escape(link)}",
                    reply_markup=others_link_keyboard(),
                )
                return

            # ── OTHERS LINK: Payment Request ID (Task 4) ─────────────────────
            elif step == "aset_ol_payment_id":
                chat_id_val = text.strip()
                if not re.match(r'^-?\d+$', chat_id_val):
                    bot.send_message(chat_id, "⛔ Please send a valid numeric Chat ID (e.g. -1001234567890).", reply_markup=cancel_keyboard())
                    return
                set_setting("payment_forward_chat_id", chat_id_val)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Payment Request Chat ID saved: <code>{chat_id_val}</code>", reply_markup=others_link_keyboard())
                return

            # ── OTHERS LINK: OTP Forward ID (Task 4) ─────────────────────────
            elif step == "aset_ol_otp_fwd":
                chat_id_val = text.strip()
                if not re.match(r'^-?\d+$', chat_id_val):
                    bot.send_message(chat_id, "⛔ Please send a valid numeric Chat ID (e.g. -1001234567890).", reply_markup=cancel_keyboard())
                    return
                set_setting("otp_forward_chat_id", chat_id_val)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ OTP Forward Chat ID saved: <code>{chat_id_val}</code>", reply_markup=others_link_keyboard())
                return

            # ── OTHERS LINK: Bot Name ─────────────────────────────────────────
            elif step == "aset_ol_bot_name":
                val = text.strip()
                if not val:
                    bot.send_message(chat_id, "⛔ Bot name cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_setting("bot_name", val)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Bot name saved: <code>{val}</code>", reply_markup=others_link_keyboard())
                return

            # ── OTHERS LINK: Powered By ───────────────────────────────────────
            elif step == "aset_ol_powered_by":
                val = text.strip()
                if not val:
                    bot.send_message(chat_id, "⛔ Powered By text cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_setting("powered_by", val)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, f"✔️ Powered By saved: <code>{val}</code>", reply_markup=others_link_keyboard())
                return

            # ── DEVELOPER INFO: set info text ─────────────────────────────────
            elif step == "adev_set_info":
                info_text = text.strip()
                if not info_text:
                    bot.send_message(chat_id, "⛔ Dev info cannot be empty.", reply_markup=cancel_keyboard())
                    return
                set_setting("developer_info", info_text)
                admin_states.pop(user.id, None)
                bot.send_message(chat_id, "✔️ Developer info saved!", reply_markup=developer_keyboard())
                return

            # ── ADD SERVICE: step 1 — service name (Task 1) ──────────────────
            if step == "asvc_add_name":
                service_name = text.strip()
                if not service_name:
                    bot.send_message(chat_id, "⛔ Service name cannot be empty.", reply_markup=cancel_keyboard())
                    return
                with get_conn() as conn:
                    try:
                        conn.execute("INSERT INTO services (name) VALUES (?)", (service_name,))
                        added = True
                    except Exception:
                        added = False
                admin_states.pop(user.id, None)
                if added:
                    bot.send_message(
                        chat_id,
                        f"✔️ <b>Service Added Successfully!</b>\n\n📟 Service: <b>{service_name}</b>",
                        reply_markup=manage_services_keyboard(),
                    )
                else:
                    bot.send_message(
                        chat_id,
                        f"❗️ Service <b>{service_name}</b> already exists.",
                        reply_markup=manage_services_keyboard(),
                    )
                return

            # ── IMPORT: step 1 — service selection ───────────────────────────
            elif step == "aimport_select_service":
                if text == "◀️ Back":
                    admin_states.pop(user.id, None)
                    bot.send_message(chat_id, f"🗂 <b>{stylish('Manage Services')}</b>", reply_markup=manage_services_keyboard())
                    return
                svc_name = text.replace("📟 ", "").strip()
                with get_conn() as conn:
                    svc = conn.execute("SELECT * FROM services WHERE name=?", (svc_name,)).fetchone()
                if not svc:
                    bot.send_message(chat_id, f"⛔ {stylish('Service not found.')}", reply_markup=import_service_keyboard())
                    return
                state["data"]["service_id"] = svc["id"]
                state["data"]["service_name"] = svc["name"]
                state["step"] = "aimport_country_info"
                bot.send_message(
                    chat_id,
                    f"✔️ Service: <b>{svc['name']}</b>\n\n"
                    f"Enter <b>Country Flag, Name and Code</b>:\n\nExample:\n🇧🇩 Bangladesh +880\n🇺🇸 USA +1",
                    reply_markup=cancel_keyboard(),
                )
                return

            # ── IMPORT: step 2 — country info ────────────────────────────────
            elif step == "aimport_country_info":
                parsed = parse_country_info(text)
                if not parsed:
                    bot.send_message(
                        chat_id,
                        "⛔ Invalid format. Use:\n🇧🇩 Bangladesh +880",
                        reply_markup=cancel_keyboard(),
                    )
                    return
                service_id = state["data"]["service_id"]
                with get_conn() as conn:
                    existing = conn.execute(
                        "SELECT * FROM countries WHERE service_id=? AND name=? AND code=?",
                        (service_id, parsed["name"], parsed["code"]),
                    ).fetchone()
                    if existing:
                        state["data"]["country_id"] = existing["id"]
                        state["data"]["country_flag"] = existing["flag"]
                        state["data"]["country_name"] = existing["name"]
                        state["data"]["country_code"] = existing["code"]
                    else:
                        conn.execute(
                            "INSERT INTO countries (service_id, flag, name, code) VALUES (?,?,?,?)",
                            (service_id, parsed["flag"], parsed["name"], parsed["code"]),
                        )
                        c = conn.execute(
                            "SELECT * FROM countries WHERE service_id=? AND name=? AND code=?",
                            (service_id, parsed["name"], parsed["code"]),
                        ).fetchone()
                        state["data"]["country_id"] = c["id"]
                        state["data"]["country_flag"] = parsed["flag"]
                        state["data"]["country_name"] = parsed["name"]
                        state["data"]["country_code"] = parsed["code"]
                state["step"] = "aimport_number_file"
                bot.send_message(
                    chat_id,
                    f"✔️ Country: <b>{state['data']['country_flag']} {state['data']['country_name']} "
                    f"+{state['data']['country_code']}</b>\n\n"
                    f"Upload a <b>.txt file</b> with numbers (one per line):\n\n"
                    f"Example:\n<code>8801711111111\n8801722222222</code>",
                    reply_markup=cancel_keyboard(),
                )
                return

            # ── INPUT RANGE: step 1 — service selection ──────────────────────
            elif step == "arange_select_service":
                if text == "◀️ Back":
                    admin_states.pop(user.id, None)
                    bot.send_message(chat_id, f"🗂 <b>{stylish('Manage Services')}</b>", reply_markup=manage_services_keyboard())
                    return
                svc_name = text.replace("📟 ", "").strip()
                with get_conn() as conn:
                    svc = conn.execute("SELECT * FROM services WHERE name=?", (svc_name,)).fetchone()
                if not svc:
                    bot.send_message(chat_id, f"⛔ {stylish('Service not found.')}", reply_markup=import_service_keyboard())
                    return
                state["data"]["service_id"] = svc["id"]
                state["data"]["service_name"] = svc["name"]
                state["step"] = "arange_country_info"
                bot.send_message(
                    chat_id,
                    f"✔️ Service: <b>{svc['name']}</b>\n\n"
                    f"Enter <b>Country Flag, Name and Code</b>:\n\nExample:\n🇧🇩 Bangladesh +880\n🇺🇸 USA +1",
                    reply_markup=cancel_keyboard(),
                )
                return

            # ── INPUT RANGE: step 2 — country info ────────────────────────────
            elif step == "arange_country_info":
                parsed = parse_country_info(text)
                if not parsed:
                    bot.send_message(
                        chat_id,
                        "⛔ Invalid format. Use:\n🇧🇩 Bangladesh +880",
                        reply_markup=cancel_keyboard(),
                    )
                    return
                service_id = state["data"]["service_id"]
                with get_conn() as conn:
                    existing = conn.execute(
                        "SELECT * FROM countries WHERE service_id=? AND name=? AND code=?",
                        (service_id, parsed["name"], parsed["code"]),
                    ).fetchone()
                    if existing:
                        state["data"]["country_id"] = existing["id"]
                        state["data"]["country_flag"] = existing["flag"]
                        state["data"]["country_name"] = existing["name"]
                        state["data"]["country_code"] = existing["code"]
                    else:
                        conn.execute(
                            "INSERT INTO countries (service_id, flag, name, code) VALUES (?,?,?,?)",
                            (service_id, parsed["flag"], parsed["name"], parsed["code"]),
                        )
                        c = conn.execute(
                            "SELECT * FROM countries WHERE service_id=? AND name=? AND code=?",
                            (service_id, parsed["name"], parsed["code"]),
                        ).fetchone()
                        state["data"]["country_id"] = c["id"]
                        state["data"]["country_flag"] = parsed["flag"]
                        state["data"]["country_name"] = parsed["name"]
                        state["data"]["country_code"] = parsed["code"]
                state["step"] = "arange_range_input"
                bot.send_message(
                    chat_id,
                    f"✔️ Country: <b>{state['data']['country_flag']} {state['data']['country_name']} "
                    f"+{state['data']['country_code']}</b>\n\n"
                    f"Enter the <b>Range ID</b> for this country (e.g. <code>880X01</code>):",
                    reply_markup=cancel_keyboard(),
                )
                return

            # ── INPUT RANGE: step 3 — range id ────────────────────────────────
            elif step == "arange_range_input":
                range_id = text.strip()
                if not range_id:
                    bot.send_message(chat_id, "⛔ Range ID cannot be empty.", reply_markup=cancel_keyboard())
                    return
                country_id = state["data"]["country_id"]
                with get_conn() as conn:
                    conn.execute("UPDATE countries SET range_id=? WHERE id=?", (range_id, country_id))
                admin_states.pop(user.id, None)
                bot.send_message(
                    chat_id,
                    f"✔️ <b>Range Saved!</b>\n\n"
                    f"📟 Service: <b>{state['data']['service_name']}</b>\n"
                    f"🗺 Country: <b>{state['data']['country_flag']} {state['data']['country_name']} "
                    f"+{state['data']['country_code']}</b>\n"
                    f"🧩 Range ID: <code>{range_id}</code>\n\n"
                    f"{stylish('Users selecting this country will now be allocated numbers dynamically from this range.')}",
                    reply_markup=manage_services_keyboard(),
                )
                return

            # ── DELETE SERVICE: select service ────────────────────────────────
            elif step == "adel_svc_select":
                if text == "◀️ Back":
                    admin_states.pop(user.id, None)
                    bot.send_message(chat_id, f"🗂 <b>{stylish('Manage Services')}</b>", reply_markup=manage_services_keyboard())
                    return
                svc_name = text.replace("📟 ", "").strip()
                with get_conn() as conn:
                    svc = conn.execute("SELECT * FROM services WHERE name=?", (svc_name,)).fetchone()
                if not svc:
                    bot.send_message(chat_id, f"⛔ {stylish('Service not found.')}", reply_markup=services_list_keyboard() or manage_services_keyboard())
                    return
                state["data"]["service_id"] = svc["id"]
                state["data"]["service_name"] = svc["name"]
                state["step"] = "adel_svc_options"
                bot.send_message(
                    chat_id,
                    f"📟 <b>{svc['name']}</b>\n\nWhat do you want to delete?",
                    reply_markup=delete_service_options_keyboard(),
                )
                return

            elif step == "adel_svc_options":
                if text == "◀️ Back":
                    state["step"] = "adel_svc_select"
                    kb = services_list_keyboard()
                    bot.send_message(chat_id, "🧹 <b>Select a Service to Delete:</b>",
                                     reply_markup=kb or manage_services_keyboard())
                    return
                elif text == f"🧹 {stylish('Delete Entire Service')}":
                    state["data"]["confirm_action"] = "delete_service"
                    state["step"] = "adel_confirm"
                    svc_name = state["data"]["service_name"]
                    bot.send_message(
                        chat_id,
                        f"❗️ Delete entire service <b>{svc_name}</b> and ALL its countries/numbers?",
                        reply_markup=confirm_keyboard_reply(),
                    )
                    return
                elif text == f"🗂 {stylish('Show Countries')}":
                    service_id = state["data"]["service_id"]
                    state["step"] = "adel_cntry_select"
                    bot.send_message(chat_id, f"🗺 <b>{stylish('Select a Country')}:</b>",
                                     reply_markup=delete_country_list_keyboard(service_id))
                    return
                return

            elif step == "adel_confirm":
                action = state["data"].get("confirm_action")
                if text == f"✔️ {stylish('Yes, Confirm')}":
                    if action == "delete_service":
                        service_id = state["data"]["service_id"]
                        svc_name = state["data"]["service_name"]
                        with get_conn() as conn:
                            conn.execute("DELETE FROM numbers WHERE country_id IN (SELECT id FROM countries WHERE service_id=?)", (service_id,))
                            conn.execute("DELETE FROM countries WHERE service_id=?", (service_id,))
                            conn.execute("DELETE FROM services WHERE id=?", (service_id,))
                        admin_states.pop(user.id, None)
                        bot.send_message(chat_id, f"✔️ Service <b>{svc_name}</b> deleted.", reply_markup=manage_services_keyboard())
                    elif action == "delete_country_full":
                        country_id = state["data"]["country_id"]
                        with get_conn() as conn:
                            c = conn.execute("SELECT * FROM countries WHERE id=?", (country_id,)).fetchone()
                            conn.execute("DELETE FROM numbers WHERE country_id=?", (country_id,))
                            conn.execute("DELETE FROM countries WHERE id=?", (country_id,))
                        admin_states.pop(user.id, None)
                        name = f"{c['flag']} {c['name']} +{c['code']}" if c else "Country"
                        bot.send_message(chat_id, f"✔️ Country <b>{name}</b> and numbers deleted.", reply_markup=manage_services_keyboard())
                    elif action == "delete_country_nums":
                        country_id = state["data"]["country_id"]
                        with get_conn() as conn:
                            c = conn.execute("SELECT * FROM countries WHERE id=?", (country_id,)).fetchone()
                            deleted = conn.execute("SELECT COUNT(*) FROM numbers WHERE country_id=?", (country_id,)).fetchone()[0]
                            conn.execute("DELETE FROM numbers WHERE country_id=?", (country_id,))
                        admin_states.pop(user.id, None)
                        name = f"{c['flag']} {c['name']} +{c['code']}" if c else "Country"
                        bot.send_message(chat_id, f"✔️ Deleted <b>{deleted}</b> numbers from <b>{name}</b>.", reply_markup=manage_services_keyboard())
                    elif action == "reset_country":
                        country_id = state["data"]["country_id"]
                        with get_conn() as conn:
                            c = conn.execute("SELECT * FROM countries WHERE id=?", (country_id,)).fetchone()
                            count = conn.execute("SELECT COUNT(*) FROM numbers WHERE country_id=? AND assigned=1", (country_id,)).fetchone()[0]
                            conn.execute("UPDATE numbers SET assigned=0, assigned_to=NULL, assigned_at=NULL WHERE country_id=?", (country_id,))
                        admin_states.pop(user.id, None)
                        name = f"{c['flag']} {c['name']} +{c['code']}" if c else "Country"
                        bot.send_message(chat_id, f"✔️ Reset <b>{count}</b> numbers in <b>{name}</b>.", reply_markup=manage_services_keyboard())
                elif text == f"⛔ {stylish('No, Cancel')}":
                    admin_states.pop(user.id, None)
                    bot.send_message(chat_id, "⛔ Cancelled.", reply_markup=manage_services_keyboard())
                return

            elif step == "adel_cntry_select":
                if text == "◀️ Back":
                    state["step"] = "adel_svc_options"
                    bot.send_message(chat_id, f"📟 <b>{state['data']['service_name']}</b>\n\nWhat do you want to delete?",
                                     reply_markup=delete_service_options_keyboard())
                    return
                service_id = state["data"]["service_id"]
                with get_conn() as conn:
                    countries = conn.execute("SELECT * FROM countries WHERE service_id=? ORDER BY name", (service_id,)).fetchall()
                selected = None
                for c in countries:
                    if text == f"{c['flag']} {c['name']} +{c['code']}":
                        selected = c
                        break
                if not selected:
                    return
                state["data"]["country_id"] = selected["id"]
                state["data"]["country_name"] = selected["name"]
                state["data"]["country_flag"] = selected["flag"]
                state["data"]["country_code"] = selected["code"]
                state["step"] = "adel_cntry_options"
                bot.send_message(
                    chat_id,
                    f"🗺 <b>{selected['flag']} {selected['name']} +{selected['code']}</b>\n\nWhat do you want to delete?",
                    reply_markup=delete_country_options_keyboard(),
                )
                return

            elif step == "adel_cntry_options":
                if text == "◀️ Back":
                    service_id = state["data"]["service_id"]
                    state["step"] = "adel_cntry_select"
                    bot.send_message(chat_id, f"🗺 <b>{stylish('Select a Country')}:</b>",
                                     reply_markup=delete_country_list_keyboard(service_id))
                    return
                elif text == f"🧹 {stylish('Delete Country + Numbers')}":
                    state["data"]["confirm_action"] = "delete_country_full"
                    state["step"] = "adel_confirm"
                    c = state["data"]
                    bot.send_message(
                        chat_id,
                        f"❗️ Delete <b>{c['country_flag']} {c['country_name']} +{c['country_code']}</b> and ALL its numbers?",
                        reply_markup=confirm_keyboard_reply(),
                    )
                    return
                elif text == f"🧹 {stylish('Delete Numbers Only')}":
                    state["data"]["confirm_action"] = "delete_country_nums"
                    state["step"] = "adel_confirm"
                    c = state["data"]
                    bot.send_message(
                        chat_id,
                        f"❗️ Delete all numbers from <b>{c['country_flag']} {c['country_name']} +{c['country_code']}</b>?",
                        reply_markup=confirm_keyboard_reply(),
                    )
                    return
                return

            elif step == "areset_svc_select":
                if text == "◀️ Back":
                    admin_states.pop(user.id, None)
                    bot.send_message(chat_id, f"🗂 <b>{stylish('Manage Services')}</b>", reply_markup=manage_services_keyboard())
                    return
                svc_name = text.replace("📟 ", "").strip()
                with get_conn() as conn:
                    svc = conn.execute("SELECT * FROM services WHERE name=?", (svc_name,)).fetchone()
                if not svc:
                    return
                state["data"]["service_id"] = svc["id"]
                state["data"]["service_name"] = svc["name"]
                state["step"] = "areset_cntry_select"
                bot.send_message(chat_id, "🗺 <b>Select Country to Reset:</b>",
                                 reply_markup=reset_countries_keyboard(svc["id"]))
                return

            elif step == "areset_cntry_select":
                if text == "◀️ Back":
                    state["step"] = "areset_svc_select"
                    kb = reset_services_keyboard()
                    bot.send_message(chat_id, "♻ <b>Select Service to Reset Numbers:</b>",
                                     reply_markup=kb or manage_services_keyboard())
                    return
                service_id = state["data"]["service_id"]
                with get_conn() as conn:
                    countries = conn.execute("SELECT * FROM countries WHERE service_id=? ORDER BY name", (service_id,)).fetchall()
                selected = None
                for c in countries:
                    if text == f"{c['flag']} {c['name']} +{c['code']}":
                        selected = c
                        break
                if not selected:
                    return
                state["data"]["country_id"] = selected["id"]
                state["data"]["country_flag"] = selected["flag"]
                state["data"]["country_name"] = selected["name"]
                state["data"]["country_code"] = selected["code"]
                state["data"]["confirm_action"] = "reset_country"
                state["step"] = "adel_confirm"
                with get_conn() as conn:
                    count = conn.execute("SELECT COUNT(*) FROM numbers WHERE country_id=? AND assigned=1", (selected["id"],)).fetchone()[0]
                bot.send_message(
                    chat_id,
                    f"❗️ Reset <b>{count}</b> assigned numbers in <b>{selected['flag']} {selected['name']} +{selected['code']}</b>?",
                    reply_markup=confirm_keyboard_reply(),
                )
                return

        # ══════════════════════════════════════════════════════════════════════
        # ADMIN MAIN MENU BUTTONS (no active state)
        # ══════════════════════════════════════════════════════════════════════
        if text == f"🛠️ {stylish('Manage Services')}":
            bot.send_message(chat_id, f"🗂 <b>{stylish('Manage Services')}</b>", reply_markup=manage_services_keyboard())
            return

        elif text == f"📊 {stylish('Dashboard')}":
            _show_dashboard(chat_id, is_main_admin=_is_main_admin)
            return

        elif text == f"🛡️ {stylish('Ban Unban')}":
            bot.send_message(chat_id, "🛑 <b>Ban / Unban Panel</b>", reply_markup=ban_unban_keyboard())
            return

        elif text == f"🛑 {stylish('Ban User')}":
            admin_states[user.id] = {"step": "aban_uid", "data": {}}
            bot.send_message(chat_id, "🛑 Enter the <b>User ID</b> to ban:", reply_markup=cancel_keyboard())
            return

        elif text == f"✔️ {stylish('Unban User')}":
            admin_states[user.id] = {"step": "aunban_uid", "data": {}}
            bot.send_message(chat_id, "✔️ Enter the <b>User ID</b> to unban:", reply_markup=cancel_keyboard())
            return

        elif text == f"📣 {stylish('Broadcast')}":
            admin_states[user.id] = {"step": "abroadcast_wait", "data": {}}
            bot.send_message(
                chat_id,
                "📣 <b>Broadcast</b>\n\nSend any message to broadcast to all users.\n\nPress ⛔ Cancel to abort.",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"💎 {stylish('Balance Mgmt')}":
            earn = get_otp_earn()
            referral_bonus = get_referral_bonus()
            bot.send_message(
                chat_id,
                f"💲 <b>Balance Management</b>\n\n"
                f"🎛️ Current OTP Earn: <b>{earn:.2f} BDT</b>\n"
                f"🎁 Current Referral Bonus: <b>{referral_bonus:.2f} BDT</b>",
                reply_markup=balance_management_keyboard(),
            )
            return

        elif text == f"🎛️ {stylish('Set OTP Earn')}":
            admin_states[user.id] = {"step": "aset_otp_earn", "data": {}}
            bot.send_message(chat_id, "🎛️ Enter new <b>OTP earn amount</b> per OTP (in BDT):", reply_markup=cancel_keyboard())
            return

        elif text == f"🎁 {stylish('Set Referral Bonus')}":
            admin_states[user.id] = {"step": "aset_referral_bonus", "data": {}}
            bot.send_message(chat_id, "🎁 Enter new <b>referral bonus</b> per valid referral (in BDT):", reply_markup=cancel_keyboard())
            return

        elif text == f"💲 {stylish('Add Balance')}":
            admin_states[user.id] = {"step": "aadd_balance", "data": {}}
            bot.send_message(chat_id, "💲 Enter: <code>user_id amount</code>\nExample: <code>123456789 50</code>", reply_markup=cancel_keyboard())
            return

        elif text == f"➖ {stylish('Remove Balance')}":
            admin_states[user.id] = {"step": "arem_balance", "data": {}}
            bot.send_message(chat_id, "➖ Enter: <code>user_id amount</code>\nExample: <code>123456789 50</code>", reply_markup=cancel_keyboard())
            return

        elif text == f"🪙 {stylish('Withdraw Mgmt')}":
            min_wd = get_min_withdraw()
            bot.send_message(
                chat_id,
                f"🪙 <b>Withdraw Management</b>\n\n🎛️ Min Withdraw: <b>{min_wd:.0f} BDT</b>",
                reply_markup=withdraw_management_keyboard(),
            )
            return

        elif text == f"➕ {stylish('Add Method')}":
            admin_states[user.id] = {"step": "awm_add", "data": {}}
            bot.send_message(chat_id, "➕ Enter the payment method name (e.g. Bkash, Nagad, Rocket):", reply_markup=cancel_keyboard())
            return

        elif text == f"🧹 {stylish('Delete Method')}":
            methods = get_all_withdraw_methods()
            if not methods:
                bot.send_message(chat_id, "⛔ No methods found.", reply_markup=withdraw_management_keyboard())
                return
            admin_states[user.id] = {"step": "awm_del", "data": {}}
            kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
            for m in methods:
                kb.add(KeyboardButton(m["name"]))
            kb.add(KeyboardButton("❎️ Cancel"))
            bot.send_message(chat_id, "🧹 Select method to delete:", reply_markup=kb)
            return

        elif text == f"🧾 {stylish('List Methods')}":
            methods = get_all_withdraw_methods()
            if not methods:
                bot.send_message(chat_id, "⛔ No methods configured.", reply_markup=withdraw_management_keyboard())
            else:
                lines = ["<b>🪙 Withdraw Methods:</b>\n"]
                for m in methods:
                    status = "✔️" if m["is_enabled"] else "⛔"
                    lines.append(f"{status} {m['name']}")
                bot.send_message(chat_id, "\n".join(lines), reply_markup=withdraw_management_keyboard())
            return

        elif text == f"🎛️ {stylish('Set Min Withdraw')}":
            admin_states[user.id] = {"step": "awm_set_min", "data": {}}
            bot.send_message(chat_id, f"🎛️ {stylish('Enter minimum withdraw amount (in BDT):')}  ", reply_markup=cancel_keyboard())
            return

        # ── SETTINGS (Task 2) ──────────────────────────────────────────────
        elif text == f"🔧 {stylish('Settings')}":
            fj = "🟩 ON" if is_force_join_enabled() else "🟥 OFF"
            support = get_setting("support_link", "Not set")
            otp_grp = get_setting("otp_group_link", "Not set")
            pmt_id = get_setting("payment_forward_chat_id", "Not set")
            otp_fwd = get_setting("otp_forward_chat_id", "Not set")
            bot.send_message(
                chat_id,
                f"🎛️ <b>Settings</b>\n\n"
                f"🔏 Force Join: <b>{fj}</b>\n\n"
                f"☎ Support Link: <code>{support}</code>\n"
                f"🗨 OTP Group Link: <code>{otp_grp}</code>\n"
                f"🪪 Payment Fwd ID: <code>{pmt_id}</code>\n"
                f"📨 OTP Fwd ID: <code>{otp_fwd}</code>",
                reply_markup=settings_keyboard(is_main_admin=(user.id == ADMIN_ID)),
            )
            return

        # ── LEADERBOARD ON/OFF ───────────────────────────────────────────
        elif text in (f"🏆 {stylish('Leaderboard')}: ON", f"🏆 {stylish('Leaderboard')}: OFF"):
            new_val = "0" if is_leaderboard_enabled() else "1"
            set_setting("leaderboard_enabled", new_val)
            status = "🟩 ENABLED" if new_val == "1" else "🟥 DISABLED"
            bot.send_message(
                chat_id,
                f"✔️ Leaderboard is now <b>{status}</b>",
                reply_markup=settings_keyboard(is_main_admin=(user.id == ADMIN_ID)),
            )
            return

        # ── TEMP MAIL DOMAINS ────────────────────────────────────────────
        elif text == f"📬 {stylish('Temp Mail Domains')}":
            bot.send_message(
                chat_id, _temp_mail_admin_status_text(), reply_markup=temp_mail_admin_keyboard()
            )
            return

        elif text == f"➕ {stylish('Add Mail Domain')}":
            admin_states[user.id] = {"step": "atm_add_domain", "data": {}}
            bot.send_message(
                chat_id,
                "➕ <b>Add Mail Domain</b>\n\n"
                "আপনার domain টি লিখুন (যেমন <code>mydomain.com</code>):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧾 {stylish('List Mail Domains')}":
            bot.send_message(
                chat_id, _temp_mail_domains_text(), reply_markup=temp_mail_admin_keyboard()
            )
            return

        elif text == f"🧹 {stylish('Del Mail Domain')}":
            rows = get_temp_mail_domains()
            if not rows:
                bot.send_message(
                    chat_id, "⛔ No mail domain added.", reply_markup=temp_mail_admin_keyboard()
                )
                return
            admin_states[user.id] = {"step": "atm_del_domain", "data": {}}
            kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
            for row in rows:
                kb.add(KeyboardButton(row["domain"]))
            kb.add(KeyboardButton("❎️ Cancel"))
            bot.send_message(chat_id, "🧹 Select a domain to delete:", reply_markup=kb)
            return

        elif text == f"🔁 {stylish('Toggle Mail Domain')}":
            rows = get_temp_mail_domains()
            if not rows:
                bot.send_message(
                    chat_id, "⛔ No mail domain added.", reply_markup=temp_mail_admin_keyboard()
                )
                return
            admin_states[user.id] = {"step": "atm_toggle_domain", "data": {}}
            kb = ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
            for row in rows:
                kb.add(KeyboardButton(row["domain"]))
            kb.add(KeyboardButton("❎️ Cancel"))
            bot.send_message(chat_id, "🔁 Select a domain to enable/disable:", reply_markup=kb)
            return

        elif text == f"🧪 {stylish('Mail Provider Status')}":
            try:
                health = _run_temp_mail_coroutine(temp_mail_engine.provider_health())
                lines = ["🧪 <b>Free Mail Provider Status</b>\n"]
                for provider, is_up in health.items():
                    label = temp_mail_engine.PROVIDER_LABELS.get(provider, provider)
                    lines.append(f"{'🟩' if is_up else '🟥'} {label}")
                lines.append("\nGet Mail সবসময় প্রথমে যেটা কাজ করে সেটা ব্যবহার করবে।")
                bot.send_message(
                    chat_id, "\n".join(lines), reply_markup=temp_mail_admin_keyboard()
                )
            except Exception as exc:
                bot.send_message(
                    chat_id,
                    f"⛔ Status check failed: <code>{_html.escape(str(exc))}</code>",
                    reply_markup=temp_mail_admin_keyboard(),
                )
            return

        # ── AUTO SMS ─────────────────────────────────────────────────────
        elif text == f"🚀 {stylish('Auto SMS')}":
            bot.send_message(chat_id, _auto_sms_status_text(), reply_markup=auto_sms_keyboard())
            return

        elif text in (f"🚀 {stylish('Auto SMS')}: ON", f"🚀 {stylish('Auto SMS')}: OFF"):
            new_val = "0" if is_auto_sms_enabled() else "1"
            if new_val == "1" and not get_setting("auto_sms_chat_id", ""):
                bot.send_message(
                    chat_id,
                    f"⛔ {stylish('Set the Auto SMS Group/Channel ID first.')}",
                    reply_markup=auto_sms_keyboard(),
                )
                return
            set_setting("auto_sms_enabled", new_val)
            bot.send_message(chat_id, _auto_sms_status_text(), reply_markup=auto_sms_keyboard())
            return

        elif text == f"🗨 {stylish('Set Auto SMS Group ID')}":
            admin_states[user.id] = {"step": "aauto_chat_id", "data": {}}
            bot.send_message(
                chat_id,
                f"🗨 {stylish('Send the Auto SMS Group/Channel ID (e.g. -1001234567890):')}",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text in (f"🧪 {stylish('Demo SMS')}: ON", f"🧪 {stylish('Demo SMS')}: OFF"):
            new_val = "0" if is_demo_sms_enabled() else "1"
            if new_val == "1" and not get_setting("auto_sms_chat_id", ""):
                bot.send_message(
                    chat_id,
                    f"⛔ {stylish('Set the Auto SMS Group/Channel ID first.')}",
                    reply_markup=auto_sms_keyboard(),
                )
                return
            set_setting("auto_sms_demo_enabled", new_val)
            if new_val == "1":
                set_setting("auto_sms_enabled", "1")
            bot.send_message(chat_id, _auto_sms_status_text(), reply_markup=auto_sms_keyboard())
            return

        elif text == f"⏱ {stylish('Set Demo Delay')}":
            admin_states[user.id] = {"step": "aauto_demo_delay", "data": {}}
            bot.send_message(
                chat_id,
                f"⏱ {stylish('Send the demo delay.')}\n\n"
                f"Examples: <code>3s</code> · <code>30s</code> · <code>3m</code> · "
                f"<code>5m</code> · <code>10m</code>\n"
                f"Plain number = seconds. Minimum <b>3 sec</b>, maximum <b>60 min</b>.",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"📨 {stylish('Send Demo SMS Now')}":
            ok = _send_demo_sms()
            bot.send_message(
                chat_id,
                f"✔️ {stylish('Demo SMS sent.')}" if ok
                else f"⛔ {stylish('Could not send. Check the Auto SMS group ID.')}",
                reply_markup=auto_sms_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Del Auto SMS Group')}":
            delete_setting("auto_sms_chat_id")
            set_setting("auto_sms_enabled", "0")
            set_setting("auto_sms_demo_enabled", "0")
            bot.send_message(chat_id, f"✔️ {stylish('Auto SMS group removed.')}", reply_markup=auto_sms_keyboard())
            return

        # ── BACKUP MENU ──────────────────────────────────────────────────
        elif text == f"🗄 {stylish('Backup')}":
            bot.send_message(
                chat_id,
                f"🗄 <b>{stylish('Backup')}</b>\n\n"
                f"📤 {stylish('Backup File')} — {stylish('download the current database')}\n"
                f"📥 {stylish('Input File')} — {stylish('restore the database from a file you upload')}",
                reply_markup=backup_keyboard(),
            )
            return

        elif text == f"📤 {stylish('Backup File')}":
            admin_states.pop(user.id, None)
            backup_path = None
            try:
                backup_path = create_database_backup()
                with open(backup_path, "rb") as f:
                    bot.send_document(
                        chat_id,
                        f,
                        caption=(
                            f"🗄 {stylish('Complete Database Backup')} — "
                            f"<code>Superfast OTP Backup.db</code>\n"
                            f"✅ {stylish('Shop products, orders, wallet and settings included.')}"
                        ),
                        visible_file_name="Superfast OTP Backup.db",
                    )
                bot.send_message(chat_id, f"✔️ {stylish('Backup sent.')}", reply_markup=backup_keyboard())
            except Exception as e:
                logger.error("Manual backup failed (%s)", type(e).__name__)
                bot.send_message(
                    chat_id,
                    f"⛔ {stylish('Backup failed. No incomplete file was sent.')}",
                    reply_markup=backup_keyboard(),
                )
            finally:
                if backup_path:
                    try:
                        os.remove(backup_path)
                    except OSError:
                        logger.warning("Could not remove temporary backup %s", backup_path)
            return

        elif text == f"📥 {stylish('Input File')}":
            admin_states[user.id] = {"step": "abackup_restore_wait", "data": {}}
            bot.send_message(
                chat_id,
                f"📥 {stylish('Send the backup .db file to restore.')}\n\n"
                f"❗️ {stylish('This will replace the current database.')}",
                reply_markup=cancel_keyboard(),
            )
            return

        # ── FORCE JOIN menu (Task 3) ───────────────────────────────────────
        elif text == f"🔏 {stylish('Force Join')}":
            fj = "🟩 ON" if is_force_join_enabled() else "🟥 OFF"
            channels = get_join_channels()
            ch_list = ""
            for ch in channels:
                type_icon = "📣" if ch["channel_type"] == "channel" else "👥"
                ch_list += f"\n{type_icon} <b>{ch['channel_name']}</b> — <code>{ch['channel_id']}</code>"
            bot.send_message(
                chat_id,
                f"🔏 <b>Force Join</b>\n\nStatus: <b>{fj}</b>\n\n"
                f"<b>Configured Channels/Groups:</b>"
                + (ch_list if ch_list else "\n<i>None configured</i>"),
                reply_markup=force_join_keyboard(),
            )
            return

        elif text == f"➕ {stylish('Add Channel')}":
            admin_states[user.id] = {"step": "aset_fj_add_channel", "data": {}}
            bot.send_message(
                chat_id,
                "📣 Send your <b>Channel link</b>:\n\nExample:\n<code>https://t.me/yourchannel</code>\nor\n<code>@yourchannel</code>",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"➕ {stylish('Add Group')}":
            admin_states[user.id] = {"step": "aset_fj_add_group", "data": {}}
            bot.send_message(
                chat_id,
                "👥 Send your <b>Group link</b>:\n\nExample:\n<code>https://t.me/yourgroup</code>\nor\n<code>@yourgroup</code>",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Delete Channel')}":
            kb = join_channels_list_keyboard(channel_type="channel")
            if not kb:
                bot.send_message(chat_id, "⛔ No channels configured.", reply_markup=force_join_keyboard())
                return
            admin_states[user.id] = {"step": "aset_fj_del_ch", "data": {}}
            bot.send_message(chat_id, "🧹 Select a channel to remove:", reply_markup=kb)
            return

        elif text == f"🧹 {stylish('Delete Group')}":
            kb = join_channels_list_keyboard(channel_type="group")
            if not kb:
                bot.send_message(chat_id, "⛔ No groups configured.", reply_markup=force_join_keyboard())
                return
            admin_states[user.id] = {"step": "aset_fj_del_gr", "data": {}}
            bot.send_message(chat_id, "🧹 Select a group to remove:", reply_markup=kb)
            return

        elif (text in (
                f"🟩 {stylish('Force Join: ON')}",
                f"🟥 {stylish('Force Join: OFF')}",
                "🟩 Force Join: ON", "🟥 Force Join: OFF",
              ) or
              text.startswith("🟩") and "Force" in text and "Join" in text or
              text.startswith("🟥") and "Force" in text and "Join" in text):
            current = get_setting("force_join_enabled", "0")
            new_val = "0" if current == "1" else "1"
            set_setting("force_join_enabled", new_val)
            status = "🟩 ENABLED" if new_val == "1" else "🟥 DISABLED"
            bot.send_message(
                chat_id,
                f"✔️ Force Join is now <b>{status}</b>",
                reply_markup=force_join_keyboard(),
            )
            return

        elif text == f"↩ {stylish('Back to Settings')}":
            admin_states.pop(user.id, None)
            fj = "🟩 ON" if is_force_join_enabled() else "🟥 OFF"
            bot.send_message(
                chat_id,
                f"🎛️ <b>Settings</b>\n\nForce Join: <b>{fj}</b>",
                reply_markup=settings_keyboard(is_main_admin=(user.id == ADMIN_ID)),
            )
            return

        # ── OTHERS LINK menu (Task 4) ──────────────────────────────────────
        elif text == f"⛓ {stylish('Others Link')}":
            support = get_setting("support_link", "Not set")
            otp_grp = get_setting("otp_group_link", "Not set")
            panel_lnk = get_setting("panel_link", "Not set")
            dev_lnk = get_setting("dev_link", "Not set")
            main_channel = get_setting("main_channel_link", "Not set")
            pmt_id = get_setting("payment_forward_chat_id", "Not set")
            otp_fwd = get_setting("otp_forward_chat_id", "Not set")
            bn = get_setting("bot_name", "OTP BOT")
            pw = get_setting("powered_by", "সুমন")
            bot.send_message(
                chat_id,
                f"⛓ <b>Others Link Settings</b>\n\n"
                f"☎ <b>Support Link:</b> <code>{support}</code>\n"
                f"🗨 <b>OTP Group Link:</b> <code>{otp_grp}</code>\n"
                f"👑 <b>Number Panel Link:</b> <code>{panel_lnk}</code>\n"
                f"⚡ <b>Bot Developer Link:</b> <code>{dev_lnk}</code>\n"
                f"📣 <b>Main Channel Link:</b> <code>{main_channel}</code>\n"
                f"🪪 <b>Payment Fwd ID:</b> <code>{pmt_id}</code>\n"
                f"📨 <b>OTP Fwd ID:</b> <code>{otp_fwd}</code>\n"
                f"🦾 <b>Bot Name:</b> <code>{bn}</code>\n"
                f"🕷 <b>Powered By:</b> <code>{pw}</code>",
                reply_markup=others_link_keyboard(),
            )
            return

        elif text == f"☎ {stylish('Support Btn')}":
            admin_states[user.id] = {"step": "aset_ol_support", "data": {}}
            cur = get_setting("support_link", "Not set")
            bot.send_message(
                chat_id,
                f"☎ Current support link: <code>{cur}</code>\n\nSend new support URL:",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🗨 {stylish('OTP Group Btn')}":
            admin_states[user.id] = {"step": "aset_ol_otpgroup", "data": {}}
            cur = get_setting("otp_group_link", "Not set")
            bot.send_message(
                chat_id,
                f"🗨 Current OTP group link: <code>{cur}</code>\n\nSend new OTP Group URL:",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"👑 {stylish('Panel Link')}":
            admin_states[user.id] = {"step": "aset_ol_panel_link", "data": {}}
            cur = get_setting("panel_link", "Not set")
            bot.send_message(
                chat_id,
                f"👑 Current Number Panel link: <code>{cur}</code>\n\nSend new Number Panel URL (https://...):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Del Panel Link')}":
            delete_setting("panel_link")
            bot.send_message(chat_id, "✔️ Number Panel link removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"🤖 {stylish('Auto SMS Bot Link')}":
            admin_states[user.id] = {"step": "aset_ol_auto_bot_link", "data": {}}
            cur = get_setting("auto_sms_bot_link", "Not set")
            bot.send_message(
                chat_id,
                f"🤖 Current Auto SMS <b>GO TO BOT</b> link: <code>{cur}</code>\n\n"
                f"Send the bot link (https://t.me/yourbot):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Del Auto Bot Link')}":
            delete_setting("auto_sms_bot_link")
            bot.send_message(chat_id, "✔️ Auto SMS bot link removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"📢 {stylish('Auto SMS Channel Link')}":
            admin_states[user.id] = {"step": "aset_ol_auto_channel_link", "data": {}}
            cur = get_setting("auto_sms_channel_link", "Not set")
            bot.send_message(
                chat_id,
                f"📢 Current Auto SMS <b>GO TO CHANNEL</b> link: <code>{cur}</code>\n\n"
                f"Send the channel link (https://t.me/yourchannel):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Del Auto Channel Link')}":
            delete_setting("auto_sms_channel_link")
            bot.send_message(chat_id, "✔️ Auto SMS channel link removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"⚡ {stylish('Dev Link')}":
            admin_states[user.id] = {"step": "aset_ol_dev_link", "data": {}}
            cur = get_setting("dev_link", "Not set")
            bot.send_message(
                chat_id,
                f"⚡ Current Bot Developer link: <code>{cur}</code>\n\nSend new Bot Developer URL (https://...):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"📣 {stylish('Main Channel')}":
            admin_states[user.id] = {"step": "aset_ol_main_channel", "data": {}}
            cur = get_setting("main_channel_link", "Not set")
            bot.send_message(
                chat_id,
                f"📣 Current main channel link: <code>{cur}</code>\n\n"
                f"Send the channel URL (for the GO TO CHANNEL button):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Del Main Channel')}":
            delete_setting("main_channel_link")
            bot.send_message(chat_id, "✔️ Main channel link removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"🧹 {stylish('Del Dev Link')}":
            delete_setting("dev_link")
            bot.send_message(chat_id, "✔️ Bot Developer link removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"🪪 {stylish('Payment Request ID')}":
            admin_states[user.id] = {"step": "aset_ol_payment_id", "data": {}}
            cur = get_setting("payment_forward_chat_id", "Not set")
            bot.send_message(
                chat_id,
                f"🪪 Current payment forward Chat ID: <code>{cur}</code>\n\nSend new Chat ID (numeric):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"📨 {stylish('OTP Forward ID')}":
            admin_states[user.id] = {"step": "aset_ol_otp_fwd", "data": {}}
            cur = get_setting("otp_forward_chat_id", "Not set")
            bot.send_message(
                chat_id,
                f"📨 Current OTP forward Chat ID: <code>{cur}</code>\n\nSend new Chat ID (numeric):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Del Support')}":
            delete_setting("support_link")
            bot.send_message(chat_id, "✔️ Support link removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"🧹 {stylish('Del OTP Group')}":
            delete_setting("otp_group_link")
            bot.send_message(chat_id, "✔️ OTP Group link removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"🧹 {stylish('Del Payment ID')}":
            delete_setting("payment_forward_chat_id")
            bot.send_message(chat_id, "✔️ Payment Request ID removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"🧹 {stylish('Del OTP Fwd')}":
            delete_setting("otp_forward_chat_id")
            bot.send_message(chat_id, "✔️ OTP Forward ID removed.", reply_markup=others_link_keyboard())
            return

        elif text == f"🦾 {stylish('Bot Name')}":
            admin_states[user.id] = {"step": "aset_ol_bot_name", "data": {}}
            cur = get_setting("bot_name", "OTP BOT")
            bot.send_message(
                chat_id,
                f"🦾 Current bot name: <code>{cur}</code>\n\nSend new bot name:",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Del Bot Name')}":
            delete_setting("bot_name")
            bot.send_message(chat_id, "✔️ Bot name reset to default.", reply_markup=others_link_keyboard())
            return

        elif text == f"🕷 {stylish('Powered By')}":
            admin_states[user.id] = {"step": "aset_ol_powered_by", "data": {}}
            cur = get_setting("powered_by", "সুমন")
            bot.send_message(
                chat_id,
                f"🕷 Current powered by text: <code>{cur}</code>\n\nSend new powered by text:",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Del Powered By')}":
            delete_setting("powered_by")
            bot.send_message(chat_id, f"✔️ {stylish('Powered By reset to default.')}", reply_markup=others_link_keyboard())
            return

        # ── API MANAGEMENT ─────────────────────────────────────────────────
        elif text == f"🗝 {stylish('API Management')}":
            lines = ["🗝 <b>API Management</b>\n"]
            for api_id, defn in API_DEFINITIONS.items():
                cfg = get_api_config(api_id)
                status = "🟩 ON" if cfg["enabled"] else "🟥 OFF"
                key_preview = cfg["key"][:8] + "..." if len(cfg["key"]) > 8 else cfg["key"]
                lines.append(f"<b>{defn['name']}</b> [{status}]\n⛓ Key: <code>{key_preview}</code>")
            bot.send_message(chat_id, "\n\n".join(lines), reply_markup=api_management_keyboard())
            return

        elif text == f"↩ {stylish('API Management')}":
            lines = ["🗝 <b>API Management</b>\n"]
            for api_id, defn in API_DEFINITIONS.items():
                cfg = get_api_config(api_id)
                status = "🟩 ON" if cfg["enabled"] else "🟥 OFF"
                key_preview = cfg["key"][:8] + "..." if len(cfg["key"]) > 8 else cfg["key"]
                lines.append(f"<b>{defn['name']}</b> [{status}]\n⛓ Key: <code>{key_preview}</code>")
            bot.send_message(chat_id, "\n\n".join(lines), reply_markup=api_management_keyboard())
            return

        # ── API MANAGEMENT DETAIL BUTTONS ─────────────────────────────────
        elif text in (f"🟩 {stylish('SMShadi')}", f"🟥 {stylish('SMShadi')}"):
            _show_api_detail(chat_id, "smshadi")
            return
        elif text in (f"🟩 {stylish('Lamix')}", f"🟥 {stylish('Lamix')}"):
            _show_api_detail(chat_id, "lamix")
            return
        elif text in (f"🟩 {stylish('YesMS API')}", f"🟥 {stylish('YesMS API')}"):
            _show_api_detail(chat_id, "yesms")
            return
        elif text in (f"🟩 {stylish('StexSMS')}", f"🟥 {stylish('StexSMS')}"):
            _show_api_detail(chat_id, "stexsms")
            return
        elif text in (f"🟩 {stylish('FastXOTPs')}", f"🟥 {stylish('FastXOTPs')}"):
            _show_api_detail(chat_id, "fastxotps")
            return
        elif text in (f"🟩 {stylish('VoltXSMS')}", f"🟥 {stylish('VoltXSMS')}"):
            _show_api_detail(chat_id, "voltxsms")
            return
        elif text in (f"🟩 {stylish('ZebraSMS')}", f"🟥 {stylish('ZebraSMS')}"):
            _show_api_detail(chat_id, "zebrasms")
            return
        elif text == f"🗝 {stylish('Set Key')} [smshadi]":
            admin_states[user.id] = {"step": "aapi_setkey_smshadi", "data": {}}
            bot.send_message(chat_id, f"🗝 {stylish('Send new API key for')} <b>SMShadi</b>:", reply_markup=cancel_keyboard())
            return
        elif text == f"🗝 {stylish('Set Key')} [lamix]":
            admin_states[user.id] = {"step": "aapi_setkey_lamix", "data": {}}
            bot.send_message(chat_id, f"🗝 {stylish('Send new API key for')} <b>Lamix</b>:", reply_markup=cancel_keyboard())
            return
        elif text == f"🗝 {stylish('Set Key')} [yesms]":
            admin_states[user.id] = {"step": "aapi_setkey_yesms", "data": {}}
            bot.send_message(chat_id, f"🗝 {stylish('Send new API key for')} <b>YesMS API</b>:", reply_markup=cancel_keyboard())
            return
        elif text == f"🗝 {stylish('Set Key')} [stexsms]":
            admin_states[user.id] = {"step": "aapi_setkey_stexsms", "data": {}}
            bot.send_message(chat_id, f"🗝 {stylish('Send new API key for')} <b>StexSMS</b>:", reply_markup=cancel_keyboard())
            return
        elif text == f"🗝 {stylish('Set Key')} [fastxotps]":
            admin_states[user.id] = {"step": "aapi_setkey_fastxotps", "data": {}}
            bot.send_message(chat_id, f"🗝 {stylish('Send new API key for')} <b>FastXOTPs</b>:", reply_markup=cancel_keyboard())
            return
        elif text == f"🗝 {stylish('Set Key')} [voltxsms]":
            admin_states[user.id] = {"step": "aapi_setkey_voltxsms", "data": {}}
            bot.send_message(chat_id, f"🗝 {stylish('Send new API key for')} <b>VoltXSMS</b>:", reply_markup=cancel_keyboard())
            return
        elif text == f"🗝 {stylish('Set Key')} [zebrasms]":
            admin_states[user.id] = {"step": "aapi_setkey_zebrasms", "data": {}}
            bot.send_message(chat_id, f"🗝 {stylish('Send new API key for')} <b>ZebraSMS</b>:", reply_markup=cancel_keyboard())
            return
        elif text == f"🧹 {stylish('Remove Key')} [smshadi]":
            remove_api_key("smshadi")
            bot.send_message(chat_id, f"✔️ {stylish('SMShadi key removed. Using default.')}", reply_markup=api_management_keyboard())
            return
        elif text == f"🧹 {stylish('Remove Key')} [lamix]":
            remove_api_key("lamix")
            bot.send_message(chat_id, f"✔️ {stylish('Lamix key removed. Using default.')}", reply_markup=api_management_keyboard())
            return
        elif text == f"🧹 {stylish('Remove Key')} [yesms]":
            remove_api_key("yesms")
            bot.send_message(chat_id, f"✔️ {stylish('YesMS API key removed. Using default.')}", reply_markup=api_management_keyboard())
            return
        elif text == f"🧹 {stylish('Remove Key')} [stexsms]":
            remove_api_key("stexsms")
            bot.send_message(chat_id, f"✔️ {stylish('StexSMS key removed. Using default.')}", reply_markup=api_management_keyboard())
            return
        elif text == f"🧹 {stylish('Remove Key')} [fastxotps]":
            remove_api_key("fastxotps")
            bot.send_message(chat_id, f"✔️ {stylish('FastXOTPs key removed. Using default.')}", reply_markup=api_management_keyboard())
            return
        elif text == f"🧹 {stylish('Remove Key')} [voltxsms]":
            remove_api_key("voltxsms")
            bot.send_message(chat_id, f"✔️ {stylish('VoltXSMS key removed. Using default.')}", reply_markup=api_management_keyboard())
            return
        elif text == f"🧹 {stylish('Remove Key')} [zebrasms]":
            remove_api_key("zebrasms")
            bot.send_message(chat_id, f"✔️ {stylish('ZebraSMS key removed.')}", reply_markup=api_management_keyboard())
            return
        elif text in (f"🟩 {stylish('Enable')} [smshadi]", f"🟥 {stylish('Disable')} [smshadi]"):
            new_state = toggle_api_enabled("smshadi")
            bot.send_message(chat_id, f"✔️ {stylish('SMShadi')} {stylish('is now')} {'🟩 ENABLED' if new_state else '🟥 DISABLED'}", reply_markup=api_management_keyboard())
            return
        elif text in (f"🟩 {stylish('Enable')} [lamix]", f"🟥 {stylish('Disable')} [lamix]"):
            new_state = toggle_api_enabled("lamix")
            bot.send_message(chat_id, f"✔️ {stylish('Lamix')} {stylish('is now')} {'🟩 ENABLED' if new_state else '🟥 DISABLED'}", reply_markup=api_management_keyboard())
            return
        elif text in (f"🟩 {stylish('Enable')} [yesms]", f"🟥 {stylish('Disable')} [yesms]"):
            new_state = toggle_api_enabled("yesms")
            bot.send_message(chat_id, f"✔️ {stylish('YesMS API')} {stylish('is now')} {'🟩 ENABLED' if new_state else '🟥 DISABLED'}", reply_markup=api_management_keyboard())
            return
        elif text in (f"🟩 {stylish('Enable')} [stexsms]", f"🟥 {stylish('Disable')} [stexsms]"):
            new_state = toggle_api_enabled("stexsms")
            bot.send_message(chat_id, f"✔️ {stylish('StexSMS')} {stylish('is now')} {'🟩 ENABLED' if new_state else '🟥 DISABLED'}", reply_markup=api_management_keyboard())
            return
        elif text in (f"🟩 {stylish('Enable')} [fastxotps]", f"🟥 {stylish('Disable')} [fastxotps]"):
            new_state = toggle_api_enabled("fastxotps")
            bot.send_message(chat_id, f"✔️ {stylish('FastXOTPs')} {stylish('is now')} {'🟩 ENABLED' if new_state else '🟥 DISABLED'}", reply_markup=api_management_keyboard())
            return
        elif text in (f"🟩 {stylish('Enable')} [voltxsms]", f"🟥 {stylish('Disable')} [voltxsms]"):
            new_state = toggle_api_enabled("voltxsms")
            bot.send_message(chat_id, f"✔️ {stylish('VoltXSMS')} {stylish('is now')} {'🟩 ENABLED' if new_state else '🟥 DISABLED'}", reply_markup=api_management_keyboard())
            return
        elif text in (f"🟩 {stylish('Enable')} [zebrasms]", f"🟥 {stylish('Disable')} [zebrasms]"):
            new_state = toggle_api_enabled("zebrasms")
            bot.send_message(chat_id, f"✔️ {stylish('ZebraSMS')} {stylish('is now')} {'🟩 ENABLED' if new_state else '🟥 DISABLED'}", reply_markup=api_management_keyboard())
            return
        elif text == f"📡 {stylish('Live Access')} [zebrasms]":
            live = _zebrasms_live_access()
            status = "🟩 OK" if live["ok"] else "🟥 FAILED"
            bot.send_message(
                chat_id,
                f"📡 <b>ZebraSMS Live Access:</b> {status}\n<code>{_html.escape(str(live['detail']))}</code>",
                reply_markup=api_detail_keyboard("zebrasms"),
            )
            return

        # ── DEVELOPER INFO (main admin only) ──────────────────────────────
        elif text == f"👨‍💻 {stylish('Developer')}":
            if user.id != ADMIN_ID:
                return
            cur = get_setting("developer_info", "Not set")
            bot.send_message(
                chat_id,
                f"👨‍💻 <b>Developer Info</b>\n\nCurrent info:\n<code>{cur}</code>",
                reply_markup=developer_keyboard(),
            )
            return

        elif text == f"✏️ {stylish('Set Dev Info')}":
            if user.id != ADMIN_ID:
                return
            admin_states[user.id] = {"step": "adev_set_info", "data": {}}
            cur = get_setting("developer_info", "Not set")
            bot.send_message(
                chat_id,
                f"Current dev info:\n<code>{cur}</code>\n\nSend new developer info text (HTML supported):",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Clear Dev Info')}":
            if user.id != ADMIN_ID:
                return
            delete_setting("developer_info")
            bot.send_message(chat_id, "✔️ Developer info cleared.", reply_markup=developer_keyboard())
            return

        # ── USERS LIST ────────────────────────────────────────────────────
        elif text == f"👥 {stylish('Users')}":
            with get_conn() as conn:
                top10 = conn.execute("""
                    SELECT u.id, u.first_name, u.username, COALESCE(w.total_otp, 0) as total_otp
                    FROM users u LEFT JOIN wallet w ON u.id=w.user_id
                    ORDER BY total_otp DESC LIMIT 10
                """).fetchall()
                total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            medals = ["🥇", "🥈", "🥉", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟"]
            lines = ["<blockquote>👥 TOP 10 MOST ACTIVE USERS</blockquote>\n"]
            for i, u in enumerate(top10):
                name = u["first_name"] or "User"
                uname = f"@{u['username']}" if u["username"] else f"ID:{u['id']}"
                lines.append(f"{medals[i]} <b>{name}</b> ({uname}) — {u['total_otp']} OTPs")
            bot.send_message(chat_id, "\n".join(lines), reply_markup=admin_keyboard(is_main_admin=_is_main_admin))
            if total_users:
                export_path = None
                try:
                    fd, export_path = tempfile.mkstemp(
                        prefix="otp_users_", suffix=".txt", dir=DATA_DIR
                    )
                    with os.fdopen(fd, "w", encoding="utf-8") as export_file:
                        export_file.write("Name | Username | UID | Total OTPs\n")
                        export_file.write("-" * 50 + "\n")
                        with get_conn() as conn:
                            cursor = conn.execute("""
                                SELECT u.id, u.first_name, u.username,
                                       COALESCE(w.total_otp, 0) AS total_otp
                                FROM users u LEFT JOIN wallet w ON u.id=w.user_id
                                ORDER BY total_otp DESC
                            """)
                            for row in cursor:
                                fields = (
                                    row["first_name"] or "User",
                                    f"@{row['username']}" if row["username"] else "N/A",
                                    row["id"],
                                    row["total_otp"],
                                )
                                clean = [
                                    str(value).replace("|", "/").replace("\r", " ").replace("\n", " ")
                                    for value in fields
                                ]
                                export_file.write(" | ".join(clean) + "\n")
                    with open(export_path, "rb") as export_file:
                        bot.send_document(
                            chat_id,
                            export_file,
                            visible_file_name="all_users.txt",
                            caption=f"📄 Total users: {total_users}",
                        )
                except Exception as exc:
                    logger.error(
                        "Admin users export failed (%s)", type(exc).__name__
                    )
                    bot.send_message(chat_id, "⚠️ User export could not be created.")
                finally:
                    if export_path:
                        try:
                            os.remove(export_path)
                        except OSError:
                            pass
            return

        # ── ADMIN MANAGEMENT ──────────────────────────────────────────────
        elif text == f"👑 {stylish('Admin Management')}":
            if not _is_main_admin:
                return
            bot.send_message(chat_id, "👑 <b>Admin Management</b>", reply_markup=admin_management_keyboard())
            return

        elif text == f"➕ {stylish('Add Admin')}":
            if not _is_main_admin:
                return
            admin_states[user.id] = {"step": "amgmt_add_uid", "data": {}}
            bot.send_message(chat_id, "🧑 Enter the <b>User ID</b> to make admin:", reply_markup=cancel_keyboard())
            return

        elif text == f"👥 {stylish('View Admins')}":
            if not _is_main_admin:
                return
            sub_admins = get_sub_admins()
            if not sub_admins:
                bot.send_message(chat_id, "ℹ️ No sub-admins added yet.", reply_markup=admin_management_keyboard())
            else:
                lines = ["<blockquote>👑 CURRENT SUB-ADMINS</blockquote>\n"]
                for row in sub_admins:
                    uid = row["user_id"]
                    try:
                        member = bot.get_chat(uid)
                        name = member.first_name or "User"
                    except Exception:
                        name = "User"
                    lines.append(f"• <b>{name}</b> — <code>{uid}</code>")
                bot.send_message(chat_id, "\n".join(lines), reply_markup=admin_management_keyboard())
            return

        elif text == f"🧹 {stylish('Remove Admin')}":
            if not _is_main_admin:
                return
            sub_admins = get_sub_admins()
            if not sub_admins:
                bot.send_message(chat_id, "ℹ️ No sub-admins to remove.", reply_markup=admin_management_keyboard())
                return
            admin_states[user.id] = {"step": "amgmt_remove_uid", "data": {}}
            bot.send_message(chat_id, "🧹 Enter the <b>User ID</b> of the admin to remove:", reply_markup=cancel_keyboard())
            return

        # ── MANAGE SERVICES BUTTONS (Task 1) ──────────────────────────────
        elif text == f"➕ {stylish('Add Service')}":
            admin_states[user.id] = {"step": "asvc_add_name", "data": {}}
            bot.send_message(
                chat_id,
                "📝 <b>Add New Service</b>\n\nEnter the <b>Service Name</b>:\n\nExample: Facebook, WhatsApp, Telegram, Google",
                reply_markup=cancel_keyboard(),
            )
            return

        elif text == f"🧹 {stylish('Delete Service')}":
            kb = services_list_keyboard()
            if not kb:
                bot.send_message(chat_id, "⛔ No services found.", reply_markup=manage_services_keyboard())
                return
            admin_states[user.id] = {"step": "adel_svc_select", "data": {}}
            bot.send_message(chat_id, "🧹 <b>Select a Service to Delete:</b>", reply_markup=kb)
            return

        elif text == f"🧾 {stylish('View Services')}":
            with get_conn() as conn:
                services = conn.execute("SELECT * FROM services ORDER BY name").fetchall()
            if not services:
                bot.send_message(chat_id, "⛔ No services found.", reply_markup=manage_services_keyboard())
                return
            lines = ["<blockquote>🧾 ALL SERVICES</blockquote>\n"]
            for i, svc in enumerate(services, 1):
                with get_conn() as conn:
                    cnt = conn.execute(
                        "SELECT COUNT(*) FROM numbers WHERE country_id IN (SELECT id FROM countries WHERE service_id=?) AND assigned=0",
                        (svc["id"],),
                    ).fetchone()[0]
                lines.append(f"{i}. <b>{svc['name']}</b> — {cnt} numbers available")
            bot.send_message(chat_id, "\n".join(lines), reply_markup=manage_services_keyboard())
            return

        elif text == f"📊 {stylish('Service Statistics')}":
            _show_service_stats(chat_id)
            return

        elif text == f"📥 {stylish('Import Numbers')}":
            kb = import_service_keyboard()
            if not kb:
                bot.send_message(chat_id, "⛔ No services found. Add a service first.", reply_markup=manage_services_keyboard())
                return
            admin_states[user.id] = {"step": "aimport_select_service", "data": {}}
            bot.send_message(chat_id, "📥 <b>Import Numbers</b>\n\nSelect a service:", reply_markup=kb)
            return

        elif text == f"♻ {stylish('Reset Numbers')}":
            kb = reset_services_keyboard()
            if not kb:
                bot.send_message(chat_id, "⛔ No services found.", reply_markup=manage_services_keyboard())
                return
            admin_states[user.id] = {"step": "areset_svc_select", "data": {}}
            bot.send_message(chat_id, "♻ <b>Select Service to Reset Numbers:</b>", reply_markup=kb)
            return

        elif text == f"🧩 {stylish('Input Range')}":
            kb = import_service_keyboard()
            if not kb:
                bot.send_message(chat_id, "⛔ No services found. Add a service first.", reply_markup=manage_services_keyboard())
                return
            admin_states[user.id] = {"step": "arange_select_service", "data": {}}
            bot.send_message(chat_id, "🧩 <b>Input Range</b>\n\nSelect a service:", reply_markup=kb)
            return

        elif text == f"◀️ {stylish('Back to Admin')}":
            admin_states.pop(user.id, None)
            bot.send_message(
                chat_id, f"🔧 <b>{stylish('Admin Panel')}</b>",
                reply_markup=admin_keyboard(is_main_admin=_is_main_admin),
            )
            return

        elif text == f"◀️ {stylish('Back to User Panel')}":
            admin_states.pop(user.id, None)
            first_name = user.first_name or "User"
            _send_welcome(chat_id, first_name, user.id)
            return

    # ══════════════════════════════════════════════════════════════════════════
    # USER PANEL
    # ══════════════════════════════════════════════════════════════════════════

    if user.id in user_states:
        ustate = user_states[user.id]
        ustep = ustate.get("step")

        if ustep == "selecting_service":
            _MAIN_MENU_BUTTONS = {
                f"📲 {stylish('Get Number')}", f"♻ {stylish('Get Another Number')}",
                f"🪪 {stylish('Balance')}", f"🟥 🪙 {stylish('Withdraw')}",
                f"🎧 {stylish('Support')}", f"🧑 {stylish('Profile')}",
                f"📊 {stylish('Traffic')}", f"🏆 {stylish('Leaderboard')}",
                f"🎁 {stylish('Refer')}",
                f"📬 {stylish('Temp Mail')}",
                f"🧿 {stylish('CUSTOM RANGE')}", "🏠 Home", f"🎛️ {stylish('Admin Panel')}",
            }
            if text == "◀️ Back":
                user_states.pop(user.id, None)
                first_name = user.first_name or "User"
                _send_welcome(chat_id, first_name, user.id)
                return
            if text in _MAIN_MENU_BUTTONS:
                # Clear state and fall through to normal main menu handling
                user_states.pop(user.id, None)
                # (falls through below)
            else:
                svc_name = text.replace("📟 ", "").strip()
                with get_conn() as conn:
                    svc = conn.execute("""
                        SELECT DISTINCT s.id, s.name FROM services s
                        WHERE s.name=? AND EXISTS (
                            SELECT 1 FROM countries c
                            WHERE c.service_id = s.id
                            AND (
                                (c.range_id IS NOT NULL AND c.range_id != '')
                                OR c.id IN (SELECT n.country_id FROM numbers n WHERE n.assigned = 0)
                            )
                        )
                    """, (svc_name,)).fetchone()
                if not svc:
                    user_states.pop(user.id, None)
                    return
                ustate["service_id"] = svc["id"]
                ustate["step"] = "selecting_country"
                bot.send_message(
                    chat_id,
                    f"🗺 <b>{stylish('Select a Country')}:</b>",
                    reply_markup=user_countries_inline_keyboard(svc["id"]),
                )
                return

        # selecting_country is now handled via inline callback (cb_select_country)

    # ── OTP WORK CUSTOM RANGE INPUT ───────────────────────────────────────────
    if user.id in user_states and user_states[user.id].get("step") == "otpwork_custom_range_input":
        # If user pressed any menu/keyboard button, cancel range input and fall through
        _SKIP_BUTTONS = {
            f"📲 {stylish('Get Number')}", f"♻ {stylish('Get Another Number')}",
            f"🪪 {stylish('Balance')}", f"🟥 🪙 {stylish('Withdraw')}",
            f"🎧 {stylish('Support')}", f"🧑 {stylish('Profile')}",
            f"📊 {stylish('Traffic')}", "🏠 Home",
            f"🏆 {stylish('Leaderboard')}", f"🎁 {stylish('Refer')}",
            f"📬 {stylish('Temp Mail')}",
            f"🧿 {stylish('CUSTOM RANGE')}", f"🎛️ {stylish('Admin Panel')}",
            f"◀️ {stylish('Back')}", "◀️ Back",
        }
        if text in _SKIP_BUTTONS:
            user_states.pop(user.id, None)
            # fall through to normal button handling below
        else:
            cstate = user_states.pop(user.id, {})
            entry = cstate.get("ow_entry", {})
            raw_range = text.strip()
            # Keep the range as-is (including X's) — the API expects the full range format
            if not re.fullmatch(r"[0-9Xx]{3,20}", raw_range):
                bot.send_message(chat_id, f"⛔ {stylish('Please enter a valid range with digits (e.g. 880X01, 995X5, 22467XXX)')}")
                return
            rid = raw_range
            loading_msg = bot.send_message(
                chat_id,
                f"⌛ {stylish('Getting number for custom range')} <code>{rid}</code>...",
            )
            full_numbers = fetch_api_numbers(rid)
            if len(full_numbers) < 1:
                try:
                    retry_kb = InlineKeyboardMarkup()
                    retry_kb.add(InlineKeyboardButton(f"♻ {stylish('Try Again')}", callback_data=f"custom_range_retry:{rid}"))
                    bot.edit_message_text(
                        f"⛔ {stylish('No number is available for range')} <code>{rid}</code>. {stylish('Please try another range.')}",
                        chat_id=chat_id,
                        message_id=loading_msg.message_id,
                        reply_markup=retry_kb,
                    )
                except Exception:
                    pass
                return
            full_number = full_numbers[0]
            service_name = entry.get("service_sid", "Facebook")
            # Strip X's only for country code prefix lookup
            digits_only = re.sub(r'[Xx]', '', str(rid))
            country_code = ""
            for length in (3, 2, 1):
                prefix = digits_only[:length]
                if prefix in PHONE_CODE_COUNTRY:
                    country_code = prefix
                    break
            if not country_code:
                country_code = digits_only[:3] if len(digits_only) >= 3 else digits_only
            country_with_flag = range_to_country_name(rid)
            flag, api_country = extract_flag_from_name(country_with_flag)
            text_card = build_number_card(
                flag, country_code, api_country, full_number, service_name,
                numbers=full_numbers,
            )
            try:
                sent = bot.edit_message_text(
                    text_card,
                    chat_id=chat_id,
                    message_id=loading_msg.message_id,
                    reply_markup=number_card_inline_keyboard(numbers=full_numbers),
                )
            except Exception:
                sent = bot.send_message(
                    chat_id, text_card,
                    reply_markup=number_card_inline_keyboard(numbers=full_numbers),
                )
            with get_conn() as conn:
                for full_number in full_numbers:
                    conn.execute(
                        """INSERT INTO allocations
                           (user_id, number_id, number, service_name, country_name,
                            country_flag, country_code, message_id, rid)
                           VALUES (?,NULL,?,?,?,?,?,?,?)""",
                        (
                            user.id, full_number, service_name, api_country,
                            flag, country_code, sent.message_id, rid,
                        ),
                    )
                conn.execute(
                    "UPDATE users SET numbers_generated = numbers_generated + ? WHERE id=?",
                    (len(full_numbers), user.id),
                )
            for full_number in full_numbers:
                _schedule_otp_polling(user.id, chat_id, sent.message_id, full_number)
            return

    # ── USER WITHDRAW STATE MACHINE ───────────────────────────────────────────
    if user.id in user_states and user_states[user.id].get("step", "").startswith("wd_"):
        wstate = user_states[user.id]
        wstep = wstate["step"]

        if wstep == "wd_enter_phone":
            phone = text.strip()
            if not phone:
                bot.send_message(chat_id, f"⛔ {stylish('Invalid phone number. Try again:')}")
                return
            wstate["phone"] = phone
            wstate["step"] = "wd_enter_amount"
            min_wd = get_min_withdraw()
            stats = get_wallet_stats(user.id)
            bot.send_message(
                chat_id,
                f"🪙 <b>{stylish('Enter Amount')}</b>\n\n{stylish('Available')}: <b>{stats['balance']:.2f} BDT</b>\n{stylish('Minimum')}: <b>{min_wd:.0f} BDT</b>",
            )
            return

        elif wstep == "wd_enter_amount":
            try:
                amount = float(text.strip())
            except ValueError:
                bot.send_message(chat_id, f"⛔ {stylish('Invalid amount. Enter a number:')}")
                return
            min_wd = get_min_withdraw()
            stats = get_wallet_stats(user.id)
            balance = stats["balance"]
            if not math.isfinite(amount) or amount <= 0:
                bot.send_message(chat_id, f"⛔ {stylish('Amount must be a positive number. Try again:')}")
                return
            if amount < min_wd:
                bot.send_message(chat_id, f"⛔ {stylish('Minimum withdraw is')} <b>{min_wd:.0f} BDT</b>. {stylish('Try again:')}")
                return
            if amount > balance:
                bot.send_message(chat_id, f"⛔ {stylish('Insufficient balance. Your balance:')} <b>{balance:.2f} BDT</b>. {stylish('Try again:')}")
                return
            wstate["amount"] = amount
            wstate["step"] = "wd_confirm"
            method = wstate["method"]
            phone = wstate["phone"]
            bot.send_message(
                chat_id,
                f"<blockquote>🧾 {stylish('WITHDRAW CONFIRMATION')}</blockquote>\n\n"
                f"🪪 <b>{stylish('Method')}:</b> {method}\n"
                f"📟 <b>{stylish('Phone')}:</b> {phone}\n"
                f"💲 <b>{stylish('Amount')}:</b> {amount:.2f} BDT\n\n"
                f"{stylish('Confirm your withdrawal?')}",
                reply_markup=withdraw_confirm_inline_keyboard(),
            )
            return

    # ── TRAFFIC button ─────────────────────────────────────────────────────────
    if text == f"📊 {stylish('Traffic')}":
        traffic_text = _build_traffic_text()
        bot.send_message(chat_id, traffic_text, parse_mode="HTML", reply_markup=_traffic_inline_keyboard())
        return

    # ── CUSTOM RANGE button (reply keyboard) ──────────────────────────────────
    if text == f"🧿 {stylish('CUSTOM RANGE')}":
        if not is_member(user.id):
            bot.send_message(chat_id, _join_prompt_text(), reply_markup=join_keyboard())
            return
        user_states[user.id] = {"step": "otpwork_custom_range_input", "ow_entry": {}}
        bot.send_message(
            chat_id,
            f"🎛 {stylish('PLEASE ENTER YOUR CUSTOM RANGE(S)')}: ({stylish('e.g., 22890XXX')})",
        )
        return

    # ── USER MAIN MENU BUTTONS ────────────────────────────────────────────────
    if text in (f"📲 {stylish('Get Number')}", f"♻ {stylish('Get Another Number')}"):
        if not is_member(user.id):
            bot.send_message(chat_id, _join_prompt_text(), reply_markup=join_keyboard())
            return
        kb = user_services_inline_keyboard()
        user_states[user.id] = {"step": "selecting_service"}
        bot.send_message(chat_id, f"📟 <b>{stylish('Select a Service')}:</b>", reply_markup=kb)
        return

    elif text == f"📬 {stylish('Temp Mail')}":
        _send_generated_temp_mail(chat_id, user.id)
        return

    elif text == f"🎧 {stylish('Support')}":
        _send_support_message(chat_id)
        return

    elif text == f"🟥 🪙 {stylish('Withdraw')}":
        stats = get_wallet_stats(user.id)
        balance = stats["balance"]
        min_wd = get_min_withdraw()
        if balance < min_wd:
            bot.send_message(chat_id, f"⛔ {stylish('Insufficient balance')}!\n{stylish('Minimum')}: {min_wd:.0f} BDT\n{stylish('Yours')}: {balance:.2f} BDT")
            return
        if has_pending_withdraw(user.id):
            bot.send_message(chat_id, f"❗️ {stylish('You already have a pending withdrawal.')}")
            return
        methods_kb = withdraw_methods_inline_keyboard()
        if not methods_kb:
            bot.send_message(chat_id, f"⛔ {stylish('No payment methods configured. Contact admin.')}")
            return
        bot.send_message(
            chat_id,
            f"🪙 <b>{stylish('Select Payment Method')}</b>\n\n{stylish('Balance')}: <b>{balance:.2f} BDT</b>",
            reply_markup=methods_kb,
        )
        return

    elif text == f"🪪 {stylish('Balance')}":
        stats = get_wallet_stats(user.id)
        bot.send_message(chat_id, build_balance_text(stats), reply_markup=balance_inline_keyboard())
        return

    elif text == f"🧑 {stylish('Profile')}":
        try:
            upsert_user(user)
            db_user = get_user(user.id)
            stats = get_wallet_stats(user.id)
            bot.send_message(
                chat_id,
                build_profile_text(user, db_user, stats),
                reply_markup=profile_inline_keyboard(),
            )
        except Exception as e:
            logger.error("Profile load failed (%s)", type(e).__name__)
            bot.send_message(chat_id, f"⛔ {stylish('Could not load your profile. Please try again.')}")
        return

    elif text == f"🏆 {stylish('Leaderboard')}":
        if not is_leaderboard_enabled():
            bot.send_message(
                chat_id,
                f"🛑 {stylish('Leaderboard is currently disabled by the admin.')}",
                reply_markup=welcome_keyboard(is_admin_user=is_admin(user.id)),
            )
            return
        sep = "━" * 30
        with get_conn() as conn:
            top = conn.execute("""
                SELECT id, username, first_name, otps_received as otp_count
                FROM users
                WHERE is_banned = 0
                ORDER BY otps_received DESC
                LIMIT 10
            """).fetchall()
        medals = ["🥇","🥈","🥉","4️⃣","5️⃣","6️⃣","7️⃣","8️⃣","9️⃣","🔟"]
        rows = ""
        for i, row in enumerate(top):
            name = row["first_name"] or f"User{row['id']}"
            rows += f"\n{medals[i]} <b>{_html.escape(name)}</b> — {row['otp_count']} OTP"
        if not rows:
            rows = "\n<i>এখনো কোনো OTP পাওয়া যায়নি।</i>"
        bot.send_message(
            chat_id,
            f"🏆 {sep}\n"
            f"   👑  {stylish('OTP LEADERBOARD')}\n"
            f"{sep}\n\n"
            f"<blockquote>{rows}</blockquote>\n\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🔷 {stylish('POWERED BY')} <b>{stylish(_powered_by())}</b>",
        )
        return

    elif text == f"🎁 {stylish('Refer')}":
        # Backward-compatible handling for users who still have the old keyboard cached.
        _send_referral_panel(chat_id, user.id)
        return

    elif text == "🏠 Home":
        first_name = user.first_name or "User"
        _send_welcome(chat_id, first_name, user.id)
        return

    elif text == f"🎛️ {stylish('Admin Panel')}":
        if not is_admin(user.id):
            return
        admin_states.pop(user.id, None)
        bot.send_message(chat_id, f"🔧 <b>{stylish('Admin Panel')}</b>", reply_markup=admin_keyboard(is_main_admin=(user.id == ADMIN_ID)))
        return


@bot.callback_query_handler(
    func=lambda c: (
        bool(c.data)
        and (
            c.data in ("temp_mail_new", "temp_mail_check")
            or c.data.startswith("temp_mail_copy_email:")
            or c.data.startswith("temp_mail_copy_otp:")
        )
    )
)
def cb_temp_mail_actions(call):
    user = call.from_user
    upsert_user(user)
    db_user = get_user(user.id)
    if db_user and db_user["is_banned"]:
        bot.answer_callback_query(call.id)
        return

    if call.data == "temp_mail_new":
        bot.answer_callback_query(call.id)
        _send_generated_temp_mail(call.message.chat.id, user.id)
        return

    if call.data == "temp_mail_check":
        bot.answer_callback_query(call.id)
        _send_temp_mail_check_result(call.message.chat.id, user.id)
        return

    value = call.data.split(":", 1)[1]
    if value == "unavailable":
        bot.answer_callback_query(
            call.id,
            "Copy is unavailable. Please use the email or OTP shown above.",
            show_alert=True,
        )
        return
    bot.answer_callback_query(call.id, text=value, show_alert=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DOCUMENT HANDLER (TXT file upload for number import)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _do_broadcast_media(message):
    user = message.from_user
    _is_main_admin = (user.id == ADMIN_ID)
    chat_id = message.chat.id
    sent = 0
    for user_ids in _iter_unbanned_user_id_batches():
        for user_id in user_ids:
            try:
                bot.copy_message(user_id, chat_id, message.message_id)
                sent += 1
            except Exception:
                pass
    admin_states.pop(user.id, None)
    bot.send_message(chat_id, f"✔️ Broadcast sent to <b>{sent}</b> users.", reply_markup=admin_keyboard(is_main_admin=_is_main_admin))


@bot.message_handler(content_types=["photo", "video", "audio", "voice", "sticker", "video_note", "animation"])
def handle_media(message):
    user = message.from_user
    if shop_handle_media and shop_handle_media(message):
        return
    if not is_admin(user.id):
        return
    state = admin_states.get(user.id)
    if state and state.get("step") == "abroadcast_wait":
        _do_broadcast_media(message)


@bot.message_handler(content_types=["document"])
def handle_document(message):
    user = message.from_user
    if shop_handle_media and shop_handle_media(message):
        return
    if not is_admin(user.id):
        return
    state = admin_states.get(user.id)
    if state and state.get("step") == "abroadcast_wait":
        _do_broadcast_media(message)
        return
    if not state:
        return
    if state.get("step") == "abackup_restore_wait":
        doc = message.document
        if not doc.file_name.lower().endswith(".db"):
            bot.send_message(message.chat.id, "⛔ Please upload a <b>.db</b> file.", reply_markup=cancel_keyboard())
            return
        tmp_path = os.path.join(DATA_DIR, f".developer_by_sumon_vai_restore_{user.id}.db")
        try:
            file_info = bot.get_file(doc.file_id)
            downloaded = bot.download_file(file_info.file_path)
            with open(tmp_path, "wb") as f:
                f.write(downloaded)

            # Validate the upload before touching the live database.
            check_conn = sqlite3.connect(tmp_path)
            try:
                integrity = check_conn.execute("PRAGMA integrity_check").fetchone()[0]
                users_table = check_conn.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='users'"
                ).fetchone()
                if integrity != "ok" or users_table is None:
                    raise ValueError("uploaded file is not a valid bot database")
            finally:
                check_conn.close()

            # Restore through SQLite's backup API instead of replacing the
            # live file with copy2(). This keeps active WAL connections safe.
            source_conn = sqlite3.connect(tmp_path, timeout=30)
            destination_conn = sqlite3.connect(DB_PATH, timeout=30)
            try:
                destination_conn.execute("PRAGMA busy_timeout = 30000")
                source_conn.backup(destination_conn)
                destination_conn.commit()
            finally:
                destination_conn.close()
                source_conn.close()

            # Re-apply the current schema after restoring an older backup.
            # This keeps Main and Shop tables/migrations available even when
            # the uploaded file was created by an earlier bot version.
            init_db()
            migrate_db()
            import shop_integration as _shop_integration
            _shop_integration.init_db()
        except Exception as e:
            logger.error("Restore failed (%s)", type(e).__name__)
            bot.send_message(message.chat.id, f"⛔ {stylish('Restore failed — invalid or corrupted file.')}", reply_markup=backup_keyboard())
            return
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        admin_states.pop(user.id, None)
        bot.send_message(message.chat.id, f"✔️ {stylish('Database restored successfully.')}", reply_markup=backup_keyboard())
        return

    if state.get("step") != "aimport_number_file":
        return

    doc = message.document
    if not doc.file_name.endswith(".txt"):
        bot.send_message(message.chat.id, "⛔ Please upload a <b>.txt</b> file.", reply_markup=cancel_keyboard())
        return

    try:
        file_info = bot.get_file(doc.file_id)
        downloaded = bot.download_file(file_info.file_path)
        content = downloaded.decode("utf-8", errors="ignore")
    except Exception as e:
        logger.error("File download failed (%s)", type(e).__name__)
        bot.send_message(message.chat.id, "⛔ Failed to download file.", reply_markup=cancel_keyboard())
        return

    raw_numbers = [normalize_number(line) for line in content.splitlines() if line.strip()]
    valid_numbers = [n for n in raw_numbers if n and n.isdigit()]

    if not valid_numbers:
        bot.send_message(message.chat.id, "⛔ No valid numbers found in file.", reply_markup=cancel_keyboard())
        return

    country_id = state["data"]["country_id"]
    service_name = state["data"]["service_name"]
    country_name = state["data"]["country_name"]
    country_flag = state["data"]["country_flag"]
    country_code = state["data"]["country_code"]

    imported = 0
    skipped = 0
    with get_conn() as conn:
        existing_numbers = {
            r[0] for r in conn.execute(
                "SELECT number FROM numbers WHERE country_id=?", (country_id,)
            ).fetchall()
        }
        for num in valid_numbers:
            if num in existing_numbers:
                skipped += 1
                continue
            conn.execute("INSERT INTO numbers (country_id, number) VALUES (?,?)", (country_id, num))
            existing_numbers.add(num)
            imported += 1

    admin_states.pop(user.id, None)
    bot.send_message(
        message.chat.id,
        f"✔️ <b>Import Complete!</b>\n\n"
        f"📟 Service: <b>{service_name}</b>\n"
        f"🗺 Country: <b>{country_flag} {country_name} +{country_code}</b>\n\n"
        f"📥 Imported: <b>{imported}</b> numbers\n"
        f"⏭ Skipped (duplicates): <b>{skipped}</b>",
        reply_markup=manage_services_keyboard(),
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TRANSIENT DATA CLEANUP — Background thread
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Keep business records (users, balances, orders, OTP history, settings, etc.).
# The delivery ledger is temporary; successful OTP hashes also live in `otps`,
# which is checked before sending so deleting the temporary row cannot re-credit
# an old OTP. Auto-SMS keeps only a compact de-duplication key for seven days.
TRANSIENT_DATA_RETENTION_SECONDS = 60 * 60
AUTO_SMS_DEDUP_RETENTION_SECONDS = 7 * 24 * 60 * 60
_transient_cleanup_last = 0.0
_transient_cleanup_lock = threading.Lock()


def _cleanup_transient_files(now=None):
    """Delete only known scratch files left behind by interrupted operations."""
    now = time.time() if now is None else now
    cutoff = now - TRANSIENT_DATA_RETENTION_SECONDS
    temp_mail_tmp = os.path.basename(TEMP_MAIL_DATA_PATH) + ".tmp"
    removed = 0
    try:
        entries = os.scandir(DATA_DIR)
    except OSError as exc:
        logger.warning("Could not scan transient files in %s: %s", DATA_DIR, exc)
        return 0

    with entries:
        for entry in entries:
            name = entry.name
            is_known_scratch = (
                name == temp_mail_tmp
                or (
                    name.startswith("voltx_backup_")
                    and name.endswith(".db")
                )
                or (
                    name.startswith(".developer_by_sumon_vai_restore_")
                    and name.endswith(".db")
                )
            )
            if not is_known_scratch:
                continue
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                if entry.stat(follow_symlinks=False).st_mtime >= cutoff:
                    continue
                os.remove(entry.path)
                removed += 1
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.warning("Could not remove stale scratch file %s: %s", name, exc)
    return removed


def _cleanup_transient_db_data(force: bool = False):
    """Expire scratch data hourly without deleting business or OTP history."""
    global _transient_cleanup_last
    now = time.time()
    with _transient_cleanup_lock:
        if not force and now - _transient_cleanup_last < 3600:
            return
        _transient_cleanup_last = now

    ledger_cutoff = int(now - TRANSIENT_DATA_RETENTION_SECONDS)
    auto_sms_cutoff = int(now - AUTO_SMS_DEDUP_RETENTION_SECONDS)
    try:
        with get_conn() as conn:
            removed = conn.execute(
                "DELETE FROM delivered_messages "
                "WHERE delivered_at IS NOT NULL AND delivered_at < ?",
                (ledger_cutoff,),
            ).rowcount
            # Older versions stored SMS bodies and phone numbers in this
            # de-duplication table. Keep the keys for restart safety, but
            # discard those payloads after one hour.
            scrubbed = conn.execute(
                """UPDATE auto_sms_deliveries
                   SET panel_name='', number='', message=''
                   WHERE created_at IS NOT NULL AND created_at < ?
                     AND (panel_name!='' OR number!='' OR message!='')""",
                (ledger_cutoff,),
            ).rowcount
            removed_auto_sms = conn.execute(
                "DELETE FROM auto_sms_deliveries "
                "WHERE created_at IS NOT NULL AND created_at < ?",
                (auto_sms_cutoff,),
            ).rowcount

        removed_files = _cleanup_transient_files(now)
        with get_conn() as conn:
            checkpoint = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if removed or scrubbed or removed_auto_sms or removed_files:
            logger.info(
                "Transient cleanup: delivery rows=%s, old SMS payloads=%s, "
                "expired Auto SMS keys=%s, scratch files=%s",
                removed, scrubbed, removed_auto_sms, removed_files,
            )
        if checkpoint and checkpoint[0]:
            logger.warning("SQLite WAL checkpoint was busy; it will be retried later.")
    except Exception as exc:
        with _transient_cleanup_lock:
            _transient_cleanup_last = 0.0
        logger.warning("Transient DB cleanup skipped: %s", exc)


def timeout_checker():
    logger.info("Timeout checker started.")
    errors = 0
    while True:
        try:
            _cleanup_transient_db_data()
            user_states.prune_if_due()
            admin_states.prune_if_due()
            if shop_cleanup_runtime_state:
                shop_cleanup_runtime_state()
            now = int(time.time())
            timeout_secs = get_positive_int_setting(
                "timeout_minutes", 20, minimum=1, maximum=1440
            ) * 60
            with get_conn() as conn:
                timed_out_groups = conn.execute("""
                    SELECT user_id, message_id, MIN(id) AS allocation_id
                    FROM allocations
                    WHERE otp_received=0 AND timed_out=0
                      AND message_id IS NOT NULL
                      AND allocated_at <= ? - ?
                    GROUP BY user_id, message_id
                    ORDER BY MIN(id)
                    LIMIT 100
                """, (now, timeout_secs)).fetchall()
                for group in timed_out_groups:
                    alloc = conn.execute(
                        "SELECT * FROM allocations WHERE id=?",
                        (group["allocation_id"],),
                    ).fetchone()
                    if not alloc:
                        continue
                    related_allocs = conn.execute(
                        """SELECT number FROM allocations
                           WHERE user_id=? AND message_id=?
                           ORDER BY id LIMIT 20""",
                        (alloc["user_id"], alloc["message_id"]),
                    ).fetchall()
                    conn.execute(
                        """UPDATE allocations SET timed_out=1
                           WHERE user_id=? AND message_id=?
                             AND otp_received=0""",
                        (alloc["user_id"], alloc["message_id"]),
                    )
                    try:
                        related_numbers = [
                            row["number"] for row in related_allocs
                            if row["number"]
                        ]
                        timeout_text = build_timeout_card(
                            alloc["country_flag"], alloc["country_code"],
                            alloc["country_name"], alloc["number"], alloc["service_name"],
                            numbers=related_numbers,
                        )
                        bot.edit_message_text(
                            timeout_text,
                            chat_id=alloc["user_id"],
                            message_id=alloc["message_id"],
                            parse_mode="HTML",
                            reply_markup=number_card_inline_keyboard(numbers=related_numbers),
                        )
                    except Exception as e:
                        logger.warning("Timeout edit failed (%s)", type(e).__name__)
            errors = 0
        except Exception as e:
            errors = min(errors + 1, 6)
            logger.error("Timeout checker failed (%s)", type(e).__name__)
            # Safe backoff: repeated failures must not spin the CPU.
            time.sleep(min(10 * errors, 120))
            continue
        time.sleep(get_positive_int_setting(
            "poll_interval", 30, minimum=5, maximum=3600
        ))


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# API OTP POLLING — Smshadi & Lamix (Task 5)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OTP_PROVIDER_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
OTP_PROVIDER_MAX_RECORDS = 1000
LEGACY_API_POLL_WORKERS = 8
LEGACY_API_POLL_CHUNK_SIZE = 20
_legacy_api_poll_pool = ThreadPoolExecutor(
    max_workers=LEGACY_API_POLL_WORKERS,
    thread_name_prefix="legacy-otp-poll",
)


def _read_provider_response_bytes(method: str, url: str, **kwargs):
    """Read a provider response with a hard decoded-body ceiling."""
    kwargs["stream"] = True
    with requests.request(method, url, **kwargs) as response:
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except (TypeError, ValueError):
                declared_length = 0
            if declared_length > OTP_PROVIDER_MAX_RESPONSE_BYTES:
                raise ValueError("provider response exceeds the configured size limit")

        chunks = []
        total_bytes = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            total_bytes += len(chunk)
            if total_bytes > OTP_PROVIDER_MAX_RESPONSE_BYTES:
                raise ValueError("provider response exceeds the configured size limit")
            chunks.append(chunk)
        return b"".join(chunks), response.status_code


def _request_provider_json(method: str, url: str, **kwargs):
    body, status_code = _read_provider_response_bytes(method, url, **kwargs)
    if status_code >= 400:
        raise requests.HTTPError(f"provider returned HTTP {status_code}")
    return json.loads(body), status_code


def _provider_number_matches(expected: str, received: str) -> bool:
    """Match full numbers, with only a safe 10-digit suffix fallback."""
    left = re.sub(r"\D", "", str(expected or ""))
    right = re.sub(r"\D", "", str(received or ""))
    if not left or not right:
        return False
    if left == right:
        return True
    return len(left) >= 10 and len(right) >= 10 and left[-10:] == right[-10:]


def _poll_api(api_url: str, api_token: str, number: str, allocated_at: int = None) -> list:
    """
    Query SMShadi or Lamix API for OTP messages for a given number.
    - Uses filternum for server-side filtering
    - Uses dt1 (allocation time) so only new OTPs are returned
    - Verifies returned 'num' field matches our number (safety check)
    - Returns list of dicts with 'message', 'dt', 'num' keys.
    """
    parsed_url = urlsplit(api_url or "")
    host = parsed_url.hostname or "invalid"
    if parsed_url.scheme.lower() != "https" or not parsed_url.hostname:
        logger.warning(
            "Refusing SMS provider request without HTTPS (host=%s)", host
        )
        return []
    try:
        params = {
            "token": api_token,
            "filternum": number,
            "records": 50,
        }
        # Add dt1 = allocation time (minus 60s buffer) so we skip old OTPs
        if allocated_at:
            dt1 = datetime.utcfromtimestamp(allocated_at - 60).strftime("%Y-%m-%d %H:%M:%S")
            params["dt1"] = dt1

        data, _ = _request_provider_json(
            "GET", api_url, params=params, timeout=10
        )

        if data.get("status") == "success":
            items = data.get("data", []) or []
            if isinstance(items, dict):
                items = [items]
            if not isinstance(items, list):
                return []
            # Safety: keep only records whose 'num' field matches our number
            # (strip non-digits from both sides for a loose match)
            num_digits = re.sub(r'\D', '', number)
            matched = []
            for item in items[:OTP_PROVIDER_MAX_RECORDS]:
                if not isinstance(item, dict):
                    continue
                item_num = re.sub(r'\D', '', str(item.get("num", "") or ""))
                # Match if item_num ends with our number or our number ends with item_num
                if _provider_number_matches(num_digits, item_num):
                    matched.append(item)
            return matched

    except Exception as e:
        logger.debug(
            "SMS provider poll failed (host=%s error=%s)",
            host,
            type(e).__name__,
        )
    return []


def _schedule_otp_polling(user_id, chat_id, message_id, number):
    """
    Called after a number is allocated to a user.
    The global background thread (fetch_otps_from_api) already polls all active
    allocations every 7 seconds — no per-number thread is needed.
    This function is a no-op placeholder kept for API compatibility.
    """
    logger.debug("OTP polling scheduled (handled by background poller)")


def _poll_yesms_success_otps() -> list:
    """Fetch recent OTP logs from YesMS GET /user_numbers endpoint."""
    cfg = get_api_config("yesms")
    if not cfg["enabled"] or not cfg["key"]:
        return []
    try:
        data, _ = _request_provider_json(
            "GET",
            f"{YESMS_BASE}/user_numbers",
            headers={"authkey": cfg["key"]},
            timeout=10,
        )
        if data.get("success"):
            all_logs = data.get("logs", []) or []
            if isinstance(all_logs, dict):
                all_logs = [all_logs]
            if not isinstance(all_logs, list):
                return []
            results = []
            for o in all_logs[:OTP_PROVIDER_MAX_RECORDS]:
                if not isinstance(o, dict):
                    continue
                raw_key = f"{o.get('number','')}|{o.get('time','')}|{o.get('otp_code','')}"
                otp_id = hashlib.sha256(raw_key.encode()).hexdigest()
                o = dict(o)
                o["otp_id"] = otp_id
                results.append(o)
            if results:
                logger.info(f"YesMS user_numbers: {len(results)} OTP(s) returned")
            return results
    except Exception as e:
        logger.warning("YesMS user_numbers request failed (%s)", type(e).__name__)
    return []


def _parse_panel_response(panel_name: str, data: dict, field_map: dict) -> list:
    """
    Generic parser for panel OTP responses — handles multiple response shapes:
      • data.otps[]  (StexSMS, FastXOTPs, VoltXSMS documented shape)
      • data[]       (plain list)
      • data directly (dict with number/message)
    field_map keys: number, message, otp_id  (values = field name in API response)
    """
    results = []
    if isinstance(data, list):
        raw_data = data
        data = {"data": data}
    elif not isinstance(data, dict):
        return results
    else:
        raw_data = data.get("data")
        # Different panel versions return the records under one of these
        # top-level keys instead of `data`.
        if raw_data is None:
            for key in ("otps", "otp", "results", "records", "items", "sms"):
                if isinstance(data.get(key), (list, dict)):
                    raw_data = data[key]
                    break
        if raw_data is None and any(
            data.get(k) for k in ("number", "full_number", "phone", "msisdn", "num")
        ):
            raw_data = data
    # Try data.otps first
    if isinstance(raw_data, dict):
        otps = raw_data.get("otps") or raw_data.get("otp") or raw_data.get("list") or []
        if not otps and raw_data:
            # data itself might be the single record
            otps = [raw_data]
    elif isinstance(raw_data, list):
        otps = raw_data
    else:
        otps = []

    if isinstance(otps, dict):
        otps = [otps]
    if not isinstance(otps, list):
        return results
    otps = otps[:OTP_PROVIDER_MAX_RECORDS]
    for o in otps:
        if not isinstance(o, dict):
            continue
        num_raw = ""
        for nf in (field_map["number"], "number", "full_number", "no_plus_number",
                   "national_number", "phone", "msisdn", "mobile", "num"):
            num_raw = str(o.get(nf, "") or "").strip()
            if num_raw:
                break
        num = normalize_number(num_raw)
        # Try multiple message field names
        msg = ""
        for mf in field_map["message"]:
            msg = str(o.get(mf, "") or "").strip()
            if msg:
                break
        if not num or not msg:
            continue
        oid_raw = o.get(field_map.get("otp_id", "otp_id"), "")
        oid = str(oid_raw) if oid_raw else hashlib.sha256(f"{num}|{msg}".encode()).hexdigest()
        results.append({"otp_id": oid, "number": num, "full_message": msg})

    logger.info(
        "%s response parsed=%s OTP(s) data_type=%s",
        panel_name,
        len(results),
        type(raw_data).__name__,
    )
    return results


def _poll_stexsms_success_otps() -> list:
    """Fetch recent OTPs from StexSMS GET /success-otp (header: mauthapi)."""
    cfg = get_api_config("stexsms")
    if not cfg["enabled"] or not cfg["key"]:
        return []
    try:
        data, status_code = _request_provider_json(
            "GET",
            f"{STEXSMS_BASE}/success-otp",
            headers={"mauthapi": cfg["key"]},
            timeout=10,
        )
        results = _parse_panel_response(
            "StexSMS", data,
            {"number": "number", "message": ["message", "msg", "sms", "text"], "otp_id": "otp_id"},
        )
        logger.info("StexSMS /success-otp HTTP=%s", status_code)
        return results
    except Exception as e:
        logger.warning("StexSMS OTP poll failed (%s)", type(e).__name__)
    return []


def _poll_fastxotps_success_otps() -> list:
    """Fetch recent OTPs from FastXOTPs GET /api/success-otp-info (header: X-API-Key)."""
    cfg = get_api_config("fastxotps")
    if not cfg["enabled"] or not cfg["key"]:
        return []
    try:
        data, status_code = _request_provider_json(
            "GET",
            f"{FASTXOTPS_BASE}/api/success-otp-info",
            headers={"X-API-Key": cfg["key"]},
            timeout=10,
        )
        results = _parse_panel_response(
            "FastXOTPs", data,
            {"number": "number", "message": ["sms", "message", "otp", "msg", "text"], "otp_id": "otp_id"},
        )
        logger.info("FastXOTPs /success-otp-info HTTP=%s", status_code)
        return results
    except Exception as e:
        logger.warning("FastXOTPs OTP poll failed (%s)", type(e).__name__)
    return []


def _poll_voltxsms_success_otps() -> list:
    """Fetch recent OTPs from VoltXSMS GET /success-otp (header: mauthapi)."""
    cfg = get_api_config("voltxsms")
    if not cfg["enabled"] or not cfg["key"]:
        return []
    try:
        data, status_code = _request_provider_json(
            "GET",
            f"{VOLTXSMS_BASE}/success-otp",
            headers={"mauthapi": cfg["key"]},
            timeout=10,
        )
        results = _parse_panel_response(
            "VoltXSMS", data,
            {"number": "number", "message": ["message", "msg", "sms", "text"], "otp_id": "otp_id"},
        )
        logger.info("VoltXSMS /success-otp HTTP=%s", status_code)
        return results
    except Exception as e:
        logger.warning("VoltXSMS OTP poll failed (%s)", type(e).__name__)
    return []


# ─── ZEBRASMS ADAPTER (documented public API only) ────────────────────────────
# Base:  https://api.zebrasms.com/api/v1
#   POST /publicapi/getnum      MAuth: KEY   body {"range": "RANGE"}
#   GET  /publicapi/getupdate   MAuth: KEY
#   GET  /publicapi/liveaccess  MAuth: KEY   [?sender=...]
# No other / undocumented endpoint is ever called.

ZEBRA_GETNUM_PATH     = "/publicapi/getnum"
ZEBRA_GETUPDATE_PATH  = "/publicapi/getupdate"
ZEBRA_LIVEACCESS_PATH = "/publicapi/liveaccess"

_zebra_last_error = {"detail": ""}


def _zebra_headers(key: str, with_json: bool = False) -> dict:
    h = {"MAuth": key, "Accept": "application/json"}
    if with_json:
        h["Content-Type"] = "application/json"
    return h


def _zebra_call(method: str, path: str, key: str, json_body=None, params=None, timeout: int = 12):
    """Single documented ZebraSMS call. Returns parsed JSON or None."""
    url = f"{ZEBRASMS_BASE}{path}"
    parsed_url = urlsplit(url)
    if parsed_url.scheme.lower() != "https" or not parsed_url.hostname:
        _zebra_last_error["detail"] = "ZebraSMS endpoint must use HTTPS."
        logger.warning("%s", _zebra_last_error["detail"])
        return None
    try:
        if method == "POST":
            body, status_code = _read_provider_response_bytes(
                "POST",
                url,
                json=json_body or {},
                headers=_zebra_headers(key, True),
                timeout=timeout,
            )
        else:
            body, status_code = _read_provider_response_bytes(
                "GET",
                url,
                params=params or None,
                headers=_zebra_headers(key),
                timeout=timeout,
            )
        try:
            data = json.loads(body)
        except Exception:
            _zebra_last_error["detail"] = f"ZebraSMS HTTP {status_code}: non-JSON response"
            logger.warning("ZebraSMS %s", _zebra_last_error["detail"])
            return None
        logger.info("ZebraSMS %s %s HTTP=%s", method, path, status_code)
        if status_code >= 400:
            _zebra_last_error["detail"] = f"ZebraSMS HTTP {status_code}"
            return None
        meta = data.get("meta") if isinstance(data, dict) else None
        code = meta.get("code") if isinstance(meta, dict) else None
        if code != 0:
            known = {
                -101: "Bad request",
                -102: "Unauthorized API key or inactive account",
                -103: "Feature unavailable for this account",
                -500: "ZebraSMS server error; retry shortly",
            }
            _zebra_last_error["detail"] = known.get(code, f"ZebraSMS API error {code}")
            logger.warning("ZebraSMS %s", _zebra_last_error["detail"])
            return None
        _zebra_last_error["detail"] = ""
        return data
    except Exception as e:
        _zebra_last_error["detail"] = f"ZebraSMS request failed ({type(e).__name__})"
        logger.warning("ZebraSMS request error: %s", _zebra_last_error["detail"])
    return None


def _zebra_rows(data) -> list:
    """Extract data.rows[] from a ZebraSMS response."""
    if not isinstance(data, dict):
        return []
    if data.get("meta", {}).get("code") != 0:
        return []
    payload = data.get("data")
    if isinstance(payload, dict):
        rows = payload.get("rows")
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = None
    if isinstance(rows, dict):
        rows = [rows]
    return [r for r in (rows or []) if isinstance(r, dict)]


def _zebra_row_number(row: dict) -> str:
    for key in ("number", "full_number", "msisdn", "phone", "no_plus_number"):
        val = str(row.get(key, "") or "").strip()
        if val:
            return normalize_number(val)
    return ""


def _poll_zebrasms_success_otps() -> list:
    """GET /publicapi/getupdate → existing internal OTP format."""
    cfg = get_api_config("zebrasms")
    if not cfg["enabled"] or not cfg["key"]:
        return []
    data = _zebra_call("GET", ZEBRA_GETUPDATE_PATH, cfg["key"])
    rows = _zebra_rows(data)
    results = []
    for row in rows[:OTP_PROVIDER_MAX_RECORDS]:
        num = _zebra_row_number(row)
        msg = str(row.get("message", "") or row.get("sms", "") or "").strip()
        if not num or not msg:
            continue
        at_ms = row.get("at_ms") or row.get("at") or ""
        sender = str(row.get("sender", "") or "")
        oid = str(at_ms) if at_ms else ""
        if not oid:
            oid = hashlib.sha256(f"{num}|{msg}".encode()).hexdigest()
        else:
            oid = hashlib.sha256(f"{num}|{oid}|{msg}".encode()).hexdigest()
        results.append({
            "otp_id": oid,
            "number": num,
            "full_message": msg,
            "sender": sender,
            "country": str(row.get("country", "") or ""),
            "operator": str(row.get("operator", "") or ""),
        })
    logger.info("ZebraSMS getupdate parsed %s OTP(s)", len(results))
    return results


def _iter_active_allocations_batches(now: int, timeout_secs: int, batch_size: int = 250):
    """Read active allocations in bounded keyset batches."""
    batch_size = max(1, min(int(batch_size), 1000))
    with get_conn() as conn:
        max_id = conn.execute(
            """SELECT COALESCE(MAX(id), 0) FROM allocations
               WHERE otp_received=0 AND timed_out=0
                 AND allocated_at > ? - ?""",
            (now, timeout_secs),
        ).fetchone()[0]
    last_id = 0
    while last_id < max_id:
        with get_conn() as conn:
            rows = conn.execute(
                """SELECT * FROM allocations
                   WHERE otp_received=0 AND timed_out=0
                     AND allocated_at > ? - ?
                     AND id>? AND id<=?
                   ORDER BY id LIMIT ?""",
                (now, timeout_secs, last_id, max_id, batch_size),
            ).fetchall()
        if not rows:
            break
        last_id = rows[-1]["id"]
        yield rows


def _poll_legacy_provider_chunk(
    provider_id: str,
    api_url: str,
    api_token: str,
    allocations: list,
) -> list:
    """Poll a small allocation chunk concurrently with a fixed worker ceiling."""
    def poll_one(alloc):
        return _poll_api(
            api_url,
            api_token,
            normalize_number(alloc["number"]),
            alloc["allocated_at"],
        )

    still_pending = []
    futures = {
        _legacy_api_poll_pool.submit(poll_one, alloc): alloc
        for alloc in allocations
    }
    for future in as_completed(futures):
        alloc = futures[future]
        try:
            messages = future.result()
        except Exception as exc:
            logger.warning(
                "Legacy SMS provider poll failed (%s)", type(exc).__name__
            )
            messages = []
        delivered_for_allocation = False
        for item in messages:
            msg_text = (item.get("message") or "").strip()
            dt = str(item.get("dt") or item.get("id") or time.time())
            if not msg_text:
                continue
            number = normalize_number(alloc["number"])
            mhash_val = msg_hash(number, dt, msg_text)
            if _deliver_otp_api(alloc, msg_text, dt, mhash_val):
                logger.info("OTP delivered by provider=%s", provider_id)
                delivered_for_allocation = True
                break
        if not delivered_for_allocation:
            still_pending.append(alloc)
    return still_pending


def _deliver_panel_otps(
    panel_name: str,
    otp_list: list,
    now: int,
    timeout_secs: int,
    active_count: int,
):
    """Forward each provider OTP once, matching allocations in bounded batches."""
    if len(otp_list) > OTP_PROVIDER_MAX_RECORDS:
        logger.warning(
            "%s response contained more than %s OTP records; excess records skipped",
            panel_name,
            OTP_PROVIDER_MAX_RECORDS,
        )
        otp_list = otp_list[:OTP_PROVIDER_MAX_RECORDS]
    logger.info(
        "%s delivery check: %s OTP(s), %s active allocation(s)",
        panel_name,
        len(otp_list),
        active_count,
    )
    for otp_item in otp_list:
        raw_num = str(otp_item.get("number", "")).strip()
        msg_text = (otp_item.get("full_message") or "").strip()
        otp_id = str(
            otp_item.get("otp_id")
            or otp_item.get("time")
            or hashlib.sha256(f"{raw_num}|{msg_text}".encode()).hexdigest()
        )
        if not raw_num or not msg_text:
            logger.warning("%s skipped an OTP with missing number or message", panel_name)
            continue
        norm_num = normalize_number(raw_num)
        try:
            _auto_forward_panel_sms(panel_name, norm_num, msg_text, otp_id)
        except Exception as exc:
            logger.warning("Auto SMS hook failed (%s)", type(exc).__name__)

    prepared_otps = []
    for otp_item in otp_list[:OTP_PROVIDER_MAX_RECORDS]:
        if not isinstance(otp_item, dict):
            continue
        raw_num = str(otp_item.get("number", "")).strip()
        msg_text = str(otp_item.get("full_message") or "").strip()
        if not raw_num or not msg_text:
            continue
        norm_num = normalize_number(raw_num)
        otp_id = str(
            otp_item.get("otp_id")
            or otp_item.get("time")
            or hashlib.sha256(f"{raw_num}|{msg_text}".encode()).hexdigest()
        )
        prepared_otps.append(
            (otp_item, raw_num, msg_text, norm_num, re.sub(r"\D", "", norm_num), otp_id)
        )

    matched_allocations = {}
    for allocation_batch in _iter_active_allocations_batches(now, timeout_secs):
        exact_numbers = {}
        suffix_numbers = {}
        for alloc in allocation_batch:
            digits = re.sub(r"\D", "", str(alloc["number"] or ""))
            if not digits:
                continue
            exact_numbers.setdefault(digits, alloc)
            if len(digits) >= 10:
                suffix_numbers.setdefault(digits[-10:], alloc)

        for index, prepared in enumerate(prepared_otps):
            if index in matched_allocations:
                continue
            number_digits = prepared[4]
            exact = exact_numbers.get(number_digits)
            suffix = (
                suffix_numbers.get(number_digits[-10:])
                if len(number_digits) >= 10 else None
            )
            if exact and suffix:
                matched_allocations[index] = (
                    exact if exact["id"] <= suffix["id"] else suffix
                )
            elif exact or suffix:
                matched_allocations[index] = exact or suffix

    for index, prepared in enumerate(prepared_otps):
        alloc = matched_allocations.get(index)
        if alloc:
            _, _, msg_text, norm_num, _, otp_id = prepared
            _deliver_otp_api(
                alloc,
                msg_text,
                otp_id,
                msg_hash(norm_num, otp_id, msg_text),
            )
        elif prepared[1] and prepared[2]:
            logger.info(
                "%s OTP had no active allocation match (active=%s)",
                panel_name,
                active_count,
            )


def fetch_otps_from_api():
    """
    Background thread: polls all enabled OTP panels every 7 seconds.
    Panels: YesMS, StexSMS, FastXOTPs, VoltXSMS, SMShadi, Lamix.
    """
    logger.info("API OTP poller started.")
    poll_errors = 0
    while True:
        try:
            now = int(time.time())
            timeout_secs = get_positive_int_setting(
                "timeout_minutes", 20, minimum=1, maximum=1440
            ) * 60
            with get_conn() as conn:
                active_count = conn.execute("""
                    SELECT COUNT(*) FROM allocations
                    WHERE otp_received=0 AND timed_out=0
                      AND allocated_at > ? - ?
                """, (now, timeout_secs)).fetchone()[0]

            # Keep polling when Auto SMS is ON, so every real panel SMS is
            # forwarded to the group even if no user has an active number.
            if not active_count and not is_auto_sms_enabled():
                # Nothing to process: do not call any panel API at all.
                poll_errors = 0
                time.sleep(15)
                continue

            # ── YesMS ────────────────────────────────────────────────────────
            try:
                otps = _poll_yesms_success_otps()
                if otps:
                    _deliver_panel_otps("YesMS", otps, now, timeout_secs, active_count)
            except Exception as e:
                logger.error("YesMS OTP poll failed (%s)", type(e).__name__)

            # ── StexSMS ───────────────────────────────────────────────────────
            try:
                otps = _poll_stexsms_success_otps()
                if otps:
                    _deliver_panel_otps("StexSMS", otps, now, timeout_secs, active_count)
            except Exception as e:
                logger.error("StexSMS OTP poll failed (%s)", type(e).__name__)

            # ── FastXOTPs ─────────────────────────────────────────────────────
            try:
                otps = _poll_fastxotps_success_otps()
                if otps:
                    _deliver_panel_otps("FastXOTPs", otps, now, timeout_secs, active_count)
            except Exception as e:
                logger.error("FastXOTPs OTP poll failed (%s)", type(e).__name__)

            # ── VoltXSMS ──────────────────────────────────────────────────────
            try:
                otps = _poll_voltxsms_success_otps()
                if otps:
                    _deliver_panel_otps("VoltXSMS", otps, now, timeout_secs, active_count)
            except Exception as e:
                logger.error("VoltXSMS OTP poll failed (%s)", type(e).__name__)

            # ── ZebraSMS ──────────────────────────────────────────────────────
            try:
                otps = _poll_zebrasms_success_otps()
                if otps:
                    _deliver_panel_otps("ZebraSMS", otps, now, timeout_secs, active_count)
            except Exception as e:
                logger.error("ZebraSMS OTP poll failed (%s)", type(e).__name__)

            # ── SMShadi + Lamix (legacy per-number polling) ───────────────────
            legacy_providers = []
            for api_id in ("smshadi", "lamix"):
                cfg = get_api_config(api_id)
                if cfg["enabled"] and cfg["url"]:
                    legacy_providers.append((cfg["url"], cfg["key"], api_id))

            if legacy_providers:
                for active_batch in _iter_active_allocations_batches(now, timeout_secs):
                    for offset in range(0, len(active_batch), LEGACY_API_POLL_CHUNK_SIZE):
                        pending = active_batch[
                            offset:offset + LEGACY_API_POLL_CHUNK_SIZE
                        ]
                        for api_url, api_token, provider_id in legacy_providers:
                            if not pending:
                                break
                            pending = _poll_legacy_provider_chunk(
                                provider_id,
                                api_url,
                                api_token,
                                pending,
                            )

            poll_errors = 0
        except Exception as e:
            poll_errors = min(poll_errors + 1, 6)
            logger.error("API fetch loop failed (%s)", type(e).__name__)
            # Safe backoff so repeated API/DB failures cannot spin the CPU.
            time.sleep(min(7 * poll_errors, 120))
            continue

        time.sleep(7)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OTP SOURCE GROUP HANDLER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
@bot.message_handler(
    func=lambda m: bool(get_setting("otp_source_group_id", "")) and str(m.chat.id) == get_setting("otp_source_group_id", "") and bool(m.text),
    content_types=["text"],
)
def handle_otp_source_group(message):
    """Listen to the OTP source group and match messages to active allocations."""
    msg_text = message.text or ""
    now = int(time.time())
    timeout_secs = get_positive_int_setting(
        "timeout_minutes", 20, minimum=1, maximum=1440
    ) * 60

    for active_batch in _iter_active_allocations_batches(now, timeout_secs):
        for alloc in active_batch:
            number = normalize_number(alloc["number"])
            digits = re.sub(r'[^0-9]', '', number)
            if len(digits) < 3:
                continue
            last3 = digits[-3:]
            if last3 in msg_text:
                _deliver_otp(alloc, msg_text, message.message_id)


# ─── PHONE CODE → COUNTRY MAPPING ─────────────────────────────────────────────

PHONE_CODE_COUNTRY = {
    "1": "🇺🇸 USA / Canada", "7": "🇷🇺 Russia",
    "20": "🇪🇬 Egypt", "27": "🇿🇦 South Africa",
    "30": "🇬🇷 Greece", "31": "🇳🇱 Netherlands", "32": "🇧🇪 Belgium",
    "33": "🇫🇷 France", "34": "🇪🇸 Spain", "36": "🇭🇺 Hungary",
    "39": "🇮🇹 Italy", "40": "🇷🇴 Romania", "41": "🇨🇭 Switzerland",
    "43": "🇦🇹 Austria", "44": "🇬🇧 United Kingdom", "45": "🇩🇰 Denmark",
    "46": "🇸🇪 Sweden", "47": "🇳🇴 Norway", "48": "🇵🇱 Poland",
    "49": "🇩🇪 Germany", "51": "🇵🇪 Peru", "52": "🇲🇽 Mexico",
    "53": "🇨🇺 Cuba", "54": "🇦🇷 Argentina", "55": "🇧🇷 Brazil",
    "56": "🇨🇱 Chile", "57": "🇨🇴 Colombia", "58": "🇻🇪 Venezuela",
    "60": "🇲🇾 Malaysia", "61": "🇦🇺 Australia", "62": "🇮🇩 Indonesia",
    "63": "🇵🇭 Philippines", "64": "🇳🇿 New Zealand", "65": "🇸🇬 Singapore",
    "66": "🇹🇭 Thailand", "81": "🇯🇵 Japan", "82": "🇰🇷 South Korea",
    "84": "🇻🇳 Vietnam", "86": "🇨🇳 China", "90": "🇹🇷 Turkey",
    "91": "🇮🇳 India", "92": "🇵🇰 Pakistan", "93": "🇦🇫 Afghanistan",
    "94": "🇱🇰 Sri Lanka", "95": "🇲🇲 Myanmar", "98": "🇮🇷 Iran",
    "211": "🇸🇸 South Sudan", "212": "🇲🇦 Morocco", "213": "🇩🇿 Algeria",
    "216": "🇹🇳 Tunisia", "218": "🇱🇾 Libya", "220": "🇬🇲 Gambia",
    "221": "🇸🇳 Senegal", "222": "🇲🇷 Mauritania", "223": "🇲🇱 Mali",
    "224": "🇬🇳 Guinea", "225": "🇨🇮 Ivory Coast", "226": "🇧🇫 Burkina Faso",
    "227": "🇳🇪 Niger", "228": "🇹🇬 Togo", "229": "🇧🇯 Benin",
    "230": "🇲🇺 Mauritius", "231": "🇱🇷 Liberia", "232": "🇸🇱 Sierra Leone",
    "233": "🇬🇭 Ghana", "234": "🇳🇬 Nigeria", "235": "🇹🇩 Chad",
    "236": "🇨🇫 Central African Rep.", "237": "🇨🇲 Cameroon",
    "238": "🇨🇻 Cape Verde", "239": "🇸🇹 Sao Tome", "240": "🇬🇶 Eq. Guinea",
    "241": "🇬🇦 Gabon", "242": "🇨🇬 Republic of Congo", "243": "🇨🇩 DR Congo",
    "244": "🇦🇴 Angola", "245": "🇬🇼 Guinea-Bissau", "248": "🇸🇨 Seychelles",
    "249": "🇸🇩 Sudan", "250": "🇷🇼 Rwanda", "251": "🇪🇹 Ethiopia",
    "252": "🇸🇴 Somalia", "253": "🇩🇯 Djibouti", "254": "🇰🇪 Kenya",
    "255": "🇹🇿 Tanzania", "256": "🇺🇬 Uganda", "257": "🇧🇮 Burundi",
    "258": "🇲🇿 Mozambique", "260": "🇿🇲 Zambia", "261": "🇲🇬 Madagascar",
    "263": "🇿🇼 Zimbabwe", "264": "🇳🇦 Namibia", "265": "🇲🇼 Malawi",
    "266": "🇱🇸 Lesotho", "267": "🇧🇼 Botswana", "268": "🇸🇿 Eswatini",
    "269": "🇰🇲 Comoros", "297": "🇦🇼 Aruba", "299": "🇬🇱 Greenland",
    "350": "🇬🇮 Gibraltar", "351": "🇵🇹 Portugal", "352": "🇱🇺 Luxembourg",
    "353": "🇮🇪 Ireland", "354": "🇮🇸 Iceland", "355": "🇦🇱 Albania",
    "356": "🇲🇹 Malta", "357": "🇨🇾 Cyprus", "358": "🇫🇮 Finland",
    "359": "🇧🇬 Bulgaria", "370": "🇱🇹 Lithuania", "371": "🇱🇻 Latvia",
    "372": "🇪🇪 Estonia", "373": "🇲🇩 Moldova", "374": "🇦🇲 Armenia",
    "375": "🇧🇾 Belarus", "380": "🇺🇦 Ukraine", "381": "🇷🇸 Serbia",
    "385": "🇭🇷 Croatia", "386": "🇸🇮 Slovenia", "387": "🇧🇦 Bosnia",
    "389": "🇲🇰 North Macedonia", "420": "🇨🇿 Czech Republic", "421": "🇸🇰 Slovakia",
    "501": "🇧🇿 Belize", "502": "🇬🇹 Guatemala", "503": "🇸🇻 El Salvador",
    "504": "🇭🇳 Honduras", "505": "🇳🇮 Nicaragua", "506": "🇨🇷 Costa Rica",
    "507": "🇵🇦 Panama", "509": "🇭🇹 Haiti", "591": "🇧🇴 Bolivia",
    "592": "🇬🇾 Guyana", "593": "🇪🇨 Ecuador", "595": "🇵🇾 Paraguay",
    "597": "🇸🇷 Suriname", "598": "🇺🇾 Uruguay", "673": "🇧🇳 Brunei",
    "675": "🇵🇬 Papua New Guinea", "679": "🇫🇯 Fiji", "850": "🇰🇵 North Korea",
    "852": "🇭🇰 Hong Kong", "853": "🇲🇴 Macau", "855": "🇰🇭 Cambodia",
    "856": "🇱🇦 Laos", "880": "🇧🇩 Bangladesh", "886": "🇹🇼 Taiwan",
    "960": "🇲🇻 Maldives", "961": "🇱🇧 Lebanon", "962": "🇯🇴 Jordan",
    "963": "🇸🇾 Syria", "964": "🇮🇶 Iraq", "965": "🇰🇼 Kuwait",
    "966": "🇸🇦 Saudi Arabia", "967": "🇾🇪 Yemen", "968": "🇴🇲 Oman",
    "971": "🇦🇪 UAE", "972": "🇮🇱 Israel", "973": "🇧🇭 Bahrain",
    "974": "🇶🇦 Qatar", "975": "🇧🇹 Bhutan", "976": "🇲🇳 Mongolia",
    "977": "🇳🇵 Nepal", "992": "🇹🇯 Tajikistan", "993": "🇹🇲 Turkmenistan",
    "994": "🇦🇿 Azerbaijan", "995": "🇬🇪 Georgia", "996": "🇰🇬 Kyrgyzstan",
    "998": "🇺🇿 Uzbekistan",
}


def range_to_country_name(range_str):
    """Extract country name from a range string like '22507XXX'.
    Tries 3-digit prefix, then 2-digit, then 1-digit."""
    digits = re.sub(r'[Xx]+$', '', range_str)
    for length in (3, 2, 1):
        prefix = digits[:length]
        if prefix in PHONE_CODE_COUNTRY:
            return PHONE_CODE_COUNTRY[prefix]
    return f"🛰 +{digits[:3]}..."


def extract_flag_from_name(country_with_flag: str) -> tuple:
    """Split '🇧🇩 Bangladesh' → ('🇧🇩', 'Bangladesh').
    Works for any flag emoji (regional indicator pairs) or plain globe emoji."""
    country_with_flag = country_with_flag.strip()
    # Flag emojis are regional indicator pairs (each char is 2 code points in some encodings)
    # Simple approach: if first char(s) form a flag emoji, split on first space
    parts = country_with_flag.split(" ", 1)
    if len(parts) == 2:
        potential_flag = parts[0]
        # Regional indicator symbols are in U+1F1E0–U+1F1FF
        if all(0x1F1E0 <= ord(c) <= 0x1F1FF for c in potential_flag) or potential_flag in ("🛰",):
            return potential_flag, parts[1]
    return "🛰", country_with_flag


def group_ranges_by_country(ranges):
    """Group ranges by country. Returns sorted list of (country_name, first_rid).
    Only one entry per country — uses the FIRST (top) range for that country.
    rid is the range digits with trailing X's stripped."""
    seen = {}
    for r in ranges:
        country = range_to_country_name(r)
        if country not in seen:
            rid = re.sub(r'[Xx]+$', '', r)
            seen[country] = rid
    return sorted(seen.items(), key=lambda x: x[0])


# ─── YesMS API HELPERS ────────────────────────────────────────────────────────

def _iso_to_flag(iso: str) -> str:
    """Convert a 2-letter ISO country code to a flag emoji (e.g. GB -> flag)."""
    if not iso or len(iso) < 2:
        return ""
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso.upper()[:2])
    except Exception:
        return ""


def _get_current_traffic_panel() -> str:
    """Return the currently-active traffic panel, rotating every 60 s among enabled ones."""
    global _traffic_panel_idx, _traffic_panel_last_sw
    panels = ["yesms", "stexsms", "fastxotps", "voltxsms", "zebrasms"]
    enabled = [p for p in panels if get_api_config(p)["enabled"] and get_api_config(p)["key"]]
    if not enabled:
        return "yesms"
    with _traffic_panel_lock:
        now = time.time()
        if now - _traffic_panel_last_sw >= 60:
            _traffic_panel_idx = (_traffic_panel_idx + 1) % len(enabled)
            _traffic_panel_last_sw = now
        return enabled[_traffic_panel_idx % len(enabled)]


def _build_traffic_rows_from_panel(panel_id: str):
    """Fetch raw traffic rows from the given panel's console endpoint.
    Returns list of (range_str, country_raw) tuples."""
    cfg = get_api_config(panel_id)
    rows = []
    if not cfg["enabled"] or not cfg["key"]:
        return rows
    try:
        if panel_id == "yesms":
            data, _ = _request_provider_json(
                "GET",
                f"{YESMS_BASE}/console_data",
                headers={"authkey": cfg["key"]},
                timeout=10,
            )
            for row in (data.get("table") or []):
                if row and len(row) >= 2:
                    rows.append((str(row[0] or ""), str(row[1] or "Unknown")))

        elif panel_id == "stexsms":
            data, _ = _request_provider_json(
                "GET",
                f"{STEXSMS_BASE}/console",
                headers={"mauthapi": cfg["key"]},
                timeout=10,
            )
            for hit in ((data.get("data") or {}).get("hits") or []):
                rng = str(hit.get("range", "") or "")
                sid = str(hit.get("sid", "") or "Unknown")
                country = _country_from_range_or_sid(rng, sid)
                rows.append((rng, country))

        elif panel_id == "fastxotps":
            data, _ = _request_provider_json(
                "GET",
                f"{FASTXOTPS_BASE}/api/live-console",
                params={"limit": 55},
                headers={"X-API-Key": cfg["key"]},
                timeout=10,
            )
            for otp in ((data.get("data") or {}).get("otps") or []):
                rng = str(otp.get("range", "") or "")
                country = str(otp.get("country", "") or "")
                if not country:
                    country = _country_from_range_or_sid(rng, "")
                rows.append((rng, country))

        elif panel_id == "zebrasms":
            for row in _zebrasms_ranges():
                rng = str(row.get("range", "") or row.get("prefix", "") or "")
                country = str(row.get("country", "") or "")
                if not country:
                    country = _country_from_range_or_sid(rng, "")
                iso2 = str(row.get("iso2", "") or "")
                if iso2 and not any(ch for ch in country if ord(ch) > 0x1F000):
                    country = f"{_iso_to_flag(iso2)} {country}".strip()
                hits = row.get("count") or row.get("hits") or row.get("live") or 1
                try:
                    hits = max(1, int(hits))
                except Exception:
                    hits = 1
                for _ in range(min(hits, 50)):
                    rows.append((rng, country))

        elif panel_id == "voltxsms":
            data, _ = _request_provider_json(
                "GET",
                f"{VOLTXSMS_BASE}/console",
                headers={"mauthapi": cfg["key"]},
                timeout=10,
            )
            for hit in ((data.get("data") or {}).get("hits") or []):
                rng = str(hit.get("range", "") or "")
                sid = str(hit.get("sid", "") or "Unknown")
                country = _country_from_range_or_sid(rng, sid)
                rows.append((rng, country))

    except Exception as e:
        logger.warning("%s traffic fetch failed (%s)", panel_id, type(e).__name__)
    return rows


def _country_from_range_or_sid(rng: str, sid: str) -> str:
    """Best-effort country name from a range string like 22507XXX."""
    try:
        return range_to_country_name(rng)
    except Exception:
        return sid or "Unknown"


PANEL_LABELS = {
    "zebrasms":  "ZebraSMS",
    "yesms":     "YesMS",
    "stexsms":   "StexSMS",
    "fastxotps": "FastXOTPs",
    "voltxsms":  "VoltXSMS",
    "zebrasms":  "ZebraSMS",
}


def _build_traffic_text() -> str:
    """Build the Live Traffic message, rotating the source panel every 60 s."""
    panel_id = _get_current_traffic_panel()
    panel_label = PANEL_LABELS.get(panel_id, panel_id)
    rows = _build_traffic_rows_from_panel(panel_id)

    country_counts: dict = {}
    country_flags:  dict = {}
    country_codes:  dict = {}
    range_counts:   dict = {}

    for rng, country_raw in rows:
        flag, country = extract_flag_from_name(country_raw)
        country = country or "Unknown"
        country_counts[country] = country_counts.get(country, 0) + 1
        if flag and flag != "🛰" and country not in country_flags:
            country_flags[country] = flag
        if rng and country not in country_codes:
            digits = re.sub(r'[Xx\s]+$', '', rng)
            for length in (3, 2, 1):
                prefix = digits[:length]
                if prefix in PHONE_CODE_COUNTRY:
                    country_codes[country] = prefix
                    break
        if rng:
            range_counts[rng] = range_counts.get(rng, 0) + 1

    total = sum(country_counts.values())
    if total == 0:
        return (
            f"📊 <b>{stylish('Live Traffic')}</b>  <i>[{panel_label}]</i>\n\n"
            f"🕰 <b>{stylish('Window')}:</b> {stylish('Latest activity')}\n"
            f"👑 <b>{stylish('Results Sent')}:</b> 0\n\n"
            f"❗️ {stylish('No traffic data available right now.')}"
        )

    top_country_name = max(country_counts, key=country_counts.get)
    top_flag = country_flags.get(top_country_name, "")
    top_code = country_codes.get(top_country_name, "")
    top_display = f"{top_flag} {top_country_name}".strip()
    if top_code:
        top_display += f" (+{top_code})"

    sorted_countries = sorted(country_counts.items(), key=lambda x: -x[1])[:10]
    sorted_ranges    = sorted(range_counts.items(),   key=lambda x: -x[1])[:10]

    lines = [
        "⚡ " + "━" * 26,
        "   📡  " + stylish("LIVE TRAFFIC") + "  <i>[" + panel_label + "]</i>",
        "━" * 26 + "\n",
        "<blockquote>",
        f"🕰 <b>{stylish('Window')}:</b> {stylish('Latest activity')}",
        f"⚡ <b>{stylish('Results Sent')}:</b> <b>{total}</b>",
        f"🏆 <b>{stylish('Top Country')}:</b> {top_display}",
        "</blockquote>",
        "",
        f"🗺 <b>{stylish('Top Countries')}:</b>",
    ]
    country_items = [
        f"{r}. {country_flags.get(n, '')} {n} (+{country_codes.get(n, '?')}) — {c}".strip()
        for r, (n, c) in enumerate(sorted_countries, 1)
    ]
    for i in range(0, len(country_items), 2):
        lines.append("  |  ".join(country_items[i:i+2]))

    if sorted_ranges:
        lines.append("")
        lines.append(f"📡 <b>{stylish('Top Ranges')}:</b>")
        range_items = [f"{r}. <code>{rng}</code> — {c}" for r, (rng, c) in enumerate(sorted_ranges, 1)]
        for i in range(0, len(range_items), 2):
            lines.append("  |  ".join(range_items[i:i+2]))

    return "\n".join(lines)


def fetch_console_traffic() -> str:
    """Public wrapper — returns formatted traffic text."""
    return _build_traffic_text()


def _traffic_inline_keyboard():
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("♻ Refresh", callback_data="traffic_refresh"))
    kb.add(InlineKeyboardButton("◀️ Back", callback_data="traffic_back"))
    return kb


def is_standard_range(rid: str) -> bool:
    """Return True if rid is a standard digit+trailing-XXX range (22465, 22465XXX).
    All 4 panels can serve these.
    Return False for YesMS search-mode range_ids with X in the middle (63x99, 880X01).
    """
    stripped = re.sub(r'[Xx]+$', '', rid)
    return bool(stripped) and stripped.isdigit()


def _fetch_yesms_number(rid: str):
    """Allocate a number from YesMS API."""
    cfg = get_api_config("yesms")
    if not cfg["enabled"] or not cfg["key"]:
        return None
    try:
        data, _ = _request_provider_json(
            "POST",
            f"{YESMS_BASE}/allocate_number",
            json={"range_id": rid},
            headers={"authkey": cfg["key"], "Content-Type": "application/json"},
            timeout=10,
        )
        if data.get("success"):
            return data.get("data")
    except Exception as e:
        logger.warning("YesMS allocate_number failed (%s)", type(e).__name__)
    return None


def _fetch_stexsms_number(rid: str):
    """Allocate from StexSMS (POST /getnum, header: mauthapi, body: {"rid": digits})."""
    cfg = get_api_config("stexsms")
    if not cfg["enabled"] or not cfg["key"]:
        return None
    clean_rid = re.sub(r'[Xx]+$', '', rid)
    try:
        data, _ = _request_provider_json(
            "POST",
            f"{STEXSMS_BASE}/getnum",
            json={"rid": clean_rid},
            headers={"mauthapi": cfg["key"], "Content-Type": "application/json"},
            timeout=10,
        )
        if data.get("meta", {}).get("code") == 200 and data.get("data"):
            return data["data"]
    except Exception as e:
        logger.warning("StexSMS getnum failed (%s)", type(e).__name__)
    return None


def _fetch_fastxotps_number(rid: str):
    """Allocate from FastXOTPs (POST /api/getnum, header: X-API-Key, body: {"range": "26134XXX"})."""
    cfg = get_api_config("fastxotps")
    if not cfg["enabled"] or not cfg["key"]:
        return None
    clean_rid    = re.sub(r'[Xx]+$', '', rid)
    range_w_xxx  = clean_rid + "XXX"
    try:
        data, _ = _request_provider_json(
            "POST",
            f"{FASTXOTPS_BASE}/api/getnum",
            json={"range": range_w_xxx},
            headers={"X-API-Key": cfg["key"], "Content-Type": "application/json"},
            timeout=10,
        )
        if data.get("meta", {}).get("code") == 200 and data.get("data"):
            return data["data"]
    except Exception as e:
        logger.warning("FastXOTPs getnum failed (%s)", type(e).__name__)
    return None


def _fetch_voltxsms_number(rid: str):
    """Allocate from VoltXSMS (POST /getnum, header: mauthapi, body: {"rid": digits})."""
    cfg = get_api_config("voltxsms")
    if not cfg["enabled"] or not cfg["key"]:
        return None
    clean_rid = re.sub(r'[Xx]+$', '', rid)
    try:
        data, _ = _request_provider_json(
            "POST",
            f"{VOLTXSMS_BASE}/getnum",
            json={"rid": clean_rid},
            headers={"mauthapi": cfg["key"], "Content-Type": "application/json"},
            timeout=10,
        )
        if data.get("meta", {}).get("code") == 200 and data.get("data"):
            return data["data"]
    except Exception as e:
        logger.warning("VoltXSMS getnum failed (%s)", type(e).__name__)
    return None


def _zebra_clean_range(rid: str) -> str:
    return str(rid or "").strip()


def _zebrasms_ranges(sender: str = "") -> list:
    """GET /publicapi/liveaccess → list of available range rows."""
    cfg = get_api_config("zebrasms")
    if not cfg["enabled"] or not cfg["key"]:
        return []
    params = {"sender": sender} if sender else None
    data = _zebra_call("GET", ZEBRA_LIVEACCESS_PATH, cfg["key"], params=params)
    return _zebra_rows(data)


def _zebrasms_live_access() -> dict:
    """Admin panel health check for ZebraSMS (documented liveaccess endpoint)."""
    cfg = get_api_config("zebrasms")
    if not cfg["key"]:
        return {"ok": False, "detail": "No API key saved", "rows": []}
    data = _zebra_call("GET", ZEBRA_LIVEACCESS_PATH, cfg["key"])
    if data is None:
        return {
            "ok": False,
            "rows": [],
            "detail": "No valid response from ZebraSMS (check API key).\n"
                      f"Last attempt: {_zebra_last_error.get('detail', '')[:300]}",
        }
    rows = _zebra_rows(data)
    preview = ", ".join(
        str(r.get("range") or r.get("prefix") or r.get("sender") or "?") for r in rows[:10]
    )
    return {
        "ok": True,
        "rows": rows,
        "detail": f"{ZEBRA_LIVEACCESS_PATH} → {len(rows)} range(s)\n{preview or str(data)[:180]}",
    }


def _zebra_map_row_to_number(row: dict) -> dict:
    """Map a ZebraSMS data.rows[] entry onto the shared panel number structure."""
    number = _zebra_row_number(row)
    if not number:
        return None
    iso2 = str(row.get("iso2", "") or "")
    payload = dict(row)
    payload.update({
        "full_number":    number,
        "no_plus_number": number,
        "national_number": str(row.get("national_number", "") or number),
        "range":          str(row.get("range", "") or ""),
        "country":        str(row.get("country", "") or ""),
        "country_name":   str(row.get("country", "") or ""),
        "iso2":           iso2,
        "country_flag":   _iso_to_flag(iso2) if iso2 else "",
        "operator":       str(row.get("operator", "") or ""),
        "dial_code":      str(row.get("dial_code", "") or ""),
        "mccmnc":         str(row.get("mccmnc", "") or ""),
        "expires_ms":     row.get("expires_ms", ""),
        "panel":          "zebrasms",
    })
    return payload


def _fetch_zebrasms_number(rid: str):
    """Allocate a number from ZebraSMS — POST /publicapi/getnum {"range": RANGE}."""
    cfg = get_api_config("zebrasms")
    if not cfg["enabled"] or not cfg["key"]:
        return None
    requested_range = _zebra_clean_range(rid)
    if not requested_range:
        return None
    data = _zebra_call(
        "POST", ZEBRA_GETNUM_PATH, cfg["key"], json_body={"range": requested_range}
    )
    for row in _zebra_rows(data):
        mapped = _zebra_map_row_to_number(row)
        if mapped:
            logger.info("ZebraSMS allocated %s (range=%s)", mapped["full_number"], requested_range)
            return mapped
    logger.warning("ZebraSMS getnum: no number returned for rid=%s", rid)
    return None


def _fetch_zebra_number_verified(rid: str):
    """Return only a fully normalized, usable ZebraSMS number payload."""
    payload = _fetch_zebrasms_number(rid)
    if not payload:
        return None
    number = _number_from_api_data(payload)
    if not number:
        return None
    payload = dict(payload)
    payload["full_number"] = number
    payload["no_plus_number"] = normalize_number(number)
    return payload


def fetch_api_number(rid: str):
    """Allocate a number for the given range id.
    - Standard ranges (22465XXX / 22465) → round-robin across all enabled panels.
    - Non-standard ranges (63x99, 880X01) → YesMS only (search-mode range_id).
    """
    global _panel_alloc_idx
    # Zebra is the primary source for every Get Number / View Range request.
    # Other panels are fallbacks, never the first source.
    zebra_cfg = get_api_config("zebrasms")
    if zebra_cfg["enabled"] and zebra_cfg["key"]:
        result = _fetch_zebra_number_verified(rid)
        if result:
            logger.info("Number allocated via ZebraSMS (primary) for rid=%s", rid)
            return result

    if not is_standard_range(rid):
        logger.debug(f"Non-standard range '{rid}' — YesMS fallback only")
        return _fetch_yesms_number(rid)

    panel_funcs = {
        "yesms":     _fetch_yesms_number,
        "stexsms":   _fetch_stexsms_number,
        "fastxotps": _fetch_fastxotps_number,
        "voltxsms":  _fetch_voltxsms_number,
        "zebrasms":  _fetch_zebrasms_number,
    }
    enabled_panels = [
        p for p in ["yesms", "stexsms", "fastxotps", "voltxsms", "zebrasms"]
        if get_api_config(p)["enabled"] and get_api_config(p)["key"]
    ]
    if not enabled_panels:
        return None

    with _panel_alloc_lock:
        start_idx = _panel_alloc_idx % len(enabled_panels)
        _panel_alloc_idx += 1

    for i in range(len(enabled_panels)):
        panel_id = enabled_panels[(start_idx + i) % len(enabled_panels)]
        result = panel_funcs[panel_id](rid)
        if result:
            logger.info(f"Number allocated via {panel_id} for rid={rid}")
            return result
    return None


# ─── CALLBACK: Change Country on number card ───────────────────────────────────

@bot.callback_query_handler(func=lambda c: c.data == "num_change_country")
def cb_num_change_country(call):
    """Handle 🗺 Change Country button on number card."""
    user = call.from_user
    bot.answer_callback_query(call.id)

    with get_conn() as conn:
        alloc = conn.execute(
            "SELECT * FROM allocations WHERE user_id=? AND message_id=?",
            (user.id, call.message.message_id),
        ).fetchone()

    if not alloc:
        bot.answer_callback_query(call.id, f"❗️ {stylish('Session expired.')}", show_alert=True)
        return

    # Cancel old allocation — DB number stays assigned=1 permanently (never re-used)
    with get_conn() as conn:
        conn.execute("UPDATE allocations SET timed_out=1 WHERE id=?", (alloc["id"],))

    # API number (number_id is NULL, e.g. Custom Range) → Change Country not applicable
    if not alloc["number_id"]:
        try:
            bot.edit_message_text(
                f"❗️ {stylish('Change Country is not available for this number.')}",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
            )
        except Exception:
            bot.send_message(call.message.chat.id, f"❗️ {stylish('Change Country is not available for this number.')}")
        return

    # DB number → edit message to show country list from local DB
    with get_conn() as conn:
        svc = conn.execute(
            "SELECT id FROM services WHERE name=?", (alloc["service_name"],)
        ).fetchone()

    if not svc:
        try:
            bot.edit_message_text(f"❗️ {stylish('Service not found.')}", chat_id=call.message.chat.id, message_id=call.message.message_id)
        except Exception:
            bot.send_message(call.message.chat.id, f"❗️ {stylish('Service not found.')}")
        return

    user_states[user.id] = {
        "step": "selecting_country",
        "service_id": svc["id"],
        "service_name": alloc["service_name"],
    }
    kb = user_countries_inline_keyboard(svc["id"])
    if not kb:
        try:
            bot.edit_message_text(f"⛔ {stylish('No countries available for this service.')}", chat_id=call.message.chat.id, message_id=call.message.message_id)
        except Exception:
            bot.send_message(call.message.chat.id, f"⛔ {stylish('No countries available for this service.')}")
        return
    try:
        bot.edit_message_text(
            f"🗺 <b>{stylish('Select a Country')}:</b>",
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=kb,
        )
    except Exception:
        bot.send_message(call.message.chat.id, f"🗺 <b>{stylish('Select a Country')}:</b>", reply_markup=kb)


@bot.callback_query_handler(func=lambda c: c.data.startswith("custom_range_retry:"))
def cb_custom_range_retry(call):
    """Handle Try Again button on 'No numbers available for range' message."""
    user = call.from_user
    bot.answer_callback_query(call.id)
    rid = call.data.split(":", 1)[1]
    chat_id = call.message.chat.id

    try:
        bot.edit_message_text(
            f"⌛ {stylish('Getting number for custom range')} <code>{rid}</code>...",
            chat_id=chat_id,
            message_id=call.message.message_id,
            reply_markup=None,
        )
    except Exception:
        pass

    full_numbers = fetch_api_numbers(rid)
    if len(full_numbers) < 1:
        try:
            retry_kb = InlineKeyboardMarkup()
            retry_kb.add(InlineKeyboardButton(f"♻ {stylish('Try Again')}", callback_data=f"custom_range_retry:{rid}"))
            bot.edit_message_text(
                f"⛔ {stylish('No number is available for range')} <code>{rid}</code>. {stylish('Please try another range.')}",
                chat_id=chat_id,
                message_id=call.message.message_id,
                reply_markup=retry_kb,
            )
        except Exception:
            pass
        return

    full_number = full_numbers[0]
    # Strip X's only for country code prefix lookup
    digits_only = re.sub(r'[Xx]', '', str(rid))
    country_code = ""
    for length in (3, 2, 1):
        prefix = digits_only[:length]
        if prefix in PHONE_CODE_COUNTRY:
            country_code = prefix
            break
    if not country_code:
        country_code = digits_only[:3] if len(digits_only) >= 3 else digits_only

    country_with_flag = range_to_country_name(rid)
    flag, api_country = extract_flag_from_name(country_with_flag)

    # Try to determine service name from allocation history, default to "Facebook"
    with get_conn() as conn:
        last_alloc = conn.execute(
            "SELECT service_name FROM allocations WHERE user_id=? AND rid=? ORDER BY id DESC LIMIT 1",
            (user.id, rid),
        ).fetchone()
    service_name = last_alloc["service_name"] if last_alloc else "Facebook"
    text_card = build_number_card(
        flag, country_code, api_country, full_number, service_name,
        numbers=full_numbers,
    )
    try:
        bot.edit_message_text(
            text_card,
            chat_id=chat_id,
            message_id=call.message.message_id,
            reply_markup=number_card_inline_keyboard(numbers=full_numbers),
        )
        msg_id = call.message.message_id
    except Exception:
        sent = bot.send_message(
            chat_id, text_card,
            reply_markup=number_card_inline_keyboard(numbers=full_numbers),
        )
        msg_id = sent.message_id

    with get_conn() as conn:
        for full_number in full_numbers:
            conn.execute(
                """INSERT INTO allocations
                   (user_id, number_id, number, service_name, country_name,
                    country_flag, country_code, message_id, rid)
                   VALUES (?,NULL,?,?,?,?,?,?,?)""",
                (user.id, full_number, service_name, api_country, flag, country_code, msg_id, rid),
            )
        conn.execute(
            "UPDATE users SET numbers_generated = numbers_generated + ? WHERE id=?",
            (len(full_numbers), user.id),
        )
    for full_number in full_numbers:
        _schedule_otp_polling(user.id, chat_id, msg_id, full_number)


def _otpwork_fetch_number(call, entry: dict, rid: str, send_new: bool = False):
    """Shared: fetch number for a given OTP Work entry + range.

    send_new=False (default): EDIT the current message into the number card.
    send_new=True: keep the current message as-is, send a NEW number card below it.
    """
    user = call.from_user
    country_name = entry.get("country", "Unknown")
    service_name = entry.get("service_sid", "Facebook")

    # Show loading state — edit if we own the message, skip if send_new
    if not send_new:
        try:
            bot.edit_message_text(
                f"⌛ {stylish('Getting number for')} <b>{_html.escape(country_name)}</b>...",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=None,
            )
        except Exception:
            pass

    full_numbers = fetch_api_numbers(rid)
    if len(full_numbers) < 1:
        retry_kb = InlineKeyboardMarkup()
        retry_kb.add(InlineKeyboardButton(f"♻ {stylish('Try Again')}", callback_data=f"custom_range_retry:{rid}"))
        if not send_new:
            try:
                bot.edit_message_text(
                    f"⛔ {stylish('No number is available for')} {_html.escape(country_name)}. {stylish('Please try another.')}",
                    chat_id=call.message.chat.id,
                    message_id=call.message.message_id,
                    reply_markup=retry_kb,
                )
                return
            except Exception:
                pass
        bot.send_message(call.message.chat.id, f"⛔ {stylish('No numbers for')} {_html.escape(country_name)}.", reply_markup=retry_kb)
        return

    full_number = full_numbers[0]
    flag, clean_name = extract_flag_from_name(country_name)
    api_country = clean_name
    # Extract country code from rid (strip X's only for prefix lookup)
    digits_only = re.sub(r'[Xx]', '', str(rid))
    country_code = ""
    for length in (3, 2, 1):
        prefix = digits_only[:length]
        if prefix in PHONE_CODE_COUNTRY:
            country_code = prefix
            break
    if not country_code:
        country_code = digits_only[:3] if len(digits_only) >= 3 else digits_only

    text_card = build_number_card(
        flag, country_code, api_country, full_number, service_name,
        numbers=full_numbers,
    )

    if send_new:
        # Change Number case: old card already has buttons removed; send fresh card below
        msg = bot.send_message(
            call.message.chat.id, text_card,
            reply_markup=number_card_inline_keyboard(numbers=full_numbers),
        )
    else:
        # Initial selection: edit the current message into the number card
        final_message_id = call.message.message_id
        try:
            bot.edit_message_text(
                text_card,
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=number_card_inline_keyboard(numbers=full_numbers),
            )
        except Exception:
            sent = bot.send_message(
                call.message.chat.id, text_card,
                reply_markup=number_card_inline_keyboard(numbers=full_numbers),
            )
            final_message_id = sent.message_id

    saved_message_id = msg.message_id if send_new else final_message_id
    with get_conn() as conn:
        for full_number in full_numbers:
            conn.execute(
                """INSERT INTO allocations
                   (user_id, number_id, number, service_name, country_name,
                    country_flag, country_code, message_id, rid)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (user.id, None, full_number, service_name, api_country, flag, country_code, saved_message_id, rid),
            )
        conn.execute(
            "UPDATE users SET numbers_generated=numbers_generated+1 WHERE id=?",
            (user.id,),
        )


@bot.callback_query_handler(func=lambda c: c.data.startswith("api_svc:") or c.data == "api_svc_back")
def cb_api_service_sel(call):
    """Service selected → group ranges by country → show country buttons."""
    user = call.from_user

    if call.data == "api_svc_back":
        bot.answer_callback_query(call.id)
        user_states.pop(user.id, None)
        kb = user_services_inline_keyboard()
        try:
            bot.edit_message_text(
                f"📟 <b>{stylish('Select a Service')}:</b>",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=kb,
            )
        except Exception:
            pass
        return

    ustate = user_states.get(user.id)
    if not ustate or ustate.get("step") != "api_selecting_service":
        bot.answer_callback_query(call.id, f"❗️ {stylish('Session expired.')}", show_alert=True)
        return

    idx = int(call.data.split(":")[1])
    services = ustate.get("api_services", [])
    if idx >= len(services):
        bot.answer_callback_query(call.id, f"❗️ {stylish('Invalid selection.')}", show_alert=True)
        return

    svc = services[idx]
    ranges = svc.get("ranges", [])
    if not ranges:
        bot.answer_callback_query(call.id, "❗️ No ranges available for this service.", show_alert=True)
        return

    # Group ranges by country — ONE button per country (first range used)
    countries = group_ranges_by_country(ranges)
    if not countries:
        bot.answer_callback_query(call.id, "❗️ Could not determine countries.", show_alert=True)
        return

    ustate["step"] = "api_selecting_country"
    ustate["api_service_idx"] = idx
    ustate["api_service_name"] = svc["sid"]
    ustate["api_countries"] = countries
    user_states[user.id] = ustate

    bot.answer_callback_query(call.id)

    kb = InlineKeyboardMarkup(row_width=1)
    for i, (cname, _rid) in enumerate(countries):
        kb.add(InlineKeyboardButton(cname, callback_data=f"api_ctry:{i}"))
    kb.add(InlineKeyboardButton("◀️ Back", callback_data="api_ctry_back"))

    try:
        bot.edit_message_text(
            f"🗺 <b>Select a Country — {svc['sid']}:</b>",
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=kb,
        )
    except Exception:
        pass


@bot.callback_query_handler(func=lambda c: c.data.startswith("api_ctry:") or c.data == "api_ctry_back")
def cb_api_country_sel(call):
    """Country selected → use first range for that country → fetch number → show card."""
    user = call.from_user

    if call.data == "api_ctry_back":
        bot.answer_callback_query(call.id)
        user_states.pop(user.id, None)
        # Back from Facebook countries → go to main service selection
        kb = user_services_inline_keyboard()
        try:
            bot.edit_message_text(
                f"📟 <b>{stylish('Select a Service')}:</b>",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=kb,
            )
        except Exception:
            pass
        return

    ustate = user_states.get(user.id)
    if not ustate or ustate.get("step") != "api_selecting_country":
        bot.answer_callback_query(call.id, f"❗️ {stylish('Session expired.')}", show_alert=True)
        return

    idx = int(call.data.split(":")[1])
    countries = ustate.get("api_countries", [])
    if idx >= len(countries):
        bot.answer_callback_query(call.id, f"❗️ {stylish('Invalid selection.')}", show_alert=True)
        return

    country_name, rid = countries[idx]
    service_name = ustate.get("api_service_name", "Other")

    bot.answer_callback_query(call.id)
    user_states.pop(user.id, None)

    # Update message to loading state (removes buttons + old text)
    try:
        bot.edit_message_text(
            f"⌛ {stylish('Getting number for')} <b>{country_name}</b>...",
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=None,
        )
    except Exception:
        pass

    full_numbers = fetch_api_numbers(rid)
    if len(full_numbers) < 1:
        try:
            bot.edit_message_text(
                f"⛔ {stylish('No number is available for')} {country_name}. {stylish('Please try another country.')}",
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=None,
            )
        except Exception:
            bot.send_message(call.message.chat.id, f"⛔ {stylish('No numbers for')} {country_name}.")
        return

    full_number = full_numbers[0]
    # Extract flag + clean name from selected country_name (e.g. "🇧🇩 Bangladesh")
    flag, clean_name = extract_flag_from_name(country_name)
    api_country = clean_name
    country_code = rid[:3] if len(rid) >= 3 else rid

    text_card = build_number_card(
        flag, country_code, api_country, full_number, service_name,
        numbers=full_numbers,
    )
    # Edit the loading message into the number card
    try:
        msg = bot.edit_message_text(
            text_card,
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=number_card_inline_keyboard(numbers=full_numbers),
        )
    except Exception:
        msg = bot.send_message(
            call.message.chat.id, text_card,
            reply_markup=number_card_inline_keyboard(numbers=full_numbers),
        )

    with get_conn() as conn:
        for full_number in full_numbers:
            conn.execute(
                """INSERT INTO allocations
                   (user_id, number_id, number, service_name, country_name,
                    country_flag, country_code, message_id, rid)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (user.id, None, full_number, service_name, api_country, flag, country_code, msg.message_id, rid),
            )
        conn.execute(
            "UPDATE users SET numbers_generated=numbers_generated+1 WHERE id=?",
            (user.id,),
        )


# ─── TRAFFIC CALLBACKS ────────────────────────────────────────────────────────
@bot.callback_query_handler(func=lambda c: c.data in ("traffic_refresh", "traffic_back"))
def cb_traffic_actions(call):
    bot.answer_callback_query(call.id)
    if call.data == "traffic_back":
        try:
            bot.delete_message(call.message.chat.id, call.message.message_id)
        except Exception:
            pass
        return
    # Refresh
    new_text = _build_traffic_text()
    try:
        bot.edit_message_text(
            new_text,
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            parse_mode="HTML",
            reply_markup=_traffic_inline_keyboard(),
        )
    except Exception:
        pass


# ─── SHOP INTEGRATION ─────────────────────────────────────────────────────────
# Import only after Main's database migration and all core handlers exist.
# The module reuses this file's bot, DB path, admin identity, and settings.
# Wire the Shop module into the hooks checked by the main router.  Importing
# these under their hook names is important: the text/media handlers are
# intentionally dispatched from Main so that Shop can share the same bot and
# database without registering duplicate catch-all handlers.
from shop_integration import (
    handle_shop_media as shop_handle_media,
    handle_shop_text as shop_handle_text,
    _prune_shop_runtime_state as shop_cleanup_runtime_state,
)


# ─── BACKGROUND WORKER SUPERVISION ────────────────────────────────────────────
def _start_worker(name: str, target):
    """Start a named daemon worker once. Never spawn a duplicate worker."""
    for thread in threading.enumerate():
        if thread.name == name and thread.is_alive():
            logger.info("Worker %s is already running; not starting a second one.", name)
            return thread
    thread = threading.Thread(target=target, daemon=True, name=name)
    thread.start()
    return thread


# ─── RAILWAY / CONTAINER HEALTH SERVER ────────────────────────────────────────
class _HealthHandler(BaseHTTPRequestHandler):
    def _send_health_response(self, include_body):
        body = b'{"status":"ok","service":"telegram-number-bot"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health", "/healthz"):
            self._send_health_response(include_body=True)
            return
        self.send_response(404)
        self.end_headers()

    def do_HEAD(self):
        if self.path in ("/", "/health", "/healthz"):
            self._send_health_response(include_body=False)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        logger.debug("health server: " + format, *args)


_health_server = None


def start_health_server():
    """Start the health endpoint. A busy port must never stop the bot itself."""
    global _health_server
    if _health_server is not None:
        return _health_server
    try:
        port = int(os.getenv("PORT", "8080"))
    except (TypeError, ValueError):
        port = 8080
    if not 1 <= port <= 65535:
        port = 8080
    try:
        # The host probes the exact PORT it assigns; silently moving to port+1
        # makes the service appear unhealthy even though the bot is running.
        # A single-threaded server is enough for health probes and keeps the
        # process from spawning one thread per request.
        server = HTTPServer(("0.0.0.0", port), _HealthHandler)
    except OSError as exc:
        logger.warning("Health server could not bind port %s: %s", port, exc)
        return None
    server.timeout = 30
    _health_server = server
    _start_worker("health-server", server.serve_forever)
    logger.info("Health server listening on 0.0.0.0:%s", server.server_address[1])
    return server


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MAIN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
if __name__ == "__main__":
    start_health_server()
    _start_temp_mail_background_loop()

    # Every worker is started through _start_worker so a re-entry (or an
    # import of this module elsewhere) can never create duplicate workers.
    _cleanup_transient_db_data(force=True)

    timeout_thread = _start_worker("timeout-checker", timeout_checker)
    api_poll_thread = _start_worker("api-otp-poller", fetch_otps_from_api)
    auto_sms_thread = _start_worker("auto-sms-engine", _auto_sms_engine_loop)
    demo_sms_thread = _start_worker("demo-sms-engine", _demo_sms_loop)

    # Automatic hourly DB backup has been disabled.
    # Backups are now taken on demand via Admin Panel → Settings → Backup.

    logger.info("Bot starting with SQLite database at %s", os.path.abspath(DB_PATH))
    # This bot uses long polling. Remove a webhook left behind by an earlier
    # deployment so getUpdates does not fail with Telegram's webhook conflict.
    # Do not discard queued updates.
    try:
        bot.remove_webhook()
    except Exception as exc:
        logger.warning("Could not clear a previous webhook before polling: %s", exc)

    bot.infinity_polling(timeout=30, long_polling_timeout=15)
