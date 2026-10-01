"""Temp Mail engine with multiple free providers + admin custom domains.

Providers supported
-------------------
* ``mailtm``     -> https://api.mail.tm      (free, stable)
* ``mailgw``     -> https://api.mail.gw      (free, sometimes down -> fallback)
* ``tempmailio`` -> https://api.internal.temp-mail.io/api/v3
* ``guerrilla``  -> https://api.guerrillamail.com
* ``imap``       -> ANY domain the admin owns (catch-all mailbox over IMAP)

Every provider exposes the same two operations:

    state = await create_account(provider, domain=None, imap_config=None)
    messages = await fetch_messages(state)

``state`` is a plain JSON-serialisable dict, so it can be stored in the
existing ``temp_mail_users.json`` file without any extra work.

``messages`` is a list of dicts: ``{"id", "from", "subject", "text"}``.
"""

from __future__ import annotations

import asyncio
import email
import imaplib
import logging
import re
import secrets
import ssl
import time
from email.header import decode_header, make_header

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(20.0, connect=10.0)
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"

MAILTM_BASE = "https://api.mail.tm"
MAILGW_BASE = "https://api.mail.gw"
TEMPMAILIO_BASE = "https://api.internal.temp-mail.io/api/v3"
GUERRILLA_BASE = "https://api.guerrillamail.com/ajax.php"
TEMPMAILPLUS_BASE = "https://tempmail.plus/api"
INBOXES_BASE = "https://inboxes.com/api/v2"
TEMPMAILLOL_BASE = "https://api.tempmail.lol"

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
}

TEMPMAILPLUS_DOMAINS = (
    "mailto.plus", "fexpost.com", "fexbox.org", "rover.info",
    "chitthi.in", "fextemp.com", "any.pink", "merepost.com",
)

INBOXES_FALLBACK_DOMAINS = (
    "blondmail.com", "chapsmail.com", "clowmail.com", "dropjar.com",
    "fivermail.com", "getairmail.com", "givmail.com", "inboxbear.com",
    "vomoto.com", "zlorkun.com",
)

# Order matters: unlimited (no-signup) providers first, dead ones last.
PUBLIC_PROVIDERS = (
    "tempmailplus", "inboxes", "tempmaillol",
    "mailtm", "tempmailio", "guerrilla", "mailgw",
)

# These never run out: any local part on their domains works instantly.
UNLIMITED_PROVIDERS = ("tempmailplus", "inboxes")

PROVIDER_LABELS = {
    "tempmailplus": "TempMail.Plus",
    "inboxes": "Inboxes.com",
    "tempmaillol": "TempMail.LOL",
    "mailtm": "Mail.tm",
    "mailgw": "Mail.gw",
    "tempmailio": "Temp-Mail.io",
    "guerrilla": "GuerrillaMail",
    "imap": "Own Domain (IMAP)",
}


def _random_local() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(12))


def _members(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("hydra:member", "messages", "data", "domains", "list"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def _address(value):
    if isinstance(value, dict):
        return str(value.get("address") or value.get("email") or "").strip()
    if isinstance(value, list) and value:
        return _address(value[0])
    return str(value or "").strip()


_TAG_RE = re.compile(r"<[^>]+>")
_STYLE_RE = re.compile(r"(?is)<(script|style)[^>]*>.*?</\1>")


def html_to_text(value) -> str:
    """Turn an HTML (or plain) mail body into readable text so OTP codes are visible."""
    if isinstance(value, (list, tuple)):
        value = "\n".join(str(item) for item in value)
    text = str(value or "")
    if "<" in text and ">" in text:
        text = _STYLE_RE.sub(" ", text)
        text = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", text)
        text = _TAG_RE.sub(" ", text)
    text = (text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'"))
    text = re.sub(r"[ \t\x00-\x08\x0b\x0c]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ─── MAIL.TM / MAIL.GW (identical API) ────────────────────────────────────────
async def _mailbase_domains(client: httpx.AsyncClient, base: str):
    response = await client.get(f"{base}/domains")
    response.raise_for_status()
    domains = []
    for item in _members(response.json()):
        domain = item.get("domain") or item.get("name") if isinstance(item, dict) else item
        if domain:
            domains.append(str(domain).strip().lstrip("@"))
    return domains


async def _mailbase_create(provider: str, base: str, domain: str | None):
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        domains = await _mailbase_domains(client, base)
        if domain and domain.lower() in {d.lower() for d in domains}:
            domains = [domain]
        if not domains:
            raise RuntimeError(f"{provider}: no domains available")

        last_error = None
        for _ in range(3):
            chosen = secrets.choice(domains)
            address = f"{_random_local()}@{chosen}"
            password = secrets.token_urlsafe(18)
            try:
                created = await client.post(
                    f"{base}/accounts", json={"address": address, "password": password}
                )
                created.raise_for_status()
                token_response = await client.post(
                    f"{base}/token", json={"address": address, "password": password}
                )
                token_response.raise_for_status()
                token = str(token_response.json().get("token") or "").strip()
                if not token:
                    raise RuntimeError(f"{provider}: no token returned")
                return {
                    "provider": provider,
                    "email": address,
                    "password": password,
                    "token": token,
                }
            except httpx.HTTPStatusError as exc:
                last_error = exc
                if exc.response.status_code != 422:
                    raise
        raise last_error or RuntimeError(f"{provider}: account creation failed")


async def _mailbase_fetch(state: dict, base: str):
    headers = {"Authorization": f"Bearer {state.get('token', '')}"}
    out = []
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        listing = await client.get(f"{base}/messages", headers=headers)
        listing.raise_for_status()
        for message in _members(listing.json()):
            if not isinstance(message, dict):
                continue
            message_id = message.get("id")
            if message_id is None:
                continue
            details = message
            try:
                detail_response = await client.get(
                    f"{base}/messages/{message_id}", headers=headers
                )
                detail_response.raise_for_status()
                payload = detail_response.json()
                if isinstance(payload, dict):
                    details = payload
            except Exception as exc:  # detail is optional
                logger.debug("mail detail fetch failed: %s", exc)
            out.append(
                {
                    "id": str(message_id),
                    "from": _address(details.get("from") or message.get("from")),
                    "subject": str(details.get("subject") or "No subject"),
                    "text": html_to_text(
                        details.get("text")
                        or details.get("html")
                        or details.get("intro")
                        or message.get("intro")
                        or ""
                    ),
                }
            )
    return out


# ─── TEMP-MAIL.IO ─────────────────────────────────────────────────────────────
async def _tempmailio_create(domain: str | None):
    body: dict = {}
    if domain:
        body = {"name": _random_local(), "domain": domain}
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        response = await client.post(f"{TEMPMAILIO_BASE}/email/new", json=body)
        if response.status_code >= 400 and body:
            response = await client.post(f"{TEMPMAILIO_BASE}/email/new", json={})
        response.raise_for_status()
        payload = response.json()
        address = str(payload.get("email") or "").strip()
        if not address:
            raise RuntimeError("tempmailio: no address returned")
        return {
            "provider": "tempmailio",
            "email": address,
            "password": "",
            "token": str(payload.get("token") or ""),
        }


async def _tempmailio_fetch(state: dict):
    address = state.get("email", "")
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        response = await client.get(f"{TEMPMAILIO_BASE}/email/{address}/messages")
        response.raise_for_status()
        payload = response.json()
    out = []
    for message in payload if isinstance(payload, list) else _members(payload):
        if not isinstance(message, dict):
            continue
        out.append(
            {
                "id": str(message.get("id") or message.get("_id") or ""),
                "from": _address(message.get("from")),
                "subject": str(message.get("subject") or "No subject"),
                "text": html_to_text(message.get("body_text") or message.get("body_html") or ""),
            }
        )
    return [m for m in out if m["id"]]


# ─── GUERRILLAMAIL ────────────────────────────────────────────────────────────
async def _guerrilla_create(domain: str | None):
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        response = await client.get(GUERRILLA_BASE, params={"f": "get_email_address"})
        response.raise_for_status()
        payload = response.json()
        sid = str(payload.get("sid_token") or "")
        address = str(payload.get("email_addr") or "")
        if domain:
            try:
                renamed = await client.get(
                    GUERRILLA_BASE,
                    params={
                        "f": "set_email_user",
                        "email_user": _random_local(),
                        "domain": domain,
                        "sid_token": sid,
                    },
                )
                renamed.raise_for_status()
                address = str(renamed.json().get("email_addr") or address)
            except Exception as exc:
                logger.debug("guerrilla domain switch failed: %s", exc)
        if not address or not sid:
            raise RuntimeError("guerrilla: no address returned")
        return {"provider": "guerrilla", "email": address, "password": "", "token": sid}


async def _guerrilla_fetch(state: dict):
    sid = state.get("token", "")
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        listing = await client.get(
            GUERRILLA_BASE, params={"f": "check_email", "seq": 0, "sid_token": sid}
        )
        listing.raise_for_status()
        payload = listing.json()
        out = []
        for message in payload.get("list", []) if isinstance(payload, dict) else []:
            if not isinstance(message, dict):
                continue
            message_id = str(message.get("mail_id") or "")
            if not message_id:
                continue
            text = str(message.get("mail_excerpt") or "")
            try:
                detail = await client.get(
                    GUERRILLA_BASE,
                    params={"f": "fetch_email", "email_id": message_id, "sid_token": sid},
                )
                detail.raise_for_status()
                detail_payload = detail.json()
                if isinstance(detail_payload, dict):
                    text = str(detail_payload.get("mail_body") or text)
            except Exception as exc:
                logger.debug("guerrilla detail fetch failed: %s", exc)
            out.append(
                {
                    "id": message_id,
                    "from": str(message.get("mail_from") or ""),
                    "subject": str(message.get("mail_subject") or "No subject"),
                    "text": html_to_text(text),
                }
            )
    return out


# ─── OWN DOMAIN OVER IMAP (catch-all) ─────────────────────────────────────────
def _decode(value) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def _body_text(message) -> str:
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "ignore"
                    )
                except Exception:
                    continue
        for part in message.walk():
            if part.get_content_type() == "text/html":
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "ignore"
                    )
                except Exception:
                    continue
        return ""
    try:
        return message.get_payload(decode=True).decode(
            message.get_content_charset() or "utf-8", "ignore"
        )
    except Exception:
        return str(message.get_payload() or "")


def _imap_connect(config: dict):
    host = str(config.get("imap_host") or "").strip()
    port = int(config.get("imap_port") or 993)
    user = str(config.get("imap_user") or "").strip()
    password = str(config.get("imap_pass") or "")
    if not host or not user:
        raise RuntimeError("IMAP host/user missing")
    if port == 143:
        connection = imaplib.IMAP4(host, port)
        # Never continue with a plaintext login when STARTTLS fails.
        connection.starttls(ssl.create_default_context())
    else:
        connection = imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context())
    connection.login(user, password)
    return connection


def _imap_fetch_sync(config: dict, address: str):
    connection = _imap_connect(config)
    out = []
    try:
        connection.select(str(config.get("imap_folder") or "INBOX"))
        status, data = connection.search(None, "TO", f'"{address}"')
        if status != "OK":
            return out
        ids = (data[0] or b"").split()[-30:]
        for raw_id in ids:
            status, payload = connection.fetch(raw_id, "(RFC822)")
            if status != "OK" or not payload or not payload[0]:
                continue
            message = email.message_from_bytes(payload[0][1])
            message_id = _decode(message.get("Message-ID")) or raw_id.decode()
            out.append(
                {
                    "id": message_id,
                    "from": _decode(message.get("From")),
                    "subject": _decode(message.get("Subject")) or "No subject",
                    "text": _body_text(message),
                }
            )
    finally:
        try:
            connection.logout()
        except Exception:
            pass
    return out


def imap_test_sync(config: dict):
    """Validate IMAP credentials; raises on failure."""
    connection = _imap_connect(config)
    try:
        connection.select(str(config.get("imap_folder") or "INBOX"))
    finally:
        try:
            connection.logout()
        except Exception:
            pass
    return True


async def _imap_create(domain: str, config: dict):
    await asyncio.to_thread(imap_test_sync, config)
    return {
        "provider": "imap",
        "email": f"{_random_local()}@{domain}",
        "password": "",
        "token": "",
        "imap": {
            "imap_host": config.get("imap_host"),
            "imap_port": config.get("imap_port") or 993,
            "imap_user": config.get("imap_user"),
            "imap_pass": config.get("imap_pass"),
            "imap_folder": config.get("imap_folder") or "INBOX",
        },
    }


# ─── TEMPMAIL.PLUS (unlimited, no signup) ─────────────────────────────────────
async def _tempmailplus_create(domain: str | None):
    chosen = domain if domain and domain in TEMPMAILPLUS_DOMAINS else secrets.choice(
        list(TEMPMAILPLUS_DOMAINS)
    )
    address = f"{_random_local()}@{chosen}"
    return {"provider": "tempmailplus", "email": address, "password": "", "token": ""}


async def _tempmailplus_fetch(state: dict):
    address = state.get("email", "")
    out = []
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                 headers=BROWSER_HEADERS) as client:
        listing = await client.get(
            f"{TEMPMAILPLUS_BASE}/mails",
            params={"email": address, "limit": 20, "epin": ""},
        )
        listing.raise_for_status()
        payload = listing.json()
        for message in (payload.get("mail_list") or []) if isinstance(payload, dict) else []:
            if not isinstance(message, dict):
                continue
            message_id = str(message.get("mail_id") or "")
            if not message_id:
                continue
            text = str(message.get("subject") or "")
            try:
                detail = await client.get(
                    f"{TEMPMAILPLUS_BASE}/mails/{message_id}",
                    params={"email": address, "epin": ""},
                )
                detail.raise_for_status()
                body = detail.json()
                if isinstance(body, dict):
                    text = body.get("text") or body.get("html") or text
            except Exception as exc:
                logger.debug("tempmailplus detail failed: %s", exc)
            out.append(
                {
                    "id": message_id,
                    "from": _address(message.get("from_mail") or message.get("from")),
                    "subject": str(message.get("subject") or "No subject"),
                    "text": html_to_text(text),
                }
            )
    return out


# ─── INBOXES.COM (unlimited, no signup) ───────────────────────────────────────
async def _inboxes_domains(client: httpx.AsyncClient):
    try:
        response = await client.get(f"{INBOXES_BASE}/domain")
        response.raise_for_status()
        domains = []
        for item in _members(response.json()) or response.json():
            if isinstance(item, dict):
                value = item.get("name") or item.get("domain")
            else:
                value = item
            if value:
                domains.append(str(value).strip().lstrip("@"))
        if domains:
            return domains
    except Exception as exc:
        logger.debug("inboxes domains failed: %s", exc)
    return list(INBOXES_FALLBACK_DOMAINS)


async def _inboxes_create(domain: str | None):
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                 headers=BROWSER_HEADERS) as client:
        domains = await _inboxes_domains(client)
        chosen = domain if domain and domain in domains else secrets.choice(domains)
        address = f"{_random_local()}@{chosen}"
        try:
            await client.get(f"{INBOXES_BASE}/inbox/{address}")
        except Exception as exc:
            logger.debug("inboxes warmup failed: %s", exc)
    return {"provider": "inboxes", "email": address, "password": "", "token": ""}


async def _inboxes_fetch(state: dict):
    address = state.get("email", "")
    out = []
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                 headers=BROWSER_HEADERS) as client:
        listing = await client.get(f"{INBOXES_BASE}/inbox/{address}")
        listing.raise_for_status()
        payload = listing.json()
        messages = payload.get("msgs") if isinstance(payload, dict) else payload
        for message in messages or []:
            if not isinstance(message, dict):
                continue
            uid = str(message.get("uid") or message.get("id") or "")
            if not uid:
                continue
            text = str(message.get("snippet") or "")
            try:
                detail = await client.get(f"{INBOXES_BASE}/message/{uid}")
                detail.raise_for_status()
                body = detail.json()
                if isinstance(body, dict):
                    text = body.get("text") or body.get("html") or text
            except Exception as exc:
                logger.debug("inboxes detail failed: %s", exc)
            out.append(
                {
                    "id": uid,
                    "from": _address(message.get("f") or message.get("from")),
                    "subject": str(message.get("s") or message.get("subject") or "No subject"),
                    "text": html_to_text(text),
                }
            )
    return out


# ─── TEMPMAIL.LOL ─────────────────────────────────────────────────────────────
async def _tempmaillol_create(domain: str | None):
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                 headers=BROWSER_HEADERS) as client:
        response = await client.get(f"{TEMPMAILLOL_BASE}/generate")
        response.raise_for_status()
        payload = response.json()
    address = str(payload.get("address") or payload.get("email") or "").strip()
    token = str(payload.get("token") or "").strip()
    if not address or not token:
        raise RuntimeError("tempmaillol: no address returned")
    return {"provider": "tempmaillol", "email": address, "password": "", "token": token}


async def _tempmaillol_fetch(state: dict):
    token = state.get("token", "")
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True,
                                 headers=BROWSER_HEADERS) as client:
        response = await client.get(f"{TEMPMAILLOL_BASE}/auth/{token}")
        response.raise_for_status()
        payload = response.json()
    out = []
    messages = payload.get("email") if isinstance(payload, dict) else payload
    for index, message in enumerate(messages or []):
        if not isinstance(message, dict):
            continue
        out.append(
            {
                "id": str(message.get("id") or f"{message.get('date', '')}-{index}"),
                "from": _address(message.get("from")),
                "subject": str(message.get("subject") or "No subject"),
                "text": html_to_text(message.get("body") or message.get("html") or ""),
            }
        )
    return out


# ─── PUBLIC API ───────────────────────────────────────────────────────────────
async def create_account(provider: str, domain: str | None = None, imap_config: dict | None = None):
    if provider == "tempmailplus":
        state = await _tempmailplus_create(domain)
    elif provider == "inboxes":
        state = await _inboxes_create(domain)
    elif provider == "tempmaillol":
        state = await _tempmaillol_create(domain)
    elif provider == "mailtm":
        state = await _mailbase_create("mailtm", MAILTM_BASE, domain)
    elif provider == "mailgw":
        state = await _mailbase_create("mailgw", MAILGW_BASE, domain)
    elif provider == "tempmailio":
        state = await _tempmailio_create(domain)
    elif provider == "guerrilla":
        state = await _guerrilla_create(domain)
    elif provider == "imap":
        if not domain:
            raise RuntimeError("imap provider needs a domain")
        state = await _imap_create(domain, imap_config or {})
    else:
        raise RuntimeError(f"Unknown mail provider: {provider}")
    state["seen_messages"] = []
    state["created_at"] = time.time()
    return state


async def fetch_messages(state: dict):
    provider = str(state.get("provider") or "mailgw")
    if provider == "tempmailplus":
        return await _tempmailplus_fetch(state)
    if provider == "inboxes":
        return await _inboxes_fetch(state)
    if provider == "tempmaillol":
        return await _tempmaillol_fetch(state)
    if provider == "mailtm":
        return await _mailbase_fetch(state, MAILTM_BASE)
    if provider == "mailgw":
        return await _mailbase_fetch(state, MAILGW_BASE)
    if provider == "tempmailio":
        return await _tempmailio_fetch(state)
    if provider == "guerrilla":
        return await _guerrilla_fetch(state)
    if provider == "imap":
        return await asyncio.to_thread(
            _imap_fetch_sync, state.get("imap") or {}, state.get("email", "")
        )
    raise RuntimeError(f"Unknown mail provider: {provider}")


async def provider_health():
    """Quick reachability probe used by the admin panel."""
    results = {}
    for provider in PUBLIC_PROVIDERS:
        try:
            if provider == "tempmailplus":
                async with httpx.AsyncClient(timeout=TIMEOUT, headers=BROWSER_HEADERS) as client:
                    response = await client.get(
                        f"{TEMPMAILPLUS_BASE}/mails",
                        params={"email": f"{_random_local()}@mailto.plus", "limit": 5, "epin": ""},
                    )
                    response.raise_for_status()
            elif provider == "inboxes":
                async with httpx.AsyncClient(timeout=TIMEOUT, headers=BROWSER_HEADERS) as client:
                    response = await client.get(f"{INBOXES_BASE}/domain")
                    response.raise_for_status()
            elif provider == "tempmaillol":
                async with httpx.AsyncClient(timeout=TIMEOUT, headers=BROWSER_HEADERS) as client:
                    response = await client.get(f"{TEMPMAILLOL_BASE}/generate")
                    response.raise_for_status()
            elif provider in ("mailtm", "mailgw"):
                base = MAILTM_BASE if provider == "mailtm" else MAILGW_BASE
                async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                    response = await client.get(f"{base}/domains")
                    response.raise_for_status()
            elif provider == "tempmailio":
                async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                    response = await client.get(f"{TEMPMAILIO_BASE}/domains")
                    response.raise_for_status()
            else:
                async with httpx.AsyncClient(timeout=TIMEOUT) as client:
                    response = await client.get(
                        GUERRILLA_BASE, params={"f": "get_email_address"}
                    )
                    response.raise_for_status()
            results[provider] = True
        except Exception as exc:
            logger.debug("provider %s down: %s", provider, exc)
            results[provider] = False
    return results
