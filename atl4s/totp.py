from __future__ import annotations

import base64
import hashlib
import hmac
import os
import sqlite3
import time
from datetime import timedelta
from urllib.parse import quote

from .util import iso, parse_iso, utcnow
from .vault import decrypt, encrypt

ISSUER = "ATL4S::V4UlT"
DIGITS = 6
PERIOD = 30
PENDING_MINUTES = 15
_SECRET_BYTES = 20


def generate_secret() -> str:
    return base64.b32encode(os.urandom(_SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    normalized = "".join(secret.split()).upper()
    padding = "=" * (-len(normalized) % 8)
    try:
        return base64.b32decode(normalized + padding, casefold=True)
    except Exception as exc:
        raise ValueError("Invalid TOTP secret.") from exc


def code_at(secret: str, timestamp: float | None = None, *, digits: int = DIGITS, period: int = PERIOD) -> str:
    """Return a standard RFC 6238 TOTP code for the supplied timestamp."""
    moment = time.time() if timestamp is None else timestamp
    counter = int(moment // period)
    digest = hmac.new(
        _decode_secret(secret),
        counter.to_bytes(8, "big"),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    value = (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF) % (10**digits)
    return f"{value:0{digits}d}"


def verify_code(secret: str, submitted: str, *, window: int = 1, at: float | None = None) -> bool:
    """Verify one code while allowing the usual adjacent time-step drift."""
    candidate = "".join((submitted or "").split())
    if len(candidate) != DIGITS or not candidate.isdigit() or not secret:
        return False
    moment = time.time() if at is None else at
    valid = False
    try:
        for offset in range(-window, window + 1):
            expected = code_at(secret, moment + (offset * PERIOD))
            valid = hmac.compare_digest(expected, candidate) or valid
    except (ValueError, TypeError):
        return False
    return valid


def provisioning_uri(secret: str, email: str) -> str:
    label = quote(f"{ISSUER}:{email}", safe="")
    issuer = quote(ISSUER, safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )


def set_pending_secret(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    conn.execute("DELETE FROM totp_pending WHERE user_id = ?", (user_id,))
    conn.execute(
        "INSERT INTO totp_pending (user_id, encrypted_secret, created_at) VALUES (?, ?, ?)",
        (user_id, encrypt(secret), iso()),
    )


def get_pending_secret(conn: sqlite3.Connection, user_id: int) -> str | None:
    row = conn.execute(
        "SELECT encrypted_secret, created_at FROM totp_pending WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    if not row:
        return None
    created = parse_iso(row["created_at"])
    if not created or created + timedelta(minutes=PENDING_MINUTES) <= utcnow():
        clear_pending_secret(conn, user_id)
        return None
    try:
        return decrypt(row["encrypted_secret"])
    except ValueError:
        clear_pending_secret(conn, user_id)
        return None


def clear_pending_secret(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("DELETE FROM totp_pending WHERE user_id = ?", (user_id,))


def enable_totp(conn: sqlite3.Connection, user_id: int, secret: str) -> None:
    conn.execute(
        "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
        (encrypt(secret), user_id),
    )
    clear_pending_secret(conn, user_id)


def disable_totp(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?",
        (user_id,),
    )
    clear_pending_secret(conn, user_id)


def secret_for_user(user: sqlite3.Row) -> str | None:
    encrypted = user["totp_secret"] if "totp_secret" in user.keys() else None
    if not encrypted:
        return None
    try:
        return decrypt(encrypted)
    except ValueError:
        return None
