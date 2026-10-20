from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import timedelta
from typing import Any

from fastapi import Request
from fastapi.responses import RedirectResponse

from .config import COOKIE_NAME, SECURE_COOKIES, SESSION_DAYS, VAULT_GRACE_SECONDS
from .util import iso, iso as now_iso, new_token, utcnow


class RedirectTo(Exception):
    def __init__(self, path: str, status_code: int = 303) -> None:
        self.path = path
        self.status_code = status_code
        super().__init__(path)


class Forbidden(Exception):
    pass


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=32,
    )
    return "scrypt$16384$8$1$" + salt.hex() + "$" + digest.hex()


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = encoded.split("$", 5)
        if scheme != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else ""


def create_session(
    conn: sqlite3.Connection,
    user_id: int,
    request: Request,
    *,
    presence: bool = False,
) -> tuple[str, str]:
    token = new_token(40)
    csrf = new_token(28)
    created = utcnow()
    expires = created + timedelta(days=SESSION_DAYS)
    presence_until = (created + timedelta(seconds=VAULT_GRACE_SECONDS)).isoformat(timespec="seconds") if presence else None
    conn.execute(
        """
        INSERT INTO sessions
            (user_id, token_hash, csrf_token, created_at, last_seen_at, expires_at,
             presence_until, ip, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            token_digest(token),
            csrf,
            iso(created),
            iso(created),
            iso(expires),
            presence_until,
            _client_ip(request),
            request.headers.get("user-agent", "")[:500],
        ),
    )
    return token, csrf


def set_session_cookie(response: RedirectResponse, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=SESSION_DAYS * 86400,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        path="/",
    )


def clear_session_cookie(response: RedirectResponse) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def load_user_from_request(conn: sqlite3.Connection, request: Request) -> sqlite3.Row | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    row = conn.execute(
        """
        SELECT s.id AS session_id, s.csrf_token, s.presence_until, s.expires_at,
               s.revoked_at, u.*
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (token_digest(token),),
    ).fetchone()
    if not row:
        return None
    if row["revoked_at"] or not row["expires_at"] or row["expires_at"] <= iso():
        return None
    now = utcnow()
    updates: dict[str, Any] = {"last_seen_at": iso(now)}
    if row["role"] == "owner":
        updates["presence_until"] = (now + timedelta(seconds=VAULT_GRACE_SECONDS)).isoformat(timespec="seconds")
    conn.execute(
        f"UPDATE sessions SET {', '.join(f'{key} = ?' for key in updates)} WHERE id = ?",
        (*updates.values(), row["session_id"]),
    )
    return row


def vault_open(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE u.role = 'owner'
          AND s.revoked_at IS NULL
          AND s.expires_at > ?
          AND s.presence_until IS NOT NULL
          AND s.presence_until > ?
        LIMIT 1
        """,
        (iso(), iso()),
    ).fetchone()
    return row is not None


def active_windows(conn: sqlite3.Connection, project_id: int | None = None) -> list[sqlite3.Row]:
    params: list[Any] = [iso()]
    clause = ""
    if project_id is not None:
        clause = "AND w.project_id = ?"
        params.append(project_id)
    return conn.execute(
        f"""
        SELECT w.*, p.name AS project_name, p.slug AS project_slug
        FROM access_windows w JOIN projects p ON p.id = w.project_id
        WHERE w.status = 'live' AND w.ended_at IS NULL
          AND w.expires_at > ?
        {clause}
        ORDER BY w.expires_at ASC
        """,
        params,
    ).fetchall()


def reviewer_can_access(conn: sqlite3.Connection, project_id: int | None = None) -> bool:
    return bool(active_windows(conn, project_id))


def require_user(request: Request) -> sqlite3.Row:
    user = getattr(request.state, "user", None)
    if not user:
        raise RedirectTo("/login")
    if user["role"] != "owner" and not getattr(request.state, "vault_open", False):
        raise RedirectTo("/locked")
    return user


def require_owner(request: Request) -> sqlite3.Row:
    user = require_user(request)
    if user["role"] != "owner":
        raise Forbidden("Owner access is required.")
    return user


def require_editor(request: Request) -> sqlite3.Row:
    user = require_user(request)
    if user["role"] not in {"owner", "full_access"}:
        raise Forbidden("Full access is required.")
    return user


def can_view_project(conn: sqlite3.Connection, user: sqlite3.Row, project_id: int) -> bool:
    if user["role"] in {"owner", "full_access"}:
        return True
    return reviewer_can_access(conn, project_id)


def csrf_ok(request: Request, submitted: str | None) -> bool:
    user = getattr(request.state, "user", None)
    if not user or not submitted:
        return False
    return hmac.compare_digest(user["csrf_token"], submitted)


def revoke_user_sessions(conn: sqlite3.Connection, user_id: int, *, except_session: int | None = None) -> None:
    if except_session is None:
        conn.execute("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (iso(), user_id))
    else:
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND id != ? AND revoked_at IS NULL",
            (iso(), user_id, except_session),
        )


def extend_presence(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute(
        "UPDATE sessions SET presence_until = ?, last_seen_at = ? WHERE id = ?",
        (
            (utcnow() + timedelta(seconds=VAULT_GRACE_SECONDS)).isoformat(timespec="seconds"),
            iso(),
            session_id,
        ),
    )


def close_presence(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute(
        "UPDATE sessions SET presence_until = ? WHERE id = ?",
        ((utcnow() + timedelta(seconds=3)).isoformat(timespec="seconds"), session_id),
    )


def invite_token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_invite(conn: sqlite3.Connection, email: str, role: str, user_id: int, hours: int = 48) -> str:
    token = new_token(32)
    created = utcnow()
    conn.execute(
        """
        INSERT INTO invites (email, role, token_hash, created_by, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            email.strip().lower(),
            role,
            invite_token_hash(token),
            user_id,
            iso(created),
            iso(created + timedelta(hours=hours)),
        ),
    )
    return token


def find_invite(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    row = conn.execute(
        "SELECT * FROM invites WHERE token_hash = ?",
        (invite_token_hash(token),),
    ).fetchone()
    if not row or row["used_at"] or row["revoked_at"]:
        return None
    if row["expires_at"] <= iso():
        return None
    return row


def consume_invite(conn: sqlite3.Connection, invite_id: int) -> None:
    conn.execute("UPDATE invites SET used_at = ? WHERE id = ?", (iso(), invite_id))


def flash_url(path: str, *, notice: str = "", error: str = "") -> str:
    from urllib.parse import urlencode

    params = {}
    if notice:
        params["notice"] = notice
    if error:
        params["error"] = error
    if not params:
        return path
    separator = "&" if "?" in path else "?"
    return path + separator + urlencode(params)


def login_redirect() -> RedirectResponse:
    response = RedirectResponse("/", status_code=303)
    return response


def utc_now_iso() -> str:
    return now_iso()
