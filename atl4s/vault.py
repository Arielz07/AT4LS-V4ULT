from __future__ import annotations

import sqlite3
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import fernet_key
from .util import iso


def _fernet() -> Fernet:
    return Fernet(fernet_key())


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(value: str) -> str:
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("The stored credential could not be decrypted.") from exc


def mask_key(value: str | None) -> str:
    if not value:
        return "not set"
    if len(value) <= 8:
        return "••••"
    return "••••••••" + value[-4:]


def list_providers(conn: sqlite3.Connection, user: sqlite3.Row) -> list[sqlite3.Row]:
    if user["role"] == "owner":
        return conn.execute(
            """
            SELECT p.*, s.encrypted_key IS NOT NULL AS has_secret,
                   u.name AS owner_name
            FROM providers p
            LEFT JOIN provider_secrets s ON s.provider_id = p.id
            LEFT JOIN users u ON u.id = p.owner_user_id
            ORDER BY p.is_builtin DESC, p.created_at ASC
            """
        ).fetchall()
    return conn.execute(
        """
        SELECT p.*, s.encrypted_key IS NOT NULL AS has_secret,
               u.name AS owner_name
        FROM providers p
        LEFT JOIN provider_secrets s ON s.provider_id = p.id
        LEFT JOIN users u ON u.id = p.owner_user_id
        WHERE p.scope = 'workspace' OR p.owner_user_id = ?
        ORDER BY p.is_builtin DESC, p.created_at ASC
        """,
        (user["id"],),
    ).fetchall()


def add_provider(
    conn: sqlite3.Connection,
    *,
    name: str,
    provider_id: str,
    base_url: str,
    default_model: str,
    scope: str,
    owner_user_id: int,
    api_key: str | None,
    budget_usd: float | None = None,
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO providers
            (name, provider_id, base_url, default_model, scope, owner_user_id,
             is_builtin, enabled, budget_usd, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?)
        """,
        (name, provider_id, base_url, default_model, scope, owner_user_id, budget_usd, iso()),
    )
    provider_pk = int(cursor.lastrowid)
    if api_key:
        conn.execute(
            "INSERT INTO provider_secrets(provider_id, encrypted_key, created_at) VALUES (?, ?, ?)",
            (provider_pk, encrypt(api_key), iso()),
        )
    return provider_pk


def provider_key(conn: sqlite3.Connection, provider_id: int) -> str | None:
    row = conn.execute("SELECT encrypted_key FROM provider_secrets WHERE provider_id = ?", (provider_id,)).fetchone()
    if not row:
        return None
    return decrypt(row["encrypted_key"])


def provider_summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "provider_id": row["provider_id"],
        "base_url": row["base_url"],
        "default_model": row["default_model"],
        "scope": row["scope"],
        "owner_name": row["owner_name"] if "owner_name" in row.keys() else None,
        "is_builtin": bool(row["is_builtin"]),
        "has_secret": bool(row["has_secret"]) if "has_secret" in row.keys() else False,
    }
