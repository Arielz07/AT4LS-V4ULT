from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .config import (
    DATA_DIR,
    DB_PATH,
    DEFAULT_MODEL,
    DEFAULT_PROVIDER_ID,
    DEFAULT_PROVIDER_MODEL,
    ensure_data_dirs,
)
from .util import iso

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'reviewer'
        CHECK (role IN ('owner', 'full_access', 'reviewer')),
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS totp_pending (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    presence_until TEXT,
    ip TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('full_access', 'reviewer')),
    token_hash TEXT NOT NULL UNIQUE,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS access_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL DEFAULT 'live'
);

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    root_path TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    project_type TEXT NOT NULL DEFAULT 'website',
    status TEXT NOT NULL DEFAULT 'active',
    health_score INTEGER,
    cover_color TEXT NOT NULL DEFAULT 'green',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_indexed_at TEXT,
    file_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    parent_path TEXT,
    name TEXT NOT NULL,
    file_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    is_empty INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(project_id, path)
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    extension TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'other',
    size INTEGER NOT NULL DEFAULT 0,
    mtime_ns INTEGER,
    sha256 TEXT,
    title TEXT,
    summary TEXT,
    word_count INTEGER NOT NULL DEFAULT 0,
    has_title INTEGER NOT NULL DEFAULT 0,
    has_description INTEGER NOT NULL DEFAULT 0,
    content_text TEXT,
    indexed_at TEXT NOT NULL,
    UNIQUE(project_id, path)
);

CREATE VIRTUAL TABLE IF NOT EXISTS file_fts USING fts5(
    path,
    title,
    summary,
    content_text,
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE IF NOT EXISTS file_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    href TEXT NOT NULL,
    target_path TEXT,
    is_external INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'unchecked',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL DEFAULT 'baseline',
    status TEXT NOT NULL DEFAULT 'running',
    verdict TEXT,
    score INTEGER,
    summary TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    evidence_path TEXT,
    line INTEGER,
    recommendation TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 80,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'subagent',
    scope TEXT NOT NULL DEFAULT 'workspace',
    owner_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    is_builtin INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    permissions_json TEXT NOT NULL DEFAULT '[]',
    system_prompt TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider_id TEXT NOT NULL,
    base_url TEXT NOT NULL,
    default_model TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'workspace',
    owner_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    is_builtin INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    budget_usd REAL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_secrets (
    provider_id INTEGER PRIMARY KEY REFERENCES providers(id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routing_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path_pattern TEXT NOT NULL,
    agent_slug TEXT,
    model TEXT,
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_files_project ON files(project_id);
CREATE INDEX IF NOT EXISTS idx_files_kind ON files(project_id, kind);
CREATE INDEX IF NOT EXISTS idx_files_sha ON files(project_id, sha256);
CREATE INDEX IF NOT EXISTS idx_folders_project ON folders(project_id);
CREATE INDEX IF NOT EXISTS idx_links_project ON file_links(project_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id, status);
CREATE INDEX IF NOT EXISTS idx_audits_project ON audits(project_id, started_at);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_windows_project ON access_windows(project_id, status, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);
"""


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    ensure_data_dirs()
    connection = sqlite3.connect(DB_PATH, timeout=15, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        seed_defaults(conn)


def seed_defaults(conn: sqlite3.Connection) -> None:
    now = iso()
    defaults = {
        "theme": "auto",
        "scene": "drift",
        "accent": "lime",
        "vault_grace_seconds": "120",
        "require_owner_presence": "1",
        "max_session_hours": "2",
        "app_version": "0.1.0",
    }
    for key, value in defaults.items():
        conn.execute("INSERT OR IGNORE INTO app_settings(key, value) VALUES (?, ?)", (key, value))

    conn.execute(
        """
        INSERT OR IGNORE INTO providers
            (name, provider_id, base_url, default_model, scope, is_builtin, enabled, created_at)
        VALUES (?, ?, ?, ?, 'workspace', 1, 1, ?)
        """,
        (
            "OpenCode",
            DEFAULT_PROVIDER_ID,
            "https://opencode.ai/inference/openai/v1",
            DEFAULT_PROVIDER_MODEL,
            now,
        ),
    )

    standard_agents = [
        (
            "structure-auditor",
            "Structure auditor",
            "Maps folder shape, finds duplicates, empty areas, misplaced assets, and oversized files.",
            "Search the project map for structural problems. Return evidence, severity, and a concise recommendation.",
            "read",
            "green",
        ),
        (
            "content-auditor",
            "Content auditor",
            "Reviews page titles, descriptions, headings, word counts, and stale content.",
            "Audit the indexed pages for missing or weak content signals. Quote paths and exact problems.",
            "read",
            "amber",
        ),
        (
            "link-auditor",
            "Link auditor",
            "Checks internal routes and referenced local assets for missing targets.",
            "Verify links against the indexed filesystem. Report broken internal targets only when evidence is clear.",
            "read",
            "blue",
        ),
        (
            "docs-cartographer",
            "Docs cartographer",
            "Builds the project map, entry points, commands, and README proposal.",
            "Describe the project structure and produce a clear map. Never invent commands that are not present.",
            "read",
            "violet",
        ),
        (
            "verifier",
            "Verifier",
            "Runs allowlisted build and test commands inside a worktree.",
            "Run only approved commands. Capture failures with the smallest useful excerpt.",
            "shell",
            "rose",
        ),
        (
            "judge",
            "Judge",
            "Reconciles findings from the specialist panel and issues the final verdict.",
            "Synthesize only the supplied findings. Do not add new claims without evidence. Resolve contradictions explicitly.",
            "read",
            "ice",
        ),
    ]
    for slug, name, description, prompt, permission, color in standard_agents:
        permissions = json.dumps(
            [
                {"action": "read", "resource": "*", "effect": "allow"},
                {"action": "edit", "resource": "*", "effect": "deny"},
                {"action": "shell", "resource": "*", "effect": "deny"},
            ]
            if permission == "read"
            else [
                {"action": "read", "resource": "*", "effect": "allow"},
                {"action": "edit", "resource": "*", "effect": "deny"},
                {"action": "shell", "resource": "*", "effect": "ask"},
            ]
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO agents
                (slug, name, description, model, mode, scope, is_builtin, enabled,
                 permissions_json, system_prompt, created_at)
            VALUES (?, ?, ?, ?, 'subagent', 'workspace', 1, 1, ?, ?, ?)
            """,
            (slug, name, description, DEFAULT_MODEL, permissions, prompt, now),
        )


def list_agents(conn: sqlite3.Connection, user: sqlite3.Row) -> list[sqlite3.Row]:
    if user["role"] == "owner":
        return conn.execute("SELECT * FROM agents ORDER BY is_builtin DESC, name").fetchall()
    return conn.execute(
        """
        SELECT * FROM agents
        WHERE scope = 'workspace' OR owner_user_id = ?
        ORDER BY is_builtin DESC, name
        """,
        (user["id"],),
    ).fetchall()


def log_event(
    conn: sqlite3.Connection,
    kind: str,
    title: str,
    detail: str = "",
    *,
    project_id: int | None = None,
    user_id: int | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO events (project_id, user_id, kind, title, detail, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (project_id, user_id, kind, title, detail, iso()),
    )


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO app_settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def project_root(project: sqlite3.Row | dict) -> Path:
    return Path(project["root_path"]).expanduser().resolve()


def data_dir() -> Path:
    return DATA_DIR


__all__ = ["DB_PATH", "connect", "init_db", "log_event", "get_setting", "set_setting", "project_root"]
