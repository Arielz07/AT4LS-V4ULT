from __future__ import annotations

import os
import secrets
from pathlib import Path

APP_NAME = "ATL4S::V4UlT"
APP_VERSION = "0.1.0"
DEFAULT_MODEL = "opencode/deepseek-v4.1-flash-free#high"
DEFAULT_PROVIDER_ID = "opencode"
DEFAULT_PROVIDER_MODEL = "deepseek-v4.1-flash-free"
VAULT_GRACE_SECONDS = 120
SESSION_DAYS = 14
MAX_USERS = 2

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_local_env() -> None:
    """Load a small bootstrap .env without overriding the real environment.

    Provider credentials intentionally belong in the encrypted vault, not here.
    """
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_local_env()


def _default_data_dir() -> Path:
    configured = os.environ.get("ATL4S_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        if root:
            return Path(root) / "ATL4S-Vault"
        return Path.home() / "AppData" / "Local" / "ATL4S-Vault"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "atl4s-vault"
    return Path.home() / ".local" / "share" / "atl4s-vault"


DATA_DIR = _default_data_dir()
DB_PATH = DATA_DIR / "atl4s-vault.db"
UPLOAD_DIR = DATA_DIR / "uploads"
BACKUP_DIR = DATA_DIR / "backups"
FONT_DIR = BASE_DIR / "atl4s" / "static" / "fonts"
SECRET_KEY_PATH = DATA_DIR / "secret.key"
FERNET_KEY_PATH = DATA_DIR / "vault.key"
TEMPLATE_DIR = BASE_DIR / "atl4s" / "templates"
STATIC_DIR = BASE_DIR / "atl4s" / "static"

SECURE_COOKIES = os.environ.get("ATL4S_SECURE_COOKIES", "0") == "1"
COOKIE_NAME = "atl4s_session"
CSRF_COOKIE = "atl4s_csrf"

IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".cache",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "dist",
    "build",
    "target",
    "coverage",
    ".idea",
    ".vscode",
    ".DS_Store",
    "$RECYCLE.BIN",
    "System Volume Information",
}

IGNORED_FILES = {
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "id_rsa",
    "id_ed25519",
}

TEXT_EXTENSIONS = {
    ".md",
    ".mdx",
    ".markdown",
    ".txt",
    ".html",
    ".htm",
    ".xhtml",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".json",
    ".jsonc",
    ".yml",
    ".yaml",
    ".toml",
    ".xml",
    ".svg",
    ".py",
    ".rb",
    ".php",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".sql",
    ".graphql",
    ".gql",
    ".astro",
    ".vue",
    ".svelte",
}

PAGE_EXTENSIONS = {".html", ".htm", ".xhtml", ".md", ".mdx", ".markdown", ".astro", ".vue", ".svelte"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico", ".tif", ".tiff"}
VIDEO_EXTENSIONS = {".mp4", ".webm", ".mov", ".mkv", ".avi", ".m4v"}
AUDIO_EXTENSIONS = {".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}

MAX_TEXT_BYTES = 768 * 1024
MAX_HASH_BYTES = 24 * 1024 * 1024


def ensure_data_dirs() -> None:
    for directory in (DATA_DIR, UPLOAD_DIR, BACKUP_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def _write_secret(path: Path, value: str) -> None:
    ensure_data_dirs()
    path.write_text(value, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def app_secret() -> str:
    if SECRET_KEY_PATH.exists():
        value = SECRET_KEY_PATH.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    _write_secret(SECRET_KEY_PATH, value)
    return value


def fernet_key() -> bytes:
    if FERNET_KEY_PATH.exists():
        value = FERNET_KEY_PATH.read_bytes().strip()
        if value:
            return value
    from cryptography.fernet import Fernet

    value = Fernet.generate_key()
    ensure_data_dirs()
    FERNET_KEY_PATH.write_bytes(value)
    try:
        FERNET_KEY_PATH.chmod(0o600)
    except OSError:
        pass
    return value


def display_path(path: Path | str) -> str:
    try:
        return str(path)
    except Exception:
        return str(path)
