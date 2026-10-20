from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or utcnow()).isoformat(timespec="seconds")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def in_future(value: str | None) -> bool:
    parsed = parse_iso(value)
    return bool(parsed and parsed > utcnow())


def slugify(value: str, fallback: str = "project") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:60] or fallback


def human_bytes(value: int | float | None) -> str:
    size = float(value or 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return "0 B"


def human_count(value: int | float | None) -> str:
    number = int(value or 0)
    if number >= 1_000_000:
        return f"{number / 1_000_000:.1f}m"
    if number >= 1_000:
        return f"{number / 1_000:.1f}k"
    return str(number)


def time_ago(value: str | None) -> str:
    parsed = parse_iso(value)
    if not parsed:
        return "never"
    delta = utcnow() - parsed
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "just now"
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 86400 * 30:
        return f"{seconds // 86400}d ago"
    return parsed.strftime("%d %b %Y")


def time_until(value: str | None) -> str:
    parsed = parse_iso(value)
    if not parsed:
        return "closed"
    seconds = int((parsed - utcnow()).total_seconds())
    if seconds <= 0:
        return "expired"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m"
    return f"{seconds // 86400}d {seconds % 86400 // 3600}h"


def new_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def is_external_link(href: str) -> bool:
    parts = urlsplit(href)
    return bool(parts.scheme or parts.netloc) and not href.startswith("#")


def local_link_target(base_file: Path, root: Path, href: str) -> Path | None:
    if not href or href.startswith("#"):
        return None
    parts = urlsplit(href)
    if parts.scheme or parts.netloc or href.startswith("//"):
        return None
    if parts.path in {"", "/"}:
        return None
    raw = parts.path
    from urllib.parse import unquote

    candidate = (base_file.parent / unquote(raw)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return candidate
    return candidate


def relative_posix(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return path.as_posix()
    return "" if relative == Path(".") else relative.as_posix()


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def safe_int(value: str | None, default: int = 0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def excerpt(value: str | None, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def duration_from_hours(value: str | None, default: int = 2) -> timedelta:
    try:
        hours = float(value or default)
    except ValueError:
        hours = float(default)
    hours = max(0.25, min(12.0, hours))
    return timedelta(hours=hours)
