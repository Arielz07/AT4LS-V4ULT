from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote, urlsplit

from .config import (
    IGNORED_DIRS,
    IGNORED_FILES,
    MAX_HASH_BYTES,
    MAX_TEXT_BYTES,
    PAGE_EXTENSIONS,
    TEXT_EXTENSIONS,
)
from .util import excerpt, iso, relative_posix


@dataclass
class ParsedFile:
    title: str
    summary: str
    word_count: int
    text: str
    links: list[str]
    meta_description: str = ""
    has_title: bool = False
    has_description: bool = False


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.description = ""
        self._in_title = False
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag == "title":
            self._in_title = True
        elif tag in {"script", "style", "noscript", "template"}:
            self._in_script = tag == "script"
            self._in_style = tag == "style"
        elif tag == "meta":
            name = attrs_dict.get("name", "").lower()
            prop = attrs_dict.get("property", "").lower()
            if name == "description" or prop == "og:description":
                self.description = attrs_dict.get("content", "").strip()
        if tag in {"a", "link", "img", "script", "source", "video", "audio"}:
            for key in ("href", "src", "poster"):
                value = attrs_dict.get(key)
                if value:
                    self.links.append(value.strip())

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)
        elif not self._in_script and not self._in_style:
            text = re.sub(r"\s+", " ", data).strip()
            if text:
                self.text_parts.append(text)


def kind_for(extension: str) -> str:
    ext = extension.lower()
    if ext in {".html", ".htm", ".xhtml", ".md", ".mdx", ".markdown", ".astro", ".vue", ".svelte"}:
        return "page"
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico", ".tif", ".tiff"}:
        return "image"
    if ext in {".mp4", ".webm", ".mov", ".mkv", ".avi", ".m4v"}:
        return "video"
    if ext in {".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac"}:
        return "audio"
    if ext in {".css", ".scss", ".sass", ".less"}:
        return "style"
    if ext in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".php", ".sh", ".bash", ".zsh", ".ps1"}:
        return "code"
    if ext in {".json", ".jsonc", ".yml", ".yaml", ".toml", ".xml", ".svg", ".sql", ".graphql", ".gql"}:
        return "data"
    if ext in {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}:
        return "archive"
    if ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt"}:
        return "document"
    return "other"


def read_text(path: Path, limit: int = MAX_TEXT_BYTES) -> str:
    try:
        raw = path.read_bytes()[:limit]
    except OSError:
        return ""
    if b"\x00" in raw[:4096]:
        return ""
    return raw.decode("utf-8", errors="replace")


def parse_file(path: Path, extension: str) -> ParsedFile:
    ext = extension.lower()
    title = path.stem.replace("-", " ").replace("_", " ").strip().title()
    summary = ""
    word_count = 0
    links: list[str] = []
    description = ""
    has_title = False
    has_description = False
    if ext not in TEXT_EXTENSIONS:
        return ParsedFile(title=title, summary="", word_count=0, text="", links=[])

    text = read_text(path)
    if not text:
        return ParsedFile(title=title, summary="", word_count=0, text="", links=[])

    if ext in {".html", ".htm", ".xhtml"}:
        parser = _PageParser()
        try:
            parser.feed(text)
        except Exception:
            pass
        candidate = " ".join(parser.title_parts).strip()
        if candidate:
            title = unescape(candidate)
            has_title = True
        body = " ".join(parser.text_parts)
        word_count = len(re.findall(r"\b[\w'-]+\b", body))
        summary = excerpt(body)
        if parser.description:
            description = excerpt(parser.description, 260)
            has_description = True
        links = parser.links
        content = body
    elif ext in {".md", ".mdx", ".markdown"}:
        heading = re.search(r"^\s*#\s+(.+)$", text, re.MULTILINE)
        if heading:
            title = heading.group(1).strip().strip("#").strip()
            has_title = True
        frontmatter = re.search(r"^---\s*\n(.*?)\n---", text, re.DOTALL)
        if frontmatter:
            desc_match = re.search(r"^description:\s*(.+)$", frontmatter.group(1), re.MULTILINE | re.IGNORECASE)
            if desc_match:
                description = excerpt(desc_match.group(1).strip().strip("\"'"), 260)
                has_description = True
        body = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
        body = re.sub(r"`[^`]*`", " ", body)
        body = re.sub(r"!?\[([^\]]*)\]\([^)]+\)", r"\1", body)
        body = re.sub(r"^[#>*\-\s]+", "", body, flags=re.MULTILINE)
        word_count = len(re.findall(r"\b[\w'-]+\b", body))
        summary = excerpt(body)
        links = re.findall(r"!?\[[^\]]*\]\(([^)\s]+)", text)
        content = text
    else:
        body = re.sub(r"\s+", " ", text)
        word_count = len(re.findall(r"\b[\w'-]+\b", body))
        summary = excerpt(body)
        content = text

    return ParsedFile(
        title=title[:220],
        summary=summary,
        word_count=word_count,
        text=content[:240_000],
        links=links,
        meta_description=description,
        has_title=has_title,
        has_description=has_description,
    )


def resolve_link(base_file: Path, root: Path, href: str) -> tuple[str, str | None, int]:
    """Return (status, target_path, is_external)."""
    if not href or href.startswith("#"):
        return "skipped", None, 0
    parts = urlsplit(href)
    if parts.scheme in {"mailto", "tel", "javascript", "data"}:
        return "skipped", None, 0
    if parts.scheme or parts.netloc or href.startswith("//"):
        return "external", None, 1
    raw = unquote(parts.path or "")
    if not raw:
        return "skipped", None, 0
    try:
        if raw.startswith("/"):
            candidate = (root / raw.lstrip("/")).resolve()
        else:
            candidate = (base_file.parent / raw).resolve()
    except OSError:
        return "broken", None, 0
    try:
        candidate.relative_to(root)
    except ValueError:
        return "external", None, 1
    target = relative_posix(candidate, root)
    if candidate.exists():
        return "ok", target, 0
    return "broken", target, 0


def sha256_file(path: Path, size: int) -> str | None:
    if size > MAX_HASH_BYTES:
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def walk_tree(root: Path) -> tuple[list[Path], list[Path]]:
    directories: list[Path] = [root]
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        retained: list[str] = []
        for dirname in sorted(dirnames):
            child = current_path / dirname
            if dirname in IGNORED_DIRS or child.is_symlink():
                continue
            try:
                child.relative_to(root)
            except ValueError:
                continue
            retained.append(dirname)
            directories.append(child)
        dirnames[:] = retained
        for filename in sorted(filenames):
            if filename in IGNORED_FILES or filename.startswith(".env"):
                continue
            child = current_path / filename
            if child.is_symlink() or not child.is_file():
                continue
            try:
                child.relative_to(root)
            except ValueError:
                continue
            files.append(child)
    return directories, files


def index_project(conn: sqlite3.Connection, project: sqlite3.Row) -> dict[str, int]:
    root = Path(project["root_path"]).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Project root does not exist: {root}")
    project_id = int(project["id"])
    now = iso()

    conn.execute(
        "DELETE FROM file_fts WHERE rowid IN (SELECT id FROM files WHERE project_id = ?)",
        (project_id,),
    )
    conn.execute("DELETE FROM file_links WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM files WHERE project_id = ?", (project_id,))
    conn.execute("DELETE FROM folders WHERE project_id = ?", (project_id,))

    directories, files = walk_tree(root)
    folder_counts: dict[str, list[int]] = {}
    for directory in directories:
        rel = relative_posix(directory, root) if directory != root else ""
        parent = relative_posix(directory.parent, root) if directory != root else None
        conn.execute(
            """
            INSERT OR REPLACE INTO folders
                (project_id, path, parent_path, name, file_count, total_bytes, is_empty, created_at)
            VALUES (?, ?, ?, ?, 0, 0, 1, ?)
            """,
            (project_id, rel, parent, directory.name if directory != root else root.name, now),
        )
        folder_counts[rel] = [0, 0]

    indexed = 0
    total_bytes = 0
    for file_path in files:
        try:
            stat = file_path.stat()
        except OSError:
            continue
        rel = relative_posix(file_path, root)
        parent = relative_posix(file_path.parent, root)
        extension = file_path.suffix.lower()
        kind = kind_for(extension)
        parsed = parse_file(file_path, extension)
        digest = sha256_file(file_path, stat.st_size)
        conn.execute(
            """
            INSERT INTO files
                (project_id, path, name, extension, kind, size, mtime_ns, sha256,
                 title, summary, word_count, has_title, has_description,
                 content_text, indexed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                rel,
                file_path.name,
                extension,
                kind,
                stat.st_size,
                stat.st_mtime_ns,
                digest,
                parsed.title,
                parsed.summary,
                parsed.word_count,
                int(parsed.has_title),
                int(parsed.has_description),
                parsed.text,
                now,
            ),
        )
        file_id = int(conn.execute("SELECT last_insert_rowid() AS id").fetchone()["id"])
        conn.execute(
            "INSERT INTO file_fts(rowid, path, title, summary, content_text) VALUES (?, ?, ?, ?, ?)",
            (file_id, rel, parsed.title, parsed.summary, parsed.text),
        )
        for href in parsed.links:
            status, target, external = resolve_link(file_path, root, href)
            conn.execute(
                """
                INSERT INTO file_links
                    (project_id, file_id, href, target_path, is_external, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (project_id, file_id, href[:2000], target, external, status, now),
            )
        indexed += 1
        total_bytes += stat.st_size
        bucket = folder_counts.setdefault(parent, [0, 0])
        bucket[0] += 1
        bucket[1] += stat.st_size

    for rel, (count, size) in folder_counts.items():
        conn.execute(
            "UPDATE folders SET file_count = ?, total_bytes = ?, is_empty = ? WHERE project_id = ? AND path = ?",
            (count, size, 1 if count == 0 else 0, project_id, rel),
        )

    conn.execute(
        """
        UPDATE projects SET file_count = ?, total_bytes = ?, last_indexed_at = ?,
            updated_at = ?, status = 'active'
        WHERE id = ?
        """,
        (indexed, total_bytes, now, now, project_id),
    )
    return {"files": indexed, "folders": len(directories), "bytes": total_bytes}


def sanitize_fts_query(query: str) -> str:
    tokens = re.findall(r"[\w][\w.@/-]*", query, flags=re.UNICODE)
    tokens = [token.replace('"', "") for token in tokens[:12] if len(token) > 1]
    if not tokens:
        return ""
    return " AND ".join(f'"{token}"*' for token in tokens)


def search_files(
    conn: sqlite3.Connection,
    query: str,
    *,
    limit: int = 50,
    project_ids: Iterable[int] | None = None,
) -> list[sqlite3.Row]:
    ids = list(project_ids) if project_ids is not None else None
    if ids is not None and not ids:
        return []
    fts = sanitize_fts_query(query)
    if fts:
        try:
            params: list[object] = [fts]
            clause = ""
            if ids is not None:
                clause = f"AND f.project_id IN ({','.join('?' for _ in ids)})"
                params.extend(ids)
            params.append(limit)
            return conn.execute(
                f"""
                SELECT f.*, p.name AS project_name, p.slug AS project_slug,
                       bm25(file_fts) AS rank
                FROM file_fts
                JOIN files f ON f.id = file_fts.rowid
                JOIN projects p ON p.id = f.project_id
                WHERE file_fts MATCH ? {clause}
                ORDER BY rank ASC
                LIMIT ?
                """,
                params,
            ).fetchall()
        except sqlite3.OperationalError:
            pass
    like = f"%{query.strip()}%"
    params = [like, like, like]
    clause = ""
    if ids is not None:
        clause = f"AND f.project_id IN ({','.join('?' for _ in ids)})"
        params.extend(ids)
    params.append(limit)
    return conn.execute(
        f"""
        SELECT f.*, p.name AS project_name, p.slug AS project_slug, 0 AS rank
        FROM files f JOIN projects p ON p.id = f.project_id
        WHERE (f.path LIKE ? OR f.title LIKE ? OR f.summary LIKE ?) {clause}
        ORDER BY f.path
        LIMIT ?
        """,
        params,
    ).fetchall()


def kind_icon(kind: str) -> str:
    return {
        "page": "file-text",
        "image": "image",
        "video": "film",
        "audio": "music",
        "style": "palette",
        "code": "code",
        "data": "braces",
        "archive": "archive",
        "document": "file",
    }.get(kind, "file")


def extension_label(extension: str) -> str:
    return extension.lstrip(".").upper() if extension else "FILE"


def page_extensions() -> set[str]:
    return PAGE_EXTENSIONS
