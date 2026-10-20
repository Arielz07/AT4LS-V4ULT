from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import timedelta

from .db import log_event
from .util import human_bytes, iso, utcnow


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    recommendation: str
    evidence_path: str | None = None
    line: int | None = None
    confidence: int = 90


SEVERITY_WEIGHT = {
    "critical": 25,
    "high": 14,
    "medium": 7,
    "low": 3,
    "info": 1,
}

VERDICT_LABEL = {
    "healthy": "Healthy",
    "watch": "Watch",
    "needs-work": "Needs work",
    "critical": "Critical",
}


def _sample_paths(paths: list[str], limit: int = 6) -> str:
    if not paths:
        return ""
    shown = " · ".join(paths[:limit])
    if len(paths) > limit:
        shown += f" · +{len(paths) - limit} more"
    return shown


def _read_readme(conn: sqlite3.Connection, project_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT * FROM files
        WHERE project_id = ?
          AND lower(path) IN ('readme.md', 'readme.txt', 'readme', 'readme.markdown')
        LIMIT 1
        """,
        (project_id,),
    ).fetchone()


def _collect(conn: sqlite3.Connection, project: sqlite3.Row) -> tuple[list[Finding], dict[str, int]]:
    project_id = int(project["id"])
    findings: list[Finding] = []
    stats: dict[str, int] = {}

    readme = _read_readme(conn, project_id)
    readme_text = (readme["content_text"] or "") if readme else ""
    if not readme:
        findings.append(
            Finding(
                "medium",
                "docs",
                "No README found at the project root",
                "A newcomer cannot identify the project purpose, entry point, or operating notes from the repository root.",
                "Add a README.md with purpose, project map, setup commands, and ownership notes.",
                confidence=98,
            )
        )
    elif len(readme_text.strip()) < 240:
        findings.append(
            Finding(
                "low",
                "docs",
                "README is very thin",
                f"{readme['path']} contains only {len(readme_text.strip())} characters.",
                "Expand the README with entry points, folder roles, commands that actually exist, and known constraints.",
                evidence_path=readme["path"],
                confidence=92,
            )
        )

    root_files = conn.execute(
        "SELECT path FROM files WHERE project_id = ? AND instr(path, '/') = 0",
        (project_id,),
    ).fetchall()
    stats["root_files"] = len(root_files)
    if len(root_files) > 40:
        findings.append(
            Finding(
                "low",
                "structure",
                "Project root is crowded",
                f"{len(root_files)} files sit directly at the root. Dense roots make ownership and navigation harder.",
                "Group related files into named folders, keeping only entry points and top-level configuration at the root.",
                confidence=84,
            )
        )

    large = conn.execute(
        """
        SELECT path, size FROM files
        WHERE project_id = ? AND size > ? ORDER BY size DESC
        """,
        (project_id, 10 * 1024 * 1024),
    ).fetchall()
    stats["large"] = len(large)
    for row in large[:10]:
        severity = "medium" if row["size"] > 50 * 1024 * 1024 else "low"
        findings.append(
            Finding(
                severity,
                "structure",
                f"Large file: {row['path']}",
                f"{human_bytes(row['size'])} is stored as a single project file.",
                "Move large media to optimized delivery storage or compress it if it is served directly.",
                evidence_path=row["path"],
                confidence=96,
            )
        )
    if len(large) > 10:
        findings.append(
            Finding(
                "low",
                "structure",
                f"{len(large) - 10} additional large files",
                "Only the first ten oversized files were listed individually.",
                "Review the remaining large assets in the file inventory.",
                confidence=90,
            )
        )

    duplicates = conn.execute(
        """
        SELECT sha256, count(*) AS copies, max(size) AS size,
               group_concat(path, '|||') AS paths
        FROM files
        WHERE project_id = ? AND sha256 IS NOT NULL AND size > 0
        GROUP BY sha256 HAVING count(*) > 1
        ORDER BY copies DESC LIMIT 8
        """,
        (project_id,),
    ).fetchall()
    stats["duplicate_groups"] = len(duplicates)
    for row in duplicates:
        paths = row["paths"].split("|||")
        findings.append(
            Finding(
                "low",
                "structure",
                f"Duplicate file content ({row['copies']} copies)",
                _sample_paths(paths),
                "Keep one canonical copy and replace the others with references, or confirm the duplication is intentional.",
                evidence_path=paths[0] if paths else None,
                confidence=99,
            )
        )

    empty_folders = conn.execute(
        "SELECT path FROM folders WHERE project_id = ? AND path != '' AND is_empty = 1",
        (project_id,),
    ).fetchall()
    stats["empty_folders"] = len(empty_folders)
    if empty_folders:
        findings.append(
            Finding(
                "low" if len(empty_folders) >= 3 else "info",
                "structure",
                f"Empty folders: {len(empty_folders)}",
                _sample_paths([row["path"] for row in empty_folders]),
                "Remove unused folders or add a short README explaining why they are intentionally empty.",
                confidence=99,
            )
        )

    deep = conn.execute(
        """
        SELECT path FROM folders
        WHERE project_id = ? AND length(path) - length(replace(path, '/', '')) >= 6
        """,
        (project_id,),
    ).fetchall()
    stats["deep_folders"] = len(deep)
    if deep:
        findings.append(
            Finding(
                "info",
                "structure",
                "Deep folder nesting detected",
                _sample_paths([row["path"] for row in deep]),
                "Consider flattening long paths so project navigation stays predictable.",
                confidence=78,
            )
        )

    html_pages = conn.execute(
        """
        SELECT path, has_title, has_description, size
        FROM files
        WHERE project_id = ? AND extension IN ('.html', '.htm', '.xhtml')
        ORDER BY path
        """,
        (project_id,),
    ).fetchall()
    stats["html_pages"] = len(html_pages)
    missing_titles = [row for row in html_pages if not row["has_title"]]
    stats["missing_titles"] = len(missing_titles)
    for row in missing_titles[:12]:
        findings.append(
            Finding(
                "medium",
                "content",
                f"Missing page title: {row['path']}",
                "The HTML document does not contain a non-empty <title> element.",
                "Add a unique, descriptive title that explains the page in a browser tab and search result.",
                evidence_path=row["path"],
                confidence=99,
            )
        )
    if len(missing_titles) > 12:
        findings.append(
            Finding(
                "medium",
                "content",
                f"{len(missing_titles) - 12} more HTML pages without titles",
                "Only the first twelve pages were listed individually.",
                "Add titles to the remaining pages; keep them unique and specific.",
                confidence=95,
            )
        )

    missing_desc = [row for row in html_pages if not row["has_description"]]
    stats["missing_descriptions"] = len(missing_desc)
    if missing_desc:
        home_pages = [row for row in missing_desc if row["path"].lower().rsplit("/", 1)[-1] in {"index.html", "index.htm", "home.html"}]
        desc_label = "HTML page" if len(missing_desc) == 1 else "HTML pages"
        desc_verb = "lacks" if len(missing_desc) == 1 else "lack"
        findings.append(
            Finding(
                "medium" if home_pages else "low",
                "content",
                f"{len(missing_desc)} {desc_label} {desc_verb} a meta description",
                _sample_paths([row["path"] for row in missing_desc]),
                "Add a concise meta description to each page. Prioritize the homepage and primary entry points.",
                evidence_path=missing_desc[0]["path"] if missing_desc else None,
                confidence=95,
            )
        )

    empty_pages = conn.execute(
        """
        SELECT path FROM files
        WHERE project_id = ? AND kind = 'page' AND word_count = 0
        ORDER BY path LIMIT 10
        """,
        (project_id,),
    ).fetchall()
    stats["empty_pages"] = len(empty_pages)
    for row in empty_pages:
        findings.append(
            Finding(
                "low",
                "content",
                f"Page has no readable text: {row['path']}",
                "The page contains no extractable words after indexing.",
                "Confirm the page is intentional. If it is a placeholder, add a clear next step or mark it as draft.",
                evidence_path=row["path"],
                confidence=82,
            )
        )

    stale_cutoff = (utcnow() - timedelta(days=365)).timestamp() * 1_000_000_000
    stale = conn.execute(
        """
        SELECT path FROM files
        WHERE project_id = ? AND kind = 'page' AND mtime_ns IS NOT NULL AND mtime_ns < ?
        ORDER BY mtime_ns ASC
        """,
        (project_id, stale_cutoff),
    ).fetchall()
    stats["stale_pages"] = len(stale)
    if stale:
        findings.append(
            Finding(
                "info",
                "content",
                f"{len(stale)} pages untouched for over a year",
                _sample_paths([row["path"] for row in stale]),
                "Review older pages for accuracy, broken assumptions, and outdated calls to action.",
                confidence=89,
            )
        )

    broken = conn.execute(
        """
        SELECT l.href, l.target_path, f.path AS source_path
        FROM file_links l JOIN files f ON f.id = l.file_id
        WHERE l.project_id = ? AND l.status = 'broken'
        ORDER BY f.path, l.href
        """,
        (project_id,),
    ).fetchall()
    stats["broken_links"] = len(broken)
    for row in broken[:20]:
        target = row["target_path"] or row["href"]
        findings.append(
            Finding(
                "medium" if len(broken) < 10 else "high",
                "links",
                f"Broken local link in {row['source_path']}",
                f"Reference points to missing target: {target}",
                "Update the reference or restore the target file. Re-run the baseline audit after the fix.",
                evidence_path=row["source_path"],
                confidence=98,
            )
        )
    if len(broken) > 20:
        findings.append(
            Finding(
                "high",
                "links",
                f"{len(broken) - 20} additional broken local links",
                "Only the first twenty references were listed individually.",
                "Fix the remaining missing targets and re-index the project.",
                confidence=96,
            )
        )

    external = conn.execute(
        "SELECT count(*) AS n FROM file_links WHERE project_id = ? AND is_external = 1",
        (project_id,),
    ).fetchone()
    stats["external_links"] = int(external["n"]) if external else 0
    stats["files"] = int(project["file_count"] or 0)

    if not findings:
        findings.append(
            Finding(
                "info",
                "content",
                "Baseline checks passed",
                "No structural, documentation, content, or local-link problems were detected by the free baseline.",
                "Keep the project indexed after major changes. Deeper model-assisted review can run in the next phase.",
                confidence=100,
            )
        )

    return findings, stats


def _score(findings: list[Finding]) -> tuple[int, str]:
    by_category: dict[str, int] = {}
    for finding in findings:
        by_category[finding.category] = by_category.get(finding.category, 0) + SEVERITY_WEIGHT.get(finding.severity, 1)
    penalty = min(85, sum(min(30, value) for value in by_category.values()))
    score = max(0, 100 - penalty)
    if score >= 90:
        verdict = "healthy"
    elif score >= 75:
        verdict = "watch"
    elif score >= 55:
        verdict = "needs-work"
    else:
        verdict = "critical"
    return score, verdict


def run_baseline_audit(
    conn: sqlite3.Connection,
    project: sqlite3.Row,
    user_id: int | None = None,
) -> tuple[int, int, str, int]:
    project_id = int(project["id"])
    started = iso()
    cursor = conn.execute(
        """
        INSERT INTO audits (project_id, kind, status, started_at)
        VALUES (?, 'baseline', 'running', ?)
        """,
        (project_id, started),
    )
    audit_id = int(cursor.lastrowid)
    try:
        findings, stats = _collect(conn, project)
        score, verdict = _score(findings)
        for finding in findings:
            conn.execute(
                """
                INSERT INTO findings
                    (audit_id, project_id, severity, category, title, detail,
                     evidence_path, line, recommendation, confidence, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
                """,
                (
                    audit_id,
                    project_id,
                    finding.severity,
                    finding.category,
                    finding.title,
                    finding.detail,
                    finding.evidence_path,
                    finding.line,
                    finding.recommendation,
                    finding.confidence,
                    iso(),
                ),
            )
        open_count = sum(1 for finding in findings if finding.severity in {"critical", "high", "medium"})
        broken_count = stats.get("broken_links", 0)
        missing_title_count = stats.get("missing_titles", 0)
        summary = (
            f"{stats.get('files', 0)} files across {stats.get('html_pages', 0)} HTML page"
            f"{'' if stats.get('html_pages', 0) == 1 else 's'}. "
            f"{len(findings)} finding{'' if len(findings) == 1 else 's'}, "
            f"{open_count} needing attention. "
            f"{broken_count} broken local link{'' if broken_count == 1 else 's'}, "
            f"{missing_title_count} page{'' if missing_title_count == 1 else 's'} without a title."
        )
        conn.execute(
            """
            UPDATE audits SET status = 'complete', verdict = ?, score = ?, summary = ?, finished_at = ?
            WHERE id = ?
            """,
            (verdict, score, summary, iso(), audit_id),
        )
        conn.execute(
            "UPDATE projects SET health_score = ?, updated_at = ? WHERE id = ?",
            (score, iso(), project_id),
        )
        log_event(
            conn,
            "audit",
            f"Baseline audit completed for {project['name']}",
            f"Score {score}/100 · {len(findings)} findings",
            project_id=project_id,
            user_id=user_id,
        )
        return audit_id, score, verdict, len(findings)
    except Exception as exc:
        conn.execute("DELETE FROM findings WHERE audit_id = ?", (audit_id,))
        conn.execute(
            "UPDATE audits SET status = 'failed', summary = ?, finished_at = ? WHERE id = ?",
            (f"Audit failed: {exc}", iso(), audit_id),
        )
        log_event(
            conn,
            "audit",
            f"Baseline audit failed for {project['name']}",
            str(exc)[:600],
            project_id=project_id,
            user_id=user_id,
        )
        raise


def severity_counts(conn: sqlite3.Connection, audit_id: int) -> dict[str, int]:
    rows = conn.execute(
        "SELECT severity, count(*) AS n FROM findings WHERE audit_id = ? GROUP BY severity",
        (audit_id,),
    ).fetchall()
    return {row["severity"]: int(row["n"]) for row in rows}
