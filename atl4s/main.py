from __future__ import annotations

import csv
import io
import json
import re
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .audits import VERDICT_LABEL, run_baseline_audit, severity_counts
from .config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_MODEL,
    DATA_DIR,
    DB_PATH,
    MAX_USERS,
    SECURE_COOKIES,
    STATIC_DIR,
    TEMPLATE_DIR,
    VAULT_GRACE_SECONDS,
)
from .db import connect, init_db, list_agents, log_event
from .indexing import index_project, search_files
from .totp import (
    disable_totp,
    enable_totp,
    generate_secret,
    get_pending_secret,
    provisioning_uri,
    secret_for_user,
    set_pending_secret,
    verify_code,
)
from .security import (
    Forbidden,
    RedirectTo,
    active_windows,
    can_view_project,
    clear_session_cookie,
    close_presence,
    consume_invite,
    create_invite,
    create_session,
    csrf_ok,
    extend_presence,
    find_invite,
    hash_password,
    load_user_from_request,
    require_editor,
    require_owner,
    require_user,
    revoke_user_sessions,
    set_session_cookie,
    vault_open,
    verify_password,
)
from .util import (
    duration_from_hours,
    excerpt,
    human_bytes,
    human_count,
    iso,
    new_token,
    parse_iso,
    safe_int,
    slugify,
    time_ago,
    time_until,
    utcnow,
)
from .vault import add_provider, list_providers


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title=APP_NAME, version=APP_VERSION, docs_url=None, redoc_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TEMPLATE_DIR)


def _severity_label(value: str) -> str:
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }.get(value, value.title())


def _verdict_label(value: str | None) -> str:
    return VERDICT_LABEL.get(value or "", "Not run")


def _initials(name: str | None) -> str:
    parts = [part for part in re.split(r"\s+", (name or "V4").strip()) if part]
    if not parts:
        return "V4"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def _absolute_url(request: Request, path: str) -> str:
    return str(request.base_url).rstrip("/") + path


def _active_nav(path: str) -> str:
    if path.startswith("/account"):
        return "account"
    if path.startswith("/projects"):
        return "projects"
    if path.startswith("/audits"):
        return "audits"
    if path.startswith("/agents"):
        return "agents"
    if path.startswith("/activity"):
        return "activity"
    if path.startswith("/settings"):
        return "settings"
    return "briefing"


templates.env.filters["human_bytes"] = human_bytes
templates.env.filters["human_count"] = human_count
templates.env.filters["time_ago"] = time_ago
templates.env.filters["time_until"] = time_until
templates.env.filters["severity_label"] = _severity_label
templates.env.filters["verdict_label"] = _verdict_label
templates.env.filters["initials"] = _initials
templates.env.filters["excerpt"] = excerpt
templates.env.filters["date"] = lambda value: (parse_iso(value).strftime("%d %b %Y, %H:%M") if parse_iso(value) else "—")


def _base_context(request: Request, **extra: Any) -> dict[str, Any]:
    user = getattr(request.state, "user", None)
    return {
        "request": request,
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "default_model": DEFAULT_MODEL,
        "user": user,
        "csrf_token": user["csrf_token"] if user else "",
        "vault_open": getattr(request.state, "vault_open", False),
        "notice": request.query_params.get("notice", ""),
        "error": request.query_params.get("error", ""),
        "active_nav": _active_nav(request.url.path),
        "path": request.url.path,
        "data_dir": str(DATA_DIR),
        "vault_grace": VAULT_GRACE_SECONDS,
        **extra,
    }


def render(request: Request, name: str, *, status_code: int = 200, **extra: Any):
    return templates.TemplateResponse(
        request=request,
        name=name,
        context=_base_context(request, **extra),
        status_code=status_code,
    )


def _form_string(form, key: str, default: str = "") -> str:
    value = form.get(key)
    if value is None:
        return default
    return str(value).strip()


def _form_raw(form, key: str, default: str = "") -> str:
    value = form.get(key)
    if value is None:
        return default
    return str(value)


def _valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def _step_up_ok(user: sqlite3.Row, password: str, code: str) -> bool:
    if not verify_password(password, user["password_hash"]):
        return False
    if not user["totp_enabled"]:
        return True
    secret = secret_for_user(user)
    return bool(secret and verify_code(secret, code))


async def _require_form(request: Request):
    form = await request.form()
    if not csrf_ok(request, _form_string(form, "_csrf")):
        raise Forbidden("The form token is invalid. Refresh the page and try again.")
    return form


def _redirect(path: str, *, notice: str = "", error: str = "") -> RedirectResponse:
    params: dict[str, str] = {}
    if notice:
        params["notice"] = notice
    if error:
        params["error"] = error
    if params:
        path += ("&" if "?" in path else "?") + urlencode(params)
    return RedirectResponse(path, status_code=303)


def _project_by_id(conn, project_id: int):
    return conn.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()


def _assert_project_access(conn, user, project) -> None:
    if not can_view_project(conn, user, int(project["id"])):
        raise RedirectTo("/locked")


def _visible_project_ids(conn, user) -> list[int] | None:
    if user["role"] in {"owner", "full_access"}:
        return None
    windows = active_windows(conn)
    return sorted({int(row["project_id"]) for row in windows})


def _latest_projects(conn, ids: list[int] | None, query: str = "") -> list[Any]:
    params: list[Any] = []
    clauses: list[str] = []
    if ids is not None:
        if not ids:
            return []
        clauses.append(f"p.id IN ({','.join('?' for _ in ids)})")
        params.extend(ids)
    if query:
        clauses.append("(p.name LIKE ? OR p.root_path LIKE ? OR p.description LIKE ?)")
        like = f"%{query}%"
        params.extend([like, like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return conn.execute(
        f"""
        SELECT p.*,
            (SELECT verdict FROM audits a WHERE a.project_id = p.id AND a.status = 'complete'
             ORDER BY a.id DESC LIMIT 1) AS latest_verdict,
            (SELECT score FROM audits a WHERE a.project_id = p.id AND a.status = 'complete'
             ORDER BY a.id DESC LIMIT 1) AS latest_score,
            (SELECT started_at FROM audits a WHERE a.project_id = p.id AND a.status = 'complete'
             ORDER BY a.id DESC LIMIT 1) AS latest_audit_at,
            (SELECT count(*) FROM findings f
             WHERE f.project_id = p.id AND f.status = 'open'
               AND f.audit_id = (SELECT max(a2.id) FROM audits a2 WHERE a2.project_id = p.id AND a2.status = 'complete')
            ) AS open_findings,
            (SELECT count(*) FROM access_windows w
             WHERE w.project_id = p.id AND w.status = 'live' AND w.ended_at IS NULL AND w.expires_at > ?
            ) AS live_windows
        FROM projects p {where}
        ORDER BY p.updated_at DESC, p.id DESC
        """,
        [iso(), *params],
    ).fetchall()


@app.middleware("http")
async def load_auth_state(request: Request, call_next):
    if request.url.path.startswith("/static/"):
        return await call_next(request)
    with connect() as conn:
        user = load_user_from_request(conn, request)
        request.state.user = user
        request.state.vault_open = vault_open(conn)
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    if response.headers.get("content-type", "").startswith("text/html"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(RedirectTo)
async def redirect_exception(request: Request, exc: RedirectTo):
    return RedirectResponse(exc.path, status_code=exc.status_code)


@app.exception_handler(Forbidden)
async def forbidden_exception(request: Request, exc: Forbidden):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": str(exc)}, status_code=403)
    return render(request, "error.html", status_code=403, page_title="Access denied", error_message=str(exc))


@app.exception_handler(404)
async def not_found_exception(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "Not found"}, status_code=404)
    return render(request, "error.html", status_code=404, page_title="Not found", error_message="That page or record does not exist.")


@app.get("/api/health")
def health():
    return {"ok": True, "app": APP_NAME, "version": APP_VERSION}


@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request):
    with connect() as conn:
        count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
    if count:
        raise RedirectTo("/login")
    token = new_token(24)
    response = render(request, "setup.html", page_title="Initialize vault", auth_page=True, setup_csrf=token)
    response.set_cookie(
        "atl4s_setup_csrf",
        token,
        max_age=3600,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        path="/",
    )
    return response


@app.post("/setup")
async def setup_submit(request: Request):
    form = await request.form()
    token = _form_string(form, "csrf")
    cookie = request.cookies.get("atl4s_setup_csrf", "")
    if not token or not cookie or not secrets.compare_digest(token, cookie):
        return render(request, "setup.html", page_title="Initialize vault", auth_page=True, setup_csrf=cookie, error="The setup token expired. Refresh and try again.")
    with connect() as conn:
        count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
        if count:
            raise RedirectTo("/login")
        email = _form_string(form, "email").lower()
        name = _form_string(form, "name")
        password = _form_raw(form, "password")
        confirm = _form_raw(form, "confirm")
        if not _valid_email(email):
            return render(request, "setup.html", page_title="Initialize vault", auth_page=True, setup_csrf=cookie, error="Enter a valid email address.", email=email, name=name)
        if not name or len(name) > 90:
            return render(request, "setup.html", page_title="Initialize vault", auth_page=True, setup_csrf=cookie, error="Give the owner a name.", email=email, name=name)
        if len(password) < 10:
            return render(request, "setup.html", page_title="Initialize vault", auth_page=True, setup_csrf=cookie, error="Use at least 10 characters for the owner password.", email=email, name=name)
        if password != confirm:
            return render(request, "setup.html", page_title="Initialize vault", auth_page=True, setup_csrf=cookie, error="The passwords do not match.", email=email, name=name)
        cursor = conn.execute(
            "INSERT INTO users (email, name, password_hash, role, created_at) VALUES (?, ?, ?, 'owner', ?)",
            (email, name, hash_password(password), iso()),
        )
        user_id = int(cursor.lastrowid)
        log_event(conn, "auth", "Owner vault initialized", f"{email} created the owner account.", user_id=user_id)
        token, _ = create_session(conn, user_id, request, presence=True)
        response = _redirect("/", notice="Vault initialized. The owner presence lock is now active.")
        set_session_cookie(response, token)
        response.delete_cookie("atl4s_setup_csrf", path="/")
        return response


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if getattr(request.state, "user", None):
        raise RedirectTo("/")
    with connect() as conn:
        users = conn.execute("SELECT id, role FROM users").fetchall()
        opened = vault_open(conn)
    if not users:
        raise RedirectTo("/setup")
    login_csrf = new_token(24)
    response = render(request, "login.html", page_title="Sign in", auth_page=True, vault_open=opened, has_owner=any(row["role"] == "owner" for row in users), login_csrf=login_csrf)
    response.set_cookie("atl4s_login_csrf", login_csrf, max_age=3600, httponly=True, samesite="lax", secure=SECURE_COOKIES, path="/")
    return response


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    email = _form_string(form, "email").lower()
    password = _form_raw(form, "password")
    submitted = _form_string(form, "csrf")
    cookie = request.cookies.get("atl4s_login_csrf", "")
    with connect() as conn:
        opened = vault_open(conn)
        users = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
        if not users:
            raise RedirectTo("/setup")
        if not cookie or not submitted or not secrets.compare_digest(cookie, submitted):
            return render(request, "login.html", page_title="Sign in", auth_page=True, vault_open=opened, has_owner=True, error="The sign-in form expired. Refresh and try again.", email=email, login_csrf=cookie)
        row = conn.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            log_event(conn, "auth", "Failed sign-in", f"Rejected credentials for {email or 'empty email'}.")
            return render(request, "login.html", page_title="Sign in", auth_page=True, vault_open=opened, has_owner=True, error="Email or password is incorrect.", email=email, login_csrf=cookie)
        if row["totp_enabled"]:
            submitted_code = _form_string(form, "totp")
            secret = secret_for_user(row)
            if not submitted_code:
                return render(request, "login.html", page_title="Sign in", auth_page=True, vault_open=opened, has_owner=True, error="Enter the 6-digit code from your authenticator app.", email=email, login_csrf=cookie)
            if not secret or not verify_code(secret, submitted_code):
                log_event(conn, "auth", "Failed authenticator check", f"Rejected TOTP for {email}.", user_id=int(row["id"]))
                return render(request, "login.html", page_title="Sign in", auth_page=True, vault_open=opened, has_owner=True, error="Email, password, or authenticator code is incorrect.", email=email, login_csrf=cookie)
        if row["role"] != "owner" and not opened:
            return render(request, "login.html", page_title="Sign in", auth_page=True, vault_open=opened, has_owner=True, error="The vault is closed. The owner must be present before collaborator access opens.", email=email, login_csrf=cookie)
        if row["role"] == "reviewer" and not active_windows(conn):
            return render(request, "login.html", page_title="Sign in", auth_page=True, vault_open=opened, has_owner=True, error="No live review session is open. The owner must start a task session first.", email=email, login_csrf=cookie)
        token, _ = create_session(conn, int(row["id"]), request, presence=row["role"] == "owner")
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (iso(), row["id"]))
        log_event(conn, "auth", f"{row['name']} signed in", f"Role: {row['role']}", user_id=row["id"])
        response = _redirect("/", notice=f"Welcome back, {row['name']}.")
        set_session_cookie(response, token)
        response.delete_cookie("atl4s_login_csrf", path="/")
        return response


@app.post("/logout")
async def logout(request: Request):
    user = getattr(request.state, "user", None)
    if user:
        form = await request.form()
        if not csrf_ok(request, _form_string(form, "_csrf")):
            raise Forbidden("The form token is invalid. Refresh the page and try again.")
        with connect() as conn:
            if user["role"] == "owner":
                conn.execute("UPDATE sessions SET presence_until = ? WHERE id = ?", (iso(utcnow()), user["session_id"]))
            conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (iso(), user["session_id"]))
            log_event(conn, "auth", f"{user['name']} signed out", user_id=user["id"])
    response = _redirect("/login", notice="Vault session closed.")
    clear_session_cookie(response)
    return response


@app.get("/locked", response_class=HTMLResponse)
def locked_page(request: Request):
    user = getattr(request.state, "user", None)
    if user and user["role"] == "owner":
        raise RedirectTo("/")
    with connect() as conn:
        opened = vault_open(conn)
        windows = active_windows(conn) if (opened and user) else []
    return render(request, "locked.html", page_title="Vault closed", auth_page=True, vault_open=opened, live_windows=windows)


@app.post("/api/presence")
async def presence_heartbeat(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        return JSONResponse({"error": "not signed in"}, status_code=401)
    submitted = request.headers.get("x-csrf", "")
    if not csrf_ok(request, submitted):
        return JSONResponse({"error": "invalid token"}, status_code=403)
    if user["role"] != "owner":
        return JSONResponse({"vault_open": getattr(request.state, "vault_open", False)})
    with connect() as conn:
        extend_presence(conn, int(user["session_id"]))
        return {"vault_open": True, "grace": VAULT_GRACE_SECONDS}


@app.post("/api/presence/close")
async def presence_close(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        return Response(status_code=204)
    submitted = request.query_params.get("csrf", "")
    if not csrf_ok(request, submitted):
        return JSONResponse({"error": "invalid token"}, status_code=403)
    with connect() as conn:
        close_presence(conn, int(user["session_id"]))
    return Response(status_code=204)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_user(request)
    with connect() as conn:
        ids = _visible_project_ids(conn, user)
        if ids is not None and not ids:
            raise RedirectTo("/locked")
        projects = _latest_projects(conn, ids)
        if ids is None:
            totals = conn.execute(
                """
                SELECT count(*) AS projects, coalesce(sum(file_count), 0) AS files,
                       coalesce(sum(total_bytes), 0) AS bytes,
                       coalesce(avg(health_score), 0) AS health
                FROM projects
                """
            ).fetchone()
        else:
            placeholders = ",".join("?" for _ in ids)
            totals = conn.execute(
                f"""
                SELECT count(*) AS projects, coalesce(sum(file_count), 0) AS files,
                       coalesce(sum(total_bytes), 0) AS bytes,
                       coalesce(avg(health_score), 0) AS health
                FROM projects WHERE id IN ({placeholders})
                """,
                ids,
            ).fetchone()
        if ids is None:
            latest_audits = conn.execute(
                """
                SELECT a.*, p.name AS project_name, p.slug AS project_slug
                FROM audits a JOIN projects p ON p.id = a.project_id
                ORDER BY a.started_at DESC LIMIT 5
                """
            ).fetchall()
            events = conn.execute(
                """
                SELECT e.*, p.name AS project_name, u.name AS user_name
                FROM events e LEFT JOIN projects p ON p.id = e.project_id
                LEFT JOIN users u ON u.id = e.user_id
                ORDER BY e.created_at DESC LIMIT 9
                """
            ).fetchall()
            windows = active_windows(conn)
            users_count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
        else:
            placeholders = ",".join("?" for _ in ids)
            latest_audits = conn.execute(
                f"""
                SELECT a.*, p.name AS project_name, p.slug AS project_slug
                FROM audits a JOIN projects p ON p.id = a.project_id
                WHERE p.id IN ({placeholders})
                ORDER BY a.started_at DESC LIMIT 5
                """,
                ids,
            ).fetchall()
            events = conn.execute(
                f"""
                SELECT e.*, p.name AS project_name, u.name AS user_name
                FROM events e LEFT JOIN projects p ON p.id = e.project_id
                LEFT JOIN users u ON u.id = e.user_id
                WHERE e.project_id IN ({placeholders})
                ORDER BY e.created_at DESC LIMIT 9
                """,
                ids,
            ).fetchall()
            windows = active_windows(conn)
            users_count = None
    return render(
        request,
        "dashboard.html",
        page_title="Briefing",
        totals=totals,
        projects=projects,
        latest_audits=latest_audits,
        events=events,
        windows=windows,
        users_count=users_count,
        is_owner=user["role"] == "owner",
        can_manage=user["role"] in {"owner", "full_access"},
    )


@app.get("/projects", response_class=HTMLResponse)
def projects_page(request: Request):
    user = require_user(request)
    query = request.query_params.get("q", "").strip()
    with connect() as conn:
        ids = _visible_project_ids(conn, user)
        if ids is not None and not ids:
            raise RedirectTo("/locked")
        projects = _latest_projects(conn, ids, query)
    return render(
        request,
        "projects.html",
        page_title="Projects",
        projects=projects,
        query=query,
        is_owner=user["role"] == "owner",
        can_manage=user["role"] in {"owner", "full_access"},
    )


@app.get("/projects/new", response_class=HTMLResponse)
def project_new_page(request: Request):
    require_owner(request)
    return render(request, "project_new.html", page_title="Add project", is_owner=True, allowed_types=["website", "app", "docs", "archive", "other"])


@app.post("/projects/new")
async def project_new_submit(request: Request):
    user = require_owner(request)
    form = await _require_form(request)
    name = _form_string(form, "name")
    raw_path = _form_string(form, "root_path")
    description = _form_string(form, "description")
    project_type = _form_string(form, "project_type", "website")
    if project_type not in {"website", "app", "docs", "archive", "other"}:
        project_type = "website"
    root = Path()
    error = ""
    if raw_path:
        try:
            root = Path(raw_path).expanduser().resolve()
        except (OSError, RuntimeError):
            error = "That folder path could not be resolved."
    if not raw_path:
        error = "Enter a folder path."
    elif error:
        pass
    elif not root.exists() or not root.is_dir():
        error = "That path does not exist or is not a folder."
    elif root == root.parent:
        error = "A filesystem root cannot be indexed. Choose a project folder."
    elif root == Path.home():
        error = "Choose a project folder inside your home directory, not the entire home directory."
    elif root == DATA_DIR or DATA_DIR in root.parents or root in DATA_DIR.parents:
        error = "The vault data directory cannot be indexed or used as a project parent."
    if not name:
        name = root.name or "Untitled project"
    if error:
        return render(
            request,
            "project_new.html",
            page_title="Add project",
            is_owner=True,
            allowed_types=["website", "app", "docs", "archive", "other"],
            error=error,
            name=name,
            root_path=raw_path,
            description=description,
            project_type=project_type,
        )
    with connect() as conn:
        existing = conn.execute("SELECT id FROM projects WHERE root_path = ?", (str(root),)).fetchone()
        if existing:
            return _redirect(f"/projects/{existing['id']}", error="That folder is already registered.")
        base_slug = slugify(name, root.name or "project")
        slug = base_slug
        counter = 2
        while conn.execute("SELECT 1 FROM projects WHERE slug = ?", (slug,)).fetchone():
            slug = f"{base_slug}-{counter}"
            counter += 1
        now = iso()
        cursor = conn.execute(
            """
            INSERT INTO projects (name, slug, root_path, description, project_type, status,
                                  cover_color, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'indexing', ?, ?, ?)
            """,
            (name[:120], slug, str(root), description[:800], project_type, "green", now, now),
        )
        project_id = int(cursor.lastrowid)
        log_event(conn, "project", f"Project added: {name}", str(root), project_id=project_id, user_id=user["id"])
        try:
            stats = index_project(conn, _project_by_id(conn, project_id))
            log_event(conn, "index", f"Indexed {name}", f"{stats['files']} files · {human_bytes(stats['bytes'])}", project_id=project_id, user_id=user["id"])
        except Exception as exc:
            conn.execute("UPDATE projects SET status = 'error', updated_at = ? WHERE id = ?", (iso(), project_id))
            log_event(conn, "index", f"Index failed: {name}", str(exc)[:500], project_id=project_id, user_id=user["id"])
            return _redirect(f"/projects/{project_id}", error=f"Project added, but indexing failed: {exc}")
    return _redirect(f"/projects/{project_id}", notice=f"{name} indexed. Baseline audit is ready to run.")


@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(request: Request, project_id: int):
    user = require_user(request)
    with connect() as conn:
        project = _project_by_id(conn, project_id)
        if not project:
            raise RedirectTo("/projects", error="Project not found.")
        _assert_project_access(conn, user, project)
        q = request.query_params.get("q", "").strip()
        kind = request.query_params.get("kind", "").strip()
        params: list[Any] = [project_id]
        clauses = ["project_id = ?"]
        if q:
            clauses.append("(path LIKE ? OR title LIKE ? OR summary LIKE ?)")
            like = f"%{q}%"
            params.extend([like, like, like])
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        files = conn.execute(
            f"SELECT * FROM files WHERE {' AND '.join(clauses)} ORDER BY path LIMIT 260",
            params,
        ).fetchall()
        kinds = conn.execute(
            "SELECT kind, count(*) AS n FROM files WHERE project_id = ? GROUP BY kind ORDER BY n DESC",
            (project_id,),
        ).fetchall()
        audits = conn.execute(
            "SELECT * FROM audits WHERE project_id = ? ORDER BY started_at DESC LIMIT 12",
            (project_id,),
        ).fetchall()
        latest = audits[0] if audits else None
        findings = conn.execute(
            "SELECT * FROM findings WHERE project_id = ? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id ASC LIMIT 6",
            (project_id,),
        ).fetchall()
        counts = severity_counts(conn, int(latest["id"])) if latest else {}
        windows = active_windows(conn, project_id) if user["role"] == "owner" else []
        selected_file = None
        selected_id = safe_int(request.query_params.get("file"), 0)
        if selected_id:
            selected_file = conn.execute("SELECT * FROM files WHERE id = ? AND project_id = ?", (selected_id, project_id)).fetchone()
        links = conn.execute(
            "SELECT status, count(*) AS n FROM file_links WHERE project_id = ? GROUP BY status",
            (project_id,),
        ).fetchall()
        link_stats = {row["status"]: row["n"] for row in links}
    return render(
        request,
        "project.html",
        page_title=project["name"],
        project=project,
        files=files,
        kinds=kinds,
        audits=audits,
        latest_audit=latest,
        findings=findings,
        severity_counts=counts,
        windows=windows,
        selected_file=selected_file,
        query=q,
        kind=kind,
        link_stats=link_stats,
        is_owner=user["role"] == "owner",
        can_manage=user["role"] in {"owner", "full_access"},
    )


@app.post("/projects/{project_id}/index")
async def project_index_submit(request: Request, project_id: int):
    user = require_editor(request)
    await _require_form(request)
    with connect() as conn:
        project = _project_by_id(conn, project_id)
        if not project:
            raise RedirectTo("/projects", error="Project not found.")
        try:
            stats = index_project(conn, project)
            log_event(conn, "index", f"Re-indexed {project['name']}", f"{stats['files']} files · {human_bytes(stats['bytes'])}", project_id=project_id, user_id=user["id"])
            return _redirect(f"/projects/{project_id}", notice=f"Index refreshed: {stats['files']} files, {human_bytes(stats['bytes'])}.")
        except Exception as exc:
            conn.execute("UPDATE projects SET status = 'error', updated_at = ? WHERE id = ?", (iso(), project_id))
            log_event(conn, "index", f"Re-index failed: {project['name']}", str(exc)[:500], project_id=project_id, user_id=user["id"])
            return _redirect(f"/projects/{project_id}", error=f"Index failed: {exc}")


@app.post("/projects/{project_id}/audit")
async def project_audit_submit(request: Request, project_id: int):
    user = require_editor(request)
    await _require_form(request)
    with connect() as conn:
        project = _project_by_id(conn, project_id)
        if not project:
            raise RedirectTo("/projects", error="Project not found.")
        try:
            audit_id, score, verdict, count = run_baseline_audit(conn, project, int(user["id"]))
            return _redirect(f"/audits/{audit_id}", notice=f"Baseline complete: {score}/100 · {_verdict_label(verdict)} · {count} findings.")
        except Exception as exc:
            return _redirect(f"/projects/{project_id}", error=f"Audit failed: {exc}")


@app.post("/projects/{project_id}/session")
async def project_session_start(request: Request, project_id: int):
    user = require_owner(request)
    form = await _require_form(request)
    with connect() as conn:
        project = _project_by_id(conn, project_id)
        if not project:
            raise RedirectTo("/projects", error="Project not found.")
        hours = duration_from_hours(_form_string(form, "hours", "2"))
        title = _form_string(form, "title") or f"Live review · {project['name']}"
        expires = utcnow() + hours
        conn.execute(
            """
            INSERT INTO access_windows (project_id, title, created_by, created_at, expires_at, status)
            VALUES (?, ?, ?, ?, ?, 'live')
            """,
            (project_id, title[:140], user["id"], iso(), iso(expires)),
        )
        log_event(conn, "access", f"Live session opened: {project['name']}", f"{title} · until {expires.strftime('%H:%M UTC')}", project_id=project_id, user_id=user["id"])
    return _redirect(f"/projects/{project_id}", notice="Live session opened. Reviewer access is now task-gated to this project.")


@app.post("/projects/{project_id}/session/end")
async def project_session_end(request: Request, project_id: int):
    user = require_owner(request)
    form = await _require_form(request)
    window_id = safe_int(_form_string(form, "window_id"), 0)
    with connect() as conn:
        project = _project_by_id(conn, project_id)
        if not project:
            raise RedirectTo("/projects", error="Project not found.")
        if window_id:
            conn.execute(
                "UPDATE access_windows SET status = 'ended', ended_at = ? WHERE id = ? AND project_id = ?",
                (iso(), window_id, project_id),
            )
        else:
            conn.execute(
                "UPDATE access_windows SET status = 'ended', ended_at = ? WHERE project_id = ? AND status = 'live' AND ended_at IS NULL",
                (iso(), project_id),
            )
        log_event(conn, "access", f"Live session closed: {project['name']}", "", project_id=project_id, user_id=user["id"])
    return _redirect(f"/projects/{project_id}", notice="Live session closed. Reviewer access to this project has ended.")


@app.post("/projects/{project_id}/delete")
async def project_delete(request: Request, project_id: int):
    user = require_owner(request)
    form = await _require_form(request)
    with connect() as conn:
        project = _project_by_id(conn, project_id)
        if not project:
            raise RedirectTo("/projects", error="Project not found.")
        if _form_string(form, "confirm") != project["name"]:
            return _redirect(f"/projects/{project_id}", error="Type the project name exactly to remove it.")
        conn.execute(
            "DELETE FROM file_fts WHERE rowid IN (SELECT id FROM files WHERE project_id = ?)",
            (project_id,),
        )
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        log_event(conn, "project", f"Project removed: {project['name']}", str(project["root_path"]), user_id=user["id"])
    return _redirect("/projects", notice="Project removed from the vault. Files on disk were not touched.")


@app.get("/files/{file_id}", response_class=HTMLResponse)
def file_detail(request: Request, file_id: int):
    user = require_user(request)
    with connect() as conn:
        row = conn.execute(
            "SELECT f.*, p.name AS project_name, p.slug AS project_slug FROM files f JOIN projects p ON p.id = f.project_id WHERE f.id = ?",
            (file_id,),
        ).fetchone()
        if not row:
            raise RedirectTo("/projects", error="File not found.")
        project = _project_by_id(conn, int(row["project_id"]))
        _assert_project_access(conn, user, project)
        links = conn.execute("SELECT * FROM file_links WHERE file_id = ? ORDER BY status, href", (file_id,)).fetchall()
        backlinks = conn.execute(
            "SELECT l.*, f.path AS source_path FROM file_links l JOIN files f ON f.id = l.file_id WHERE l.target_path = ? AND l.project_id = ? LIMIT 30",
            (row["path"], row["project_id"]),
        ).fetchall()
    return render(
        request,
        "file.html",
        page_title=row["name"],
        file=row,
        project=project,
        links=links,
        backlinks=backlinks,
    )


@app.get("/audits", response_class=HTMLResponse)
def audits_page(request: Request):
    user = require_user(request)
    with connect() as conn:
        ids = _visible_project_ids(conn, user)
        if ids is not None and not ids:
            raise RedirectTo("/locked")
        if ids is None:
            audits = conn.execute(
                """
                SELECT a.*, p.name AS project_name, p.slug AS project_slug, p.root_path,
                       (SELECT count(*) FROM findings f WHERE f.audit_id = a.id) AS finding_count
                FROM audits a JOIN projects p ON p.id = a.project_id
                ORDER BY a.started_at DESC LIMIT 100
                """
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in ids)
            audits = conn.execute(
                f"""
                SELECT a.*, p.name AS project_name, p.slug AS project_slug, p.root_path,
                       (SELECT count(*) FROM findings f WHERE f.audit_id = a.id) AS finding_count
                FROM audits a JOIN projects p ON p.id = a.project_id
                WHERE p.id IN ({placeholders})
                ORDER BY a.started_at DESC LIMIT 100
                """,
                ids,
            ).fetchall()
    return render(request, "audits.html", page_title="Audits", audits=audits, can_manage=user["role"] in {"owner", "full_access"})


@app.get("/audits/{audit_id}", response_class=HTMLResponse)
def audit_detail(request: Request, audit_id: int):
    user = require_user(request)
    severity = request.query_params.get("severity", "").strip()
    status = request.query_params.get("status", "").strip()
    with connect() as conn:
        audit = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
        if not audit:
            raise RedirectTo("/audits", error="Audit not found.")
        project = _project_by_id(conn, int(audit["project_id"]))
        _assert_project_access(conn, user, project)
        clauses = ["audit_id = ?"]
        params: list[Any] = [audit_id]
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)
        findings = conn.execute(
            f"""
            SELECT * FROM findings WHERE {' AND '.join(clauses)}
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                     category, title
            """,
            params,
        ).fetchall()
        counts = severity_counts(conn, audit_id)
        total = conn.execute("SELECT count(*) AS n FROM findings WHERE audit_id = ?", (audit_id,)).fetchone()["n"]
        open_count = conn.execute("SELECT count(*) AS n FROM findings WHERE audit_id = ? AND status = 'open'", (audit_id,)).fetchone()["n"]
    return render(
        request,
        "audit_detail.html",
        page_title=f"Audit #{audit_id}",
        audit=audit,
        project=project,
        findings=findings,
        counts=counts,
        total_findings=total,
        open_count=open_count,
        severity=severity,
        status=status,
        can_manage=user["role"] in {"owner", "full_access"},
    )


@app.post("/findings/{finding_id}/status")
async def finding_status(request: Request, finding_id: int):
    user = require_editor(request)
    form = await _require_form(request)
    new_status = _form_string(form, "status", "open")
    if new_status not in {"open", "resolved", "dismissed"}:
        new_status = "open"
    with connect() as conn:
        finding = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not finding:
            raise RedirectTo("/audits", error="Finding not found.")
        project = _project_by_id(conn, int(finding["project_id"]))
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (new_status, finding_id))
        log_event(conn, "finding", f"Finding marked {new_status}", finding["title"], project_id=int(finding["project_id"]), user_id=user["id"])
        return _redirect(f"/audits/{finding['audit_id']}#finding-{finding_id}", notice=f"Finding marked {new_status}.")


@app.get("/agents", response_class=HTMLResponse)
def agents_page(request: Request):
    user = require_user(request)
    with connect() as conn:
        agents = list_agents(conn, user)
        providers = list_providers(conn, user)
        provider_count = len(providers)
    return render(
        request,
        "agents.html",
        page_title="Agents & providers",
        agents=agents,
        providers=providers,
        provider_count=provider_count,
        can_manage=user["role"] in {"owner", "full_access"},
        is_owner=user["role"] == "owner",
    )


@app.post("/agents/new")
async def agent_new(request: Request):
    user = require_editor(request)
    form = await _require_form(request)
    name = _form_string(form, "name")
    description = _form_string(form, "description")
    model = _form_string(form, "model", DEFAULT_MODEL) or DEFAULT_MODEL
    prompt = _form_string(form, "system_prompt")
    scope = _form_string(form, "scope", "personal")
    if not name:
        return _redirect("/agents", error="Give the agent a name.")
    if user["role"] != "owner":
        scope = "personal"
    if scope not in {"personal", "workspace"}:
        scope = "personal"
    with connect() as conn:
        base = slugify(name, "agent")
        slug = base
        counter = 2
        while conn.execute("SELECT 1 FROM agents WHERE slug = ?", (slug,)).fetchone():
            slug = f"{base}-{counter}"
            counter += 1
        permissions = json.dumps([
            {"action": "read", "resource": "*", "effect": "allow"},
            {"action": "edit", "resource": "*", "effect": "deny"},
            {"action": "shell", "resource": "*", "effect": "deny"},
        ])
        conn.execute(
            """
            INSERT INTO agents
                (slug, name, description, model, mode, scope, owner_user_id, is_builtin,
                 enabled, permissions_json, system_prompt, created_at)
            VALUES (?, ?, ?, ?, 'subagent', ?, ?, 0, 1, ?, ?, ?)
            """,
            (slug, name[:100], description[:400], model[:180], scope, user["id"], permissions, prompt[:8000], iso()),
        )
        log_event(conn, "agent", f"Custom agent registered: {name}", f"{scope} · {model}", user_id=user["id"])
    return _redirect("/agents", notice=f"{name} registered. Runtime execution is the next integration layer.")


@app.post("/providers/new")
async def provider_new(request: Request):
    user = require_editor(request)
    form = await _require_form(request)
    name = _form_string(form, "name")
    provider_id = slugify(_form_string(form, "provider_id", "custom"), "custom")
    base_url = _form_string(form, "base_url")
    model = _form_string(form, "default_model")
    api_key = _form_raw(form, "api_key").strip()
    scope = _form_string(form, "scope", "personal")
    budget_raw = _form_string(form, "budget_usd")
    if user["role"] != "owner":
        scope = "personal"
    if scope not in {"personal", "workspace"}:
        scope = "personal"
    if not name or not base_url or not model:
        return _redirect("/agents", error="Provider name, base URL, and model are required.")
    parsed_url = urlsplit(base_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc or not parsed_url.hostname:
        return _redirect("/agents", error="Provider base URL must be a valid http:// or https:// URL.")
    if parsed_url.scheme == "http" and parsed_url.hostname.lower() not in {"127.0.0.1", "localhost", "::1"}:
        return _redirect("/agents", error="Use HTTPS for remote providers. Plain HTTP is only allowed for localhost.")
    budget = None
    if budget_raw:
        try:
            budget = float(budget_raw)
        except ValueError:
            return _redirect("/agents", error="Budget must be a number.")
        if budget < 0 or budget > 1_000_000:
            return _redirect("/agents", error="Budget must be between 0 and 1,000,000 USD.")
    with connect() as conn:
        if conn.execute("SELECT 1 FROM providers WHERE name = ?", (name,)).fetchone():
            return _redirect("/agents", error="A provider with that name already exists.")
        owner_id = user["id"] if scope == "personal" else None
        try:
            add_provider(
                conn,
                name=name[:100],
                provider_id=provider_id,
                base_url=base_url[:500],
                default_model=model[:180],
                scope=scope,
                owner_user_id=owner_id,
                api_key=api_key or None,
                budget_usd=budget,
            )
            log_event(conn, "provider", f"Provider registered: {name}", f"{scope} · {provider_id}", user_id=user["id"])
        except Exception as exc:
            return _redirect("/agents", error=f"Could not register provider: {exc}")
    return _redirect("/agents", notice=f"{name} registered. Credentials are sealed in the local vault.")


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    user = require_user(request)
    with connect() as conn:
        pending = get_pending_secret(conn, int(user["id"]))
    return render(
        request,
        "account.html",
        page_title="Account security",
        totp_enabled=bool(user["totp_enabled"]),
        pending_secret=pending or "",
        totp_uri=provisioning_uri(pending, user["email"]) if pending else "",
    )


@app.post("/account/totp/start")
async def account_totp_start(request: Request):
    user = require_user(request)
    form = await _require_form(request)
    password = _form_raw(form, "password")
    if user["totp_enabled"]:
        return _redirect("/account", error="Authenticator protection is already enabled. Disable it before enrolling a new device.")
    if not verify_password(password, user["password_hash"]):
        return _redirect("/account", error="Current password is incorrect.")
    secret = generate_secret()
    with connect() as conn:
        set_pending_secret(conn, int(user["id"]), secret)
        log_event(conn, "auth", "Authenticator enrollment started", "Pending TOTP confirmation", user_id=int(user["id"]))
    return _redirect("/account", notice="Authenticator secret created. Add it to your app, then confirm a 6-digit code.")


@app.post("/account/totp/enable")
async def account_totp_enable(request: Request):
    user = require_user(request)
    form = await _require_form(request)
    code = _form_string(form, "code")
    with connect() as conn:
        pending = get_pending_secret(conn, int(user["id"]))
        if not pending:
            return _redirect("/account", error="The enrollment window expired. Start again.")
        if not verify_code(pending, code):
            return _redirect("/account", error="That code did not match. Check the time on your device and try the current code.")
        enable_totp(conn, int(user["id"]), pending)
        log_event(conn, "auth", "Authenticator enabled", "TOTP is now required at sign-in", user_id=int(user["id"]))
    return _redirect("/account", notice="Authenticator protection is enabled. Use it on your next sign-in.")


@app.post("/account/totp/disable")
async def account_totp_disable(request: Request):
    user = require_user(request)
    form = await _require_form(request)
    password = _form_raw(form, "password")
    code = _form_string(form, "totp")
    if not user["totp_enabled"]:
        return _redirect("/account", error="Authenticator protection is not enabled.")
    if not _step_up_ok(user, password, code):
        return _redirect("/account", error="Password or authenticator code is incorrect. Nothing was changed.")
    with connect() as conn:
        disable_totp(conn, int(user["id"]))
        log_event(conn, "auth", "Authenticator disabled", "TOTP was removed after password and code confirmation", user_id=int(user["id"]))
    return _redirect("/account", notice="Authenticator protection is off.")


@app.get("/activity", response_class=HTMLResponse)
def activity_page(request: Request):
    user = require_user(request)
    with connect() as conn:
        ids = _visible_project_ids(conn, user)
        if ids is not None and not ids:
            raise RedirectTo("/locked")
        if ids is None:
            events = conn.execute(
                """
                SELECT e.*, p.name AS project_name, u.name AS user_name
                FROM events e LEFT JOIN projects p ON p.id = e.project_id
                LEFT JOIN users u ON u.id = e.user_id
                ORDER BY e.created_at DESC LIMIT 250
                """
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in ids)
            events = conn.execute(
                f"""
                SELECT e.*, p.name AS project_name, u.name AS user_name
                FROM events e LEFT JOIN projects p ON p.id = e.project_id
                LEFT JOIN users u ON u.id = e.user_id
                WHERE e.project_id IN ({placeholders})
                ORDER BY e.created_at DESC LIMIT 250
                """,
                ids,
            ).fetchall()
    return render(request, "activity.html", page_title="Activity", events=events)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    user = require_owner(request)
    invite_token = request.query_params.get("invite", "").strip()
    with connect() as conn:
        users = conn.execute("SELECT * FROM users ORDER BY role = 'owner' DESC, created_at").fetchall()
        invites = conn.execute(
            """
            SELECT i.*, u.name AS creator_name FROM invites i
            LEFT JOIN users u ON u.id = i.created_by
            WHERE i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > ?
            ORDER BY i.created_at DESC
            """,
            (iso(),),
        ).fetchall()
        windows = active_windows(conn)
        stats = conn.execute(
            """
            SELECT (SELECT count(*) FROM projects) AS projects,
                   (SELECT count(*) FROM files) AS files,
                   (SELECT count(*) FROM audits) AS audits,
                   (SELECT count(*) FROM findings WHERE status = 'open') AS findings,
                   (SELECT count(*) FROM providers) AS providers
            """
        ).fetchone()
        events = conn.execute(
            """
            SELECT e.*, u.name AS user_name FROM events e
            LEFT JOIN users u ON u.id = e.user_id
            ORDER BY e.created_at DESC LIMIT 12
            """
        ).fetchall()
    invite_link = _absolute_url(request, f"/invite/{invite_token}") if invite_token else ""
    return render(
        request,
        "settings.html",
        page_title="Settings",
        users=users,
        invites=invites,
        windows=windows,
        stats=stats,
        events=events,
        invite_link=invite_link,
        max_users=MAX_USERS,
        database_path=str(DB_PATH),
        secure_cookies=SECURE_COOKIES,
        is_owner=True,
    )


@app.post("/settings/invite")
async def settings_invite(request: Request):
    user = require_owner(request)
    form = await _require_form(request)
    email = _form_string(form, "email").lower()
    role = _form_string(form, "role", "reviewer")
    if role not in {"reviewer", "full_access"}:
        role = "reviewer"
    if not _valid_email(email):
        return _redirect("/settings", error="Enter a valid email address for the collaborator.")
    if role == "full_access" and not _step_up_ok(user, _form_raw(form, "password"), _form_string(form, "totp")):
        return _redirect("/settings", error="Granting full access requires owner step-up: current password and authenticator code when enabled.")
    with connect() as conn:
        count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
        if count >= MAX_USERS:
            return _redirect("/settings", error="This vault already has its two people. Remove a collaborator before inviting another.")
        if role == "reviewer" and not active_windows(conn):
            return _redirect("/settings", error="A reviewer invite needs a live task session. Open one from a project first.")
        pending = conn.execute(
            "SELECT count(*) AS n FROM invites WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > ?",
            (iso(),),
        ).fetchone()["n"]
        if count + pending >= MAX_USERS:
            return _redirect("/settings", error="There is already a pending invite for the second seat. Revoke it first.")
        token = create_invite(conn, email, role, int(user["id"]))
        log_event(conn, "access", f"Invite created for {email}", f"Role: {role}", user_id=user["id"])
    return _redirect(f"/settings?invite={token}", notice="Invite created. Copy the one-time link now; it is shown only in this view.")


@app.post("/settings/invites/{invite_id}/revoke")
async def settings_invite_revoke(request: Request, invite_id: int):
    user = require_owner(request)
    await _require_form(request)
    with connect() as conn:
        invite = conn.execute("SELECT * FROM invites WHERE id = ?", (invite_id,)).fetchone()
        if not invite:
            raise RedirectTo("/settings", error="Invite not found.")
        conn.execute("UPDATE invites SET revoked_at = ? WHERE id = ?", (iso(), invite_id))
        log_event(conn, "access", f"Invite revoked for {invite['email']}", user_id=user["id"])
    return _redirect("/settings", notice="Invite revoked.")


@app.post("/settings/users/{user_id}/role")
async def settings_user_role(request: Request, user_id: int):
    user = require_owner(request)
    form = await _require_form(request)
    new_role = _form_string(form, "role", "reviewer")
    password = _form_raw(form, "password")
    code = _form_string(form, "totp")
    if new_role not in {"reviewer", "full_access"}:
        return _redirect("/settings", error="Unknown role.")
    if not _step_up_ok(user, password, code):
        return _redirect("/settings", error="Step-up confirmation failed. Re-enter the owner password and authenticator code.")
    with connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target or target["role"] == "owner":
            return _redirect("/settings", error="The owner role cannot be changed here.")
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        log_event(conn, "access", f"Role changed for {target['name']}", f"{target['role']} → {new_role}", user_id=user["id"])
    return _redirect("/settings", notice="Collaborator role updated after step-up confirmation.")


@app.post("/settings/users/{user_id}/revoke")
async def settings_user_revoke(request: Request, user_id: int):
    user = require_owner(request)
    await _require_form(request)
    with connect() as conn:
        target = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not target:
            raise RedirectTo("/settings", error="User not found.")
        if target["role"] == "owner":
            return _redirect("/settings", error="The owner account cannot be removed.")
        conn.execute("DELETE FROM agents WHERE owner_user_id = ? AND scope = 'personal'", (user_id,))
        conn.execute("DELETE FROM providers WHERE owner_user_id = ? AND scope = 'personal'", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.execute("UPDATE invites SET revoked_at = ? WHERE role IN ('reviewer', 'full_access') AND used_at IS NULL AND revoked_at IS NULL", (iso(),))
        log_event(conn, "access", f"Collaborator removed: {target['name']}", target["email"], user_id=user["id"])
    return _redirect("/settings", notice="Collaborator removed and their sessions were revoked.")


@app.post("/settings/windows/{window_id}/end")
async def settings_window_end(request: Request, window_id: int):
    user = require_owner(request)
    await _require_form(request)
    with connect() as conn:
        row = conn.execute("SELECT * FROM access_windows WHERE id = ?", (window_id,)).fetchone()
        if not row:
            raise RedirectTo("/settings", error="Session not found.")
        conn.execute("UPDATE access_windows SET status = 'ended', ended_at = ? WHERE id = ?", (iso(), window_id))
        log_event(conn, "access", "Live session ended", f"Window #{window_id}", project_id=int(row["project_id"]), user_id=user["id"])
    return _redirect("/settings", notice="Live session ended.")


@app.get("/invite/{token}", response_class=HTMLResponse)
def invite_page(request: Request, token: str):
    with connect() as conn:
        invite = find_invite(conn, token)
        opened = vault_open(conn)
        has_task = bool(active_windows(conn)) if invite else False
        users_count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
    if not invite:
        return render(request, "invite.html", page_title="Invite", auth_page=True, invalid=True, vault_open=opened)
    if users_count >= MAX_USERS:
        return render(request, "invite.html", page_title="Invite", auth_page=True, invalid=True, vault_open=opened, reason="The two seats in this vault are already filled.")
    if not opened:
        return render(request, "invite.html", page_title="Invite", auth_page=True, vault_closed=True, invite=invite, vault_open=False)
    if invite["role"] == "reviewer" and not has_task:
        return render(request, "invite.html", page_title="Invite", auth_page=True, no_task=True, invite=invite, vault_open=True)
    csrf = new_token(24)
    response = render(request, "invite.html", page_title="Accept invite", auth_page=True, invite=invite, invite_csrf=csrf, vault_open=opened)
    response.set_cookie("atl4s_invite_csrf", csrf, max_age=3600, httponly=True, samesite="lax", secure=SECURE_COOKIES, path="/")
    return response


@app.post("/invite/{token}")
async def invite_submit(request: Request, token: str):
    form = await request.form()
    cookie = request.cookies.get("atl4s_invite_csrf", "")
    submitted = _form_string(form, "csrf")
    if not cookie or not submitted or not secrets.compare_digest(cookie, submitted):
        return render(request, "invite.html", page_title="Invite", auth_page=True, invalid=True, error="The invite form expired. Reopen the invite link.")
    with connect() as conn:
        invite = find_invite(conn, token)
        opened = vault_open(conn)
        if not invite:
            return render(request, "invite.html", page_title="Invite", auth_page=True, invalid=True, error="This invite is no longer valid.")
        if not opened:
            return render(request, "invite.html", page_title="Invite", auth_page=True, vault_closed=True, invite=invite, error="The vault is closed.")
        if invite["role"] == "reviewer" and not active_windows(conn):
            return render(request, "invite.html", page_title="Invite", auth_page=True, no_task=True, invite=invite, error="The live session has ended.")
        count = conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"]
        if count >= MAX_USERS:
            return render(request, "invite.html", page_title="Invite", auth_page=True, invalid=True, error="This vault is full.")
        email = _form_string(form, "email").lower()
        name = _form_string(form, "name")
        password = _form_raw(form, "password")
        if email != invite["email"].lower():
            return render(request, "invite.html", page_title="Accept invite", auth_page=True, invite=invite, invite_csrf=cookie, error="Use the email address this invite was sent to.")
        if not name:
            return render(request, "invite.html", page_title="Accept invite", auth_page=True, invite=invite, invite_csrf=cookie, error="Enter your name.")
        if len(password) < 10:
            return render(request, "invite.html", page_title="Accept invite", auth_page=True, invite=invite, invite_csrf=cookie, error="Use at least 10 characters.")
        cursor = conn.execute(
            "INSERT INTO users (email, name, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (email, name[:90], hash_password(password), invite["role"], iso()),
        )
        user_id = int(cursor.lastrowid)
        consume_invite(conn, int(invite["id"]))
        session, _ = create_session(conn, user_id, request, presence=False)
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (iso(), user_id))
        log_event(conn, "auth", f"{name} joined the vault", f"Role: {invite['role']}", user_id=user_id)
        response = _redirect("/", notice=f"Welcome, {name}. Your access is tied to the owner presence lock and live session policy.")
        set_session_cookie(response, session)
        response.delete_cookie("atl4s_invite_csrf", path="/")
        return response


@app.get("/search", response_class=HTMLResponse)
def search_page(request: Request):
    user = require_user(request)
    query = request.query_params.get("q", "").strip()
    with connect() as conn:
        ids = _visible_project_ids(conn, user)
        if ids is not None and not ids:
            raise RedirectTo("/locked")
        results = search_files(conn, query, project_ids=ids) if query else []
    return render(request, "search.html", page_title="Search", query=query, results=results)


@app.get("/exports/files.csv")
def export_files(request: Request):
    user = require_user(request)
    with connect() as conn:
        ids = _visible_project_ids(conn, user)
        if ids is not None and not ids:
            raise RedirectTo("/locked")
        if ids is None:
            rows = conn.execute(
                """
                SELECT p.name AS project, f.path, f.kind, f.size, f.word_count, f.title
                FROM files f JOIN projects p ON p.id = f.project_id ORDER BY p.name, f.path
                """
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in ids)
            rows = conn.execute(
                f"""
                SELECT p.name AS project, f.path, f.kind, f.size, f.word_count, f.title
                FROM files f JOIN projects p ON p.id = f.project_id
                WHERE p.id IN ({placeholders}) ORDER BY p.name, f.path
                """,
                ids,
            ).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["project", "path", "kind", "size_bytes", "word_count", "title"])
    for row in rows:
        writer.writerow([row["project"], row["path"], row["kind"], row["size"], row["word_count"], row["title"] or ""])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="atl4s-files.csv"', "Cache-Control": "no-store"},
    )


@app.get("/exports/findings.csv")
def export_findings(request: Request):
    user = require_user(request)
    with connect() as conn:
        ids = _visible_project_ids(conn, user)
        if ids is not None and not ids:
            raise RedirectTo("/locked")
        if ids is None:
            rows = conn.execute(
                """
                SELECT p.name AS project, a.started_at, f.severity, f.category, f.title,
                       f.evidence_path, f.recommendation, f.status
                FROM findings f JOIN projects p ON p.id = f.project_id
                JOIN audits a ON a.id = f.audit_id ORDER BY a.started_at DESC, f.id
                """
            ).fetchall()
        else:
            placeholders = ",".join("?" for _ in ids)
            rows = conn.execute(
                f"""
                SELECT p.name AS project, a.started_at, f.severity, f.category, f.title,
                       f.evidence_path, f.recommendation, f.status
                FROM findings f JOIN projects p ON p.id = f.project_id
                JOIN audits a ON a.id = f.audit_id
                WHERE p.id IN ({placeholders}) ORDER BY a.started_at DESC, f.id
                """,
                ids,
            ).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["project", "audit_started", "severity", "category", "title", "evidence_path", "recommendation", "status"])
    for row in rows:
        writer.writerow([row["project"], row["started_at"], row["severity"], row["category"], row["title"], row["evidence_path"] or "", row["recommendation"], row["status"]])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="atl4s-findings.csv"', "Cache-Control": "no-store"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("atl4s.main:app", host="127.0.0.1", port=8000, reload=False)
