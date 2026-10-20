from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from atl4s.db import connect
from atl4s.indexing import resolve_link, sanitize_fts_query
from atl4s.main import app
from atl4s.security import hash_password, verify_password
from atl4s.totp import code_at, generate_secret, get_pending_secret, verify_code
from atl4s.util import iso, slugify, utcnow


def _hidden(html: str, name: str) -> str:
    match = re.search(rf'name="{re.escape(name)}" value="([^"]+)"', html)
    assert match, f"missing hidden field {name}"
    return match.group(1)


def _csrf(html: str) -> str:
    match = re.search(r'name="csrf-token" content="([^"]+)"', html)
    assert match, "missing csrf meta token"
    return match.group(1)


def _sample_site(root):
    root.mkdir()
    (root / "README.md").write_text(
        "# Sample Site\n\nA small sample website used to exercise the ATL4S baseline index and audit flow.",
        encoding="utf-8",
    )
    (root / "index.html").write_text(
        "<!doctype html><html><head><title>Sample Site</title>"
        '<meta name="description" content="A sample site for the vault."></head>'
        '<body><h1>Hello vault</h1><p>Read the <a href="about.html">about page</a> or '
        '<a href="missing.html">missing page</a>.</p></body></html>',
        encoding="utf-8",
    )
    (root / "about.html").write_text(
        "<!doctype html><html><head></head><body><p>About this sample.</p>"
        '<a href="/index.html">Home</a></body></html>',
        encoding="utf-8",
    )
    (root / "style.css").write_text("body { color: #111; }\n", encoding="utf-8")
    (root / "docs").mkdir()
    return root


def test_password_round_trip():
    encoded = hash_password("a-long-test-password")
    assert encoded.startswith("scrypt$")
    assert verify_password("a-long-test-password", encoded)
    assert not verify_password("wrong-password", encoded)


def test_slugify_and_fts_sanitizer():
    assert slugify("Hello, World!") == "hello-world"
    assert slugify("   ", "fallback") == "fallback"
    assert sanitize_fts_query("hello world") == '"hello"* AND "world"*'
    assert sanitize_fts_query('   ') == ""


def test_totp_rfc6238_vector():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert code_at(secret, 59) == "287082"
    assert verify_code(secret, "287082", at=59)
    assert not verify_code(secret, "287083", at=59)
    assert len(generate_secret()) == 32


def test_root_relative_links_stay_inside_project(tmp_path):
    root = tmp_path / "site"
    root.mkdir()
    index = root / "index.html"
    index.write_text("<title>Home</title>", encoding="utf-8")
    (root / "about.html").write_text("<title>About</title>", encoding="utf-8")
    (root / "docs").mkdir()

    assert resolve_link(root / "about.html", root, "/index.html")[:2] == ("ok", "index.html")
    assert resolve_link(root / "about.html", root, "/docs/")[:2] == ("ok", "docs")
    assert resolve_link(root / "about.html", root, "missing.html")[0] == "broken"
    assert resolve_link(root / "about.html", root, "https://example.com/x")[0] == "external"


def test_complete_vertical_slice(tmp_path):
    site = _sample_site(tmp_path / "sample-site")

    with TestClient(app) as client:
        response = client.get("/setup")
        assert response.status_code == 200
        setup_token = _hidden(response.text, "csrf")
        response = client.post(
            "/setup",
            data={
                "csrf": setup_token,
                "name": "Test Owner",
                "email": "owner@example.test",
                "password": "owner-password-123",
                "confirm": "owner-password-123",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert "Presence lock" in response.text
        token = _csrf(response.text)

        with TestClient(app) as guest:
            response = guest.get("/setup", follow_redirects=False)
            assert response.status_code == 303
            assert response.headers["location"] == "/login"
            response = guest.get("/login")
            assert response.status_code == 200
            assert _hidden(response.text, "csrf")
            response = guest.post(
                "/login",
                data={"csrf": "wrong", "email": "owner@example.test", "password": "owner-password-123"},
                follow_redirects=True,
            )
            assert response.status_code == 200
            assert "expired" in response.text.lower()

        response = client.get("/projects")
        assert response.status_code == 200
        assert "no projects yet" in response.text.lower()

        response = client.post(
            "/projects/new",
            data={
                "_csrf": token,
                "root_path": str(site),
                "name": "Sample Site",
                "description": "Test project",
                "project_type": "website",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"].startswith("/projects/")

        response = client.get("/projects/1")
        assert response.status_code == 200
        assert "File inventory" in response.text
        assert "index.html" in response.text
        assert "README.md" in response.text

        with connect() as conn:
            files = conn.execute("SELECT path, has_title, has_description FROM files ORDER BY path").fetchall()
            assert {row["path"] for row in files} == {"README.md", "about.html", "index.html", "style.css"}
            assert conn.execute("SELECT 1 FROM folders WHERE path = 'docs' AND is_empty = 1").fetchone()
            link_rows = {row["href"]: row for row in conn.execute("SELECT href, status, target_path FROM file_links")}
            assert link_rows["/index.html"]["status"] == "ok"
            assert link_rows["/index.html"]["target_path"] == "index.html"
            assert link_rows["missing.html"]["status"] == "broken"

        response = client.post("/projects/1/audit", data={"_csrf": token}, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/audits/")
        audit_id = int(re.search(r"/audits/(\d+)", response.headers["location"]).group(1))

        response = client.get(f"/audits/{audit_id}")
        assert response.status_code == 200
        assert "Broken local link" in response.text
        assert "Missing page title" in response.text
        assert "meta description" in response.text

        with connect() as conn:
            audit = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
            assert audit["status"] == "complete"
            assert audit["score"] is not None and 0 <= audit["score"] <= 100
            assert audit["verdict"] in {"healthy", "watch", "needs-work", "critical"}
            assert conn.execute(
                "SELECT 1 FROM findings WHERE audit_id = ? AND evidence_path = 'about.html'",
                (audit_id,),
            ).fetchone()
            # Checking a live link must not create a finding.
            assert not conn.execute(
                "SELECT 1 FROM findings WHERE audit_id = ? AND title LIKE '%/index.html%'",
                (audit_id,),
            ).fetchone()

        response = client.get("/search?q=Hello")
        assert response.status_code == 200
        assert "index.html" in response.text

        response = client.get("/files/1")
        assert response.status_code == 200
        assert "File record" in response.text

        response = client.get("/settings")
        assert response.status_code == 200
        assert "Vault seats" in response.text
        assert "Test Owner" in response.text

        response = client.post(
            "/account/totp/start",
            data={"_csrf": token, "password": "owner-password-123"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        with connect() as conn:
            owner_secret = get_pending_secret(conn, 1)
        assert owner_secret
        account_page = client.get("/account")
        assert owner_secret in account_page.text
        response = client.post(
            "/account/totp/enable",
            data={"_csrf": token, "code": code_at(owner_secret)},
            follow_redirects=False,
        )
        assert response.status_code == 303
        with connect() as conn:
            owner_row = conn.execute("SELECT totp_secret, totp_enabled FROM users WHERE id = 1").fetchone()
            assert owner_row["totp_enabled"] == 1
            assert owner_row["totp_secret"] != owner_secret

        response = client.post(
            "/agents/new",
            data={
                "_csrf": token,
                "name": "Owner Private Scout",
                "description": "Owner-only personal test agent.",
                "model": "opencode/deepseek-v4.1-flash-free#low",
                "scope": "personal",
                "system_prompt": "Read only.",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "Owner Private Scout" in client.get("/agents").text

        response = client.post(
            "/providers/new",
            data={
                "_csrf": token,
                "name": "Insecure gateway",
                "provider_id": "insecure",
                "base_url": "http://example.test/v1",
                "default_model": "test-model",
                "scope": "personal",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "HTTPS" in response.headers["location"]

        # Reviewer access requires a live window and an owner-present vault.
        response = client.post(
            "/projects/1/session",
            data={"_csrf": token, "hours": "2", "title": "Review pass"},
            follow_redirects=False,
        )
        assert response.status_code == 303

        rejected_invite = client.post(
            "/settings/invite",
            data={"_csrf": token, "email": "full@example.test", "role": "full_access"},
            follow_redirects=False,
        )
        assert rejected_invite.status_code == 303
        assert "step-up" in rejected_invite.headers["location"].lower()

        response = client.post(
            "/settings/invite",
            data={"_csrf": token, "email": "reviewer@example.test", "role": "reviewer"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        invite_url = response.headers["location"]
        invite_token = parse_qs(urlparse(invite_url).query)["invite"][0]

        with TestClient(app) as guest:
            locked = guest.get("/locked")
            assert locked.status_code == 200
            assert "Review pass" not in locked.text

        with TestClient(app) as reviewer:
            response = reviewer.get(f"/invite/{invite_token}")
            assert response.status_code == 200
            invite_csrf = _hidden(response.text, "csrf")
            response = reviewer.post(
                f"/invite/{invite_token}",
                data={
                    "csrf": invite_csrf,
                    "name": "Test Reviewer",
                    "email": "reviewer@example.test",
                    "password": "reviewer-password-123",
                },
                follow_redirects=False,
            )
            assert response.status_code == 303

            project_page = reviewer.get("/projects/1")
            assert project_page.status_code == 200
            reviewer_csrf = _csrf(project_page.text)
            assert reviewer.get("/audits").status_code == 200
            assert reviewer.get("/settings").status_code == 403
            assert reviewer.get("/projects/new").status_code == 403
            agent_page = reviewer.get("/agents")
            assert agent_page.status_code == 200
            assert "Owner Private Scout" not in agent_page.text

            rejected = client.post(
                "/settings/users/2/role",
                data={"_csrf": token, "role": "full_access", "password": "owner-password-123"},
                follow_redirects=False,
            )
            assert rejected.status_code == 303
            assert "step-up" in rejected.headers["location"].lower()
            elevated = client.post(
                "/settings/users/2/role",
                data={
                    "_csrf": token,
                    "role": "full_access",
                    "password": "owner-password-123",
                    "totp": code_at(owner_secret),
                },
                follow_redirects=False,
            )
            assert elevated.status_code == 303
            with connect() as conn:
                assert conn.execute("SELECT role FROM users WHERE id = 2").fetchone()["role"] == "full_access"
            restored = client.post(
                "/settings/users/2/role",
                data={
                    "_csrf": token,
                    "role": "reviewer",
                    "password": "owner-password-123",
                    "totp": code_at(owner_secret),
                },
                follow_redirects=False,
            )
            assert restored.status_code == 303
            with connect() as conn:
                assert conn.execute("SELECT role FROM users WHERE id = 2").fetchone()["role"] == "reviewer"

            with connect() as conn:
                conn.execute(
                    "UPDATE sessions SET presence_until = ? WHERE user_id = 1",
                    (iso(utcnow() - timedelta(minutes=5)),),
                )

            presence = reviewer.post("/api/presence", headers={"X-CSRF": reviewer_csrf})
            assert presence.status_code == 200
            assert presence.json()["vault_open"] is False
            response = reviewer.get("/projects/1", follow_redirects=False)
            assert response.status_code == 303
            assert response.headers["location"] == "/locked"
            assert reviewer.get("/", follow_redirects=False).headers["location"] == "/locked"

        with connect() as conn:
            assert conn.execute("SELECT count(*) AS n FROM users").fetchone()["n"] == 2
            assert conn.execute("SELECT count(*) AS n FROM access_windows WHERE status = 'live'").fetchone()["n"] == 1
            assert conn.execute("SELECT count(*) AS n FROM invites WHERE used_at IS NOT NULL").fetchone()["n"] == 1

        response = client.post("/logout", data={"_csrf": token}, follow_redirects=False)
        assert response.status_code == 303

        with TestClient(app) as owner_login:
            response = owner_login.get("/login")
            assert response.status_code == 200
            login_csrf = _hidden(response.text, "csrf")
            response = owner_login.post(
                "/login",
                data={"csrf": login_csrf, "email": "owner@example.test", "password": "owner-password-123"},
                follow_redirects=True,
            )
            assert response.status_code == 200
            assert "6-digit" in response.text
            response = owner_login.post(
                "/login",
                data={
                    "csrf": login_csrf,
                    "email": "owner@example.test",
                    "password": "owner-password-123",
                    "totp": code_at(owner_secret),
                },
                follow_redirects=False,
            )
            assert response.status_code == 303
            assert response.headers["location"].startswith("/")
            assert owner_login.get("/").status_code == 200
