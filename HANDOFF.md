# ATL4S::V4UlT — development handoff

This is the working handoff for the next developer.

## Current status

The repository contains a stable first vertical slice plus TOTP authentication:

- FastAPI + Jinja2 + SQLite/FTS5 backend.
- Owner setup, password login, TOTP enrollment/login, hashed sessions, CSRF.
- Owner presence lock and reviewer task windows.
- Invite-only second seat, reviewer and full-access roles, owner step-up.
- Read-only project registration and indexing.
- HTML/Markdown extraction, local link validation, duplicate/large-file checks.
- Deterministic baseline audits, findings ledger, scoring, and CSV exports.
- Agent/provider registry with encrypted provider credentials.
- Glass UI, dark/light/auto themes, local fonts, responsive layout.
- Integration suite: **5 passing tests**.

## Quick start

```bash
./run.sh
```

Windows PowerShell:

```powershell
.\run.ps1
```

Open `http://127.0.0.1:8000`. The first visit redirects to `/setup`.

Use a separate data directory during development if you do not want to touch real vault data:

```bash
ATL4S_DATA_DIR=/tmp/atl4s-dev ./run.sh
```

## Test command

```bash
.venv/bin/pytest -q
```

The suite creates its own temporary `ATL4S_DATA_DIR`. A Starlette/httpx deprecation warning is expected and harmless.

## Important paths

| Path | Purpose |
| --- | --- |
| `atl4s/main.py` | Routes, middleware, forms, view models |
| `atl4s/security.py` | Sessions, CSRF, presence, invites, windows |
| `atl4s/db.py` | Schema, seed data, event log, agent visibility |
| `atl4s/indexing.py` | Filesystem walker, parsers, links, FTS search |
| `atl4s/audits.py` | Deterministic checks and scoring |
| `atl4s/totp.py` | RFC 6238 codes and encrypted TOTP enrollment |
| `atl4s/vault.py` | Fernet encryption and provider credentials |
| `atl4s/templates/` | Jinja pages and shell |
| `atl4s/static/` | App CSS, JS, local fonts |
| `tests/test_core.py` | End-to-end and unit coverage |

Default runtime data lives outside the repository under `~/.local/share/atl4s-vault` on Linux or `%LOCALAPPDATA%\ATL4S-Vault` on Windows.

## Security invariants to preserve

1. Maximum two users: one owner and one collaborator.
2. Owner presence is required for collaborator access. A running Uvicorn process is not presence.
3. Reviewer access requires both owner presence and a live project window.
4. Reviewer pages must stay task-scoped. Do not give reviewers provider/agent management or filesystem-root controls.
5. Full-access elevation and full-access invites require owner password step-up, plus TOTP when enabled.
6. Never expose provider API keys or TOTP secrets to templates, logs, CSV, or the browser beyond the current user's enrollment view.
7. No agent writes, commits, pushes, deploys, or destructive filesystem actions.
8. Indexing is read-only. Symlinks are skipped.
9. All state-changing forms need CSRF protection.
10. `.env` is bootstrap-only. Never put provider keys there.

## What is intentionally unfinished

1. Owner-managed allowed-root policy and password rotation.
2. Model-assisted agent execution, verifier/judge passes, and per-folder routing UI.
3. Web Push/native notifications. The in-app event log is the current source of truth.
4. Continuous mode without owner presence.
5. Cloudflare Access-aware deployment checks. Current Cloudflare guidance is in `README.md`.
6. True OS-window transparency. The glass effect is browser-native.

## Suggested next slice

Start with the agent runtime, but keep deterministic findings authoritative:

1. Add a routing-rules page and storage editing for `routing_rules`.
2. Add provider/model client code with strict read-only tool boundaries.
3. Run specialist agents over the indexed project, attach their output to an audit as model findings, and mark provenance.
4. Add verifier and judge passes that consume existing findings rather than inventing new ones.
5. Keep all execution manual and owner-initiated until continuous mode is explicitly designed.

## Git handoff

```bash
git config user.name "Your Name"
git config user.email "you@example.com"
git remote add origin <your-remote>
git push -u origin main
```

Do not commit `.env`, database files, `vault.key`, `secret.key`, or the `.venv` directory. They are covered by `.gitignore`.
