# Project history: how the repo got to its current state

Last updated: 2026-10-30. Sources: git history of this repo, `docs/FINAL_SIMPLE_PLAN.md` (since removed; see `316e79b`),
and the code on both lines. **Facts** come from commits and files. **Inferences** are
marked as such; no document records the reasoning behind the decisions below.

## 1. What the project is

A KeePass-backed credential manager with two ways to reach it:

1. **Desktop GUI** (Tk / ttkbootstrap), shipped as a Windows exe.
2. **Network server**, so the vault can be reached from other devices over a private network.

Both use the same backend, `secure_credentials/src/keepass_backend.py` (`KeePassHandler`).

## 2. Timeline

| Date | Event | Branch |
|---|---|---|
| 2025-07-08 | Local repo starts: desktop GUI app, exe build (`5fc5299` "add version", `50b10b0` "dep update"). | `master` (local) |
| 2025-10-28 | GitHub repo `nydiokar/KeySafe` created. First push is a fresh root commit `fdbf2c4` "v1", a snapshot of the desktop app. The July history was not pushed. | `main` |
| 2025-10-28 | Same day on `main`: **Flask web app** (browser login, add/edit/delete/view, `HOST=0.0.0.0`), Linux support, CI (flake8, mypy, safety, bandit, codecov), pre-commit, Dependabot, docs (`docs/DEPLOYMENT.md` etc.). | `main` |
| 2025-12-07 | **FastAPI server** added (`316e79b` "add API layer and web UI"): read-only API plus single-page UI, bound to a Yggdrasil address. Plan in `FINAL_SIMPLE_PLAN.md` (added in `316e79b`, removed 2026-10-31 as obsolete). | `master` |
| 2025-12-08 | Backend security refactor (`62b7017`, `2a86ab0`): per-credential encryption, legacy plaintext handling removed, auto-lock. | `master` |
| 2025-12-08 | Last `main` commit: Dependabot PR #1 merged. | `main` |
| 2026-01-24 | Last `master` commit before today: custom vault paths via CLI / `VAULT_PATH`. | `master` |
| 2026-03 | Last Dependabot run on `main`; no runs after that. | `main` |
| 2026-10-30 | Dependency upgrade, CI, Dependabot config, tag-based release (`b4742c6`), release `v1.2.0`. Histories merged (`c10737b`). `main` fast-forwarded to `master`. | both |

## 3. How the two lines diverged

**Fact:** `master` and `main` had no common ancestor. `master` begins at root commit `5fc5299`;
`main` begins at root commit `fdbf2c4`. GitHub's "7 ahead / 27 behind" comparison was
counting two disjoint histories.

**Inference:** the GitHub repo was created on 2025-10-28 from a snapshot of the local project
rather than by pushing the local repo, so history was never shared. Work then continued in
two places: the Flask web app on `main`, and (in December) the FastAPI server on the local
`master` line, which does not contain the Flask code.

**Consequences:**
- Dependabot and CI were configured on `main`, which held the older code. The newer FastAPI
  work on `master` got no dependency updates, and Dependabot on `main` stopped after March 2026.
- The newest code (FastAPI, encryption refactor) was not on the repo's default branch.

## 4. Flask vs FastAPI: what each was

| | Flask (`main`, 2025-10-28) | FastAPI (`master`, 2025-12-07) |
|---|---|---|
| Purpose | Full credential manager in the browser | Read/retrieve from a phone or another device over a private network |
| Operations | Add, edit, delete, view, search | List names, view one credential (needs its own password) |
| Binding | `HOST` env var, documented with `0.0.0.0` | Single configured address (Yggdrasil in the current code) |
| Auth | Flask-Login session cookie | Global unlock with master password; auto-lock after 5 min idle |
| Server | Flask development server (`app.run`) | uvicorn |
| TLS | Documented via `SSL_CERT` / `SSL_KEY`; `main()` never reads them | None in code; relies on the overlay network |
| Backend | Pre-December-8 backend | Current backend with per-credential encryption |

Defects found in the Flask code (verified by reading `web_app.py` at `dbc8866`):
- `SECRET_KEY` falls back to the hardcoded `"dev-secret-key-change-in-production"`, so session cookies are forgeable when the variable is unset.
- Documented TLS settings are not implemented.
- Development server in the documented deployment path.
- No auto-lock; one global handler shared by all sessions.

## 5. Decision (2026-10-30)

**Keep the FastAPI server. Do not carry the Flask web app forward.**

Reasons:
1. The Flask app has the defects above; making it safe is about the same work as extending FastAPI.
2. Two web stacks double the dependencies to patch and the attack surface.
3. The FastAPI design (read-only, auto-lock, private-network binding, per-credential password) matches the stated goal: reach the vault from other devices over a private network.
4. FastAPI sits on the current backend; Flask would need porting and re-testing.

The Flask code is not deleted. It remains in git history and can be inspected with, for example:

```powershell
git show dbc8866:secure_credentials/src/web_app.py
```

Direction for the kept server: `docs/FASTAPI_ROADMAP.md`.

## 6. What was done to unify the repo (2026-10-30)

1. Dependencies upgraded to current patched versions; `pip-audit` clean. Python floor raised to 3.10.
2. `pkg_resources` (removed in recent setuptools) replaced with `importlib.metadata`.
3. Added: smoke tests, CI (pytest + pip-audit), Dependabot config, tag-triggered release workflow (exe + wheel + sdist + checksums). Release `v1.2.0` published.
4. `main` merged into `master` with the `ours` strategy (no force-push): all 27 `main` commits preserved, `master`'s file tree kept. `LICENSE` restored from `main`. `main` then fast-forwarded to `master`.
5. `master` and `main` currently point at the same commit; the `master` branch is redundant and can be deleted.

## 7. Since the merge (2026-10-31)

- API server rewritten around sessions, throttling, strict CSP and a network-agnostic `BIND_HOST`; release 1.3.0. Work items and status: `docs/FASTAPI_ROADMAP.md`; user-visible changes: `CHANGELOG.md`.
- Bugs found in review and fixed: the "read-only" retrieval wrote the vault file on every read; backend logs contained entry names and notes; `launcher.py` and `run_app.py direct_gui` crashed for a missing `SecurityManager`; names with a double quote could be stored but not found.
- `docs/FINAL_SIMPLE_PLAN.md` removed (obsolete); `docs/QUICKSTART.md`, `docs/VAULT_SYNC.md`, `docs/SERVICE.md` added.

## 8. Known leftovers

- `installer.nsi` (local, git-ignored) is stale: version 1.0.0, placeholder URLs; releases ship a portable exe.
- GUI uses a legacy ttkbootstrap theme name; repo clutter; see roadmap C9, C10.
- Dependabot PRs #3 and #4 were opened against the old workflow files; Dependabot should supersede them (roadmap C6).
