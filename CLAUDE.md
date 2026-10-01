# clamav-console

Multi-tenant ClamAV management console for an MSP.

- `cmd/agent`, `internal/agent`: Go endpoint agent (systemd unit / Windows service). Talks to local clamd, outbound HTTPS only.
- `cmd/server`, `internal/server`: console server (agent API, server-rendered htmx UI, Postgres).
- `internal/protocol`: agent/server wire types and the agent action allowlist, shared by both binaries.
- `db/migrations`: goose SQL migrations, applied by the server on start.
- `deploy/`: Docker Compose (Caddy + server + Postgres). `packaging/`: agent install scripts.
- Design: `docs/design/phase1.md`. Operations: `docs/operations.md`.

Common commands: `make test`, `make lint`, `make build`, `make dist`. Integration tests need `TEST_DATABASE_URL`.

# Project rules (security). These are permanent and non-negotiable.

## 1. Agent actions are a fixed allowlist
- The agent may only execute action types defined in `internal/protocol/actions.go`, each with a typed, validated parameter struct.
- Never add arbitrary command execution, shell invocation, script download-and-run, or "run this string" features to the agent, under any name, ever.
- Never pass server-supplied data to `os/exec`, a shell, or a file path without validation against an allowlist held in the agent's **local** config. `os/exec` is banned in `internal/agent` by a test and lint rule; do not remove or weaken them.
- The agent never listens on a network port. It only makes outbound HTTPS requests and talks to clamd over a Unix socket or loopback TCP.
- Adding or changing an action type is a security change: update the allowlist, validators, tests (including malicious-input tests) and docs in the same change.

## 2. All admin actions are audited
- Every state-changing admin operation writes an `audit_log` entry via `internal/server/audit`, in the same transaction as the change. Denied and failed attempts are audited too.
- `audit_log` is append-only, enforced in the database (grants + trigger). Never add code or migrations that update or delete audit rows outside the documented retention procedure.
- Never write secrets (passwords, tokens, credentials, keys) into audit details or logs.

## 3. The web UI requires authentication
- Every UI and admin route except the login page, static assets, `/healthz` and `/readyz` is behind session authentication and CSRF checks. Register new routes through the authenticated router.
- Keep the MFA-ready design: authorization checks use the session `auth_level`; never add shortcuts around it.
- No default or hard-coded credentials.

## 4. Secrets come from environment variables only
- Never commit secrets, real tokens, private keys, certificates or `.env` files. `.env.example` contains placeholders only.
- Store only HMAC hashes of enrollment tokens, agent credentials and session tokens.
- gitleaks runs in CI; do not bypass it.

## 5. Agent releases are signed offline
- Agent binaries and install scripts are signed with a minisign key that never lives on the server or in this repo.
- The public key is embedded in the agent (`internal/release/minisign.pub`) and in both install scripts, which verify signatures before installing. Never replace signature verification with checksum-only verification, and never fetch the public key from the server.

## 6. Agent 401 handling
- The server returns HTTP 401 with error code `agent_revoked` only for a revoked credential (or an agent whose tenant is archived).
- The agent stops permanently **only** on `agent_revoked`. Any other 401 means keep running, log loudly, and retry with slow backoff (30 to 60 minutes). Never make the agent exit on a generic 401.
