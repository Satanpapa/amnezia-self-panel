# Amnezia Panel

Self-hosted control plane for AmneziaWG, WireGuard, OpenVPN and OpenVPN over Cloak.

**Current stack**
- Backend: Rust, Tokio, Axum, SQLx, SQLite, Argon2id.
- Frontend: React, TypeScript, Vite.
- Deployment target: Linux VPS with Docker runtime (not implemented yet).

## Current progress

- [x] Rust API bootstrap and SQLite migrations.
- [x] Health endpoint and authenticated runtime-status endpoint.
- [x] First-run administrator setup (one administrator, one-time setup).
- [x] Argon2id password hashing.
- [x] Opaque random session token in HttpOnly cookie; only its SHA-256 hash is stored.
- [x] Login, session check and logout endpoints.
- [x] React setup/login screens connected to the API.
- [x] GitHub Actions: Rust `cargo check` + `cargo test`, frontend production build.
- [x] Preview data model for protocol containers and clients.
- [x] Container/client CRUD foundations, IPv4 allocation and one-time subscription token issuance (preview only).
- [x] RuntimeAdapter boundary and safe PreviewRuntime implementation.
- [ ] Docker Engine adapter and real container lifecycle.
- [ ] VPN protocol/peer lifecycle and configuration export.
- [ ] Traffic accounting, quotas and subscription URLs.

## Run locally

Requirements: Rust stable toolchain, Node.js 22+, npm.

### Backend

```bash
cd backend
cp .env.example .env
cargo run
```

The API binds to `127.0.0.1:4000` by default and creates `data/amnezia-panel.db`.

### Frontend

In another terminal:

```bash
cd web
npm install
npm run dev
```

Open the Vite URL (normally http://127.0.0.1:5173). The dev server proxies `/api` requests to the Rust API.

## API

- `GET /api/health`
- `GET /api/setup/status`
- `POST /api/setup/initialize`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/auth/logout`
- `GET /api/runtime/status` (authenticated)
- `GET /api/containers` / `POST /api/containers`
- `POST /api/containers/:container_id/clients`
- `GET /api/clients`
- `POST /api/clients/:client_id/disable`

The initial admin password must be 12-256 characters. Usernames are 3-32 ASCII letters, digits, underscore or hyphen.

## Security notes

- The API binds to loopback by default. Keep it behind a trusted reverse proxy.
- Set `COOKIE_SECURE=true` when serving over HTTPS.
- Use HTTPS in production; do not expose the development server directly to the Internet.
- The initial version does not yet include login rate limiting, full CSRF defenses, password reset or multi-user roles.
- Container/client records are preview metadata only. No WireGuard keys, peer configs, running VPN process, Docker container or subscription download is created yet.
- VPN key generation, `vpn://` serialization and Docker execution are not production-ready until verified against official Amnezia/WireGuard behavior.

## Runtime architecture

The HTTP layer depends on a `RuntimeAdapter` trait rather than directly invoking Docker or shell commands. The currently wired `PreviewRuntime` reports metadata-only mode and explicitly returns `can_manage_vpn=false`. A Docker implementation will be added behind the same boundary after its lifecycle and failure behavior are covered by tests.

## Project docs

- [Russian development plan](./ПЛАН-РАЗРАБОТКИ.md)
- [Backend architecture decisions](./docs/TECH-STACK.md)
