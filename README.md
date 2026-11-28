# Amnezia Panel

Self-hosted control plane for AmneziaWG, WireGuard, OpenVPN and OpenVPN over Cloak.

**Current stack**
- Backend: Rust, Tokio, Axum, SQLx, SQLite, Argon2id.
- Frontend: React, TypeScript, Vite.
- Deployment target: Linux VPS; read-only Docker daemon probe is implemented, container lifecycle is not.

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
- [x] Database-level trigger guards against duplicate client IP allocation during concurrent creates.
- [x] Container/client CRUD foundations, IPv4 allocation and one-time subscription token issuance (preview only).
- [x] Reject overlapping IPv4 address pools for newly created VPN records.
- [x] Enforce transport compatibility in API and UI: WireGuard / AmneziaWG use UDP; OpenVPN over Cloak uses TCP.
- [x] Generate Curve25519 keypairs for WireGuard-compatible server profiles and clients; encrypt both private keys at rest with ChaCha20-Poly1305.
- [x] Provision server identity once through an authenticated endpoint; prevent accidental replacement and increment profile revision.
- [x] Store only the public key in normal client API responses; private key ciphertext is never serialized.
- [x] Persist validated AmneziaWG 1.5 / 2.0 / 3.1 profile settings (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5 and AWG 3.1 transport flags) as metadata.
- [x] Validate AWG junk packet ranges, padding constraints, header range overlaps and version-gated S3/S4 fields.
- [x] Edit saved AWG profiles through a revision-checked API; every accepted edit increments the profile revision and creates an audit event.
- [x] Protocol Studio UI with AWG profile editor, server overview, searchable/filterable client list and responsive navigation.
- [x] Unit tests for subnet overlap and adjacency.
- [x] RuntimeAdapter boundary and safe PreviewRuntime implementation.
- [x] Read-only Linux host preflight for `CAP_NET_ADMIN`, TUN, kernel modules, `ip`, `wg` / `awg` and userspace daemons.
- [x] Docker Engine connectivity adapter (read-only health probe).
- [ ] Docker container create/start/stop/remove lifecycle.
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

The API binds to `127.0.0.1:4000` by default and creates `data/amnezia-panel.db`. `RUNTIME_MODE=preview` is the safe default. Set `RUNTIME_MODE=host` for a read-only Linux preflight (CAP_NET_ADMIN, `ip`, WireGuard/AmneziaWG tools, kernel module or TUN/userspace implementation). Set `RUNTIME_MODE=docker` to enable a read-only Docker daemon health check. Host preflight does not create interfaces or peers.

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
- `GET /api/runtime/status` (authenticated; reports Docker/preview state and whether `WIREGUARD_MASTER_KEY` is configured)
- `GET /api/containers` / `POST /api/containers`
- `PUT /api/containers/:container_id/awg-profile` (authenticated, revision-checked metadata update)
- `POST /api/containers/:container_id/wireguard-server-key` (one-time encrypted server-key provisioning)
- `POST /api/containers/:container_id/clients`

AmneziaWG profiles are submitted with `awg_settings` when creating an `amnezia-awg` record. Settings are persisted as JSON metadata and validated server-side (including AWG 3.1 ContentPaddingAddition, RandomTrailers and DisableCookies). Existing AWG profiles can be edited; updates require the current `expected_revision`, increment `revision`, and are audited. This is still metadata-only: settings are not applied to a running interface or emitted into client configs. HeaderProtectionKey is intentionally not exposed until its separate secret-generation, storage and synchronization lifecycle is implemented.
- `GET /api/clients`
- `POST /api/clients/:client_id/disable`

For AmneziaWG/WireGuard key provisioning, configure `WIREGUARD_MASTER_KEY` in the backend `.env` as 64 hex characters (32 random bytes). Generate it once with `openssl rand -hex 32`. The backend keeps its copied environment value, decoded bytes, and resident master key in zeroizing wrappers. Back it up securely outside the database: losing it makes encrypted private keys unrecoverable. Do not rotate it without a migration/rewrapping procedure.

The initial admin password must be 12-256 characters. Usernames are 3-32 ASCII letters, digits, underscore or hyphen.

## Security notes

- The API binds to loopback by default. Keep it behind a trusted reverse proxy.
- Set `COOKIE_SECURE=true` when serving over HTTPS.
- Use HTTPS in production; do not expose the development server directly to the Internet.
- The initial version does not yet include login rate limiting, full CSRF defenses, password reset or multi-user roles.
- Container records and runtime remain preview-only. WireGuard/AmneziaWG server and client keypairs are generated and private keys are encrypted at rest, but peers are not installed into a running VPN interface and no working client configuration or subscription download is produced yet.
- Curve25519 keypair generation and authenticated encryption at rest are implemented. The authenticated decryption primitive is implemented with zeroizing plaintext buffers, but no client-facing private-key export/config endpoint exists yet. Actual peer installation/revocation, `vpn://` serialization and Docker execution are not implemented yet.

## Runtime architecture

The HTTP layer depends on a `RuntimeAdapter` trait rather than directly invoking Docker or shell commands. `PreviewRuntime` reports metadata-only mode. `HostRuntime` performs a read-only Linux prerequisite probe for the official `awg` / `wg` tools, kernel modules or userspace TUN daemons, `/dev/net/tun`, and `CAP_NET_ADMIN`. `DockerRuntime` uses Bollard to ping the local Docker daemon with a three-second timeout. Both report `can_manage_vpn=false`: the panel does not yet create, start, stop, or remove VPN containers. Docker socket access is highly privileged; do not expose the API publicly or mount the socket into an untrusted container.

## Project docs

- [Russian development plan](./ПЛАН-РАЗРАБОТКИ.md)
- [Backend architecture decisions](./docs/TECH-STACK.md)
