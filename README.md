# Amnezia Panel

Self-hosted control plane for AmneziaWG, WireGuard, OpenVPN and OpenVPN over Cloak.

**Current stack**
- Backend: Rust, Tokio, Axum, SQLx, SQLite, Argon2id.
- Frontend: React, TypeScript, Vite.
- Deployment target: Linux VPS. Opt-in host WireGuard / AmneziaWG interface start/stop is implemented; Docker daemon probe remains read-only.

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
- [x] Generate a 32-byte AWG 3.1 HeaderProtectionKey once, encrypt it with a separate `HPK1` envelope and never serialize the secret.
- [x] Require AWG 3.1 plus S1-S4 >= 12 to provision HeaderProtectionKey; preserve this invariant when editing an already-provisioned profile.
- [x] Store only the public key in normal client API responses; private key ciphertext is never serialized.
- [x] Authenticated, audited, no-store server/client `.conf` draft downloads with keypair consistency checks and disabled/expired client restrictions.
- [x] Persist validated AmneziaWG 1.5 / 2.0 / 3.1 profile settings (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5 and AWG 3.1 transport flags) as metadata.
- [x] Validate AWG junk packet ranges, padding constraints, header range overlaps and version-gated S3/S4 fields.
- [x] Guard current upstream AmneziaWG 3.1 tool limits: ContentPaddingAddition 0–65535 and combined I1-I5 strings <=3000 characters.
- [x] Edit saved AWG profiles through a revision-checked API; every accepted edit increments the profile revision and creates an audit event.
- [x] Protocol Studio UI with AWG profile editor, server overview, searchable/filterable client list and responsive navigation.
- [x] Unit tests for subnet overlap and adjacency.
- [x] RuntimeAdapter boundary, safe PreviewRuntime, read-only Docker health probe.
- [x] Linux host prerequisite checks for root, `CAP_NET_ADMIN`, TUN/kernel modules and root-owned `ip`, `wg`, `awg`, `wg-quick`, `awg-quick` / userspace daemons.
- [x] Opt-in Linux host interface start/stop through fixed `wg-quick` / `awg-quick` argv (no shell), protected `0700` config directory and `0600` files.
- [x] Authenticated server start/stop API and dashboard controls, with a separate DB runtime-operation lock and audit events.
- [x] Startup recovery marks interrupted start/stop operations as requiring cleanup; host stop is idempotent when the interface/config have already disappeared.
- [x] Read-only live peer stats from `wg/awg show <interface> dump`, with public keys/IPs/handshake/RX/TX only; endpoint and preshared-key columns are discarded.
- [x] Clients UI shows live RX/TX and latest handshake, automatically refreshed every 15 seconds for running host-mode profiles.
- [x] Overview aggregates live peer RX/TX counters across running host profiles.
- [x] Client creation while stopped is persisted for the next start; live WireGuard / AmneziaWG peer addition and revocation are serialized with the shared per-profile runtime-operation lock.
- [x] Authenticated one-time `POST /api/containers/:id/awg-header-protection-key` endpoint and dashboard status/button.
- [ ] Docker container create/start/stop/remove lifecycle.
- [x] Initial server interface start/stop and initial active-peer installation from generated configuration.
- [x] Live peer revocation for running Linux-host WireGuard / AmneziaWG interfaces via the protocol control CLI; the API removes the peer before committing the disabled state and records whether runtime removal was applied.
- [x] Live peer addition to running Linux-host WireGuard / AmneziaWG interfaces through fixed-argument `wg set` / `awg set` commands, with /32 validation, encrypted private-key storage and rollback on command failure.
- [x] Background expiration cleanup every 30 seconds in explicitly enabled host mode; it verifies the interface, removes expired peers, updates client state and records a system audit event.
- [x] Cumulative per-client RX+TX traffic accounting with persisted counter snapshots and counter-reset handling.
- [x] Automatic traffic-quota enforcement in the 30-second Linux host policy worker; zero means unlimited and reached quotas remove the live peer.
- [ ] Profile-wide hot reload and subscription URLs.

## Run locally

Requirements: Rust stable toolchain, Node.js 22+, npm.

### Backend

```bash
cd backend
cp .env.example .env
cargo run
```

The API binds to `127.0.0.1:4000` by default and creates `data/amnezia-panel.db`. `RUNTIME_MODE=preview` is the safe default. Set `RUNTIME_MODE=host` for the Linux host runtime. It requires effective UID 0, `CAP_NET_ADMIN`, `ip`, `wg` / `awg`, `wg-quick` / `awg-quick`, and the appropriate kernel module or userspace TUN implementation. Host mutations remain disabled unless `HOST_RUNTIME_ALLOW_MUTATIONS=true` is explicitly set. Set `RUNTIME_MODE=docker` to enable a read-only Docker daemon health check. With mutations disabled, host mode performs only a prerequisite check. With the explicit opt-in enabled, the backend uses fixed `wg-quick up/down` or `awg-quick up/down` binaries resolved only from root-owned, non-writable system directories; no shell is invoked and child PATH/environment are sanitized. Generated server config files contain the server private key in plaintext in the private config directory (`0700` directory, `0600` files) while an interface is active. Run the panel only on a trusted host and keep its admin UI private.

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
- `POST /api/containers/:container_id/awg-header-protection-key` (one-time encrypted AWG 3.1 header-protection key provisioning; requires S1-S4 >= 12)
- `POST /api/containers/:container_id/clients`
- `POST /api/containers/:container_id/start` (host runtime only; builds config and starts the WG/AWG interface)
- `POST /api/containers/:container_id/stop` (host runtime only; stops a managed WG/AWG interface)
- `GET /api/containers/:container_id/peer-stats` (authenticated, read-only; live peer handshake and RX/TX counters)
- `GET /api/containers/:container_id/server-config` (authenticated server `.conf` draft; includes active, unexpired peers)
- `GET /api/clients/:client_id/config` (authenticated `.conf` draft; denied for disabled or expired clients)

AmneziaWG profiles are submitted with `awg_settings` when creating an `amnezia-awg` record. Settings are persisted as JSON metadata and validated server-side (including AWG 3.1 ContentPaddingAddition, RandomTrailers and DisableCookies). Existing AWG profiles can be edited while stopped; updates require the current `expected_revision`, increment `revision`, and are audited. AWG settings are rendered into the next server/client `.conf` and are applied when the interface is started. The active interface is not hot-reloaded; backend and UI reject profile edits while it is running. The current model stores one shared AWG parameter set rather than independent server/client overrides. HeaderProtectionKey is provisioned once as a cryptographically random 32-byte secret and encrypted at rest with a separate `HPK1` authenticated-encryption envelope. The API returns only an `awg_header_protection_key_configured` boolean; the secret is never included in normal API responses or audit records. Provisioning requires AWG 3.1 and S1-S4 >= 12. Once provisioned, profile edits cannot lower any of those padding values or switch away from AWG 3.1.
- `GET /api/clients`
- `POST /api/clients/:client_id/disable`

For AmneziaWG/WireGuard key provisioning, configure `WIREGUARD_MASTER_KEY` in the backend `.env` as 64 hex characters (32 random bytes). Generate it once with `openssl rand -hex 32`. The backend keeps its copied environment value, decoded bytes, and resident master key in zeroizing wrappers. Back it up securely outside the database: losing it makes encrypted private keys unrecoverable. Do not rotate it without a migration/rewrapping procedure.

The initial admin password must be 12-256 characters. Usernames are 3-32 ASCII letters, digits, underscore or hyphen.

## Security notes

- The API binds to loopback by default. Keep it behind a trusted reverse proxy.
- Set `COOKIE_SECURE=true` when serving over HTTPS.
- Use HTTPS in production; do not expose the development server directly to the Internet.
- The initial version does not yet include login rate limiting, full CSRF defenses, password reset or multi-user roles.
- Preview remains the safe default. In opt-in Linux host mode, authenticated start/stop operations can create/remove a real WireGuard/AmneziaWG interface through the official quick tools. The server configuration is generated from currently enabled and unexpired clients at start time. New WireGuard / AmneziaWG peers can be added live with a fixed-argument `wg set` / `awg set` operation; live revocation removes the peer before the client is marked disabled. Both operations use a per-profile synchronization lock to serialize against start/stop and automatic expiry. A policy worker runs every 30 seconds in explicitly enabled Linux host mode, verifies that the interface still exists, accounts cumulative RX+TX per client, removes expired or quota-exhausted peers and commits an audit event. Traffic usage is cumulative across service restarts; a detected interface/peer counter reset starts a new counter segment rather than underflowing. Quota enforcement can overshoot by up to one polling interval plus command latency. Client creation still requires a stopped profile for protocols other than WireGuard / AmneziaWG. Authenticated `.conf` downloads still carry a draft marker and do not configure NAT/forwarding, firewall policy, IPv6 routing or automatic startup/recovery.
- Curve25519 keypair generation and authenticated encryption at rest are implemented. AWG 3.1 HeaderProtectionKey is stored separately and encrypted at rest. The authenticated decryption primitive and authorized client `.conf` export endpoint are implemented with zeroizing plaintext buffers. Live peer installation and revocation are implemented for Linux-host WireGuard / AmneziaWG; profile-wide settings changes still require a full interface stop/start. The initial enabled peers are installed as part of interface startup. The authenticated peer-stats endpoint reads the fixed `wg/awg show <interface> dump` format with a 1 MiB bounded, zeroized output buffer and discards peer endpoint and preshared-key columns before constructing its no-store response. The clients table polls this endpoint every 15 seconds while the corresponding host interface is running and displays cumulative usage against each client's configured quota. Startup recovery clears stale operation locks and checks every persisted running WG/AWG profile against the actual Linux link state. Missing interfaces are marked as requiring cleanup; probe errors leave the database state unchanged. Stopping an already-absent interface is safe when its protected config is also absent. `vpn://` serialization and Docker container lifecycle are not implemented yet. Client `.conf` uses split-tunnel routing for the VPN profile's IPv4 subnet only. Full-tunnel Internet routing, IPv6, firewall policy, forwarding and NAT must be implemented before this can act as a full Internet VPN.

## Runtime architecture

The HTTP layer depends on a `RuntimeAdapter` trait rather than directly invoking Docker or shell commands. `PreviewRuntime` reports metadata-only mode. `HostRuntime` checks the official `awg` / `wg`, `awg-quick` / `wg-quick` tools, kernel modules or userspace TUN daemons, `/dev/net/tun`, and `CAP_NET_ADMIN`. It can manage an interface only when `HOST_RUNTIME_ALLOW_MUTATIONS=true` is set. `DockerRuntime` uses Bollard to ping the local Docker daemon with a three-second timeout. `HostRuntime` reports `can_manage_vpn=true` only when its Linux dependencies are present and `HOST_RUNTIME_ALLOW_MUTATIONS=true`; it requires effective root plus `CAP_NET_ADMIN`. Docker remains ping-only and reports `can_manage_vpn=false`. Docker socket access is highly privileged; do not expose the API publicly or mount the socket into an untrusted container.

## Project docs

- [Russian development plan](./ПЛАН-РАЗРАБОТКИ.md)
- [Backend architecture decisions](./docs/TECH-STACK.md)
