CREATE TABLE IF NOT EXISTS protocol_containers (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    protocol TEXT NOT NULL CHECK (protocol IN ('amnezia-awg', 'wireguard', 'openvpn', 'openvpn-cloak')),
    status TEXT NOT NULL DEFAULT 'preview' CHECK (status IN ('preview', 'starting', 'running', 'stopped', 'error')),
    endpoint TEXT NOT NULL,
    listen_port INTEGER NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    transport TEXT NOT NULL CHECK (transport IN ('udp', 'tcp')),
    subnet TEXT NOT NULL,
    dns TEXT NOT NULL,
    mtu INTEGER NOT NULL CHECK (mtu BETWEEN 576 AND 9000),
    revision INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_protocol_containers_created_at ON protocol_containers(created_at);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY NOT NULL,
    container_id TEXT NOT NULL REFERENCES protocol_containers(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    assigned_ip TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    subscription_token_hash TEXT NOT NULL UNIQUE,
    traffic_limit_bytes INTEGER NOT NULL DEFAULT 0 CHECK (traffic_limit_bytes >= 0),
    traffic_used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (traffic_used_bytes >= 0),
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE(container_id, assigned_ip)
);

CREATE INDEX IF NOT EXISTS idx_clients_container_id ON clients(container_id);
CREATE INDEX IF NOT EXISTS idx_clients_enabled ON clients(enabled);
