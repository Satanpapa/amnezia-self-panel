ALTER TABLE clients
    ADD COLUMN last_rx_bytes INTEGER NOT NULL DEFAULT 0 CHECK (last_rx_bytes >= 0);

ALTER TABLE clients
    ADD COLUMN last_tx_bytes INTEGER NOT NULL DEFAULT 0 CHECK (last_tx_bytes >= 0);
