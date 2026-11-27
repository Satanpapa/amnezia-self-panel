ALTER TABLE clients ADD COLUMN wireguard_public_key TEXT;
ALTER TABLE clients ADD COLUMN wireguard_private_key_encrypted BLOB;
