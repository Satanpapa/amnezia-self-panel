-- Guard IPv4 peer allocation at the database boundary.
-- SQLite serializes writers; the trigger prevents two concurrent requests from
-- reserving the same address even when their preflight SELECTs race.
CREATE TRIGGER IF NOT EXISTS clients_prevent_duplicate_ip_insert
BEFORE INSERT ON clients
WHEN EXISTS (
    SELECT 1 FROM clients
    WHERE container_id = NEW.container_id
      AND assigned_ip = NEW.assigned_ip
)
BEGIN
    SELECT RAISE(ABORT, 'duplicate_client_ip');
END;

CREATE TRIGGER IF NOT EXISTS clients_prevent_duplicate_ip_update
BEFORE UPDATE OF container_id, assigned_ip ON clients
WHEN EXISTS (
    SELECT 1 FROM clients
    WHERE container_id = NEW.container_id
      AND assigned_ip = NEW.assigned_ip
      AND id <> OLD.id
)
BEGIN
    SELECT RAISE(ABORT, 'duplicate_client_ip');
END;
