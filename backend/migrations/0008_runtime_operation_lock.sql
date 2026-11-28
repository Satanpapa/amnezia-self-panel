ALTER TABLE protocol_containers
ADD COLUMN runtime_operation TEXT
CHECK (runtime_operation IS NULL OR runtime_operation IN ('start', 'stop'));

CREATE INDEX IF NOT EXISTS idx_protocol_containers_runtime_operation
ON protocol_containers(runtime_operation);
