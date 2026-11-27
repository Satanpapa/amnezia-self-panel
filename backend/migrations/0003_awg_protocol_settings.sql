ALTER TABLE protocol_containers
ADD COLUMN awg_settings_json TEXT NOT NULL DEFAULT '{}';
