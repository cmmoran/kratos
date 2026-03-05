ALTER TABLE session_devices ADD COLUMN trusted bool NOT NULL DEFAULT false;
ALTER TABLE session_devices ADD COLUMN fingerprint varchar(128) NULL;
ALTER TABLE session_devices ADD COLUMN authentication_methods jsonb;

DROP INDEX IF EXISTS unique_session_device CASCADE;
CREATE UNIQUE INDEX IF NOT EXISTS unique_session_device
  ON session_devices (nid, session_id, ip_address, user_agent, fingerprint, location);
