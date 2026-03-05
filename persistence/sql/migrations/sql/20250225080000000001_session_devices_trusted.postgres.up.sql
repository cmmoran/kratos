ALTER TABLE session_devices ADD COLUMN trusted bool NOT NULL DEFAULT false;
ALTER TABLE session_devices ADD COLUMN fingerprint varchar(128) NULL;
ALTER TABLE session_devices ADD COLUMN authentication_methods jsonb;

ALTER TABLE session_devices
  DROP CONSTRAINT IF EXISTS unique_session_device;

DROP INDEX IF EXISTS unique_session_device;

ALTER TABLE session_devices
  ADD CONSTRAINT unique_session_device
    UNIQUE (nid, session_id, ip_address, user_agent, fingerprint, location);
