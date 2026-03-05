ALTER TABLE session_devices ADD COLUMN trusted bool NOT NULL DEFAULT false;
ALTER TABLE session_devices ADD COLUMN fingerprint varchar(128) NULL;
ALTER TABLE session_devices ADD COLUMN authentication_methods json;

DROP INDEX unique_session_device ON session_devices;
CREATE UNIQUE INDEX unique_session_device
  ON session_devices (nid, session_id, ip_address, user_agent, fingerprint, location);
