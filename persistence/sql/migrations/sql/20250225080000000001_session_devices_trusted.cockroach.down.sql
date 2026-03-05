DROP INDEX IF EXISTS unique_session_device CASCADE;
CREATE UNIQUE INDEX IF NOT EXISTS unique_session_device
  ON session_devices (nid, session_id, ip_address, user_agent);

ALTER TABLE session_devices DROP COLUMN authentication_methods;
ALTER TABLE session_devices DROP COLUMN fingerprint;
ALTER TABLE session_devices DROP COLUMN trusted;
