ALTER TABLE session_devices
  DROP CONSTRAINT IF EXISTS unique_session_device;

DROP INDEX IF EXISTS unique_session_device;

ALTER TABLE session_devices
  ADD CONSTRAINT unique_session_device
    UNIQUE (nid, session_id, ip_address, user_agent);

ALTER TABLE session_devices DROP COLUMN authentication_methods;
ALTER TABLE session_devices DROP COLUMN fingerprint;
ALTER TABLE session_devices DROP COLUMN trusted;
