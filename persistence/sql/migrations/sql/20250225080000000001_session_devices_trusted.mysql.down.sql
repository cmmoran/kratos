DROP INDEX unique_session_device ON session_devices;
CREATE UNIQUE INDEX unique_session_device
  ON session_devices (nid, session_id, ip_address, user_agent);

ALTER TABLE session_devices DROP COLUMN authentication_methods;
ALTER TABLE session_devices DROP COLUMN fingerprint;
ALTER TABLE session_devices DROP COLUMN trusted;
