ALTER TABLE session_devices DROP COLUMN trusted;
ALTER TABLE session_devices DROP COLUMN fingerprint;
ALTER TABLE session_devices DROP COLUMN authentication_methods;

alter table public.session_devices
  drop constraint unique_session_device;

alter table public.session_devices
  add constraint unique_session_device
    unique (nid, session_id, ip_address, user_agent);
