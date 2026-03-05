ALTER TABLE session_devices ADD COLUMN trusted bool NOT NULL DEFAULT 'false';
ALTER TABLE session_devices ADD COLUMN fingerprint varchar(128) NULL;
ALTER TABLE session_devices ADD COLUMN authentication_methods jsonb;

alter table public.session_devices
  drop constraint unique_session_device;

alter table public.session_devices
  add constraint unique_session_device
    unique (nid, session_id, ip_address, user_agent, fingerprint, location);
