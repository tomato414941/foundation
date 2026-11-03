ALTER TABLE resources DROP CONSTRAINT resources_kind_check;
ALTER TABLE resources ADD CONSTRAINT resources_kind_check
  CHECK (kind IN ('variable','connection','service','method','app','object','environment','function','keyring','ssh_key','ssh_host'));

-- Which SSH key each account of a server lets in, as decided here, and what the server last showed for it. A removed
-- authorization stays until the server shows the key gone, so that what was not applied can be followed.
CREATE TABLE ssh_authorizations (
  id uuid PRIMARY KEY,
  host_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  key_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  account text NOT NULL,
  expires_at timestamptz,
  from_hosts text,
  desired text NOT NULL CHECK (desired IN ('present','absent')),
  -- Whether the server's managed lines hold this authorization's line, another line for its key, or neither.
  observed text NOT NULL DEFAULT 'unknown' CHECK (observed IN ('unknown','present','different','absent')),
  -- Whether the key was also let in outside the managed lines, where removing the authorization cannot reach it.
  unmanaged boolean NOT NULL DEFAULT false,
  observed_at timestamptz,
  granted_by uuid NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  revoked_by uuid,
  revoked_at timestamptz,
  UNIQUE (host_id,key_id,account)
);
CREATE INDEX ssh_authorizations_key ON ssh_authorizations(key_id);
-- The last attempt to apply or check an account's authorized keys. Each report names the generation it read, so that
-- an older report cannot replace a newer one.
CREATE TABLE ssh_host_accounts (
  host_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  account text NOT NULL,
  generation integer NOT NULL DEFAULT 0,
  outcome text CHECK (outcome IN ('verified','conflict','unreachable','denied','host_key_mismatch','invalid_file','failed')),
  message text,
  attempted_at timestamptz,
  verified_at timestamptz,
  unmanaged jsonb NOT NULL DEFAULT '[]',
  PRIMARY KEY (host_id,account)
);
