-- Foundation schema 001
CREATE TABLE system_settings (
  name text PRIMARY KEY,
  value jsonb NOT NULL
);
CREATE TABLE principals (
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  public_key jsonb,
  -- Whom this principal belongs to, if anyone. Its owner acts as it; one who owns principals is not removed.
  owner_id uuid REFERENCES principals(id) ON DELETE RESTRICT CHECK (owner_id <> id),
  -- When it came to its owner, kept by stamp_owned_at.
  owned_at timestamptz,
  retired_at timestamptz,
  merged_into uuid REFERENCES principals(id) ON DELETE SET NULL CHECK (merged_into <> id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT principals_owned_at CHECK ((owner_id IS NULL) = (owned_at IS NULL))
);
CREATE INDEX principals_owner ON principals(owner_id) WHERE owner_id IS NOT NULL;
CREATE TABLE credentials (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('email','passkey','key')),
  name text NOT NULL,
  identifier text NOT NULL UNIQUE,
  data jsonb NOT NULL DEFAULT '{}',
  private_wrap text,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
CREATE INDEX credentials_principal ON credentials(principal_id);
CREATE TABLE sessions (
  id uuid PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  credential_id uuid REFERENCES credentials(id) ON DELETE CASCADE,
  request_id uuid,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE challenges (
  id uuid PRIMARY KEY,
  kind text NOT NULL,
  browser_hash text,
  principal_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  data jsonb NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE resources (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  -- When it came to its owner, kept by stamp_owned_at.
  owned_at timestamptz NOT NULL,
  kind text NOT NULL CHECK (kind IN ('variable','connection','service','method','app','object','keyring','ssh_key','ssh_host')),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  data jsonb NOT NULL,
  sealed jsonb,
  private_data text,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX resources_owner ON resources(owner_id,kind,created_at,id);
-- When each principal and thing came to its owner: when it was made there, taken on or passed on, kept as the owner
-- changes, whichever way it changes. A principal without an owner has none.
CREATE FUNCTION stamp_owned_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' OR NEW.owner_id IS DISTINCT FROM OLD.owner_id THEN
    NEW.owned_at := CASE WHEN NEW.owner_id IS NULL THEN NULL ELSE now() END;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER principals_owned_at BEFORE INSERT OR UPDATE OF owner_id ON principals
  FOR EACH ROW EXECUTE FUNCTION stamp_owned_at();
CREATE TRIGGER resources_owned_at BEFORE INSERT OR UPDATE OF owner_id ON resources
  FOR EACH ROW EXECUTE FUNCTION stamp_owned_at();
CREATE TABLE relations (
  subject_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  relation text NOT NULL CHECK (relation ~ '^[a-z][a-z_]*[a-z]$'),
  principal_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  resource_id uuid REFERENCES resources(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((principal_id IS NULL) <> (resource_id IS NULL)),
  CHECK (subject_id <> principal_id)
);
CREATE UNIQUE INDEX relations_on_principal ON relations(principal_id, relation, subject_id) WHERE principal_id IS NOT NULL;
CREATE UNIQUE INDEX relations_on_resource ON relations(resource_id, relation, subject_id) WHERE resource_id IS NOT NULL;
CREATE INDEX relations_subject ON relations(subject_id, relation);
CREATE UNIQUE INDEX relations_payer ON relations(principal_id) WHERE relation = 'payer';
CREATE UNIQUE INDEX resources_name ON resources(owner_id,kind,name) WHERE kind <> 'connection';
CREATE TABLE object_blobs (
  id uuid PRIMARY KEY,
  resource_id uuid REFERENCES resources(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE resource_references (
  resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  referenced_id uuid NOT NULL REFERENCES resources(id) ON DELETE RESTRICT,
  PRIMARY KEY(resource_id,referenced_id),
  CHECK (resource_id <> referenced_id)
);
-- The records of what principals did name who acted by id alone: deleting a principal neither waits for them nor
-- removes them from the history of others. What a principal owns still goes with it.
-- A request asks a principal, or whoever enters its code, to make operations. Who asked and what it asked for are kept
-- encrypted in its record; it ends approved, declined, withdrawn or expired.
CREATE TABLE requests (
  id uuid PRIMARY KEY,
  from_id uuid NOT NULL,
  to_id uuid,
  owner_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  message text NOT NULL DEFAULT '',
  record text NOT NULL,
  proposal jsonb,
  code_hash text,
  attempts integer NOT NULL DEFAULT 0,
  state text NOT NULL CHECK(state IN ('pending','approved','declined','withdrawn','expired')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  answered_at timestamptz,
  answered_by uuid
);
CREATE INDEX requests_from ON requests(from_id,created_at DESC);
CREATE INDEX requests_to ON requests(to_id,state,created_at DESC);
-- An operation changes something in Foundation. Its input, result and the sign-in it was made with are kept encrypted
-- in its record; one a request asked for names that request and its place in it.
CREATE TABLE operations (
  id uuid PRIMARY KEY,
  request_id uuid REFERENCES requests(id) ON DELETE CASCADE,
  position integer,
  owner_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid NOT NULL,
  name text NOT NULL,
  state text NOT NULL CHECK(state IN ('stopped','in_progress','succeeded','failed','uncertain','cancelled')),
  record text NOT NULL,
  revision integer NOT NULL DEFAULT 1,
  lease_token uuid,
  lease_until timestamptz,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(request_id,position)
);
CREATE INDEX operations_actor ON operations(actor_id,created_at DESC);
CREATE INDEX operations_owner ON operations(owner_id,created_at DESC);
CREATE TABLE schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE operation_continuations (
  id uuid PRIMARY KEY,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  binding_id uuid NOT NULL,
  revision integer NOT NULL,
  envelope jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE request_links (
  token_hash text PRIMARY KEY,
  request_id uuid NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL
);
CREATE TABLE integration_settings (
  principal_id uuid PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  settings jsonb NOT NULL
);
CREATE TABLE payment_accounts (
  principal_id uuid PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  customer_id text NOT NULL UNIQUE,
  subscription_id text UNIQUE,
  status text NOT NULL DEFAULT 'pending'
);
CREATE TABLE billing_events (
  id uuid PRIMARY KEY,
  reference text NOT NULL UNIQUE,
  payer_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  -- Who used it, by id alone: the payer keeps the usage after that principal is deleted.
  principal_id uuid NOT NULL,
  amount bigint NOT NULL CHECK(amount >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz
);
CREATE INDEX billing_events_usage ON billing_events(created_at,principal_id);
CREATE TABLE payment_webhooks (
  id text PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE usage_limits (
  principal_id uuid PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  storage_bytes bigint NOT NULL DEFAULT 1073741824
);
CREATE TABLE audit_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid,
  action text NOT NULL,
  target_id uuid,
  details jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_owner ON audit_log(owner_id,id DESC);
CREATE TABLE principal_key_bindings (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  binding jsonb NOT NULL,
  signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE UNIQUE INDEX principal_current_binding ON principal_key_bindings(principal_id) WHERE retired_at IS NULL;
CREATE TABLE resource_custody (
  resource_id uuid PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
  content jsonb NOT NULL
);
CREATE TABLE connection_operations (
  id uuid PRIMARY KEY,
  resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  renewer_id uuid NOT NULL,
  expected_revision integer NOT NULL,
  state text NOT NULL CHECK(state IN ('prepared','in_flight','committed','uncertain','aborted')),
  fence bigint GENERATED ALWAYS AS IDENTITY,
  result jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX connection_current_operation ON connection_operations(resource_id) WHERE state IN ('prepared','in_flight','uncertain');
CREATE TABLE oauth_relays (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  binding_id uuid NOT NULL,
  state_digest text NOT NULL UNIQUE,
  callback_digest text,
  sealed jsonb,
  expires_at timestamptz NOT NULL,
  received_at timestamptz
);

CREATE TABLE key_rotations (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  previous jsonb NOT NULL,
  replacement jsonb NOT NULL,
  previous_signature text NOT NULL,
  -- The replacement private keys sealed for the previous keys, for the holders of those to follow.
  handoff jsonb NOT NULL,
  state text NOT NULL DEFAULT 'preparing' CHECK (state IN ('preparing','committed','cancelled')),
  completed_items integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE UNIQUE INDEX principal_preparing_rotation ON key_rotations(principal_id) WHERE state='preparing';
CREATE UNIQUE INDEX committed_key_replacement ON key_rotations(principal_id,(previous#>>'{binding,id}')) WHERE state='committed';
CREATE TABLE key_rotation_items (
  rotation_id uuid NOT NULL REFERENCES key_rotations(id) ON DELETE CASCADE,
  kind text NOT NULL,
  item_id uuid NOT NULL,
  source_digest text NOT NULL,
  payload jsonb NOT NULL,
  -- The rotating principal's signature; null when an authority of the item prepared it with its own keys.
  signature text,
  PRIMARY KEY(rotation_id,kind,item_id)
);
-- Which SSH key signs in to which account of a server. A record only: Foundation does not change or read the servers.
CREATE TABLE ssh_authorizations (
  id uuid PRIMARY KEY,
  host_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  key_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  account text NOT NULL,
  granted_by uuid NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (host_id,key_id,account)
);
CREATE INDEX ssh_authorizations_key ON ssh_authorizations(key_id);
