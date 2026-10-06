CREATE TABLE IF NOT EXISTS system_settings (
  name text PRIMARY KEY,
  value jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS principals (
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  public_key jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS relations (
  id uuid PRIMARY KEY,
  subject_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  relation text NOT NULL CHECK (relation IN ('owner','agent','member','payer')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (subject_id, principal_id, relation),
  CHECK (subject_id <> principal_id)
);
CREATE INDEX IF NOT EXISTS relations_target ON relations(principal_id, relation);
CREATE TABLE IF NOT EXISTS principal_grants (
  target_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actions text[] NOT NULL,
  PRIMARY KEY(target_id,principal_id)
);
CREATE TABLE IF NOT EXISTS credentials (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('email','passkey','key')),
  name text NOT NULL,
  identifier text NOT NULL UNIQUE,
  data jsonb NOT NULL DEFAULT '{}',
  private_wrap text,
  expires_at timestamptz,
  environment_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz
);
CREATE INDEX IF NOT EXISTS credentials_principal ON credentials(principal_id);
CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  credential_id uuid REFERENCES credentials(id) ON DELETE CASCADE,
  request_id uuid,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS challenges (
  id uuid PRIMARY KEY,
  kind text NOT NULL,
  browser_hash text,
  principal_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  data jsonb NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS resources (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('secret','connection','service','app','object','environment','function')),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  data jsonb NOT NULL,
  sealed jsonb,
  private_data text,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS resources_owner ON resources(owner_id,kind,created_at,id);
CREATE UNIQUE INDEX IF NOT EXISTS resources_name ON resources(owner_id,kind,name) WHERE kind <> 'connection';
ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_owner_id_kind_name_key;
CREATE TABLE IF NOT EXISTS object_blobs (
  id uuid PRIMARY KEY,
  resource_id uuid REFERENCES resources(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS environment_jobs (
  resource_id uuid PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
  machine_id text,
  lease_until timestamptz,
  lease_token uuid,
  attempts integer NOT NULL DEFAULT 0,
  retry_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS grants (
  resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actions text[] NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(resource_id,principal_id)
);
CREATE TABLE IF NOT EXISTS resource_references (
  resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  referenced_id uuid NOT NULL REFERENCES resources(id) ON DELETE RESTRICT,
  PRIMARY KEY(resource_id,referenced_id),
  CHECK (resource_id <> referenced_id)
);
CREATE TABLE IF NOT EXISTS runs (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  resource_id uuid REFERENCES resources(id) ON DELETE SET NULL,
  kind text NOT NULL CHECK(kind IN ('http','command','function')),
  state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled')),
  private_input text NOT NULL,
  result jsonb,
  error text,
  lease_until timestamptz,
  lease_token uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS runs_queue ON runs(state,created_at);
CREATE INDEX IF NOT EXISTS runs_owner ON runs(owner_id,created_at DESC);
CREATE TABLE IF NOT EXISTS approval_requests (
  id uuid PRIMARY KEY,
  from_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  to_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  message text NOT NULL,
  operations text NOT NULL,
  results jsonb NOT NULL,
  state text NOT NULL CHECK(state IN ('pending','running','approved','declined','cancelled','expired')),
  code_hash text,
  attempts integer NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  private_input text,
  continue_url text
);
CREATE INDEX IF NOT EXISTS requests_recipient ON approval_requests(to_id,state,created_at);
CREATE TABLE IF NOT EXISTS request_links (
  token_hash text PRIMARY KEY,
  request_id uuid NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS integration_settings (
  principal_id uuid PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  settings jsonb NOT NULL,
  webhook_secret text NOT NULL
);
CREATE TABLE IF NOT EXISTS webhooks (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  payload jsonb NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  next_attempt timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz
);
CREATE TABLE IF NOT EXISTS payment_accounts (
  principal_id uuid PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  customer_id text NOT NULL UNIQUE,
  subscription_id text UNIQUE,
  status text NOT NULL DEFAULT 'pending'
);
CREATE TABLE IF NOT EXISTS billing_events (
  id uuid PRIMARY KEY,
  reference text NOT NULL UNIQUE,
  payer_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  meter text NOT NULL CHECK(meter IN ('compute','storage')),
  amount bigint NOT NULL CHECK(amount >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz
);
CREATE TABLE IF NOT EXISTS payment_webhooks (
  id text PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS usage_limits (
  principal_id uuid PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  compute_seconds bigint NOT NULL DEFAULT 3600,
  storage_bytes bigint NOT NULL DEFAULT 1073741824
);
CREATE TABLE IF NOT EXISTS audit_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid REFERENCES principals(id) ON DELETE SET NULL,
  action text NOT NULL,
  target_id uuid,
  details jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_owner ON audit_log(owner_id,id DESC);
