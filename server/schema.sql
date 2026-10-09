CREATE TABLE IF NOT EXISTS system_settings (
  name text PRIMARY KEY,
  value jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS principals (
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  public_key jsonb,
  -- Whom this principal belongs to, if anyone. Its owner acts as it; one who owns principals is not removed.
  owner_id uuid REFERENCES principals(id) ON DELETE RESTRICT CHECK (owner_id <> id),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS principals_owner ON principals(owner_id) WHERE owner_id IS NOT NULL;
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
  kind text NOT NULL CHECK (kind IN ('variable','connection','service','method','app','object','environment','function')),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  data jsonb NOT NULL,
  sealed jsonb,
  private_data text,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS resources_owner ON resources(owner_id,kind,created_at,id);
-- The lines drawn between principals and onto what they hold: the subject is the relation of the object, a principal
-- or a resource. What each relation may be is the authorization schema's; whom a thing belongs to is kept with it.
CREATE TABLE IF NOT EXISTS relations (
  subject_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  relation text NOT NULL CHECK (relation ~ '^[a-z][a-z_]*[a-z]$'),
  principal_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  resource_id uuid REFERENCES resources(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((principal_id IS NULL) <> (resource_id IS NULL)),
  CHECK (subject_id <> principal_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS relations_on_principal ON relations(principal_id, relation, subject_id) WHERE principal_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS relations_on_resource ON relations(resource_id, relation, subject_id) WHERE resource_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS relations_subject ON relations(subject_id, relation);
-- One payer at most for each principal.
CREATE UNIQUE INDEX IF NOT EXISTS relations_payer ON relations(principal_id) WHERE relation = 'payer';
CREATE UNIQUE INDEX IF NOT EXISTS resources_name ON resources(owner_id,kind,name) WHERE kind <> 'connection';
CREATE TABLE IF NOT EXISTS connection_method_aliases (
  service_id uuid NOT NULL,
  scheme text NOT NULL CHECK (scheme IN ('oauth','token','role')),
  method_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  PRIMARY KEY (service_id,scheme)
);
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
  retry_at timestamptz NOT NULL DEFAULT now(),
  volume_id text,
  bootstrap_digest text,
  bootstrap_ciphertext text,
  bootstrap_expires_at timestamptz,
  enrollment_digest text
);
ALTER TABLE environment_jobs ADD COLUMN IF NOT EXISTS ssh_port integer CHECK (ssh_port BETWEEN 1024 AND 65535);
CREATE UNIQUE INDEX IF NOT EXISTS environment_ssh_port ON environment_jobs(ssh_port) WHERE ssh_port IS NOT NULL;
CREATE TABLE IF NOT EXISTS environment_deletions (
  resource_id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid REFERENCES principals(id) ON DELETE SET NULL,
  state text NOT NULL CHECK (state IN ('pending','failed','complete')),
  error text,
  requested_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
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
  continue_url text,
  proposal jsonb,
  credential_id uuid REFERENCES credentials(id) ON DELETE CASCADE
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
  settings jsonb NOT NULL
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

CREATE TABLE IF NOT EXISTS principal_key_bindings (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  binding jsonb NOT NULL,
  signature text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS principal_current_binding ON principal_key_bindings(principal_id) WHERE retired_at IS NULL;
CREATE TABLE IF NOT EXISTS resource_custody (
  resource_id uuid PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
  content jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS executor_environments (
  resource_id uuid PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
  executor_id uuid NOT NULL REFERENCES principals(id),
  registration jsonb NOT NULL,
  heartbeat_at timestamptz,
  stopped_at timestamptz
);
CREATE TABLE IF NOT EXISTS execution_tasks (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid NOT NULL REFERENCES principals(id),
  environment_id uuid NOT NULL,
  kind text NOT NULL CHECK(kind IN ('http','command','function','connect','refresh','revoke')),
  state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled','uncertain')),
  actor jsonb NOT NULL,
  request jsonb NOT NULL,
  receipt jsonb,
  error text,
  phase text NOT NULL DEFAULT 'queued' CHECK(phase IN ('queued','claimed','dispatched','settled')),
  cancel_requested boolean NOT NULL DEFAULT false,
  lease_token uuid,
  lease_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS execution_queue ON execution_tasks(environment_id,state,created_at);
CREATE INDEX IF NOT EXISTS execution_owner ON execution_tasks(owner_id,created_at DESC);
CREATE TABLE IF NOT EXISTS environment_processes (
  id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid NOT NULL REFERENCES principals(id),
  executor_id uuid NOT NULL REFERENCES principals(id),
  environment_id uuid NOT NULL,
  state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled','uncertain')),
  actor jsonb NOT NULL,
  request jsonb NOT NULL,
  result jsonb,
  error text,
  phase text NOT NULL DEFAULT 'queued' CHECK(phase IN ('queued','claimed','dispatched','settled')),
  cancel_requested boolean NOT NULL DEFAULT false,
  lease_token uuid,
  lease_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS process_queue ON environment_processes(environment_id,state,created_at);
CREATE TABLE IF NOT EXISTS connection_operations (
  id uuid PRIMARY KEY,
  resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  executor_id uuid NOT NULL REFERENCES principals(id),
  expected_revision integer NOT NULL,
  state text NOT NULL CHECK(state IN ('prepared','in_flight','committed','uncertain','aborted')),
  fence bigint GENERATED ALWAYS AS IDENTITY,
  result jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS connection_current_operation ON connection_operations(resource_id) WHERE state IN ('prepared','in_flight','uncertain');
CREATE TABLE IF NOT EXISTS oauth_relays (
  id uuid PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES execution_tasks(id) ON DELETE CASCADE,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  executor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  state_digest text NOT NULL UNIQUE,
  callback_digest text,
  sealed jsonb,
  expires_at timestamptz NOT NULL,
  received_at timestamptz
);
