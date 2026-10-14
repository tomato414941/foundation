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
  kind text NOT NULL CHECK (kind IN ('variable','connection','service','method','app','object','environment','function','keyring')),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  data jsonb NOT NULL,
  sealed jsonb,
  private_data text,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS resources_owner ON resources(owner_id,kind,created_at,id);
ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_kind_check;
ALTER TABLE resources ADD CONSTRAINT resources_kind_check
  CHECK (kind IN ('variable','connection','service','method','app','object','environment','function','keyring'));
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
DROP TABLE IF EXISTS connection_method_aliases;
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
ALTER TABLE environment_jobs DROP COLUMN IF EXISTS ssh_port;
ALTER TABLE environment_jobs ADD COLUMN IF NOT EXISTS provider text CHECK (provider='ec2');
ALTER TABLE environment_jobs ADD COLUMN IF NOT EXISTS network_slot integer CHECK (network_slot BETWEEN 0 AND 4091);
ALTER TABLE environment_jobs ADD COLUMN IF NOT EXISTS metered_at timestamptz;
CREATE UNIQUE INDEX IF NOT EXISTS environment_network_slot ON environment_jobs(network_slot) WHERE network_slot IS NOT NULL;
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
CREATE TABLE IF NOT EXISTS executions (
  id uuid PRIMARY KEY,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  creator_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  owner_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  responder_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  message text NOT NULL DEFAULT '',
  proposal jsonb,
  code_hash text,
  attempts integer NOT NULL DEFAULT 0,
  response text NOT NULL DEFAULT 'none' CHECK(response IN ('none','pending','accepted','declined','cancelled','expired')),
  state text NOT NULL CHECK(state IN ('waiting','running','succeeded','failed','uncertain','cancelled')),
  wait text CHECK(wait IN ('approval','input','execution')),
  snapshot text NOT NULL,
  revision integer NOT NULL DEFAULT 1,
  lease_token uuid,
  lease_until timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE executions ADD COLUMN IF NOT EXISTS creator_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS owner_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS responder_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS message text NOT NULL DEFAULT '', ADD COLUMN IF NOT EXISTS proposal jsonb,
  ADD COLUMN IF NOT EXISTS code_hash text, ADD COLUMN IF NOT EXISTS attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS response text NOT NULL DEFAULT 'none';
ALTER TABLE executions DROP CONSTRAINT IF EXISTS executions_wait_check;
ALTER TABLE executions DROP CONSTRAINT IF EXISTS operation_executions_wait_check;
ALTER TABLE executions ADD CONSTRAINT executions_wait_check CHECK(wait IN ('approval','input','execution'));
CREATE INDEX IF NOT EXISTS executions_actor ON executions(actor_id,created_at DESC);
CREATE INDEX IF NOT EXISTS executions_recipient ON executions(responder_id,state,created_at);
CREATE TABLE IF NOT EXISTS requests (
  id uuid PRIMARY KEY,
  execution_id uuid NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  from_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  to_id uuid REFERENCES principals(id) ON DELETE CASCADE,
  message text NOT NULL DEFAULT '',
  purpose text NOT NULL CHECK(purpose IN ('input','approval')),
  state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','accepted','declined','cancelled','expired')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  answered_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS request_pending ON requests(execution_id) WHERE state='pending';
CREATE INDEX IF NOT EXISTS request_recipient ON requests(to_id,state,created_at);
CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS operation_continuations (
  id uuid PRIMARY KEY,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  binding_id uuid NOT NULL,
  revision integer NOT NULL,
  envelope jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS request_links (
  token_hash text PRIMARY KEY,
  request_id uuid NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
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
CREATE INDEX IF NOT EXISTS billing_events_usage ON billing_events(meter,created_at,principal_id);
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
CREATE TABLE IF NOT EXISTS function_invocations (
  id uuid PRIMARY KEY,
  function_id uuid NOT NULL,
  function_owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  executor_id uuid NOT NULL REFERENCES principals(id),
  environment_id uuid NOT NULL,
  executor jsonb NOT NULL,
  actor jsonb NOT NULL,
  input_digest text NOT NULL,
  request jsonb NOT NULL,
  publication jsonb NOT NULL,
  state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled','uncertain')),
  completion jsonb,
  error jsonb,
  phase text NOT NULL DEFAULT 'queued' CHECK(phase IN ('queued','claimed','dispatched','settled')),
  cancel_requested boolean NOT NULL DEFAULT false,
  lease_token uuid,
  lease_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);
CREATE INDEX IF NOT EXISTS invocation_queue ON function_invocations(environment_id,state,created_at);
CREATE INDEX IF NOT EXISTS invocation_owner ON function_invocations(owner_id,id);
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
  execution_id uuid NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  operation_index integer NOT NULL,
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  binding_id uuid NOT NULL,
  state_digest text NOT NULL UNIQUE,
  callback_digest text,
  sealed jsonb,
  expires_at timestamptz NOT NULL,
  received_at timestamptz
);

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='oauth_relays' AND column_name='run_id') THEN
    DELETE FROM oauth_relays;
    ALTER TABLE oauth_relays DROP COLUMN run_id, DROP COLUMN executor_id,
      ADD COLUMN execution_id uuid NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
      ADD COLUMN operation_index integer NOT NULL, ADD COLUMN binding_id uuid NOT NULL;
  END IF;
END $$;
