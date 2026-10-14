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
  retired_at timestamptz,
  merged_into uuid REFERENCES principals(id) ON DELETE SET NULL CHECK (merged_into <> id),
  created_at timestamptz NOT NULL DEFAULT now()
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
  environment_id uuid,
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
  kind text NOT NULL CHECK (kind IN ('variable','connection','service','method','app','object','environment','function','keyring')),
  name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  data jsonb NOT NULL,
  sealed jsonb,
  private_data text,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX resources_owner ON resources(owner_id,kind,created_at,id);
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
CREATE TABLE environment_jobs (
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
  enrollment_digest text,
  provider text CHECK (provider='ec2'),
  network_slot integer CHECK (network_slot BETWEEN 0 AND 4091),
  metered_at timestamptz
);
CREATE UNIQUE INDEX environment_network_slot ON environment_jobs(network_slot) WHERE network_slot IS NOT NULL;
CREATE TABLE environment_deletions (
  resource_id uuid PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid REFERENCES principals(id) ON DELETE SET NULL,
  state text NOT NULL CHECK (state IN ('pending','failed','complete')),
  error text,
  requested_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE TABLE resource_references (
  resource_id uuid NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
  referenced_id uuid NOT NULL REFERENCES resources(id) ON DELETE RESTRICT,
  PRIMARY KEY(resource_id,referenced_id),
  CHECK (resource_id <> referenced_id)
);
CREATE TABLE function_settings (
  function_id uuid PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
  environment_id uuid REFERENCES resources(id) ON DELETE SET NULL,
  version integer NOT NULL CHECK (version > 0),
  approval jsonb NOT NULL
);
CREATE TABLE executions (
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
CREATE INDEX executions_actor ON executions(actor_id,created_at DESC);
CREATE INDEX executions_recipient ON executions(responder_id,state,created_at);
CREATE TABLE requests (
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
CREATE UNIQUE INDEX request_pending ON requests(execution_id) WHERE state='pending';
CREATE INDEX request_recipient ON requests(to_id,state,created_at);
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
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  meter text NOT NULL CHECK(meter IN ('compute','storage')),
  amount bigint NOT NULL CHECK(amount >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz
);
CREATE INDEX billing_events_usage ON billing_events(meter,created_at,principal_id);
CREATE TABLE payment_webhooks (
  id text PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE usage_limits (
  principal_id uuid PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
  compute_seconds bigint NOT NULL DEFAULT 3600,
  storage_bytes bigint NOT NULL DEFAULT 1073741824
);
CREATE TABLE audit_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  actor_id uuid REFERENCES principals(id) ON DELETE SET NULL,
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
CREATE TABLE executor_environments (
  resource_id uuid PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
  executor_id uuid NOT NULL REFERENCES principals(id),
  registration jsonb NOT NULL,
  heartbeat_at timestamptz,
  stopped_at timestamptz
);
CREATE TABLE execution_tasks (
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
CREATE INDEX execution_queue ON execution_tasks(environment_id,state,created_at);
CREATE INDEX execution_owner ON execution_tasks(owner_id,created_at DESC);
CREATE INDEX execution_operation_context ON execution_tasks((request->'intent'->'operationContext'->>'id'),created_at)
  WHERE request->'intent'->'operationContext'->>'id' IS NOT NULL;
CREATE TABLE environment_processes (
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
CREATE INDEX process_queue ON environment_processes(environment_id,state,created_at);
CREATE TABLE function_invocations (
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
  settings jsonb,
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
CREATE INDEX invocation_queue ON function_invocations(environment_id,state,created_at);
CREATE INDEX invocation_owner ON function_invocations(owner_id,id);
CREATE TABLE connection_operations (
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
CREATE UNIQUE INDEX connection_current_operation ON connection_operations(resource_id) WHERE state IN ('prepared','in_flight','uncertain');
CREATE TABLE oauth_relays (
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
