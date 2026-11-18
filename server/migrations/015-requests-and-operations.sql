-- Requests and operations take the place of executions. What waited for someone is a request; what was done is an
-- operation, which names the request it came from. The records are moved by the migration that runs this file.
ALTER TABLE requests RENAME TO execution_requests;
DROP TABLE request_links;
DROP TABLE oauth_relays;
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
CREATE TABLE request_links (
  token_hash text PRIMARY KEY,
  request_id uuid NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL
);
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
