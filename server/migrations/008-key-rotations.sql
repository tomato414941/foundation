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
