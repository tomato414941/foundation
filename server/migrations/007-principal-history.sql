-- A principal can be deleted after it has acted for or with others. Their records of what it did keep who acted, by id
-- and by the keys they recorded, and neither stop the deletion nor go with it. What it owned still goes with it.
-- Older databases named some of these constraints after earlier tables, so they are found by table and column.
DO $$
DECLARE kept record;
BEGIN
  FOR kept IN SELECT DISTINCT c.conrelid::regclass AS name, c.conname FROM pg_constraint c
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
    WHERE c.contype = 'f' AND c.confrelid = 'principals'::regclass AND (c.conrelid::regclass::text, a.attname::text) IN (
      ('execution_tasks', 'actor_id'), ('environment_processes', 'actor_id'), ('environment_processes', 'executor_id'),
      ('function_invocations', 'actor_id'), ('function_invocations', 'executor_id'), ('connection_operations', 'executor_id'),
      ('executions', 'actor_id'), ('executions', 'creator_id'), ('executions', 'responder_id'),
      ('requests', 'from_id'), ('requests', 'to_id'), ('audit_log', 'actor_id'), ('environment_deletions', 'actor_id'),
      ('billing_events', 'principal_id'))
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', kept.name, kept.conname);
  END LOOP;
END $$;
