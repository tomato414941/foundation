-- The name each new output of a run gets, by the JSON pointer of its value: a label kept apart from the run its
-- requester signed.
ALTER TABLE execution_tasks ADD COLUMN output_names jsonb NOT NULL DEFAULT '{}'::jsonb;
