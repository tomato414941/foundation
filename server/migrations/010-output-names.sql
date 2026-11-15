-- The name each new output of a function invocation gets, by the JSON pointer of its value: a label kept apart from the
-- request the executor receives.
ALTER TABLE function_invocations ADD COLUMN output_names jsonb NOT NULL DEFAULT '{}'::jsonb;
