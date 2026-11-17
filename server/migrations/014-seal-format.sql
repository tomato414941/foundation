-- A connection is renewed by one of its readers on a device of its own, and items no longer name executors that could
-- use them. Items still sealed under the earlier policy are sealed again by their owners' devices.
ALTER TABLE connection_operations RENAME COLUMN executor_id TO renewer_id;
UPDATE resources SET data = data - 'executors' WHERE data ? 'executors';
