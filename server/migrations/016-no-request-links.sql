-- A request is answered only by one signed in as whom it is sent to: no link signs anyone in to one request, and the
-- sessions such links opened end. Nor is everything given to a principal taken back at once; each line is erased.
DROP TABLE request_links;
DELETE FROM sessions WHERE request_id IS NOT NULL;
ALTER TABLE sessions DROP COLUMN request_id;
DELETE FROM operations WHERE name = 'principal.revoke';
