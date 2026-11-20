-- Sealed items no longer carry a signed policy: Foundation decides who may open each item, and each value is sealed for
-- those principals by the public key each has, named by its JWK thumbprint (RFC 7638).
CREATE FUNCTION pg_temp.thumbprint(key jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT translate(rtrim(encode(sha256(convert_to('{"crv":"' || (key->>'crv') || '","kty":"' || (key->>'kty') ||
    '","x":"' || (key->>'x') || '","y":"' || (key->>'y') || '"}', 'UTF8')), 'base64'), '='), '+/', '-_')
$$;
-- Items still in an earlier form open on no device.
DELETE FROM resources WHERE id IN (SELECT resource_id FROM resource_custody WHERE content->'policy'->>'format' IS DISTINCT FROM '3');
UPDATE resource_custody c SET content = jsonb_build_object(
  'revision', c.content->'materialRevision',
  'updatedAt', c.content->'updatedAt',
  'metadata', (c.content->'metadata') - 'methodDigest' - 'authorizationDigest',
  'sealed', (c.content->'sealed') || jsonb_build_object('recipients', (
    SELECT jsonb_agg(jsonb_set(r, '{header,kid}', to_jsonb(pg_temp.thumbprint((
      SELECT b->'encryption' FROM jsonb_array_elements(c.content->'policy'->'readers') b WHERE b->>'id' = r->'header'->>'kid')))) ORDER BY n)
    FROM jsonb_array_elements(c.content->'sealed'->'recipients') WITH ORDINALITY AS e(r, n))));
UPDATE resources SET data = data - 'recipients' - 'custodyRevision' - 'methodDigest' - 'authorizationDigest'
  WHERE kind IN ('variable','connection','app');
UPDATE connection_operations SET result = NULL WHERE result IS NOT NULL;
-- What items held before sealed content was kept apart from them.
ALTER TABLE resources DROP COLUMN sealed;
-- Lines on what a key protects are drawn directly. A line of an owner to its own item gives nothing.
DELETE FROM relations l USING resources r WHERE l.resource_id = r.id AND r.kind IN ('variable','connection','app')
  AND (l.subject_id = r.owner_id OR l.relation NOT IN ('reader','revealer','editor'));
-- Keys are no longer bound and signed, nor kept in signed lists.
DROP TABLE principal_key_bindings;
DELETE FROM resources WHERE kind = 'keyring';
ALTER TABLE resources DROP CONSTRAINT resources_kind_check;
ALTER TABLE resources ADD CONSTRAINT resources_kind_check
  CHECK (kind IN ('variable','connection','service','method','app','object','ssh_key','ssh_host'));
-- Progress and callbacks are sealed for the identity's key; those sealed before are dropped, as they are short-lived.
DELETE FROM operation_continuations;
ALTER TABLE operation_continuations DROP COLUMN binding_id;
DELETE FROM oauth_relays;
ALTER TABLE oauth_relays DROP COLUMN binding_id;
