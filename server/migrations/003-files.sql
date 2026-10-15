ALTER TABLE resources DROP CONSTRAINT resources_kind_check;
UPDATE resources SET kind='file' WHERE kind='object';
ALTER TABLE resources ADD CONSTRAINT resources_kind_check
  CHECK (kind IN ('variable','connection','service','method','app','file','environment','function','keyring'));

ALTER TABLE object_blobs RENAME TO file_blobs;
ALTER TABLE file_blobs RENAME CONSTRAINT object_blobs_pkey TO file_blobs_pkey;
ALTER TABLE file_blobs RENAME CONSTRAINT object_blobs_resource_id_fkey TO file_blobs_resource_id_fkey;

UPDATE audit_log SET action='file.upload' WHERE action='object.upload';
UPDATE audit_log SET details=jsonb_set(details,'{kind}','"file"'::jsonb)
  WHERE action='resource.delete' AND details->>'kind'='object';
