ALTER TABLE resources DROP CONSTRAINT resources_kind_check;
UPDATE resources SET kind='object' WHERE kind='file';
ALTER TABLE resources ADD CONSTRAINT resources_kind_check
  CHECK (kind IN ('variable','connection','service','method','app','object','environment','function','keyring'));

ALTER TABLE file_blobs RENAME TO object_blobs;
ALTER TABLE object_blobs RENAME CONSTRAINT file_blobs_pkey TO object_blobs_pkey;
ALTER TABLE object_blobs RENAME CONSTRAINT file_blobs_resource_id_fkey TO object_blobs_resource_id_fkey;

UPDATE audit_log SET action='object.upload' WHERE action='file.upload';
UPDATE audit_log SET details=jsonb_set(details,'{kind}','"object"'::jsonb)
  WHERE action='resource.delete' AND details->>'kind'='file';
