ALTER TABLE environment_jobs ADD COLUMN IF NOT EXISTS ssh_ciphertext text;
ALTER TABLE environment_jobs ADD COLUMN IF NOT EXISTS ssh_checked_at timestamptz;
ALTER TABLE environment_jobs ADD COLUMN IF NOT EXISTS ssh_sync_at timestamptz;
ALTER TABLE environment_jobs ADD COLUMN IF NOT EXISTS provision_expires_at timestamptz;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM environment_jobs j JOIN resources r ON r.id=j.resource_id
             WHERE r.data->>'driver'='managed' AND j.ssh_ciphertext IS NULL) THEN
    RAISE EXCEPTION 'Migrate existing managed VMs to SSH before applying this deployment. Their disks have been retained.';
  END IF;
END $$;

ALTER TABLE environment_jobs DROP COLUMN IF EXISTS bootstrap_digest;
ALTER TABLE environment_jobs DROP COLUMN IF EXISTS bootstrap_ciphertext;
ALTER TABLE environment_jobs DROP COLUMN IF EXISTS bootstrap_expires_at;
ALTER TABLE environment_jobs DROP COLUMN IF EXISTS enrollment_digest;
ALTER TABLE environment_processes ALTER COLUMN executor_id DROP NOT NULL;
