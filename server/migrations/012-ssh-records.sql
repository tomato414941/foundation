-- Which SSH key signs in to which account of a server is now a record only: Foundation no longer applies it to the
-- servers or follows what they show. Authorizations already taken out or expired go, along with what followed the
-- servers and what only applying used: host keys, authorized keys files and key revocations.
DELETE FROM ssh_authorizations WHERE desired='absent' OR expires_at<=now();
ALTER TABLE ssh_authorizations DROP COLUMN expires_at, DROP COLUMN from_hosts, DROP COLUMN desired, DROP COLUMN observed,
  DROP COLUMN unmanaged, DROP COLUMN observed_at, DROP COLUMN revoked_by, DROP COLUMN revoked_at;
DROP TABLE ssh_host_accounts;
UPDATE resources SET data=data-'hostKeys'-'authorizedKeysFile' WHERE kind='ssh_host';
UPDATE resources SET data=data-'revokedAt' WHERE kind='ssh_key';
