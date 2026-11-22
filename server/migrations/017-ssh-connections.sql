-- A way into a server over SSH is a connection: it holds the server, the account and the private key, and is opened
-- where it is used. The SSH keys, servers and records of which key signs in where that Foundation kept beside it go;
-- each private key stays as the variable it was kept in.
DELETE FROM operations WHERE name LIKE 'ssh.%';
DROP TABLE ssh_authorizations;
DELETE FROM resources WHERE kind IN ('ssh_key','ssh_host');
ALTER TABLE resources DROP CONSTRAINT resources_kind_check;
ALTER TABLE resources ADD CONSTRAINT resources_kind_check
  CHECK (kind IN ('variable','connection','service','method','app','object'));
