export const SCHEMA_VERSION = 22;
// The schema as it is, and the steps from every version a running Foundation may still be on. A version nobody
// runs any more has no step: a database older than the oldest step is refused, not migrated.
export const STEPS = {
  // Who asked for a connection is a record, not a column on the connection.
  21: 'ALTER TABLE holdings DROP COLUMN kept_by;',
  22: migrateGrantsAndObjects,
};

// A held thing was one row for every kind, with the columns of each kind side by side. Now the row says only
// that it is held; what it is (a grant, or an object) has a table of its own. A secret becomes a grant given
// by hand; a connection becomes a grant the service authorized; an object stays an object. The sealed content
// is opened under the binding it had and sealed again under the grant's.
function migrateGrantsAndObjects(store) {
  const db = store.db, vault = store.vault;
  const rows = db.prepare('SELECT * FROM holdings').all();
  db.exec(`
    DROP INDEX IF EXISTS holdings_holder; DROP INDEX IF EXISTS holdings_name;
    ALTER TABLE holdings RENAME TO holdings_old;
    CREATE TABLE holdings (id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('grant','object')), name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
    CREATE INDEX holdings_holder ON holdings(holder_id, kind, name);
    CREATE UNIQUE INDEX holdings_object_name ON holdings(holder_id, name) WHERE kind='object';
    CREATE TABLE grants (
      holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE,
      method TEXT NOT NULL CHECK(method IN ('given','authorized','delegated')), provider TEXT, purpose TEXT NOT NULL DEFAULT '',
      connector TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
      generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB
    );
    CREATE TABLE objects (holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
  `);
  const holding = db.prepare('INSERT INTO holdings (id,holder_id,kind,name,created_at,updated_at) VALUES (?,?,?,?,?,?)');
  const given = db.prepare("INSERT INTO grants (holding_id,method,size,state) VALUES (?,'given',?,?)");
  const authorized = db.prepare("INSERT INTO grants (holding_id,method,provider,connector,subject,status,generation,state) VALUES (?,'authorized',?,?,?,?,?,?)");
  const object = db.prepare('INSERT INTO objects (holding_id,size,type) VALUES (?,?,?)');
  for (const row of rows) {
    holding.run(row.id, row.holder_id, row.kind === 'object' ? 'object' : 'grant', row.name, row.created_at, row.updated_at);
    const binding = `grant:${row.holder_id}:${row.id}`;
    if (row.kind === 'secret') given.run(row.id, row.size, vault.sealBytes(vault.openBytes(row.content, `entry:${row.holder_id}:${row.id}`), binding));
    else if (row.kind === 'connection') authorized.run(row.id, row.connector.split('.')[0], row.connector, row.subject, row.status === 'connected' ? 'usable' : row.status, row.generation, vault.seal(vault.open(row.content, `connection:${row.holder_id}:${row.id}`), binding));
    else object.run(row.id, row.size, row.type);
  }
  db.exec('DROP TABLE holdings_old;');
}

export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
  CREATE TABLE credentials (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('key','link')), scope TEXT, expires_at INTEGER, created_at TEXT NOT NULL, last_used_at TEXT
  );
  CREATE INDEX credentials_principal ON credentials(principal_id);
  CREATE TABLE relations (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','holding')), object_id TEXT NOT NULL,
    alias TEXT, scope TEXT, created_at TEXT NOT NULL,
    PRIMARY KEY (subject_id, relation, object_type, object_id)
  );
  CREATE INDEX relations_object ON relations(object_type, object_id, relation);
  CREATE UNIQUE INDEX relations_alias ON relations(subject_id, relation, alias) WHERE alias IS NOT NULL;
  CREATE TABLE settings (
    principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    return_url TEXT NOT NULL, refresh_url TEXT, webhook_url TEXT, webhook_secret TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL, secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE requests (
    id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT,
    kind TEXT NOT NULL CHECK(kind IN ('actor','store','connect')), input TEXT NOT NULL,
    purpose TEXT NOT NULL, steps TEXT NOT NULL, code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX requests_from ON requests(from_id, created_at);
  CREATE INDEX requests_to ON requests(to_id, created_at);
  CREATE TABLE holdings (
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('grant','object')), name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX holdings_holder ON holdings(holder_id, kind, name);
  CREATE UNIQUE INDEX holdings_object_name ON holdings(holder_id, name) WHERE kind='object';
  CREATE TABLE grants (
    holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK(method IN ('given','authorized','delegated')), provider TEXT, purpose TEXT NOT NULL DEFAULT '',
    connector TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
    generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB
  );
  CREATE TABLE objects (holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
  CREATE TABLE records (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX records_actor ON records(actor_id, at);
  CREATE INDEX records_object ON records(object_type, object_id, at);
  PRAGMA user_version = ${SCHEMA_VERSION};
`;
