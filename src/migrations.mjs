export const SCHEMA_VERSION = 25;
// The schema as it is, and the steps from every version a running Foundation may still be on. A version nobody
// runs any more has no step: a database older than the oldest step is refused, not migrated.
export const STEPS = {
  // Who asked for a connection is a record, not a column on the connection.
  21: 'ALTER TABLE holdings DROP COLUMN kept_by;',
  22: migrateGrantsAndObjects,
  // A grant is told apart by its name and its method; no provider or tags are kept about it.
  23: 'DROP TABLE grant_tags; ALTER TABLE grants DROP COLUMN provider;',
  24: migrateGoogleConnections,
  25: holdAppsAsTheirOwnKind,
};

// An OAuth app becomes a holding of its own kind, and a connection says which app it was made through. SQLite
// changes a CHECK only by making the table again: the children of holdings move to new tables first, so dropping
// the old ones never cascades into data. Nothing else refers to requests.
function holdAppsAsTheirOwnKind(store) {
  store.db.exec(`
    CREATE TABLE holdings_next (
      id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('grant','object','app')), name TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    INSERT INTO holdings_next SELECT id, holder_id, kind, name, created_at, updated_at FROM holdings;
    CREATE TABLE grants_next (
      holding_id TEXT PRIMARY KEY REFERENCES holdings_next(id) ON DELETE CASCADE,
      method TEXT NOT NULL CHECK(method IN ('given','authorized','delegated')),
      connector TEXT, app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
      generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB
    );
    INSERT INTO grants_next (holding_id, method, connector, subject, status, generation, size, state)
      SELECT holding_id, method, connector, subject, status, generation, size, state FROM grants;
    CREATE TABLE objects_next (holding_id TEXT PRIMARY KEY REFERENCES holdings_next(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
    INSERT INTO objects_next SELECT holding_id, size, type FROM objects;
    CREATE TABLE apps (
      holding_id TEXT PRIMARY KEY REFERENCES holdings_next(id) ON DELETE CASCADE,
      connector TEXT NOT NULL, client_id TEXT NOT NULL, secret BLOB NOT NULL
    );
    DROP TABLE grants; DROP TABLE objects; DROP TABLE holdings;
    ALTER TABLE holdings_next RENAME TO holdings; ALTER TABLE grants_next RENAME TO grants; ALTER TABLE objects_next RENAME TO objects;
    CREATE INDEX holdings_holder ON holdings(holder_id, kind, name);
    CREATE UNIQUE INDEX holdings_object_name ON holdings(holder_id, name) WHERE kind='object';
    CREATE UNIQUE INDEX holdings_app_name ON holdings(holder_id, name) WHERE kind='app';
    CREATE INDEX grants_app ON grants(app_id) WHERE app_id IS NOT NULL;
    CREATE TABLE requests_next (
      id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT,
      kind TEXT NOT NULL CHECK(kind IN ('actor','store','connect','app')), input TEXT NOT NULL,
      purpose TEXT NOT NULL, steps TEXT NOT NULL, code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','denied','cancelled')),
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    INSERT INTO requests_next SELECT id, from_id, to_id, kind, input, purpose, steps, code, attempts, progress, result, reason, status, created_at, expires_at FROM requests;
    DROP TABLE requests; ALTER TABLE requests_next RENAME TO requests;
    CREATE INDEX requests_from ON requests(from_id, created_at);
    CREATE INDEX requests_to ON requests(to_id, created_at);
  `);
}

// Gmail (one connector per read range) and Google Cloud were Google connections under fixed scopes. Now there is
// one Google connection, asking for the scopes the holder chose, and naming the account by its address. Each old
// connection keeps its id and asks for what it had, plus what names the account; its tokens cannot say who the
// account is (or came from another OAuth client), so the holder connects it again once.
function migrateGoogleConnections(store) {
  const db = store.db, vault = store.vault, base = ['openid', 'https://www.googleapis.com/auth/userinfo.email'];
  const rows = db.prepare("SELECT g.holding_id, g.connector, g.subject, g.state, h.holder_id FROM grants g JOIN holdings h ON h.id=g.holding_id WHERE g.connector IN ('gmail.readonly','gmail.metadata','gmail.read-send','gcp.oauth')").all();
  const update = db.prepare("UPDATE grants SET connector='google.oauth', subject=?, state=?, status=CASE status WHEN 'disconnecting' THEN status ELSE 'reconnect_required' END, generation=generation+1 WHERE holding_id=?");
  for (const row of rows) {
    const binding = `grant:${row.holder_id}:${row.holding_id}`, state = vault.open(row.state, binding);
    const granted = Array.isArray(state.facts?.scopes) ? state.facts.scopes : [];
    state.requested_scopes = [...new Set([...base, ...granted.map(scope => scope === 'email' ? base[1] : scope)])].sort();
    // Google Cloud named the account by its Google ID; its address was its label.
    const email = row.connector === 'gcp.oauth' ? String(state.facts?.label || '').toLowerCase() : row.subject;
    update.run(/^[^\s@]+@[^\s@]+$/.test(email) ? email : row.subject, vault.seal(state, binding), row.holding_id);
  }
}

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
      method TEXT NOT NULL CHECK(method IN ('given','authorized','delegated')), provider TEXT,
      connector TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
      generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB
    );
    CREATE TABLE grant_tags (holding_id TEXT NOT NULL REFERENCES holdings(id) ON DELETE CASCADE, tag TEXT NOT NULL, PRIMARY KEY (holding_id, tag));
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
    kind TEXT NOT NULL CHECK(kind IN ('actor','store','connect','app')), input TEXT NOT NULL,
    purpose TEXT NOT NULL, steps TEXT NOT NULL, code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX requests_from ON requests(from_id, created_at);
  CREATE INDEX requests_to ON requests(to_id, created_at);
  CREATE TABLE holdings (
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('grant','object','app')), name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX holdings_holder ON holdings(holder_id, kind, name);
  CREATE UNIQUE INDEX holdings_object_name ON holdings(holder_id, name) WHERE kind='object';
  CREATE UNIQUE INDEX holdings_app_name ON holdings(holder_id, name) WHERE kind='app';
  CREATE TABLE grants (
    holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE,
    method TEXT NOT NULL CHECK(method IN ('given','authorized','delegated')),
    connector TEXT, app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
    generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB
  );
  CREATE INDEX grants_app ON grants(app_id) WHERE app_id IS NOT NULL;
  CREATE TABLE objects (holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
  -- An OAuth app someone holds: which service it is for, its client ID, and its sealed secret (and eBay's RuName).
  CREATE TABLE apps (
    holding_id TEXT PRIMARY KEY REFERENCES holdings(id) ON DELETE CASCADE,
    connector TEXT NOT NULL, client_id TEXT NOT NULL, secret BLOB NOT NULL
  );
  CREATE TABLE records (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX records_actor ON records(actor_id, at);
  CREATE INDEX records_object ON records(object_type, object_id, at);
  PRAGMA user_version = ${SCHEMA_VERSION};
`;
