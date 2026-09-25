export const SCHEMA_VERSION = 19;
// Names are opaque identifiers. Connection state is stored independently of ordinary values.
// Migrations preserve resource identity and plaintext, and rebind ciphertext explicitly when needed.
export const STEPS = {
  19: migrateHoldings,
  18: migratePrincipalGraph,
  17: migratePrincipals,
  16: migrateResponsibilities,
  // Each run of a built-in function is written down for the owner: which key, what, where to, and how it went.
  15: `
  CREATE TABLE invocations (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, key_id TEXT, key_name TEXT NOT NULL, function TEXT NOT NULL,
    target TEXT NOT NULL, status TEXT NOT NULL, detail TEXT NOT NULL, at TEXT NOT NULL
  );
  CREATE INDEX invocations_owner ON invocations(owner_id, at);
  `,
  // Where a product sends its user back when a link cannot be used, and where it hears that a request finished.
  14: `
    ALTER TABLE integrations ADD COLUMN refresh_url TEXT;
    ALTER TABLE integrations ADD COLUMN webhook_url TEXT;
    ALTER TABLE integrations ADD COLUMN webhook_secret TEXT;
  `,
  // Another product may hold an account for each of its own users, with no login of its own: the product
  // vouches for who the user is, and hands them to one request at a time through a single-use link.
  13: `
  CREATE TABLE integrations (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
    return_url TEXT NOT NULL, created_at TEXT NOT NULL, last_used_at TEXT
  );
  CREATE TABLE accounts (
    id TEXT PRIMARY KEY, integration_id TEXT NOT NULL, external_id TEXT NOT NULL, created_at TEXT NOT NULL,
    UNIQUE(integration_id, external_id)
  );
  CREATE TABLE request_links (
    token_hash TEXT PRIMARY KEY, request_id TEXT NOT NULL, owner_id TEXT NOT NULL, kind TEXT NOT NULL, expires_at INTEGER NOT NULL
  );
  `,
  12: migrateNames,
  // A key may have several requests open at once, each with its own address, and writes the owner's steps as a
  // list. Requests still open are dropped rather than carried: each lasts a day at most, and asking again works.
  11: `
    DROP TABLE access_requests;
    CREATE TABLE requests (
      id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, key_id TEXT NOT NULL, owner_id TEXT NOT NULL, requester_name TEXT NOT NULL,
      adapter TEXT, purpose TEXT NOT NULL, details TEXT NOT NULL, steps TEXT NOT NULL, progress TEXT, credential_id TEXT,
      status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    CREATE INDEX requests_token ON requests(token_hash, created_at);
  `,
};

// Everything Foundation knew as a kind of thing becomes a principal and lines between principals. A key was
// a principal made by its owner that acts for them; an app one made by its developer; an account one made by
// its app, which calls it by a name of its own. Their credentials are all one kind of thing, and a single-use
// link is a credential too: one scoped to a single request. A key waiting to be approved is a principal
// already, with a request open to whoever will own it. What an app needs to hand its users back are its
// settings. Nothing else changes: what is held keeps its holder.
// What a principal has is one kind of thing: a holding, with an id of its own. A secret, an object and a
// connection differ in what is done with the content, not in what they are. Lines drawn onto a held thing point
// at its id, so a name can change or be reused without the line following the wrong thing.
function migrateHoldings({ db }) {
  db.exec(`
    CREATE TABLE holdings (
      id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('secret','object','connection')), name TEXT NOT NULL,
      size INTEGER NOT NULL DEFAULT 0, readable INTEGER NOT NULL DEFAULT 0, type TEXT, content BLOB,
      connector TEXT, subject TEXT, status TEXT, generation INTEGER NOT NULL DEFAULT 1, kept_by TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE INDEX holdings_holder ON holdings(holder_id, kind, name);
    CREATE UNIQUE INDEX holdings_name ON holdings(holder_id, kind, name) WHERE kind <> 'connection';
    INSERT INTO holdings (id,holder_id,kind,name,size,readable,content,created_at,updated_at)
      SELECT id,owner_id,'secret',name,size,readable,content,created_at,updated_at FROM secrets;
    INSERT INTO holdings (id,holder_id,kind,name,content,connector,subject,status,generation,kept_by,created_at,updated_at)
      SELECT id,owner_id,'connection',label,state,connector,subject,status,generation,kept_by,created_at,updated_at FROM connections;
    CREATE TABLE relations_next (
      subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
      object_type TEXT NOT NULL CHECK(object_type IN ('principal','holding')), object_id TEXT NOT NULL,
      alias TEXT, scope TEXT, created_at TEXT NOT NULL,
      PRIMARY KEY (subject_id, relation, object_type, object_id)
    );
    INSERT INTO relations_next SELECT subject_id,relation,'principal',object_id,alias,scope,created_at FROM relations WHERE object_type='principal';
    INSERT OR IGNORE INTO relations_next
      SELECT r.subject_id,r.relation,'holding',h.id,NULL,r.scope,r.created_at FROM relations r
      JOIN holdings h ON h.kind='secret' AND h.holder_id=r.holder_id AND h.name=r.object_id WHERE r.object_type='secret';
    DROP TABLE relations;
    ALTER TABLE relations_next RENAME TO relations;
    CREATE INDEX relations_object ON relations(object_type, object_id, relation);
    CREATE UNIQUE INDEX relations_alias ON relations(subject_id, relation, alias) WHERE alias IS NOT NULL;
    DROP TABLE secrets;
    DROP TABLE connections;
  `);
}

function migratePrincipalGraph({ db }) {
  const now = new Date().toISOString();
  db.exec(`
    CREATE TABLE credentials_next (
      id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK(kind IN ('key','link')), scope TEXT, expires_at INTEGER, created_at TEXT NOT NULL, last_used_at TEXT
    );
    INSERT INTO credentials_next (id,hash,principal_id,kind,scope,expires_at,created_at,last_used_at)
      SELECT lower(hex(randomblob(16))),hash,principal_id,'key',NULL,NULL,created_at,last_used_at FROM credentials;
    DROP TABLE credentials;
    ALTER TABLE credentials_next RENAME TO credentials;
    CREATE INDEX credentials_principal ON credentials(principal_id);
    CREATE TABLE relations (
      subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
      object_type TEXT NOT NULL CHECK(object_type IN ('principal','secret','object','connection')), holder_id TEXT NOT NULL DEFAULT '', object_id TEXT NOT NULL,
      alias TEXT, scope TEXT, created_at TEXT NOT NULL,
      PRIMARY KEY (subject_id, relation, object_type, holder_id, object_id)
    );
    CREATE INDEX relations_object ON relations(object_type, holder_id, object_id, relation);
    CREATE UNIQUE INDEX relations_alias ON relations(subject_id, relation, alias) WHERE alias IS NOT NULL;
    CREATE TABLE settings (
      principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
      return_url TEXT NOT NULL, refresh_url TEXT, webhook_url TEXT, webhook_secret TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE records (
      id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
      object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
    );
    CREATE INDEX records_actor ON records(actor_id, at);
    CREATE INDEX records_object ON records(object_type, object_id, at);
  `);
  const relate = db.prepare('INSERT OR IGNORE INTO relations (subject_id,relation,object_type,object_id,alias,scope,created_at) VALUES (?,?,?,?,?,?,?)');
  for (const row of db.prepare('SELECT id,owner_id,created_at FROM keys').all()) {
    relate.run(row.owner_id, 'owner', 'principal', row.id, null, null, row.created_at);
    relate.run(row.id, 'actor', 'principal', row.owner_id, null, null, row.created_at);
  }
  for (const row of db.prepare('SELECT * FROM integrations').all()) {
    relate.run(row.owner_id, 'owner', 'principal', row.id, null, null, row.created_at);
    db.prepare('INSERT INTO settings (principal_id,return_url,refresh_url,webhook_url,webhook_secret,created_at) VALUES (?,?,?,?,?,?)')
      .run(row.id, row.return_url, row.refresh_url, row.webhook_url, row.webhook_secret, row.created_at);
  }
  for (const row of db.prepare('SELECT * FROM accounts').all()) relate.run(row.integration_id, 'owner', 'principal', row.id, row.external_id, null, row.created_at);
  // Requests now name who asks and who is asked. A key still waiting to be approved is a principal with a
  // credential and an open request to nobody in particular; finished approvals are not carried.
  db.exec(`
    CREATE TABLE requests_next (
      id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT,
      kind TEXT NOT NULL CHECK(kind IN ('actor','store','connect')), input TEXT NOT NULL,
      purpose TEXT NOT NULL, steps TEXT NOT NULL, code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','denied','cancelled')),
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    INSERT INTO requests_next (id,from_id,to_id,kind,input,purpose,steps,progress,result,reason,status,created_at,expires_at)
      SELECT r.id,r.key_id,r.owner_id,r.kind,r.input,r.purpose,r.steps,r.progress,r.result,r.reason,r.status,r.created_at,r.expires_at
      FROM requests r;
  `);
  for (const row of db.prepare('SELECT * FROM key_requests WHERE expires_at>?').all(Date.now())) {
    let from = row.key_id ?? row.id;
    if (row.status === 'pending') {
      from = db.prepare('SELECT lower(hex(randomblob(16))) AS id').get().id;
      db.prepare('INSERT INTO principals (id,name,created_at) VALUES (?,?,?)').run(from, row.name, now);
      db.prepare("INSERT INTO credentials (id,hash,principal_id,kind,created_at) VALUES (lower(hex(randomblob(16))),?,?,'key',?)").run(row.token_hash, from, now);
    }
    db.prepare('INSERT INTO requests_next (id,from_id,to_id,kind,input,purpose,steps,code,attempts,progress,result,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(row.id, from, row.owner_id ?? null, 'actor', JSON.stringify({ name: row.name }), '', '[]', row.confirmation_code, row.confirmation_attempts, row.progress,
        row.status === 'done' ? JSON.stringify({ principal_id: row.key_id }) : null, row.status, row.created_at, row.expires_at);
  }
  for (const row of db.prepare('SELECT * FROM request_links WHERE expires_at>?').all(Date.now())) {
    db.prepare("INSERT OR IGNORE INTO credentials (id,hash,principal_id,kind,scope,expires_at,created_at) VALUES (lower(hex(randomblob(16))),?,?,'link',?,?,?)")
      .run(row.token_hash, row.owner_id, 'request:' + row.request_id, row.expires_at, now);
  }
  db.exec(`
    DROP TABLE requests;
    ALTER TABLE requests_next RENAME TO requests;
    CREATE INDEX requests_from ON requests(from_id, created_at);
    CREATE INDEX requests_to ON requests(to_id, created_at);
    DROP TABLE key_requests;
    DROP TABLE request_links;
    DROP TABLE accounts;
    DROP TABLE integrations;
    DROP TABLE keys;
  `);
}

// Whoever comes to Foundation is a principal: a row of its own, with a name and a beginning, and the
// credentials that prove it kept apart from it. Keys and apps had carried their own hash and name; those
// move to the principal they are. People known only by the id their login gave them get a row too.
function migratePrincipals({ db }) {
  db.exec(`
    CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
    CREATE TABLE credentials (
      hash TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK(kind IN ('key','app-key')), created_at TEXT NOT NULL, last_used_at TEXT
    );
    CREATE INDEX credentials_principal ON credentials(principal_id);
  `);
  const principal = db.prepare('INSERT OR IGNORE INTO principals (id,name,created_at) VALUES (?,?,?)');
  const credential = db.prepare('INSERT INTO credentials (hash,principal_id,kind,created_at,last_used_at) VALUES (?,?,?,?,?)');
  for (const row of db.prepare('SELECT id,name,created_at,token_hash,last_used_at FROM keys').all()) {
    principal.run(row.id, row.name, row.created_at); credential.run(row.token_hash, row.id, 'key', row.created_at, row.last_used_at);
  }
  for (const row of db.prepare('SELECT id,name,created_at,token_hash,last_used_at FROM integrations').all()) {
    principal.run(row.id, row.name, row.created_at); credential.run(row.token_hash, row.id, 'app-key', row.created_at, row.last_used_at);
  }
  for (const row of db.prepare('SELECT id,created_at FROM accounts').all()) principal.run(row.id, '', row.created_at);
  const now = new Date().toISOString();
  for (const table of ['keys', 'integrations', 'secrets', 'connections', 'sessions', 'requests', 'key_requests']) {
    for (const row of db.prepare(`SELECT DISTINCT owner_id FROM ${table} WHERE owner_id IS NOT NULL`).all()) principal.run(row.owner_id, '', now);
  }
  db.exec(`
    CREATE TABLE keys_next (id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE, owner_id TEXT NOT NULL, created_at TEXT NOT NULL);
    INSERT INTO keys_next SELECT id,owner_id,created_at FROM keys;
    DROP TABLE keys;
    ALTER TABLE keys_next RENAME TO keys;
    CREATE TABLE integrations_next (
      id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE, owner_id TEXT NOT NULL,
      return_url TEXT NOT NULL, refresh_url TEXT, webhook_url TEXT, webhook_secret TEXT, created_at TEXT NOT NULL
    );
    INSERT INTO integrations_next SELECT id,owner_id,return_url,refresh_url,webhook_url,webhook_secret,created_at FROM integrations;
    DROP TABLE integrations;
    ALTER TABLE integrations_next RENAME TO integrations;
  `);
}

function migrateResponsibilities({ db, vault }) {
  db.exec(`
    ALTER TABLE acquisitions RENAME TO connections;
    ALTER TABLE connections RENAME COLUMN adapter TO connector;
    DROP INDEX acquisitions_owner;
    CREATE INDEX connections_owner ON connections(owner_id,id);
    ALTER TABLE keys DROP COLUMN issued_until;
    ALTER TABLE keys DROP COLUMN issued_nonexpiring;
    DROP TABLE invocations;
    ALTER TABLE requests RENAME TO previous_requests;
    DROP INDEX requests_token;
    CREATE TABLE requests (
      id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, key_id TEXT NOT NULL, owner_id TEXT NOT NULL, requester_name TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('connect','store')), input TEXT NOT NULL,
      purpose TEXT NOT NULL, steps TEXT NOT NULL, progress TEXT, result TEXT, reason TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','done','denied','cancelled')),
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    CREATE INDEX requests_token ON requests(token_hash,created_at);
    UPDATE key_requests SET status='done' WHERE status='approved';
  `);
  for (const row of db.prepare('SELECT * FROM previous_requests').all()) {
    const kind = row.adapter ? 'connect' : 'store';
    const input = kind === 'connect' ? { connector: row.adapter } : { fields: JSON.parse(row.details) };
    const result = row.status === 'done' ? kind === 'connect' ? { connection_id: row.credential_id } : { names: JSON.parse(row.credential_id) } : null;
    const cancelled = row.status === 'pending' && !db.prepare('SELECT 1 FROM keys WHERE id=? AND owner_id=? AND token_hash=?').get(row.key_id, row.owner_id, row.token_hash);
    db.prepare('INSERT INTO requests (id,token_hash,key_id,owner_id,requester_name,kind,input,purpose,steps,progress,result,reason,status,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(row.id, row.token_hash, row.key_id, row.owner_id, row.requester_name, kind, JSON.stringify(input), row.purpose, row.steps, row.progress,
        result === null ? null : JSON.stringify(result), cancelled ? 'requester_revoked' : null, cancelled ? 'cancelled' : row.status, row.created_at, row.expires_at);
  }
  db.exec('DROP TABLE previous_requests;');
  for (const row of db.prepare('SELECT id,owner_id,state FROM connections').all()) {
    const old = vault.open(row.state, `acquisition:${row.owner_id}:${row.id}`);
    const state = { private_state: Object.hasOwn(old, 'private_state') ? old.private_state : old.renewal, facts: old.facts || {}, expires_at: old.expires_at ?? null };
    db.prepare('UPDATE connections SET state=? WHERE id=?').run(vault.seal(state, `connection:${row.owner_id}:${row.id}`), row.id);
  }
  for (const row of db.prepare('SELECT * FROM oauth_flows').all()) {
    const binding = `oauth:${row.session_id}:${row.id}`, { adapter, ...flow } = vault.open(row.payload, binding);
    db.prepare('UPDATE oauth_flows SET payload=? WHERE id=?').run(vault.seal({ ...flow, connector: adapter }, binding), row.id);
  }
}

function migrateNames(store) {
  const { db, vault } = store;
  db.exec('ALTER TABLE secrets RENAME COLUMN path TO name;');
  // Preserve every stored value as-is. Formerly generated values are ordinary snapshots,
  // not candidates for deletion or ownership inference during migration.
  const connections = db.prepare('SELECT owner_id,prefix,id FROM acquisitions').all();
  const connectionId = (owner, prefix) => connections.find(row => row.owner_id === owner && row.prefix === prefix)?.id;
  for (const request of db.prepare('SELECT id,owner_id,adapter,details,credential_id FROM requests').all()) {
    const details = JSON.parse(request.details).map(({ path, ...rest }) => ({ name: path, ...rest }));
    const target = request.credential_id === null ? null : request.adapter
      ? connectionId(request.owner_id, request.credential_id) ?? request.credential_id
      : JSON.stringify(request.credential_id.split(', '));
    db.prepare('UPDATE requests SET details=?,credential_id=? WHERE id=?').run(JSON.stringify(details), target, request.id);
  }
  for (const flow of db.prepare('SELECT f.*,s.owner_id FROM oauth_flows f JOIN sessions s ON s.id=f.session_id').all()) {
    const binding = `oauth:${flow.session_id}:${flow.id}`;
    const value = vault.open(flow.payload, binding);
    if (value.previous?.prefix) {
      const { prefix, ...previous } = value.previous;
      value.previous = { ...previous, id: connectionId(flow.owner_id, prefix) ?? prefix };
      db.prepare('UPDATE oauth_flows SET payload=? WHERE id=?').run(vault.seal(value, binding), flow.id);
    }
  }
  db.exec(`
    ALTER TABLE acquisitions RENAME TO previous_acquisitions;
    CREATE TABLE acquisitions (
      id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, adapter TEXT NOT NULL, subject TEXT NOT NULL,
      label TEXT NOT NULL, state TEXT NOT NULL, status TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
      kept_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      UNIQUE(owner_id, adapter, subject)
    );
    INSERT INTO acquisitions SELECT id,owner_id,adapter,subject,label,state,status,generation,kept_by,created_at,updated_at FROM previous_acquisitions;
    DROP TABLE previous_acquisitions;
    CREATE INDEX acquisitions_owner ON acquisitions(owner_id,id);
  `);
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
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('secret','object','connection')), name TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0, readable INTEGER NOT NULL DEFAULT 0, type TEXT, content BLOB,
    connector TEXT, subject TEXT, status TEXT, generation INTEGER NOT NULL DEFAULT 1, kept_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX holdings_holder ON holdings(holder_id, kind, name);
  CREATE UNIQUE INDEX holdings_name ON holdings(holder_id, kind, name) WHERE kind <> 'connection';
  CREATE TABLE records (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX records_actor ON records(actor_id, at);
  CREATE INDEX records_object ON records(object_type, object_id, at);
  PRAGMA user_version = ${SCHEMA_VERSION};
`;
