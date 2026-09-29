export const SCHEMA_VERSION = 34;
// The schema as it is, and the steps from every version a running Foundation may still be on. A version nobody
// runs any more has no step: a database older than the oldest step is refused, not migrated.
export const STEPS = {
  31: oneKindOfLine,
  32: separateSecrets,
  33: namesApart,
  34: requestsAsDetails,
};

// What one principal was given is kept in one place. A line names a role (owner, actor, viewer, editor) or one
// action (credential.disconnect); the permissions kept beside it join it, and the scope nothing read goes.
function oneKindOfLine({ db }) {
  db.exec(`
    CREATE TABLE relations_next (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL,
    alias TEXT, created_at TEXT NOT NULL,
    PRIMARY KEY (subject_id, relation, object_type, object_id)
    );
    INSERT INTO relations_next SELECT subject_id, relation, object_type, object_id, alias, created_at FROM relations;
    INSERT OR IGNORE INTO relations_next SELECT subject_id, action, object_type, object_id, NULL, created_at FROM permissions;
    DROP TABLE permissions; DROP TABLE relations; ALTER TABLE relations_next RENAME TO relations;
    CREATE INDEX relations_object ON relations(object_type, object_id, relation);
    CREATE UNIQUE INDEX relations_alias ON relations(subject_id, relation, alias) WHERE alias IS NOT NULL;
  `);
}
oneKindOfLine.rebuilds = true;

// Keep private bytes independently of managed authorizations. IDs, ownership and the existing values survive.
// A legacy token with several input fields becomes one ordinary JSON secret, retaining every input field.
function separateSecrets({ db, vault }) {
  const rows = db.prepare(`SELECT r.*,c.service,c.auth_scheme,c.state,c.generation FROM resources r JOIN credentials c ON c.resource_id=r.id
    WHERE c.service IS NULL OR c.auth_scheme='token' ORDER BY (c.service IS NOT NULL),r.created_at,r.id`).all();
  db.exec(`
    CREATE TABLE resources_next (
      id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('secret','credential','object','app','service','environment')), name TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    INSERT INTO resources_next SELECT * FROM resources;
    CREATE TABLE secrets (
      resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
      size INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 1, content BLOB NOT NULL
    );
    CREATE TABLE credentials_next (
      resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
      service TEXT NOT NULL, auth_scheme TEXT NOT NULL CHECK(auth_scheme IN ('oauth','role')),
      app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
      generation INTEGER NOT NULL DEFAULT 1, state BLOB
    );
    INSERT INTO credentials_next SELECT resource_id,service,auth_scheme,app_id,subject,status,generation,state FROM credentials WHERE auth_scheme IN ('oauth','role');
  `);
  const used = new Set();
  const ordinary = ['list', 'read', 'content', 'write', 'remove', 'rename', 'share'];
  for (const row of rows) {
    const context = `credential:${row.holder_id}:${row.id}`;
    let content;
    if (row.service === null) content = vault.openBytes(row.state, context);
    else {
      const fields = vault.open(row.state, context)?.private_state?.fields;
      if (!fields || typeof fields !== 'object' || Array.isArray(fields) || !Object.keys(fields).length || Object.values(fields).some(value => typeof value !== 'string')) {
        throw new Error('A stored token cannot be migrated safely: ' + row.id);
      }
      content = Buffer.from(Object.keys(fields).length === 1 ? Object.values(fields)[0] : JSON.stringify(fields), 'utf8');
    }
    let name = row.name;
    for (let suffix = 1; used.has(row.holder_id + ':' + name); suffix++) {
      const tail = ' (' + row.id + (suffix > 1 ? '-' + suffix : '') + ')', prefix = Array.from(row.name);
      while (prefix.join('').length + tail.length > 200) prefix.pop();
      name = prefix.join('') + tail;
    }
    used.add(row.holder_id + ':' + name);
    db.prepare("UPDATE resources_next SET kind='secret',name=? WHERE id=?").run(name, row.id);
    db.prepare('INSERT INTO secrets (resource_id,size,generation,content) VALUES (?,?,?,?)')
      .run(row.id, content.length, row.generation, vault.sealBytes(content, `secret:${row.holder_id}:${row.id}`));
    const lines = db.prepare("SELECT * FROM relations WHERE object_type='resource' AND object_id=?").all(row.id);
    for (const line of lines) {
      // Viewing a former connection only exposed its metadata; migration must not expose its token to that viewer.
      const managed = row.service !== null;
      const relation = managed && ['viewer', 'editor'].includes(line.relation) ? 'secret.read'
        : managed && ['credential.content', 'credential.write', 'credential.remove'].includes(line.relation) ? null
        : managed && line.relation === 'credential.disconnect' ? 'secret.remove'
        : ordinary.some(action => line.relation === 'credential.' + action) ? line.relation.replace('credential.', 'secret.') : line.relation;
      if (relation !== line.relation) {
        db.prepare('DELETE FROM relations WHERE subject_id=? AND relation=? AND object_type=? AND object_id=?').run(line.subject_id, line.relation, line.object_type, line.object_id);
        if (relation) db.prepare('INSERT OR IGNORE INTO relations (subject_id,relation,object_type,object_id,alias,created_at) VALUES (?,?,?,?,?,?)')
          .run(line.subject_id, relation, line.object_type, line.object_id, line.alias, line.created_at);
      }
    }
  }
  for (const action of ordinary) db.prepare(`INSERT OR IGNORE INTO relations (subject_id,relation,object_type,object_id,alias,created_at)
    SELECT subject_id,?,object_type,object_id,alias,created_at FROM relations WHERE object_type='principal' AND relation=?`).run('secret.' + action, 'credential.' + action);
  db.exec(`
    DELETE FROM relations WHERE relation IN ('credential.content','credential.write','credential.remove','credential.register-token');
    DROP TABLE credentials; DROP TABLE resources;
    ALTER TABLE resources_next RENAME TO resources;
    ALTER TABLE credentials_next RENAME TO credentials;
    CREATE INDEX resources_holder ON resources(holder_id,kind,name);
    CREATE UNIQUE INDEX resources_secret_name ON resources(holder_id,name) WHERE kind='secret';
    CREATE UNIQUE INDEX resources_object_name ON resources(holder_id,name) WHERE kind='object';
    CREATE UNIQUE INDEX resources_app_name ON resources(holder_id,name) WHERE kind='app';
    CREATE UNIQUE INDEX resources_service_name ON resources(holder_id,name) WHERE kind='service';
    CREATE INDEX credentials_app ON credentials(app_id) WHERE app_id IS NOT NULL;
    UPDATE requests SET status='cancelled',reason='request_changed' WHERE kind='connect' AND status='pending' AND json_extract(input,'$.auth_scheme')='token';
  `);
  for (const row of db.prepare('SELECT resource_id,definition FROM services').all()) {
    const definition = JSON.parse(row.definition);
    if (definition.auth_schemes?.token) {
      delete definition.auth_schemes.token;
      db.prepare('UPDATE services SET definition=? WHERE resource_id=?').run(JSON.stringify(definition), row.resource_id);
    }
  }
}
separateSecrets.rebuilds = true;

// A line says who, which relation, onto what, and nothing more: the name an owner calls what it owns by is the
// owner's own record. What is done to a principal as a whole is named as that principal's action.
function namesApart({ db }) {
  db.exec(`
    CREATE TABLE aliases (
    owner_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    alias TEXT NOT NULL, PRIMARY KEY (owner_id, principal_id), UNIQUE (owner_id, alias)
    );
    INSERT INTO aliases SELECT subject_id, object_id, alias FROM relations WHERE relation='owner' AND object_type='principal' AND alias IS NOT NULL;
    CREATE TABLE relations_next (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (subject_id, relation, object_type, object_id)
    );
    INSERT OR IGNORE INTO relations_next SELECT subject_id, CASE relation WHEN 'overview.read' THEN 'principal.overview' WHEN 'export.read' THEN 'principal.export' WHEN 'usage.read' THEN 'principal.usage' WHEN 'injection.create' THEN 'principal.inject' WHEN 'function.list' THEN 'principal.functions' WHEN 'function.invoke' THEN 'principal.invoke' WHEN 'resource.list' THEN 'principal.shown' WHEN 'audit_log.list' THEN 'principal.audit-log' ELSE relation END, object_type, object_id, created_at FROM relations;
    DROP TABLE relations; ALTER TABLE relations_next RENAME TO relations;
    CREATE INDEX relations_object ON relations(object_type, object_id, relation);
  `);
}
namesApart.rebuilds = true;

// A request says what it asks as authorization details (RFC 9396): a type and what that type needs. Asking to act for
// someone becomes asking for a relation; a store, a connect and an app request keep their input as their detail. Who
// asked is kept by the name they had then. A request is granted, not done; the code a person types is a user code, and only a request addressed to nobody has one.
function requestsAsDetails({ db }) {
  db.exec(`
    CREATE TABLE requests_next (
    id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT,
    type TEXT NOT NULL CHECK(type IN ('relation','secret','credential','app')), detail TEXT NOT NULL,
    requester_name TEXT NOT NULL DEFAULT '', binding_message TEXT NOT NULL, steps TEXT NOT NULL, user_code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','granted','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    INSERT INTO requests_next SELECT id, from_id, to_id,
      CASE kind WHEN 'actor' THEN 'relation' WHEN 'store' THEN 'secret' WHEN 'connect' THEN 'credential' ELSE 'app' END,
      CASE kind WHEN 'actor' THEN '{"relation":"actor"}' ELSE input END,
      COALESCE(CASE kind WHEN 'actor' THEN json_extract(input, '$.name') END, (SELECT name FROM principals WHERE id=from_id), ''),
      purpose, steps, CASE WHEN to_id IS NULL THEN code END, attempts, progress,
      CASE WHEN kind='actor' AND status='done' THEN json_object('relation','actor','object_type','principal','object_id',to_id) ELSE result END,
      reason, CASE status WHEN 'done' THEN 'granted' ELSE status END, created_at, expires_at
    FROM requests;
    DROP TABLE requests; ALTER TABLE requests_next RENAME TO requests;
    CREATE INDEX requests_from ON requests(from_id, created_at);
    CREATE INDEX requests_to ON requests(to_id, created_at);
  `);
}
requestsAsDetails.rebuilds = true;

export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
  CREATE TABLE access_keys (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, last_used_at TEXT, expires_at INTEGER, environment_id TEXT
  );
  CREATE INDEX access_keys_principal ON access_keys(principal_id);
  CREATE TABLE request_links (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL
  );
  CREATE INDEX request_links_principal ON request_links(principal_id);
  CREATE TABLE relations (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY (subject_id, relation, object_type, object_id)
  );
  CREATE INDEX relations_object ON relations(object_type, object_id, relation);
  CREATE TABLE aliases (
    owner_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    alias TEXT NOT NULL, PRIMARY KEY (owner_id, principal_id), UNIQUE (owner_id, alias)
  );
  CREATE TABLE settings (
    principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    return_url TEXT NOT NULL, refresh_url TEXT, webhook_url TEXT, webhook_secret TEXT, created_at TEXT NOT NULL
  );
  CREATE TABLE sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL, secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE requests (
    id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT,
    type TEXT NOT NULL CHECK(type IN ('relation','secret','credential','app')), detail TEXT NOT NULL,
    requester_name TEXT NOT NULL DEFAULT '', binding_message TEXT NOT NULL, steps TEXT NOT NULL, user_code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','granted','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX requests_from ON requests(from_id, created_at);
  CREATE INDEX requests_to ON requests(to_id, created_at);
  -- What a holder holds: one row each, and a row in the table of its kind.
  CREATE TABLE resources (
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('secret','credential','object','app','service','environment')), name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX resources_holder ON resources(holder_id, kind, name);
  CREATE UNIQUE INDEX resources_secret_name ON resources(holder_id, name) WHERE kind='secret';
  CREATE UNIQUE INDEX resources_object_name ON resources(holder_id, name) WHERE kind='object';
  CREATE UNIQUE INDEX resources_app_name ON resources(holder_id, name) WHERE kind='app';
  CREATE UNIQUE INDEX resources_service_name ON resources(holder_id, name) WHERE kind='service';
  -- Arbitrary private bytes are not managed authorizations.
  CREATE TABLE secrets (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    size INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 1, content BLOB NOT NULL
  );
  -- State used to obtain or renew credentials at a service.
  CREATE TABLE credentials (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    service TEXT NOT NULL, auth_scheme TEXT NOT NULL CHECK(auth_scheme IN ('oauth','role')),
    app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
    generation INTEGER NOT NULL DEFAULT 1, state BLOB
  );
  CREATE INDEX credentials_app ON credentials(app_id) WHERE app_id IS NOT NULL;
  CREATE TABLE objects (resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
  -- An OAuth app someone holds: which service it is for, its client ID, what else is said of it, and its sealed secret.
  CREATE TABLE apps (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    service TEXT NOT NULL, client_id TEXT NOT NULL, secret BLOB NOT NULL, settings TEXT NOT NULL DEFAULT '{}'
  );
  -- A service a holder described, for one Foundation's catalog does not know.
  CREATE TABLE services (resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE, definition TEXT NOT NULL);
  -- A machine lent to a holder: what it is, how long it lives, who it acts as inside (if anyone), and where it runs.
  CREATE TABLE environments (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    size TEXT NOT NULL, lifetime TEXT NOT NULL CHECK(lifetime IN ('exit','idle')), idle_seconds INTEGER NOT NULL, max_seconds INTEGER NOT NULL,
    identity TEXT, runner TEXT NOT NULL, machine TEXT,
    status TEXT NOT NULL CHECK(status IN ('starting','ready','busy','stopped')),
    started_at INTEGER NOT NULL, last_active_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE TABLE environment_commands (
    id TEXT PRIMARY KEY, environment_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE, by_id TEXT NOT NULL,
    command TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('running','done','timed_out','failed')),
    exit_code INTEGER, stdout TEXT, stderr TEXT, started_at INTEGER NOT NULL, ended_at INTEGER
  );
  CREATE INDEX environment_commands_environment ON environment_commands(environment_id, started_at);
  -- Computing is spent, not lent: what each principal used in a month, and the most its owner lets it use.
  CREATE TABLE compute_usage (principal_id TEXT NOT NULL, month TEXT NOT NULL, seconds INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (principal_id, month));
  CREATE TABLE compute_limits (principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE, monthly_seconds INTEGER NOT NULL);
  CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX audit_log_actor ON audit_log(actor_id, at);
  CREATE INDEX audit_log_object ON audit_log(object_type, object_id, at);
  PRAGMA user_version = ${SCHEMA_VERSION};
`;
