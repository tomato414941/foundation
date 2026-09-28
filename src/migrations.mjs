import { randomUUID } from 'node:crypto';

export const SCHEMA_VERSION = 27;
// The schema as it is, and the steps from every version a running Foundation may still be on. A version nobody
// runs any more has no step: a database older than the oldest step is refused, not migrated.
export const STEPS = {
  27: holdByService,
};

// The names for what is kept became those of the rest of the field, and a credential says the service it works at
// and the scheme it came by, where a connector said both in one name:
//   holdings -> resources      grants -> credentials (a given grant is a secret: no service)
//   credentials (of principals) -> access_keys      records -> audit_log      lines onto 'holding' -> 'resource'
// A generic OAuth 2.0 app named its service in its own settings; that service becomes a service its holder
// described, and the app and its credentials point at it. Each credential's state is sealed again under its new
// binding. Flows in progress named connectors, and are dropped: whoever was connecting starts again.
function holdByService(store) {
  const db = store.db, vault = store.vault;
  const serviceOf = connector => {
    if (connector === 'aws.role') return ['aws', 'role'];
    const match = /^([a-z][a-z0-9-]*)\.oauth$/.exec(connector ?? '');
    if (!match) throw new Error('Migration cannot place connector ' + connector);
    return [match[1], 'oauth'];
  };
  const rename = value => value === undefined || value === null ? value : value === 'oauth2' ? 'oauth2' : serviceOf(value)[0];
  const grants = db.prepare('SELECT g.*, h.holder_id FROM grants g JOIN holdings h ON h.id=g.holding_id').all();
  const apps = db.prepare('SELECT a.*, h.holder_id, h.name, h.created_at, h.updated_at FROM apps a JOIN holdings h ON h.id=a.holding_id').all();
  db.exec(`
    ALTER TABLE credentials RENAME TO access_keys;
    DROP INDEX IF EXISTS credentials_principal; CREATE INDEX access_keys_principal ON access_keys(principal_id);
    CREATE TABLE resources (
      id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('credential','object','app','service')), name TEXT NOT NULL,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE credentials (
      resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
      service TEXT, auth_scheme TEXT CHECK(auth_scheme IN ('oauth','token','role')),
      app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
      generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB,
      CHECK((service IS NULL) = (auth_scheme IS NULL))
    );
    CREATE TABLE objects_next (resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
    CREATE TABLE apps_next (
      resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
      service TEXT NOT NULL, client_id TEXT NOT NULL, secret BLOB NOT NULL, settings TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE services (resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE, definition TEXT NOT NULL);
    INSERT INTO resources SELECT id, holder_id, CASE kind WHEN 'grant' THEN 'credential' ELSE kind END, name, created_at, updated_at FROM holdings;
    INSERT INTO objects_next SELECT holding_id, size, type FROM objects;
  `);
  // A generic app's service, described by its holder under the app's own name.
  const described = new Map();
  const insertResource = db.prepare('INSERT INTO resources (id,holder_id,kind,name,created_at,updated_at) VALUES (?,?,?,?,?,?)');
  const insertService = db.prepare('INSERT INTO services (resource_id,definition) VALUES (?,?)');
  const insertApp = db.prepare('INSERT INTO apps_next (resource_id,service,client_id,secret,settings) VALUES (?,?,?,?,?)');
  for (const app of apps) {
    if (app.connector !== 'oauth2') { insertApp.run(app.holding_id, serviceOf(app.connector)[0], app.client_id, app.secret, app.settings); continue; }
    const settings = JSON.parse(app.settings), id = randomUUID();
    const definition = { version: 1, name: settings.service_name, ...(settings.api_base_url ? { api: settings.api_base_url } : {}), auth_schemes: { oauth: {
      authorize: settings.authorize_url, token: settings.token_url,
      ...(settings.userinfo_url ? { identity: { url: settings.userinfo_url } } : {}), ...(settings.revoke_url ? { revoke: { url: settings.revoke_url, style: 'rfc7009' } } : {}),
      injection: { OAUTH_ACCESS_TOKEN: '{access_token}', OAUTH_EXPIRES_AT: '{expires_at}' } } } };
    insertResource.run(id, app.holder_id, 'service', app.name, app.created_at, app.updated_at);
    insertService.run(id, JSON.stringify(definition));
    insertApp.run(app.holding_id, id, app.client_id, app.secret, '{}');
    described.set(app.holding_id, id);
  }
  const insertCredential = db.prepare('INSERT INTO credentials (resource_id,service,auth_scheme,app_id,subject,status,generation,size,state) VALUES (?,?,?,?,?,?,?,?,?)');
  for (const grant of grants) {
    const from = `grant:${grant.holder_id}:${grant.holding_id}`, to = `credential:${grant.holder_id}:${grant.holding_id}`;
    if (grant.method === 'given') {
      insertCredential.run(grant.holding_id, null, null, null, null, grant.status, grant.generation, grant.size, vault.sealBytes(vault.openBytes(grant.state, from), to));
      continue;
    }
    const [service, scheme] = grant.connector === 'oauth2' ? [described.get(grant.app_id), 'oauth'] : serviceOf(grant.connector);
    if (!service) throw new Error('Migration cannot place a generic connection without its app: ' + grant.holding_id);
    insertCredential.run(grant.holding_id, service, scheme, grant.app_id, grant.subject, grant.status, grant.generation, grant.size, vault.seal(vault.open(grant.state, from), to));
  }
  // Lines onto what is held point at resources; the audit log speaks of credentials, keys and injections.
  db.exec(`
    DROP TABLE grants; DROP TABLE objects; DROP TABLE apps; DROP TABLE holdings;
    ALTER TABLE objects_next RENAME TO objects; ALTER TABLE apps_next RENAME TO apps;
    CREATE INDEX resources_holder ON resources(holder_id, kind, name);
    CREATE UNIQUE INDEX resources_object_name ON resources(holder_id, name) WHERE kind='object';
    CREATE UNIQUE INDEX resources_app_name ON resources(holder_id, name) WHERE kind='app';
    CREATE UNIQUE INDEX resources_service_name ON resources(holder_id, name) WHERE kind='service';
    CREATE INDEX credentials_app ON credentials(app_id) WHERE app_id IS NOT NULL;
    CREATE TABLE relations_next (
      subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
      object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL,
      alias TEXT, scope TEXT, created_at TEXT NOT NULL,
      PRIMARY KEY (subject_id, relation, object_type, object_id)
    );
    INSERT INTO relations_next SELECT subject_id, relation, CASE object_type WHEN 'holding' THEN 'resource' ELSE object_type END, object_id, alias, scope, created_at FROM relations;
    DROP TABLE relations; ALTER TABLE relations_next RENAME TO relations;
    CREATE INDEX relations_object ON relations(object_type, object_id, relation);
    CREATE UNIQUE INDEX relations_alias ON relations(subject_id, relation, alias) WHERE alias IS NOT NULL;
    CREATE TABLE audit_log (
      id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
      object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
    );
    CREATE INDEX audit_log_actor ON audit_log(actor_id, at);
    CREATE INDEX audit_log_object ON audit_log(object_type, object_id, at);
    DELETE FROM oauth_flows;
  `);
  const ACTIONS = { 'connection.created': 'credential.created', 'connection.renewed': 'credential.renewed', 'connection.removed': 'credential.removed',
    delivery: 'injection', 'credential.issued': 'key.issued', 'credential.revoked': 'key.revoked' };
  const TYPES = { holding: 'resource', grant: 'credential' };
  // A detail that named a connector names its service; one that named a principal's credential names its key.
  const detail = (action, value) => {
    const next = { ...value };
    if ('connector' in next) { next.service = rename(next.connector); delete next.connector; }
    if (action === 'credential.revoked' && 'credential' in next) { next.key = next.credential; delete next.credential; }
    if ('connections_stopped' in next) { next.credentials_stopped = next.connections_stopped; delete next.connections_stopped; }
    return next;
  };
  const insertEntry = db.prepare('INSERT INTO audit_log (id,at,actor_id,action,object_type,object_id,detail) VALUES (?,?,?,?,?,?,?)');
  for (const row of db.prepare('SELECT * FROM records').all()) {
    insertEntry.run(row.id, row.at, row.actor_id, ACTIONS[row.action] ?? row.action, TYPES[row.object_type] ?? row.object_type, row.object_id, JSON.stringify(detail(row.action, JSON.parse(row.detail))));
  }
  db.exec('DROP TABLE records;');
  // Requests to connect or to register an app named a connector and a connection; they name a service, a scheme and
  // a credential. What happened to them names services.
  const renamed = value => {
    if (Array.isArray(value)) return value.map(renamed);
    if (!value || typeof value !== 'object') return value;
    const next = {};
    for (const [key, one] of Object.entries(value)) {
      if (key === 'connector') next.service = rename(one);
      else if (key === 'connection_id') next.credential_id = one;
      else next[key] = renamed(one);
    }
    return next;
  };
  const update = db.prepare('UPDATE requests SET input=?, result=?, progress=? WHERE id=?');
  for (const row of db.prepare("SELECT id, kind, input, result, progress FROM requests WHERE kind IN ('connect','app') OR progress LIKE '%connector%'").all()) {
    const input = renamed(JSON.parse(row.input));
    if (row.kind === 'connect' && input.service !== undefined && input.auth_scheme === undefined) input.auth_scheme = input.service === 'aws' ? 'role' : 'oauth';
    update.run(JSON.stringify(input), row.result === null ? null : JSON.stringify(renamed(JSON.parse(row.result))), row.progress === null ? null : JSON.stringify(renamed(JSON.parse(row.progress))), row.id);
  }
}

export const SCHEMA = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
  CREATE TABLE access_keys (
    id TEXT PRIMARY KEY, hash TEXT NOT NULL UNIQUE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('key','link')), scope TEXT, expires_at INTEGER, created_at TEXT NOT NULL, last_used_at TEXT
  );
  CREATE INDEX access_keys_principal ON access_keys(principal_id);
  CREATE TABLE relations (
    subject_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, relation TEXT NOT NULL CHECK(relation IN ('owner','actor','viewer','editor')),
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL,
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
  -- What a holder holds: one row each, and a row in the table of its kind.
  CREATE TABLE resources (
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('credential','object','app','service')), name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX resources_holder ON resources(holder_id, kind, name);
  CREATE UNIQUE INDEX resources_object_name ON resources(holder_id, name) WHERE kind='object';
  CREATE UNIQUE INDEX resources_app_name ON resources(holder_id, name) WHERE kind='app';
  CREATE UNIQUE INDEX resources_service_name ON resources(holder_id, name) WHERE kind='service';
  -- A credential for a service (by the scheme it came by), or a secret (no service).
  CREATE TABLE credentials (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    service TEXT, auth_scheme TEXT CHECK(auth_scheme IN ('oauth','token','role')),
    app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
    generation INTEGER NOT NULL DEFAULT 1, size INTEGER NOT NULL DEFAULT 0, state BLOB,
    CHECK((service IS NULL) = (auth_scheme IS NULL))
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
  CREATE TABLE audit_log (
    id TEXT PRIMARY KEY, at TEXT NOT NULL, actor_id TEXT NOT NULL, action TEXT NOT NULL,
    object_type TEXT NOT NULL, object_id TEXT NOT NULL, detail TEXT NOT NULL
  );
  CREATE INDEX audit_log_actor ON audit_log(actor_id, at);
  CREATE INDEX audit_log_object ON audit_log(object_type, object_id, at);
  PRAGMA user_version = ${SCHEMA_VERSION};
`;
