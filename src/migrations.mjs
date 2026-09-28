export const SCHEMA_VERSION = 31;
// The schema as it is, and the steps from every version a running Foundation may still be on. A version nobody
// runs any more has no step: a database older than the oldest step is refused, not migrated.
export const STEPS = {
  31: oneKindOfLine,
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
    object_type TEXT NOT NULL CHECK(object_type IN ('principal','resource')), object_id TEXT NOT NULL,
    alias TEXT, created_at TEXT NOT NULL,
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
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('credential','object','app','service','environment')), name TEXT NOT NULL,
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
