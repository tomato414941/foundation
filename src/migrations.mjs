import { checkDefinition } from './service-definition.mjs';
import { ensureAgent } from './keys.mjs';
import { newContentKey, sealContent, seal } from '../cli/envelope.mjs';

export const SCHEMA_VERSION = 47;
// The schema as it is, and the steps from every version a running Foundation may still be on. A version nobody
// runs any more has no step: a database older than the oldest step is refused, not migrated.
export const STEPS = {
  31: oneKindOfLine,
  32: separateSecrets,
  33: namesApart,
  34: requestsAsDetails,
  35: standardReferences,
  36: connectionsWithMethods,
  37: provenHere,
  38: addressesOnly,
  39: passkeys,
  40: webauthnCredentials,
  41: payment,
  42: agents,
  43: durableEnvironmentStops,
  44: envelopes,
  45: ownerOfResources,
  46: mergeTickets,
  47: sealedConnections,
};

// A stop is kept until the runner confirms it. Rebuilding widens the status check without changing resource IDs.
function durableEnvironmentStops({ db }) {
  db.exec(`
    CREATE TABLE environments_next (
      resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
      size TEXT NOT NULL, lifetime TEXT NOT NULL CHECK(lifetime IN ('exit','idle')), idle_seconds INTEGER NOT NULL, max_seconds INTEGER NOT NULL,
      identity TEXT, runner TEXT NOT NULL, machine TEXT,
      status TEXT NOT NULL CHECK(status IN ('starting','ready','busy','stopping','stopped')),
      started_at INTEGER NOT NULL, last_active_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      stop_attempts INTEGER NOT NULL DEFAULT 0, stop_retry_at INTEGER,
      remove_requested INTEGER NOT NULL DEFAULT 0 CHECK(remove_requested IN (0,1))
    );
    INSERT INTO environments_next (resource_id,size,lifetime,idle_seconds,max_seconds,identity,runner,machine,status,started_at,last_active_at,expires_at)
      SELECT resource_id,size,lifetime,idle_seconds,max_seconds,identity,runner,machine,status,started_at,last_active_at,expires_at FROM environments;
    DROP TABLE environments;
    ALTER TABLE environments_next RENAME TO environments;
  `);
}
durableEnvironmentStops.rebuilds = true;

// A one-time data conversion, never a runtime parser for earlier definitions. Refuse any expression that cannot
// be represented faithfully, and let Store roll the entire migration back rather than guess or discard data.
export function migrateServiceReferences(input) {
  const definition = structuredClone(input), oauth = definition.auth_schemes?.oauth;
  const token = value => value.replace(/~/g, '~0').replace(/\//g, '~1');
  const path = value => {
    if (Array.isArray(value)) return value.map(path);
    if (typeof value !== 'string' || !value) throw new Error('Invalid stored field selector');
    return '/' + value.split('.').map(token).join('/');
  };
  const url = value => value.replace(/^\{([a-z_]+)\}$/, '{+$1}');
  if (oauth && !oauth.adapter) {
    oauth.authorize = url(oauth.authorize); oauth.token = url(oauth.token);
    if (oauth.revoke) oauth.revoke.url = url(oauth.revoke.url);
    if (oauth.ok_field !== undefined) oauth.ok_field = '/' + token(oauth.ok_field);
    if (oauth.identity) {
      const who = oauth.identity;
      if (who.url !== undefined) who.url = url(who.url);
      for (const key of ['id', 'label']) if (who[key] !== undefined) who[key] = path(who[key]);
      if (who.ok_field !== undefined) who.ok_field = '/' + token(who.ok_field);
    }
    oauth.injection = Object.fromEntries(Object.entries(oauth.injection).map(([name, template]) => {
      const match = typeof template === 'string' && /^\{([a-z_]+)\}$/.exec(template);
      if (!match) throw new Error('Output ' + name + ' needs an explicit conversion');
      return [name, '/' + token(match[1])];
    }));
  }
  delete definition.version;
  return checkDefinition(definition);
}

function standardReferences({ db }) {
  const converted = db.prepare('SELECT resource_id,definition FROM services').all().map(row => {
    try { return { id: row.resource_id, definition: JSON.stringify(migrateServiceReferences(JSON.parse(row.definition))) }; }
    catch (error) { throw new Error('Service ' + row.resource_id + ' could not be migrated: ' + error.message); }
  });
  for (const row of converted) db.prepare('UPDATE services SET definition=? WHERE resource_id=?').run(row.definition, row.id);
}

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

// A way into a service is a connection, whatever its method: OAuth, a role, or a token the holder gave. The kind, the
// table, the actions drawn onto it and what requests say of it take that name; a connection's state is sealed to it
// under that name; and a token becomes one of its methods.
function connectionsWithMethods({ db, vault }) {
  const indexes = db.prepare("SELECT sql FROM sqlite_schema WHERE type='index' AND tbl_name='resources' AND sql IS NOT NULL").all().map(row => row.sql);
  const sealed = db.prepare('SELECT c.resource_id, c.state, r.holder_id FROM credentials c JOIN resources r ON r.id=c.resource_id WHERE c.state IS NOT NULL').all()
    .map(row => ({ id: row.resource_id, state: vault.seal(vault.open(row.state, `credential:${row.holder_id}:${row.resource_id}`), `connection:${row.holder_id}:${row.resource_id}`) }));
  db.exec(`
    CREATE TABLE resources_next (
    id TEXT PRIMARY KEY, holder_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('secret','connection','object','app','service','environment')), name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    INSERT INTO resources_next SELECT id, holder_id, CASE kind WHEN 'credential' THEN 'connection' ELSE kind END, name, created_at, updated_at FROM resources;
    DROP TABLE resources; ALTER TABLE resources_next RENAME TO resources;
    CREATE TABLE connections (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    service TEXT NOT NULL, auth_scheme TEXT NOT NULL CHECK(auth_scheme IN ('oauth','role','token')),
    app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
    generation INTEGER NOT NULL DEFAULT 1, state BLOB
    );
    INSERT INTO connections SELECT resource_id, service, auth_scheme, app_id, subject, status, generation, state FROM credentials;
    DROP TABLE credentials;
    CREATE INDEX connections_app ON connections(app_id) WHERE app_id IS NOT NULL;
    UPDATE relations SET relation='connection.' || substr(relation, 12) WHERE relation LIKE 'credential.%';
    CREATE TABLE requests_next (
    id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT,
    type TEXT NOT NULL CHECK(type IN ('relation','secret','connection','app')), detail TEXT NOT NULL,
    requester_name TEXT NOT NULL DEFAULT '', binding_message TEXT NOT NULL, steps TEXT NOT NULL, user_code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','granted','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    INSERT INTO requests_next SELECT id, from_id, to_id, CASE type WHEN 'credential' THEN 'connection' ELSE type END,
      CASE WHEN json_extract(detail, '$.credential_id') IS NOT NULL THEN json_remove(json_set(detail, '$.connection_id', json_extract(detail, '$.credential_id')), '$.credential_id')
        WHEN json_extract(detail, '$.relation') LIKE 'credential.%' THEN json_set(detail, '$.relation', 'connection.' || substr(json_extract(detail, '$.relation'), 12)) ELSE detail END,
      requester_name, binding_message, steps, user_code, attempts, progress,
      CASE WHEN json_extract(result, '$.credential_id') IS NOT NULL THEN json_remove(json_set(result, '$.connection_id', json_extract(result, '$.credential_id')), '$.credential_id')
        WHEN json_extract(result, '$.relation') LIKE 'credential.%' THEN json_set(result, '$.relation', 'connection.' || substr(json_extract(result, '$.relation'), 12)) ELSE result END,
      reason, status, created_at, expires_at FROM requests;
    DROP TABLE requests; ALTER TABLE requests_next RENAME TO requests;
    CREATE INDEX requests_from ON requests(from_id, created_at);
    CREATE INDEX requests_to ON requests(to_id, created_at);
    UPDATE audit_log SET object_type='connection' WHERE object_type='credential';
  `);
  for (const sql of indexes) db.exec(sql);
  for (const row of sealed) db.prepare('UPDATE connections SET state=? WHERE resource_id=?').run(row.state, row.id);
}
connectionsWithMethods.rebuilds = true;

// Proving who one is happens here, the same way for every principal: a session says which proof it rests on and when
// it was given, and an email address a principal receives at is one such proof. Sessions no longer carry another
// service's tokens, so the old ones end; the addresses they were signed in with are kept as proven.
function provenHere({ db }) {
  const now = Date.now();
  db.exec(`
    CREATE TABLE emails (
      address TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, verified_at INTEGER NOT NULL
    );
    CREATE INDEX emails_principal ON emails(principal_id);
  `);
  db.prepare('INSERT OR IGNORE INTO emails (address,principal_id,verified_at) SELECT lower(s.email), s.owner_id, ? FROM sessions s JOIN principals p ON p.id=s.owner_id ORDER BY s.expires_at DESC').run(now);
  db.exec(`
    DROP TABLE oauth_flows; DROP TABLE sessions;
    ${SESSIONS}
    CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
    ${CHALLENGES}
  `);
}
provenHere.rebuilds = true;

// When an address was first proven was kept with it but read by nothing, and for addresses carried over it was only
// the time of the carrying. When a principal last proved anything is its sessions'.
function addressesOnly({ db }) {
  db.exec('ALTER TABLE emails DROP COLUMN verified_at');
}

// A principal may prove itself with a passkey: a public key it registered, answered with a WebAuthn signature from a
// browser, a security key or the CLI alike. What is waiting to be answered may now be a passkey's challenge too.
function passkeys({ db }) {
  db.exec(`
    CREATE TABLE passkeys (
      id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, public_key BLOB NOT NULL,
      sign_count INTEGER NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER
    );
    CREATE INDEX passkeys_principal ON passkeys(principal_id);
    DROP TABLE challenges;
    CREATE TABLE challenges (
      id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','passkey')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at);
    CREATE INDEX challenges_handle ON challenges(handle);`);
}
passkeys.rebuilds = true;

// What is kept is a WebAuthn credential, made by a browser, a security key or the CLI - and only some of those are
// passkeys - so it is called that, as the specification calls it, and a session proved by one says webauthn. A key
// proof of another kind never came to be. What was waiting to be answered ends.
function webauthnCredentials({ db }) {
  db.exec(`
    DROP INDEX passkeys_principal; ALTER TABLE passkeys RENAME TO webauthn_credentials;
    CREATE INDEX webauthn_credentials_principal ON webauthn_credentials(principal_id);
    CREATE TABLE sessions_next (
      id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
      proof TEXT NOT NULL CHECK(proof IN ('email','webauthn')), proof_ref TEXT NOT NULL, proved_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    INSERT INTO sessions_next SELECT id, principal_id, CASE proof WHEN 'passkey' THEN 'webauthn' ELSE proof END, proof_ref, proved_at, created_at, expires_at FROM sessions;
    DROP TABLE sessions; ALTER TABLE sessions_next RENAME TO sessions;
    CREATE INDEX sessions_principal ON sessions(principal_id, expires_at);
    DROP TABLE challenges;
    ${CHALLENGES}`);
}
webauthnCredentials.rebuilds = true;

// What costs money is paid by whoever uses it: a principal may be a customer of Foundation's Stripe account, and
// what it uses is recorded here before it is sent there, so none of it is lost or sent twice.
function payment({ db }) {
  db.exec(PAYMENT);
}

// What was called acting for a principal is using what it holds, not deciding for it: the line is an agent's. A line
// that named one action (connection.disconnect) is now that action's own relation on the thing (disconnect_grant);
// one drawn onto a principal has a place only where the action makes something (connection.connect), and is
// otherwise dropped. Requests say the same.
function agents({ db }) {
  db.exec(`
    UPDATE relations SET relation='agent' WHERE relation='actor';
    UPDATE relations SET relation='connection_connect_grant' WHERE object_type='principal' AND relation='connection.connect';
    DELETE FROM relations WHERE object_type='principal' AND relation LIKE '%.%';
    UPDATE relations SET relation=replace(substr(relation, instr(relation, '.') + 1), '-', '_') || '_grant' WHERE object_type='resource' AND relation LIKE '%.%';
    UPDATE requests SET detail=json_set(detail, '$.relation', 'agent') WHERE json_extract(detail, '$.relation')='actor';
    UPDATE requests SET result=json_set(result, '$.relation', 'agent') WHERE json_extract(result, '$.relation')='actor';
    UPDATE requests SET detail=json_set(detail, '$.relation', replace(substr(json_extract(detail, '$.relation'), instr(json_extract(detail, '$.relation'), '.') + 1), '-', '_') || '_grant')
      WHERE json_extract(detail, '$.relation') LIKE '%.%';
    UPDATE requests SET result=json_set(result, '$.relation', replace(substr(json_extract(result, '$.relation'), instr(json_extract(result, '$.relation'), '.') + 1), '-', '_') || '_grant')
      WHERE json_extract(result, '$.relation') LIKE '%.%';
  `);
}

// A secret is sealed for those it was handed to, with a key of its own, and the server keeps no way to open it
// but Foundation's own principal's key. What the server held until now it had been opening for its holders, to
// inject; so each is sealed for Foundation's principal, which becomes those holders' agent, and the holders seal
// it for themselves when they have keys.
function envelopes({ db, vault }) {
  db.exec(KEYS);
  const agent = ensureAgent(db, vault), at = new Date().toISOString();
  for (const row of db.prepare('SELECT s.resource_id, s.content, r.holder_id FROM secrets s JOIN resources r ON r.id=s.resource_id').all()) {
    const content = vault.openBytes(row.content, `secret:${row.holder_id}:${row.resource_id}`), contentKey = newContentKey(), sealed = sealContent(contentKey, content);
    db.prepare('UPDATE secrets SET content=?, size=? WHERE resource_id=?').run(sealed, sealed.length, row.resource_id);
    db.prepare('INSERT INTO envelopes (resource_id,principal_id,wrapped) VALUES (?,?,?)').run(row.resource_id, agent, seal(contentKey, db.prepare('SELECT public_key FROM principal_keys WHERE principal_id=?').get(agent).public_key));
    db.prepare('INSERT OR IGNORE INTO relations (subject_id,relation,object_type,object_id,created_at) VALUES (?,?,?,?,?)').run(agent, 'agent', 'principal', row.holder_id, at);
  }
}

// A principal's one public key; its private key wrapped per credential, as the client made it; and each secret's
// key sealed per recipient. Bytes the server keeps and gives back, never opens.
const KEYS = `
  CREATE TABLE principal_keys (principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE, public_key BLOB NOT NULL, created_at TEXT NOT NULL);
  CREATE TABLE key_wraps (credential_id TEXT PRIMARY KEY REFERENCES webauthn_credentials(id) ON DELETE CASCADE, wrapped BLOB NOT NULL);
  CREATE TABLE envelopes (
    resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    wrapped BLOB NOT NULL, PRIMARY KEY (resource_id, principal_id)
  );
  CREATE INDEX envelopes_principal ON envelopes(principal_id);`;

// What a resource records of who has it is its owner, as a principal records its own: one name for the one relation
// that is made rather than drawn, and is what a transfer changes.
function ownerOfResources({ db }) {
  db.exec(`
    ALTER TABLE resources RENAME COLUMN holder_id TO owner_id;
    DROP INDEX resources_holder; CREATE INDEX resources_owner ON resources(owner_id, kind, name);
  `);
}

// A challenge may also be the ticket between the two steps of making another account one with this (merge).
// Rebuilt to widen the check; what was pending is kept. A credential keeps the user handle it was made with, since
// the device answers with it, and merging moves credentials between principals.
function mergeTickets({ db }) {
  db.exec(`
    ALTER TABLE webauthn_credentials ADD COLUMN user_handle TEXT NOT NULL DEFAULT '';
    UPDATE webauthn_credentials SET user_handle=principal_id;
    CREATE TABLE challenges_next (
      id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn','merge')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
    );
    INSERT INTO challenges_next SELECT id, purpose, subject, handle, data, created_at, expires_at FROM challenges;
    DROP TABLE challenges;
    ALTER TABLE challenges_next RENAME TO challenges;
    CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at);
  `);
}

// A connection's state is sealed like a secret: with a key of its own, in an envelope for Foundation's principal,
// which runs the scheme. What the server sealed under its own key is opened once and sealed anew; nothing else
// about the connection changes.
function sealedConnections({ db, vault }) {
  const agent = ensureAgent(db, vault), publicKey = db.prepare('SELECT public_key FROM principal_keys WHERE principal_id=?').get(agent).public_key;
  for (const row of db.prepare('SELECT c.resource_id, c.state, r.owner_id FROM connections c JOIN resources r ON r.id=c.resource_id').all()) {
    const state = vault.open(row.state, `connection:${row.owner_id}:${row.resource_id}`), contentKey = newContentKey();
    db.prepare('UPDATE connections SET state=? WHERE resource_id=?').run(sealContent(contentKey, Buffer.from(JSON.stringify(state))), row.resource_id);
    db.prepare('INSERT OR REPLACE INTO envelopes (resource_id,principal_id,wrapped) VALUES (?,?,?)').run(row.resource_id, agent, seal(contentKey, publicKey));
  }
}

// A session: what proving who one is leaves, for any principal. proof is how (an email reached, a WebAuthn signature),
// proof_ref which address or credential, and proved_at when; an operation that needs a fresh or stronger proof asks
// again.
const SESSIONS = `
  CREATE TABLE sessions (
    id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    proof TEXT NOT NULL CHECK(proof IN ('email','webauthn')), proof_ref TEXT NOT NULL, proved_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX sessions_principal ON sessions(principal_id, expires_at);`;
// A WebAuthn credential's record: its public key (COSE) and how many times its authenticator says it has signed.
const WEBAUTHN_CREDENTIALS = `
  CREATE TABLE webauthn_credentials (
    id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE, public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL, name TEXT NOT NULL, user_handle TEXT NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER
  );
  CREATE INDEX webauthn_credentials_principal ON webauthn_credentials(principal_id);`;
// A principal that pays: its Stripe customer, and the subscription its use is charged to once a payment method is set,
// with that subscription's status as Stripe last said it.
// What it used, recorded once (a machine's seconds weighted by its size, or a day's stored megabytes) and sent to
// Stripe's meter; sent_at says it went.
const PAYMENT = `
  CREATE TABLE payment_accounts (
    principal_id TEXT PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE, customer_id TEXT NOT NULL UNIQUE, subscription_id TEXT UNIQUE,
    status TEXT, created_at INTEGER NOT NULL
  );
  CREATE TABLE meter_events (
    id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, meter TEXT NOT NULL CHECK(meter IN ('compute','storage')), value INTEGER NOT NULL,
    at INTEGER NOT NULL, sent_at INTEGER
  );
  CREATE INDEX meter_events_unsent ON meter_events(sent_at) WHERE sent_at IS NULL;`;
// A single-use value someone must give back to prove something: that they receive at an address (subject). handle
// lets the browser that asked find what it is waiting for; it proves nothing.
const CHALLENGES = `
  CREATE TABLE challenges (
    id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK(purpose IN ('email','webauthn','merge')), subject TEXT NOT NULL, handle TEXT, data TEXT NOT NULL,
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX challenges_subject ON challenges(purpose, subject, created_at);
  CREATE INDEX challenges_handle ON challenges(handle);`;

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
  CREATE TABLE emails (address TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE);
  CREATE INDEX emails_principal ON emails(principal_id);
  ${SESSIONS}
  ${CHALLENGES}
  ${WEBAUTHN_CREDENTIALS}
  ${PAYMENT}
  CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE requests (
    id TEXT PRIMARY KEY, from_id TEXT NOT NULL, to_id TEXT,
    type TEXT NOT NULL CHECK(type IN ('relation','secret','connection','app')), detail TEXT NOT NULL,
    requester_name TEXT NOT NULL DEFAULT '', binding_message TEXT NOT NULL, steps TEXT NOT NULL, user_code TEXT, attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, result TEXT, reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','granted','denied','cancelled')),
    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX requests_from ON requests(from_id, created_at);
  CREATE INDEX requests_to ON requests(to_id, created_at);
  -- What a owner holds: one row each, and a row in the table of its kind.
  CREATE TABLE resources (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('secret','connection','object','app','service','environment')), name TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
  );
  CREATE INDEX resources_owner ON resources(owner_id, kind, name);
  CREATE UNIQUE INDEX resources_secret_name ON resources(owner_id, name) WHERE kind='secret';
  CREATE UNIQUE INDEX resources_object_name ON resources(owner_id, name) WHERE kind='object';
  CREATE UNIQUE INDEX resources_app_name ON resources(owner_id, name) WHERE kind='app';
  CREATE UNIQUE INDEX resources_service_name ON resources(owner_id, name) WHERE kind='service';
  -- Private bytes the owner keeps, for no service in particular: sealed by the client with the secret's own key.
  CREATE TABLE secrets (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    size INTEGER NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 1, content BLOB NOT NULL
  );
  -- A way into a service as some account: by OAuth, a role, or a token the owner gave. The account is known when the
  -- method can say; the state is what the method keeps, sealed.
  CREATE TABLE connections (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    service TEXT NOT NULL, auth_scheme TEXT NOT NULL CHECK(auth_scheme IN ('oauth','role','token')),
    app_id TEXT, subject TEXT, status TEXT NOT NULL DEFAULT 'usable' CHECK(status IN ('usable','reconnect_required','disconnecting')),
    generation INTEGER NOT NULL DEFAULT 1, state BLOB
  );
  CREATE INDEX connections_app ON connections(app_id) WHERE app_id IS NOT NULL;
  CREATE TABLE objects (resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE, size INTEGER NOT NULL DEFAULT 0, type TEXT);
  -- An OAuth app someone holds: which service it is for, its client ID, what else is said of it, and its sealed secret.
  CREATE TABLE apps (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    service TEXT NOT NULL, client_id TEXT NOT NULL, secret BLOB NOT NULL, settings TEXT NOT NULL DEFAULT '{}'
  );
  -- A service a owner described, for one Foundation's catalog does not know.
  CREATE TABLE services (resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE, definition TEXT NOT NULL);
  -- A machine lent to a owner: what it is, how long it lives, who it acts as inside (if anyone), and where it runs.
  CREATE TABLE environments (
    resource_id TEXT PRIMARY KEY REFERENCES resources(id) ON DELETE CASCADE,
    size TEXT NOT NULL, lifetime TEXT NOT NULL CHECK(lifetime IN ('exit','idle')), idle_seconds INTEGER NOT NULL, max_seconds INTEGER NOT NULL,
    identity TEXT, runner TEXT NOT NULL, machine TEXT,
    status TEXT NOT NULL CHECK(status IN ('starting','ready','busy','stopping','stopped')),
    started_at INTEGER NOT NULL, last_active_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    stop_attempts INTEGER NOT NULL DEFAULT 0, stop_retry_at INTEGER,
    remove_requested INTEGER NOT NULL DEFAULT 0 CHECK(remove_requested IN (0,1))
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
  ${KEYS}
  PRAGMA user_version = ${SCHEMA_VERSION};
`;
