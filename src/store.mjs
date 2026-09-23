import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Vault } from './crypto.mjs';
import { fail } from './errors.mjs';
import { SECRET_COUNT_MAX, SECRET_TOTAL_MAX } from './secrets.mjs';

export const digest = (value) => createHash('sha256').update(value).digest('hex');
const now = () => new Date().toISOString();
const parse = row => ({ ...row, readable: row.readable === 1 });
export const ACQUISITION_LIMIT = 50;
const entryBinding = row => `entry:${row.owner_id}:${row.id}`;

const SCHEMA_VERSION = 12;
// Names are opaque identifiers. Connection state is stored independently of ordinary values.
// Both kinds retain their original authenticated-encryption bindings across migrations.
const STEPS = {
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

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE keys (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
    last_used_at TEXT, issued_until INTEGER, issued_nonexpiring INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL, secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE key_requests (
    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, name TEXT NOT NULL, confirmation_code TEXT NOT NULL,
    confirmation_attempts INTEGER NOT NULL DEFAULT 0, progress TEXT, owner_id TEXT, key_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX key_requests_token ON key_requests(token_hash, created_at);
  CREATE TABLE requests (
    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, key_id TEXT NOT NULL, owner_id TEXT NOT NULL, requester_name TEXT NOT NULL,
    adapter TEXT, purpose TEXT NOT NULL, details TEXT NOT NULL, steps TEXT NOT NULL, progress TEXT, credential_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX requests_token ON requests(token_hash, created_at);
  CREATE TABLE secrets (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL,
    size INTEGER NOT NULL, readable INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(owner_id, name)
  );
  CREATE TABLE acquisitions (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, adapter TEXT NOT NULL, subject TEXT NOT NULL,
    label TEXT NOT NULL, state TEXT NOT NULL, status TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
    kept_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(owner_id, adapter, subject)
  );
  CREATE INDEX acquisitions_owner ON acquisitions(owner_id, id);
  CREATE INDEX secrets_owner ON secrets(owner_id, name);
  PRAGMA user_version = ${SCHEMA_VERSION};
`;

export class Store {
  constructor(path, key) {
    this.transactionDepth = 0;
    this.vault = new Vault(key);
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=3000; PRAGMA secure_delete=ON;');
    // Known earlier schemas are migrated transactionally; unrecognized files are left intact.
    const version = this.db.prepare('PRAGMA user_version').get().user_version;
    const empty = !this.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'metadata'").get();
    // Migrations and the encryption-key check share a transaction.
    const behind = !empty && version >= 1 && version < SCHEMA_VERSION && [...Array(SCHEMA_VERSION - version)].every((_, step) => STEPS[version + step + 1]);
    const mine = version === SCHEMA_VERSION && !empty, fresh = version === 0 && empty;
    if (!mine && !fresh && !behind) { this.db.close(); throw new Error('This database was not created by this version of Foundation. Start from a new database file.'); }
    try {
      this.transaction(() => {
        if (fresh) this.db.exec(SCHEMA);
        if (behind) {
          for (let next = version + 1; next <= SCHEMA_VERSION; next++) {
            const step = STEPS[next];
            if (typeof step === 'function') step(this); else this.db.exec(step);
          }
          this.db.exec('PRAGMA user_version = ' + SCHEMA_VERSION);
        }
        const check = this.db.prepare("SELECT value FROM metadata WHERE name='key_check'").get();
        if (check) this.vault.open(check.value, 'key_check');
        else this.db.prepare('INSERT INTO metadata VALUES (?, ?)').run('key_check', this.vault.seal(true, 'key_check'));
      });
      this.sweep();
    } catch (error) { this.db.close(); throw error; }
  }
  transaction(fn) {
    const nested = this.transactionDepth > 0, savepoint = 'foundation_' + this.transactionDepth;
    this.db.exec(nested ? 'SAVEPOINT ' + savepoint : 'BEGIN IMMEDIATE');
    this.transactionDepth++;
    try { const result = fn(); this.db.exec(nested ? 'RELEASE ' + savepoint : 'COMMIT'); return result; }
    catch (error) { this.db.exec(nested ? 'ROLLBACK TO ' + savepoint + '; RELEASE ' + savepoint : 'ROLLBACK'); throw error; }
    finally { this.transactionDepth--; }
  }
  sweep() {
    this.db.prepare('DELETE FROM oauth_flows WHERE expires_at<=?').run(Date.now());
    this.db.prepare('DELETE FROM sessions WHERE expires_at<=?').run(Date.now());
    this.db.prepare('DELETE FROM requests WHERE expires_at<=?').run(Date.now());
    this.db.prepare('DELETE FROM key_requests WHERE expires_at<=?').run(Date.now());
  }
  // Storage. Listing never opens anything; only reading and delivering do.
  secrets(ownerId, prefix) {
    const columns = 'name, size, readable, created_at, updated_at';
    return (prefix === undefined
      ? this.db.prepare(`SELECT ${columns} FROM secrets WHERE owner_id=? ORDER BY name`).all(ownerId)
      : this.db.prepare(`SELECT ${columns} FROM secrets WHERE owner_id=? AND substr(name,1,length(?))=? COLLATE BINARY ORDER BY name`).all(ownerId, prefix, prefix)).map(parse);
  }
  secret(ownerId, name) {
    const row = this.db.prepare('SELECT * FROM secrets WHERE owner_id=? AND name=?').get(ownerId, name);
    return row ? parse(row) : undefined;
  }
  secretContent(row) { return this.vault.openBytes(row.content, entryBinding(row)); }
  usage(ownerId) { return this.db.prepare('SELECT COUNT(*) AS count, COALESCE(SUM(size),0) AS bytes FROM secrets WHERE owner_id=?').get(ownerId); }
  // Writing the same name again replaces what is there.
  writeSecret(ownerId, entry) {
    return this.transaction(() => {
      const stamp = now(), existing = this.secret(ownerId, entry.name);
      const { count, bytes } = this.usage(ownerId);
      if (!existing && count >= SECRET_COUNT_MAX) fail(409, 'secret_limit', `保管できるのは${SECRET_COUNT_MAX}件までです。使わないものを消してください。`);
      if (bytes - (existing?.size ?? 0) + entry.content.length > SECRET_TOTAL_MAX) fail(409, 'storage_full', '保管できる合計は20MBまでです。使わないものを消してください。');
      const id = existing?.id ?? randomUUID();
      const sealed = this.vault.sealBytes(entry.content, `entry:${ownerId}:${id}`);
      if (existing) {
        this.db.prepare('UPDATE secrets SET size=?, readable=?, content=?, updated_at=? WHERE id=?')
          .run(entry.content.length, entry.readable, sealed, stamp, id);
      } else {
        this.db.prepare('INSERT INTO secrets (id,owner_id,name,size,readable,content,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)')
          .run(id, ownerId, entry.name, entry.content.length, entry.readable, sealed, stamp, stamp);
      }
      return this.secrets(ownerId, entry.name)[0];
    });
  }
  // Renaming preserves the bytes: encryption is bound to the row ID, not the name.
  renameSecret(ownerId, name, { name: to }) {
    return this.transaction(() => {
      const row = this.secret(ownerId, name);
      if (!row) return undefined;
      if (to !== name && this.secret(ownerId, to)) fail(409, 'name_taken', 'その名前はすでに使われています。');
      this.db.prepare('UPDATE secrets SET name=?, updated_at=? WHERE id=?').run(to, now(), row.id);
      return this.secrets(ownerId, to)[0];
    });
  }
  removeSecret(ownerId, name) { return this.db.prepare('DELETE FROM secrets WHERE owner_id=? AND name=?').run(ownerId, name).changes > 0; }
  // Connections have stable IDs; they own no names in the value store.
  acquisitions(ownerId) { return this.db.prepare('SELECT * FROM acquisitions WHERE owner_id=? ORDER BY created_at,id').all(ownerId); }
  acquisition(ownerId, id) { return this.db.prepare('SELECT * FROM acquisitions WHERE owner_id=? AND id=?').get(ownerId, id); }
  acquisitionState(row) { return this.vault.open(row.state, `acquisition:${row.owner_id}:${row.id}`); }
  // Only connection state is committed here. No ordinary value is created or modified.
  saveAcquisition(ownerId, { adapter, subject, label, state, keptBy }, previous) {
    return this.transaction(() => {
      const stamp = now();
      const existing = previous ? this.acquisition(ownerId, previous.id) : undefined;
      if (previous) {
        if (!existing || existing.generation !== previous.generation) fail(409, 'connection_changed', '状態が変わりました。もう一度お試しください。');
        if (existing.subject !== subject) fail(409, 'account_changed', '登録し直すには同じアカウントを選んでください。');
      }
      if (!previous && this.db.prepare('SELECT 1 FROM acquisitions WHERE owner_id=? AND adapter=? AND subject=?').get(ownerId, adapter, subject)) fail(409, 'already_connected', 'この認証情報は登録済みです。');
      if (!previous && this.acquisitions(ownerId).length >= ACQUISITION_LIMIT) fail(409, 'acquisition_limit', `登録できる接続は${ACQUISITION_LIMIT}件までです。`);
      const id = existing?.id ?? randomUUID();
      const sealed = this.vault.seal(state, `acquisition:${ownerId}:${id}`);
      if (existing) this.db.prepare("UPDATE acquisitions SET adapter=?, subject=?, label=?, state=?, status='connected', generation=generation+1, updated_at=? WHERE id=?").run(adapter, subject, label, sealed, stamp, id);
      else this.db.prepare("INSERT INTO acquisitions (id,owner_id,adapter,subject,label,state,status,kept_by,created_at,updated_at) VALUES (?,?,?,?,?,?,'connected',?,?,?)").run(id, ownerId, adapter, subject, label, sealed, keptBy ?? '', stamp, stamp);
      return this.acquisition(ownerId, id);
    });
  }
  // A refresh that produced nothing new still says when it happened; one that failed marks the acquisition.
  saveState(acquisition, state) {
    return this.transaction(() => {
      const current = this.acquisition(acquisition.owner_id, acquisition.id);
      if (!current || current.generation !== acquisition.generation || current.status !== 'connected') fail(409, 'connection_changed', 'この接続は変更または解除されています。');
      this.db.prepare('UPDATE acquisitions SET state=?, updated_at=? WHERE id=?').run(this.vault.seal(state, `acquisition:${acquisition.owner_id}:${acquisition.id}`), now(), acquisition.id);
    });
  }
  reconnectRequired(acquisition) {
    this.db.prepare("UPDATE acquisitions SET status='reconnect_required', generation=generation+1, updated_at=? WHERE id=? AND owner_id=? AND generation=? AND status='connected'").run(now(), acquisition.id, acquisition.owner_id, acquisition.generation);
  }
  disconnect(ownerId, id) {
    return this.transaction(() => {
      const acquisition = this.acquisition(ownerId, id);
      if (!acquisition) fail(404, 'not_found', '接続が見つかりません。');
      this.db.prepare("UPDATE acquisitions SET status='disconnecting', generation=generation+1, updated_at=? WHERE id=?").run(now(), acquisition.id);
      return acquisition;
    });
  }
  removeAcquisition(ownerId, id) {
    return this.db.prepare('DELETE FROM acquisitions WHERE owner_id=? AND id=?').run(ownerId, id).changes > 0;
  }
  keys(ownerId) {
    return this.db.prepare('SELECT id,name,created_at,last_used_at,issued_until,issued_nonexpiring FROM keys WHERE owner_id=? ORDER BY created_at,id').all(ownerId);
  }
  // A key issued from the dashboard: the owner carries the secret to the runtime themselves.
  addKey(ownerId, name) {
    if (this.keys(ownerId).length >= 50) fail(409, 'key_limit', '登録できるアクセスキーは50件までです。');
    const id = randomUUID(), token = `fdn_${randomBytes(32).toString('base64url')}`;
    this.db.prepare('INSERT INTO keys (id,owner_id,name,token_hash,created_at) VALUES (?,?,?,?,?)').run(id, ownerId, name, digest(token), now());
    return { ...this.keys(ownerId).find((key) => key.id === id), token };
  }
  removeKey(ownerId, id) { this.db.prepare('DELETE FROM keys WHERE owner_id=? AND id=?').run(ownerId, id); }
  renameKey(ownerId, id, name) {
    if (!this.db.prepare('UPDATE keys SET name=? WHERE owner_id=? AND id=?').run(name, ownerId, id).changes) fail(404, 'not_found', 'アクセスキーが見つかりません。');
  }
  keyDetails(key) {
    return this.db.prepare('SELECT id,name,created_at,last_used_at,issued_until,issued_nonexpiring FROM keys WHERE id=?').get(key.id);
  }
  authenticate(token) {
    if (typeof token !== 'string' || !/^fdn_[A-Za-z0-9_-]{43}$/.test(token)) return;
    return this.db.prepare('SELECT id,owner_id,name FROM keys WHERE token_hash=?').get(digest(token));
  }
  // The approved key and requested value must belong to the same owner.
  requireAccess(key, name) {
    if (key.owner_id !== this.db.prepare('SELECT owner_id FROM keys WHERE id=?').get(key.id)?.owner_id) fail(403, 'access_denied', 'これは利用できません。');
    if (!this.secret(key.owner_id, name)) fail(404, 'not_found', '保管されたものが見つかりません。');
  }
  recordIssuance(key, until) { this.db.prepare('UPDATE keys SET last_used_at=?, issued_until=MAX(COALESCE(issued_until,0),?), issued_nonexpiring=MAX(issued_nonexpiring,?) WHERE id=?').run(now(), until ?? 0, until === null ? 1 : 0, key.id); }
  createSession(value) {
    this.sweep();
    const token = randomBytes(32).toString('base64url'), id = digest(token);
    this.db.prepare('DELETE FROM sessions WHERE owner_id=? AND id IN (SELECT id FROM sessions WHERE owner_id=? ORDER BY expires_at DESC LIMIT -1 OFFSET 19)').run(value.user.id, value.user.id);
    this.db.prepare('INSERT INTO sessions VALUES (?,?,?,?,?)').run(id, value.user.id, value.user.email, this.vault.seal(value, `session:${id}`), Date.now() + 14 * 86400_000);
    return token;
  }
  session(token) {
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return;
    const row = this.db.prepare('SELECT * FROM sessions WHERE id=? AND expires_at>?').get(digest(token), Date.now());
    return row ? { ...row, value: this.vault.open(row.secret, `session:${row.id}`) } : undefined;
  }
  updateSession(id, value) { return this.db.prepare('UPDATE sessions SET secret=?,email=? WHERE id=? AND owner_id=? AND expires_at>?').run(this.vault.seal(value, `session:${id}`), value.user.email, id, value.user.id, Date.now()).changes > 0; }
  removeSession(token) { if (typeof token === 'string') this.db.prepare('DELETE FROM sessions WHERE id=?').run(digest(token)); }
  addFlow(sessionId, payload) {
    this.sweep();
    this.db.prepare('DELETE FROM oauth_flows WHERE session_id=?').run(sessionId);
    const state = randomBytes(32).toString('base64url'), id = digest(state);
    this.db.prepare('INSERT INTO oauth_flows VALUES (?,?,?,?)').run(id, sessionId, this.vault.seal(payload, `oauth:${sessionId}:${id}`), Date.now() + 600_000);
    return state;
  }
  takeFlow(sessionId, state) {
    if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(state)) return;
    const id = digest(state);
    const row = this.db.prepare('DELETE FROM oauth_flows WHERE id=? AND session_id=? AND expires_at>? RETURNING payload').get(id, sessionId, Date.now());
    return row ? this.vault.open(row.payload, `oauth:${sessionId}:${id}`) : undefined;
  }
  close() { this.db.close(); }
}
