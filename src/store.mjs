import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Vault } from './crypto.mjs';
import { fail } from './errors.mjs';

export const digest = (value) => createHash('sha256').update(value).digest('hex');
const now = () => new Date().toISOString();
const publicColumns = 'id, owner_id, adapter, subject, service, name, names, kept_by, status, generation, created_at, updated_at';
const binding = credential => `credential:${credential.owner_id}:${credential.id}`;
const parse = row => ({ ...row, names: JSON.parse(row.names) });
export const CREDENTIAL_LIMIT = 100;

const SCHEMA_VERSION = 1;
// credentials: one thing being kept, whatever put it there. secret holds the values it delivers, sealed and
//   bound to this owner and this row; names lists those values in the clear, so listing never opens one.
//   adapter and subject name the acquisition behind it, and are empty when nothing acquired it: a value a key
//   kept itself sits in the same table and is delivered the same way. Only refreshing and revoking tell them apart.
//   service is the owner's name for the group it sits in; kept_by is the key that put it there, as it was named
//   then, and is empty when the owner did it from the dashboard.
// agents: access keys the owner approved; each may use every credential of its owner.
// access_requests: one request from a runtime, as it asked and as it went. adapter is empty when the request only asks
//   for the key to be approved.
// documents: what a key wrote down and can read back whole: the state of something it is in the middle of,
//   or anything else it needs to survive the conversation. One document per collection and name.
// files: what a key placed in the file space. The bytes live in the backend under the id; a row is never changed.
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE credentials (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, adapter TEXT NOT NULL, subject TEXT NOT NULL, service TEXT NOT NULL,
    name TEXT NOT NULL, names TEXT NOT NULL, kept_by TEXT NOT NULL, status TEXT NOT NULL, secret TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(owner_id, adapter, subject)
  );
  CREATE TABLE agents (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
    last_used_at TEXT, issued_until INTEGER, issued_nonexpiring INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE sessions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL, secret TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE oauth_flows (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, payload TEXT NOT NULL, expires_at INTEGER NOT NULL);
  CREATE TABLE access_requests (
    id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, requester_name TEXT NOT NULL, adapter TEXT,
    purpose TEXT NOT NULL, details TEXT NOT NULL, guidance TEXT NOT NULL, confirmation_code TEXT NOT NULL, confirmation_attempts INTEGER NOT NULL DEFAULT 0,
    progress TEXT, owner_id TEXT, agent_id TEXT, credential_id TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX access_requests_token ON access_requests(token_hash, created_at);
  CREATE TABLE files (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, agent_id TEXT NOT NULL, name TEXT NOT NULL, content_type TEXT NOT NULL,
    size INTEGER NOT NULL, sha256 TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
  );
  CREATE INDEX files_owner ON files(owner_id, created_at);
  CREATE TABLE documents (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, collection TEXT NOT NULL, name TEXT NOT NULL,
    body TEXT NOT NULL, size INTEGER NOT NULL, kept_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(owner_id, collection, name)
  );
  CREATE INDEX documents_owner ON documents(owner_id, collection, name);
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
    // The database is created in this exact shape and never migrated. Any other shape is refused.
    const version = this.db.prepare('PRAGMA user_version').get().user_version;
    const empty = !this.db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'metadata'").get();
    // Only two files are acceptable: one this version made, and one that is new. Anything else is left untouched.
    const mine = version === SCHEMA_VERSION && !empty, fresh = version === 0 && empty;
    if (!mine && !fresh) { this.db.close(); throw new Error('This database was not created by this version of Foundation. Start from a new database file.'); }
    try {
      this.transaction(() => {
        if (fresh) this.db.exec(SCHEMA);
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
    this.db.prepare('DELETE FROM access_requests WHERE expires_at<=?').run(Date.now());
    this.db.prepare('DELETE FROM files WHERE expires_at<=?').run(Date.now());
  }
  credentials(ownerId) { return this.db.prepare(`SELECT ${publicColumns} FROM credentials WHERE owner_id=? ORDER BY created_at, id`).all(ownerId).map(parse); }
  credential(ownerId, id) {
    const row = this.db.prepare('SELECT * FROM credentials WHERE owner_id=? AND id=?').get(ownerId, id);
    return row ? parse(row) : undefined;
  }
  secret(credential) { return this.vault.open(credential.secret, binding(credential)); }
  // Stores a new credential, or replaces the secret of `previous` when the same subject is registered again.
  // `details.adapter` and `details.subject` are empty for a value nothing acquired; `names` is what it delivers.
  register(ownerId, details, secret, previous) {
    return this.transaction(() => {
      const stamp = now(), names = JSON.stringify(details.names ?? []);
      if (previous) {
        const current = this.credential(ownerId, previous.id);
        if (!current || current.generation !== previous.generation || current.status === 'disconnecting') fail(409, 'connection_changed', '認証情報の状態が変わりました。もう一度お試しください。');
        if (current.subject !== details.subject) fail(409, 'account_changed', '登録し直すには同じアカウントを選んでください。');
        this.db.prepare("UPDATE credentials SET name=?, names=?, secret=?, status='connected', generation=generation+1, updated_at=? WHERE id=?").run(details.name, names, this.vault.seal(secret, binding(current)), stamp, current.id);
        return current.id;
      }
      if (this.credentials(ownerId).length >= CREDENTIAL_LIMIT) fail(409, 'credential_limit', `預けられるのは${CREDENTIAL_LIMIT}件までです。使わないものを解除してください。`);
      if (details.adapter && this.db.prepare('SELECT 1 FROM credentials WHERE owner_id=? AND adapter=? AND subject=?').get(ownerId, details.adapter, details.subject)) fail(409, 'already_connected', 'この認証情報は登録済みです。');
      const id = randomUUID();
      this.db.prepare('INSERT INTO credentials (id,owner_id,adapter,subject,service,name,names,kept_by,status,secret,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(id, ownerId, details.adapter ?? '', details.subject ?? randomUUID(), details.service, details.name, names, details.kept_by ?? '', 'connected', this.vault.seal(secret, binding({ owner_id: ownerId, id })), stamp, stamp);
      return id;
    });
  }
  updateCredential(ownerId, id, name, service) {
    if (!this.credential(ownerId, id)) fail(404, 'not_found', '認証情報が見つかりません。');
    this.db.prepare('UPDATE credentials SET name=?, service=?, updated_at=? WHERE owner_id=? AND id=?').run(name, service, now(), ownerId, id);
  }
  // Replaces what a credential delivers, keeping everything the owner named. Used when acquisition refreshes
  // it, and when a key replaces a value it keeps itself.
  saveSecret(credential, secret, names) {
    const result = names === undefined
      ? this.db.prepare("UPDATE credentials SET secret=?, updated_at=? WHERE owner_id=? AND id=? AND generation=? AND status='connected'").run(this.vault.seal(secret, binding(credential)), now(), credential.owner_id, credential.id, credential.generation)
      : this.db.prepare("UPDATE credentials SET secret=?, names=?, updated_at=? WHERE owner_id=? AND id=? AND generation=? AND status='connected'").run(this.vault.seal(secret, binding(credential)), JSON.stringify(names), now(), credential.owner_id, credential.id, credential.generation);
    if (!result.changes) fail(409, 'connection_changed', 'この認証情報は変更または解除されています。');
  }
  reconnectRequired(credential) {
    this.db.prepare("UPDATE credentials SET status='reconnect_required', generation=generation+1, updated_at=? WHERE id=? AND owner_id=? AND generation=? AND status='connected'").run(now(), credential.id, credential.owner_id, credential.generation);
  }
  disconnect(ownerId, id) {
    return this.transaction(() => {
      const credential = this.credential(ownerId, id);
      if (!credential) fail(404, 'not_found', '認証情報が見つかりません。');
      this.db.prepare("UPDATE credentials SET status='disconnecting', generation=generation+1, updated_at=? WHERE owner_id=? AND id=?").run(now(), ownerId, id);
      return credential;
    });
  }
  removeCredential(ownerId, id) { return this.db.prepare('DELETE FROM credentials WHERE owner_id=? AND id=?').run(ownerId, id).changes > 0; }
  // Documents: the same storage, for what is read back whole rather than handed to a command.
  documents(ownerId, collection) {
    const where = collection === undefined ? '' : ' AND collection=?', args = collection === undefined ? [ownerId] : [ownerId, collection];
    return this.db.prepare(`SELECT id, collection, name, size, kept_by, created_at, updated_at FROM documents WHERE owner_id=?${where} ORDER BY collection, name`).all(...args);
  }
  document(ownerId, collection, name) {
    const row = this.db.prepare('SELECT * FROM documents WHERE owner_id=? AND collection=? AND name=?').get(ownerId, collection, name);
    return row ? { ...row, body: this.vault.open(row.body, `document:${ownerId}:${row.id}`) } : undefined;
  }
  writeDocument(ownerId, { collection, name, body, keptBy }) {
    return this.transaction(() => {
      const stamp = now(), existing = this.db.prepare('SELECT id FROM documents WHERE owner_id=? AND collection=? AND name=?').get(ownerId, collection, name);
      const size = Buffer.byteLength(JSON.stringify(body));
      if (existing) {
        this.db.prepare('UPDATE documents SET body=?, size=?, kept_by=?, updated_at=? WHERE id=?').run(this.vault.seal(body, `document:${ownerId}:${existing.id}`), size, keptBy, stamp, existing.id);
        return existing.id;
      }
      if (this.documents(ownerId).length >= 500) fail(409, 'document_limit', '保管できる記録は500件までです。');
      const id = randomUUID();
      this.db.prepare('INSERT INTO documents (id,owner_id,collection,name,body,size,kept_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)')
        .run(id, ownerId, collection, name, this.vault.seal(body, `document:${ownerId}:${id}`), size, keptBy, stamp, stamp);
      return id;
    });
  }
  removeDocument(ownerId, collection, name) { return this.db.prepare('DELETE FROM documents WHERE owner_id=? AND collection=? AND name=?').run(ownerId, collection, name).changes > 0; }
  agents(ownerId) {
    return this.db.prepare('SELECT id,name,created_at,last_used_at,issued_until,issued_nonexpiring FROM agents WHERE owner_id=? ORDER BY created_at,id').all(ownerId);
  }
  // A key issued from the dashboard: the owner carries the secret to the runtime themselves.
  addAgent(ownerId, name) {
    if (this.agents(ownerId).length >= 50) fail(409, 'agent_limit', '登録できるアクセスキーは50件までです。');
    const id = randomUUID(), token = `fdn_${randomBytes(32).toString('base64url')}`;
    this.db.prepare('INSERT INTO agents (id,owner_id,name,token_hash,created_at) VALUES (?,?,?,?,?)').run(id, ownerId, name, digest(token), now());
    return { ...this.agents(ownerId).find((agent) => agent.id === id), token };
  }
  removeAgent(ownerId, id) { this.db.prepare('DELETE FROM agents WHERE owner_id=? AND id=?').run(ownerId, id); }
  renameAgent(ownerId, id, name) {
    if (!this.db.prepare('UPDATE agents SET name=? WHERE owner_id=? AND id=?').run(name, ownerId, id).changes) fail(404, 'not_found', 'アクセスキーが見つかりません。');
  }
  agentDetails(agent) {
    return this.db.prepare('SELECT id,name,created_at,last_used_at,issued_until,issued_nonexpiring FROM agents WHERE id=?').get(agent.id);
  }
  authenticate(token) {
    if (typeof token !== 'string' || !/^fdn_[A-Za-z0-9_-]{43}$/.test(token)) return;
    return this.db.prepare('SELECT id,owner_id,name FROM agents WHERE token_hash=?').get(digest(token));
  }
  // Possession of an approved key is the whole authorization: the key still exists, and the credential is its owner's.
  requireAccess(agent, credentialId) {
    if (!this.db.prepare('SELECT 1 FROM agents a JOIN credentials c ON c.owner_id=a.owner_id WHERE a.id=? AND a.owner_id=? AND c.id=? AND c.status!=?').get(agent.id, agent.owner_id, credentialId, 'disconnecting')) fail(403, 'access_denied', 'この認証情報は利用できません。');
  }
  recordIssuance(agent, until) { this.db.prepare('UPDATE agents SET last_used_at=?, issued_until=MAX(COALESCE(issued_until,0),?), issued_nonexpiring=MAX(issued_nonexpiring,?) WHERE id=?').run(now(), until ?? 0, until === null ? 1 : 0, agent.id); }
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
