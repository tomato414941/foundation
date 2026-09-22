import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Vault } from './crypto.mjs';
import { fail } from './errors.mjs';

export const digest = (value) => createHash('sha256').update(value).digest('hex');
const now = () => new Date().toISOString();
const publicColumns = 'id, owner_id, adapter, subject, service, name, requested_by, status, generation, created_at, updated_at';
const binding = credential => `credential:${credential.owner_id}:${credential.id}`;

const SCHEMA_VERSION = 4;
// credentials: what the owner handed over, one row each. adapter is how it is handled; subject identifies it
//   at the service; service is the name of what it reaches; secret is sealed and bound to owner and id.
//   requested_by is the name of the key whose request it was registered through, as it was then; empty when the owner
//   registered it from the dashboard.
// agents: access keys the owner approved; each may use every credential of its owner.
// access_requests: one request from a runtime, as it asked and as it went. adapter is empty when the request only asks
//   for the key to be approved.
// files: what a key placed in the file space. The bytes live in the backend under the id; a row is never changed.
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
  CREATE TABLE credentials (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, adapter TEXT NOT NULL, subject TEXT NOT NULL, service TEXT NOT NULL,
    name TEXT NOT NULL, requested_by TEXT, status TEXT NOT NULL, secret TEXT NOT NULL,
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
    if (version !== SCHEMA_VERSION && !(version === 0 && empty)) { this.db.close(); throw new Error('This database was not created by this version of Foundation. Start from a new database file.'); }
    try {
      this.transaction(() => {
        if (version === 0) this.db.exec(SCHEMA);
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
  credentials(ownerId) { return this.db.prepare(`SELECT ${publicColumns} FROM credentials WHERE owner_id=? ORDER BY created_at, id`).all(ownerId); }
  credential(ownerId, id) { return this.db.prepare('SELECT * FROM credentials WHERE owner_id=? AND id=?').get(ownerId, id); }
  secret(credential) { return this.vault.open(credential.secret, binding(credential)); }
  // Stores a new credential, or replaces the secret of `previous` when the same subject registers again.
  register(ownerId, details, secret, previous) {
    return this.transaction(() => {
      const stamp = now();
      if (previous) {
        const current = this.credential(ownerId, previous.id);
        if (!current || current.generation !== previous.generation || current.status === 'disconnecting') fail(409, 'connection_changed', '認証情報の状態が変わりました。もう一度お試しください。');
        if (current.subject !== details.subject) fail(409, 'account_changed', '登録し直すには同じアカウントを選んでください。');
        this.db.prepare("UPDATE credentials SET name=?, secret=?, status='connected', generation=generation+1, updated_at=? WHERE id=?").run(details.name, this.vault.seal(secret, binding(current)), stamp, current.id);
        return current.id;
      }
      if (this.credentials(ownerId).length >= 25) fail(409, 'credential_limit', '登録できる認証情報は25件までです。');
      if (this.db.prepare('SELECT 1 FROM credentials WHERE owner_id=? AND adapter=? AND subject=?').get(ownerId, details.adapter, details.subject)) fail(409, 'already_connected', 'この認証情報は登録済みです。');
      const id = randomUUID();
      this.db.prepare('INSERT INTO credentials (id,owner_id,adapter,subject,service,name,requested_by,status,secret,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .run(id, ownerId, details.adapter, details.subject, details.service, details.name, details.requested_by ?? '', 'connected', this.vault.seal(secret, binding({ owner_id: ownerId, id })), stamp, stamp);
      return id;
    });
  }
  updateCredential(ownerId, id, name) {
    if (!this.credential(ownerId, id)) fail(404, 'not_found', '認証情報が見つかりません。');
    this.db.prepare('UPDATE credentials SET name=?, updated_at=? WHERE owner_id=? AND id=?').run(name, now(), ownerId, id);
  }
  saveSecret(credential, secret) {
    const result = this.db.prepare("UPDATE credentials SET secret=? WHERE owner_id=? AND id=? AND generation=? AND status='connected'").run(this.vault.seal(secret, binding(credential)), credential.owner_id, credential.id, credential.generation);
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
  removeCredential(ownerId, id) { this.db.prepare('DELETE FROM credentials WHERE owner_id=? AND id=?').run(ownerId, id); }
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
