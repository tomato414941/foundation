import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Vault } from './crypto.mjs';
import { fail } from './errors.mjs';
import { ENTRY_COUNT_MAX, ENTRY_TOTAL_MAX } from './entries.mjs';

export const digest = (value) => createHash('sha256').update(value).digest('hex');
const now = () => new Date().toISOString();
const parse = row => ({ ...row, readable: row.readable === 1 });
export const ACQUISITION_LIMIT = 50;
const entryBinding = row => `entry:${row.owner_id}:${row.id}`;

const SCHEMA_VERSION = 1;
// entries: everything Foundation keeps, whatever it is. Bytes at a path, sealed and bound to this owner and
//   this row. media_type is what the writer said they are and is never checked. env, filename and session are
//   how a command receives them, settled when they were written. readable is 0 when they may only be delivered.
//   version rises on every write, so a writer can refuse to overwrite what it has not seen.
// acquisitions: the entries under `prefix` are obtained and kept current by Foundation itself, through one
//   adapter, for one subject at that service. state holds what the adapter needs to refresh them, sealed.
//   Every other entry has no row here and is simply what was put there.
// agents: access keys the owner approved; each may use everything its owner keeps.
// access_requests: one request from a runtime, as it asked and as it went.
// files: what a key published in the sharing space. The bytes live in the backend under the id; a row is never changed.
const SCHEMA = `
  CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
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
  CREATE TABLE entries (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, path TEXT NOT NULL, media_type TEXT NOT NULL,
    size INTEGER NOT NULL, env TEXT, filename TEXT, session TEXT, readable INTEGER NOT NULL,
    content TEXT NOT NULL, kept_by TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(owner_id, path)
  );
  CREATE TABLE acquisitions (
    id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, prefix TEXT NOT NULL, adapter TEXT NOT NULL, subject TEXT NOT NULL,
    label TEXT NOT NULL, state TEXT NOT NULL, status TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 1,
    kept_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
    UNIQUE(owner_id, prefix), UNIQUE(owner_id, adapter, subject)
  );
  CREATE INDEX acquisitions_owner ON acquisitions(owner_id, prefix);
  CREATE INDEX entries_owner ON entries(owner_id, path);
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
  // Storage. Listing never opens anything; only reading and delivering do.
  entries(ownerId, prefix) {
    const columns = 'path, media_type, size, env, filename, session, readable, kept_by, version, created_at, updated_at';
    return (prefix === undefined
      ? this.db.prepare(`SELECT ${columns} FROM entries WHERE owner_id=? ORDER BY path`).all(ownerId)
      : this.db.prepare(`SELECT ${columns} FROM entries WHERE owner_id=? AND (path=? OR path LIKE ?) ORDER BY path`).all(ownerId, prefix, prefix.replaceAll('%', '\\%').replaceAll('_', '\\_') + '/%')).map(parse);
  }
  entry(ownerId, path) {
    const row = this.db.prepare('SELECT * FROM entries WHERE owner_id=? AND path=?').get(ownerId, path);
    return row ? parse(row) : undefined;
  }
  entryContent(row) { return this.vault.openBytes(row.content, entryBinding(row)); }
  usage(ownerId) { return this.db.prepare('SELECT COUNT(*) AS count, COALESCE(SUM(size),0) AS bytes FROM entries WHERE owner_id=?').get(ownerId); }
  // Writing the same path again replaces it. `ifVersion` refuses to, unless it is still the version the
  // writer last saw, so two things working at once fail instead of quietly losing one another's work.
  writeEntry(ownerId, entry, ifVersion) {
    return this.transaction(() => {
      const stamp = now(), existing = this.entry(ownerId, entry.path);
      if (ifVersion !== undefined && (existing?.version ?? 0) !== ifVersion) fail(409, 'version_conflict', `${entry.path} は他から変更されています。読み直してからやり直してください。`);
      const { count, bytes } = this.usage(ownerId);
      if (!existing && count >= ENTRY_COUNT_MAX) fail(409, 'entry_limit', `保管できるのは${ENTRY_COUNT_MAX}件までです。使わないものを消してください。`);
      if (bytes - (existing?.size ?? 0) + entry.content.length > ENTRY_TOTAL_MAX) fail(409, 'storage_full', '保管できる合計は20MBまでです。使わないものを消してください。');
      const id = existing?.id ?? randomUUID();
      const sealed = this.vault.sealBytes(entry.content, `entry:${ownerId}:${id}`);
      if (existing) {
        this.db.prepare('UPDATE entries SET media_type=?, size=?, env=?, filename=?, session=?, readable=?, content=?, kept_by=?, version=version+1, updated_at=? WHERE id=?')
          .run(entry.media_type, entry.content.length, entry.env, entry.filename, entry.session ?? null, entry.readable, sealed, entry.kept_by, stamp, id);
      } else {
        this.db.prepare('INSERT INTO entries (id,owner_id,path,media_type,size,env,filename,session,readable,content,kept_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)')
          .run(id, ownerId, entry.path, entry.media_type, entry.content.length, entry.env, entry.filename, entry.session ?? null, entry.readable, sealed, entry.kept_by, stamp, stamp);
      }
      return this.entries(ownerId, entry.path)[0];
    });
  }
  removeEntry(ownerId, path) { return this.db.prepare('DELETE FROM entries WHERE owner_id=? AND path=?').run(ownerId, path).changes > 0; }
  removeUnder(ownerId, prefix) {
    return this.db.prepare('DELETE FROM entries WHERE owner_id=? AND (path=? OR path LIKE ?)').run(ownerId, prefix, prefix.replaceAll('%', '\\%').replaceAll('_', '\\_') + '/%').changes;
  }
  // An acquisition owns the entries under its prefix: it wrote them and it keeps them current.
  acquisitions(ownerId) { return this.db.prepare('SELECT * FROM acquisitions WHERE owner_id=? ORDER BY prefix').all(ownerId); }
  acquisition(ownerId, prefix) { return this.db.prepare('SELECT * FROM acquisitions WHERE owner_id=? AND prefix=?').get(ownerId, prefix); }
  // Which acquisition, if any, keeps this path current.
  acquisitionFor(ownerId, path) {
    return this.db.prepare('SELECT * FROM acquisitions WHERE owner_id=? AND (?=prefix OR ? LIKE prefix || ?) ORDER BY length(prefix) DESC LIMIT 1').get(ownerId, path, path, '/%');
  }
  acquisitionState(row) { return this.vault.open(row.state, `acquisition:${row.owner_id}:${row.id}`); }
  // Records an acquisition and everything it produced, together: the entries under its prefix are exactly
  // what it last obtained, and nothing it no longer produces is left behind.
  saveAcquisition(ownerId, { prefix, adapter, subject, label, state, keptBy }, entries, previous) {
    return this.transaction(() => {
      const stamp = now();
      const existing = previous ? this.acquisition(ownerId, previous.prefix) : this.acquisition(ownerId, prefix);
      if (previous) {
        if (!existing || existing.generation !== previous.generation) fail(409, 'connection_changed', '状態が変わりました。もう一度お試しください。');
        if (existing.subject !== subject) fail(409, 'account_changed', '登録し直すには同じアカウントを選んでください。');
      } else if (existing) {
        fail(409, 'already_connected', 'この保管先はすでに使われています。');
      }
      if (!previous && this.db.prepare('SELECT 1 FROM acquisitions WHERE owner_id=? AND adapter=? AND subject=?').get(ownerId, adapter, subject)) fail(409, 'already_connected', 'この認証情報は登録済みです。');
      if (!previous && this.acquisitions(ownerId).length >= ACQUISITION_LIMIT) fail(409, 'acquisition_limit', `登録できる接続は${ACQUISITION_LIMIT}件までです。`);
      const id = existing?.id ?? randomUUID();
      const sealed = this.vault.seal(state, `acquisition:${ownerId}:${id}`);
      if (existing) this.db.prepare("UPDATE acquisitions SET adapter=?, subject=?, label=?, state=?, status='connected', generation=generation+1, updated_at=? WHERE id=?").run(adapter, subject, label, sealed, stamp, id);
      else this.db.prepare("INSERT INTO acquisitions (id,owner_id,prefix,adapter,subject,label,state,status,kept_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'connected',?,?,?)").run(id, ownerId, prefix, adapter, subject, label, sealed, keptBy ?? '', stamp, stamp);
      this.replaceUnder(ownerId, prefix, entries, keptBy ?? '');
      return this.acquisition(ownerId, prefix);
    });
  }
  // The entries an acquisition produced this time, and only those.
  replaceUnder(ownerId, prefix, entries, keptBy) {
    return this.transaction(() => {
      const wanted = new Set(entries.map(entry => entry.path));
      for (const row of this.entries(ownerId, prefix)) if (!wanted.has(row.path)) this.removeEntry(ownerId, row.path);
      for (const entry of entries) this.writeEntry(ownerId, { ...entry, kept_by: keptBy });
    });
  }
  // A refresh that produced nothing new still says when it happened; one that failed marks the acquisition.
  saveState(acquisition, state, entries) {
    return this.transaction(() => {
      const current = this.acquisition(acquisition.owner_id, acquisition.prefix);
      if (!current || current.generation !== acquisition.generation || current.status !== 'connected') fail(409, 'connection_changed', 'この接続は変更または解除されています。');
      this.db.prepare('UPDATE acquisitions SET state=?, updated_at=? WHERE id=?').run(this.vault.seal(state, `acquisition:${acquisition.owner_id}:${acquisition.id}`), now(), acquisition.id);
      if (entries) this.replaceUnder(acquisition.owner_id, acquisition.prefix, entries, acquisition.kept_by);
    });
  }
  reconnectRequired(acquisition) {
    this.db.prepare("UPDATE acquisitions SET status='reconnect_required', generation=generation+1, updated_at=? WHERE id=? AND owner_id=? AND generation=? AND status='connected'").run(now(), acquisition.id, acquisition.owner_id, acquisition.generation);
  }
  disconnect(ownerId, prefix) {
    return this.transaction(() => {
      const acquisition = this.acquisition(ownerId, prefix);
      if (!acquisition) fail(404, 'not_found', '接続が見つかりません。');
      this.db.prepare("UPDATE acquisitions SET status='disconnecting', generation=generation+1, updated_at=? WHERE id=?").run(now(), acquisition.id);
      return acquisition;
    });
  }
  removeAcquisition(ownerId, prefix) {
    return this.transaction(() => {
      this.removeUnder(ownerId, prefix);
      return this.db.prepare('DELETE FROM acquisitions WHERE owner_id=? AND prefix=?').run(ownerId, prefix).changes > 0;
    });
  }
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
  // Possession of an approved key is the whole authorization: the key still exists, and what it asks for is
  // its owner's. An acquisition being disconnected stops delivering before its entries are gone.
  requireAccess(agent, path) {
    if (agent.owner_id !== this.db.prepare('SELECT owner_id FROM agents WHERE id=?').get(agent.id)?.owner_id) fail(403, 'access_denied', 'これは利用できません。');
    if (!this.entry(agent.owner_id, path)) fail(404, 'not_found', '保管されたものが見つかりません。');
    if (this.acquisitionFor(agent.owner_id, path)?.status === 'disconnecting') fail(403, 'access_denied', 'これは利用できません。');
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
