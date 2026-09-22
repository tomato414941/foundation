import { DatabaseSync } from 'node:sqlite';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Vault } from './crypto.mjs';
import { fail } from './errors.mjs';

export const digest = (value) => createHash('sha256').update(value).digest('hex');
const now = () => new Date().toISOString();
const publicColumns = 'id, provider, email, name, purpose, scopes, status, created_at, updated_at';
const unpack = (row) => row ? { ...row, scopes: JSON.parse(row.scopes) } : undefined;

export class Store {
  constructor(path, key) {
    this.transactionDepth = 0;
    this.vault = new Vault(key);
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=3000; PRAGMA secure_delete=ON;');
    const version = this.db.prepare('PRAGMA user_version').get().user_version;
    if (version > 5) { this.db.close(); throw new Error('Unsupported database version'); }
    if (version === 1) {
      const count = ['accounts', 'agents', 'grants'].reduce((sum, table) => sum + this.db.prepare('SELECT count(*) AS n FROM ' + table).get().n, 0);
      // Never assign legacy owner-key data to the first Supabase user who logs in.
      if (count) { this.db.close(); throw new Error('Legacy data needs an explicit owner migration; database left unchanged'); }
    }
    try {
      this.transaction(() => {
        if (version === 1) this.db.exec('DROP TABLE grants; DROP TABLE agents; DROP TABLE accounts;');
        this.db.exec(`
          CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, provider TEXT NOT NULL DEFAULT 'gmail',
            email TEXT NOT NULL COLLATE NOCASE, name TEXT NOT NULL, purpose TEXT NOT NULL,
            scopes TEXT NOT NULL, status TEXT NOT NULL, credentials TEXT NOT NULL,
            generation INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            UNIQUE(owner_id, provider, email)
          );
          CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
            generation INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
            last_used_at TEXT, issued_until INTEGER
          );
          CREATE TABLE IF NOT EXISTS grants (
            agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            PRIMARY KEY(agent_id, account_id)
          );
          CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, email TEXT NOT NULL,
            credentials TEXT NOT NULL, expires_at INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS oauth_flows (
            id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            payload TEXT NOT NULL, expires_at INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS access_requests (
            id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, requester_name TEXT NOT NULL,
            provider TEXT NOT NULL, purpose TEXT NOT NULL, mode TEXT NOT NULL, confirmation_code TEXT NOT NULL,
            owner_id TEXT, agent_id TEXT, account_id TEXT,
            status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
          );
          CREATE INDEX IF NOT EXISTS access_requests_token ON access_requests(token_hash, created_at);
        `);
        if (!this.db.prepare('PRAGMA table_info(agents)').all().some(column => column.name === 'issued_nonexpiring')) this.db.exec('ALTER TABLE agents ADD COLUMN issued_nonexpiring INTEGER NOT NULL DEFAULT 0');
        const requestColumns = this.db.prepare('PRAGMA table_info(access_requests)').all().map(column => column.name);
        if (!requestColumns.includes('confirmation_attempts')) this.db.exec('ALTER TABLE access_requests ADD COLUMN confirmation_attempts INTEGER NOT NULL DEFAULT 0');
        if (!requestColumns.includes('details')) this.db.exec("ALTER TABLE access_requests ADD COLUMN details TEXT NOT NULL DEFAULT '{}'");
        if (!requestColumns.includes('progress')) this.db.exec('ALTER TABLE access_requests ADD COLUMN progress TEXT');
        if (!requestColumns.includes('note')) this.db.exec("ALTER TABLE access_requests ADD COLUMN note TEXT NOT NULL DEFAULT ''");
        this.db.exec('PRAGMA user_version=5;');
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
  }
  accounts(ownerId) { return this.db.prepare(`SELECT ${publicColumns} FROM accounts WHERE owner_id=? ORDER BY created_at, id`).all(ownerId).map(unpack); }
  account(ownerId, id) { return unpack(this.db.prepare('SELECT * FROM accounts WHERE owner_id=? AND id=?').get(ownerId, id)); }
  secrets(account) { return this.vault.open(account.credentials, `account:${account.owner_id}:${account.id}`); }
  connect(ownerId, details, credentials, previous) {
    return this.transaction(() => {
      const stamp = now();
      if (previous) {
        const current = this.account(ownerId, previous.id);
        if (!current || current.generation !== previous.generation || current.status === 'disconnecting') fail(409, 'connection_changed', '接続状態が変わりました。もう一度お試しください。');
        if (current.email !== details.email) fail(409, 'account_changed', '再接続には同じアカウントを選んでください。');
        // Reauthorization cannot silently expand previously issued runtime grants.
        if (JSON.stringify(current.scopes.slice().sort()) !== JSON.stringify(details.scopes.slice().sort())) this.db.prepare('DELETE FROM grants WHERE account_id=?').run(current.id);
        this.db.prepare("UPDATE accounts SET name=?, purpose=?, scopes=?, credentials=?, status='connected', generation=generation+1, updated_at=? WHERE id=?").run(details.name, details.purpose, JSON.stringify(details.scopes), this.vault.seal(credentials, `account:${ownerId}:${current.id}`), stamp, current.id);
        return current.id;
      }
      if (this.accounts(ownerId).length >= 25) fail(409, 'account_limit', '接続できるアカウントは25件までです。');
      const provider = details.provider || 'gmail';
      if (this.db.prepare('SELECT 1 FROM accounts WHERE owner_id=? AND provider=? AND email=?').get(ownerId, provider, details.email)) fail(409, 'already_connected', 'このアカウントは接続済みです。');
      const id = randomUUID();
      this.db.prepare('INSERT INTO accounts (id,owner_id,provider,email,name,purpose,scopes,status,credentials,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)').run(id, ownerId, provider, details.email, details.name, details.purpose, JSON.stringify(details.scopes), 'connected', this.vault.seal(credentials, `account:${ownerId}:${id}`), stamp, stamp);
      return id;
    });
  }
  updateAccount(ownerId, id, name, purpose) {
    if (!this.account(ownerId, id)) fail(404, 'not_found', '接続が見つかりません。');
    this.db.prepare('UPDATE accounts SET name=?, purpose=?, updated_at=? WHERE owner_id=? AND id=?').run(name, purpose, now(), ownerId, id);
  }
  saveCredentials(account, credentials) {
    const result = this.db.prepare("UPDATE accounts SET credentials=? WHERE owner_id=? AND id=? AND generation=? AND status='connected'").run(this.vault.seal(credentials, `account:${account.owner_id}:${account.id}`), account.owner_id, account.id, account.generation);
    if (!result.changes) fail(409, 'connection_changed', 'この接続は変更または解除されています。');
  }
  reconnectRequired(account) {
    this.db.prepare("UPDATE accounts SET status='reconnect_required', generation=generation+1, updated_at=? WHERE id=? AND owner_id=? AND generation=? AND status='connected'").run(now(), account.id, account.owner_id, account.generation);
  }
  disconnect(ownerId, id) {
    return this.transaction(() => {
      const account = this.account(ownerId, id);
      if (!account) fail(404, 'not_found', '接続が見つかりません。');
      this.db.prepare("UPDATE accounts SET status='disconnecting', generation=generation+1, updated_at=? WHERE owner_id=? AND id=?").run(now(), ownerId, id);
      this.db.prepare('DELETE FROM grants WHERE account_id=?').run(id);
      return account;
    });
  }
  removeAccount(ownerId, id) { this.db.prepare('DELETE FROM accounts WHERE owner_id=? AND id=?').run(ownerId, id); }
  agents(ownerId) {
    return this.db.prepare('SELECT id,name,created_at,last_used_at,issued_until,issued_nonexpiring FROM agents WHERE owner_id=? ORDER BY created_at,id').all(ownerId).map((agent) => ({ ...agent, accountIds: this.db.prepare('SELECT account_id FROM grants WHERE agent_id=? ORDER BY account_id').all(agent.id).map((row) => row.account_id) }));
  }
  validateAccountIds(ownerId, ids) {
    if (!Array.isArray(ids) || ids.length > 25 || ids.some((id) => typeof id !== 'string' || !this.account(ownerId, id) || this.account(ownerId, id).status === 'disconnecting')) fail(400, 'invalid_accounts', '利用できる接続先を選んでください。');
    return [...new Set(ids)];
  }
  addAgent(ownerId, name, accountIds) {
    const ids = this.validateAccountIds(ownerId, accountIds);
    if (!ids.length) fail(400, 'invalid_accounts', 'アカウントを一つ以上選んでください。');
    if (this.agents(ownerId).length >= 50) fail(409, 'agent_limit', '登録できるアクセスキーは50件までです。');
    const id = randomUUID(), token = `fdn_${randomBytes(32).toString('base64url')}`;
    this.transaction(() => {
      this.db.prepare('INSERT INTO agents (id,owner_id,name,token_hash,created_at) VALUES (?,?,?,?,?)').run(id, ownerId, name, digest(token), now());
      for (const accountId of ids) this.db.prepare('INSERT INTO grants VALUES (?,?)').run(id, accountId);
    });
    return { ...this.agents(ownerId).find((agent) => agent.id === id), token };
  }
  setGrants(ownerId, id, accountIds) {
    if (!this.db.prepare('SELECT 1 FROM agents WHERE owner_id=? AND id=?').get(ownerId, id)) fail(404, 'not_found', 'アクセスキーが見つかりません。');
    const ids = this.validateAccountIds(ownerId, accountIds);
    this.transaction(() => {
      this.db.prepare('DELETE FROM grants WHERE agent_id=?').run(id);
      for (const accountId of ids) this.db.prepare('INSERT INTO grants VALUES (?,?)').run(id, accountId);
      this.db.prepare('UPDATE agents SET generation=generation+1 WHERE owner_id=? AND id=?').run(ownerId, id);
    });
  }
  removeAgent(ownerId, id) { this.db.prepare('DELETE FROM agents WHERE owner_id=? AND id=?').run(ownerId, id); }
  renameAgent(ownerId, id, name) {
    if (!this.db.prepare('UPDATE agents SET name=? WHERE owner_id=? AND id=?').run(name, ownerId, id).changes) fail(404, 'not_found', 'アクセスキーが見つかりません。');
  }
  agentDetails(agent) {
    const row = this.db.prepare('SELECT id,name,created_at,last_used_at,issued_until,issued_nonexpiring FROM agents WHERE id=?').get(agent.id);
    return { ...row, accounts: this.allowedAccounts(agent).map(account => ({ id: account.id, provider: account.provider, name: account.name, status: account.status })) };
  }
  authenticate(token) {
    if (typeof token !== 'string' || !/^fdn_[A-Za-z0-9_-]{43}$/.test(token)) return;
    return this.db.prepare('SELECT id,owner_id,name,generation FROM agents WHERE token_hash=?').get(digest(token));
  }
  allowedAccounts(agent) {
    return this.accounts(agent.owner_id).filter((account) => this.db.prepare('SELECT 1 FROM grants WHERE agent_id=? AND account_id=?').get(agent.id, account.id));
  }
  requireGrant(agent, accountId) {
    if (!this.db.prepare('SELECT 1 FROM grants g JOIN agents a ON a.id=g.agent_id JOIN accounts c ON c.id=g.account_id WHERE a.id=? AND a.owner_id=? AND a.generation=? AND c.owner_id=? AND g.account_id=?').get(agent.id, agent.owner_id, agent.generation, agent.owner_id, accountId)) fail(403, 'access_denied', 'この接続を利用する許可がありません。');
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
    return row ? { ...row, value: this.vault.open(row.credentials, `session:${row.id}`) } : undefined;
  }
  updateSession(id, value) { return this.db.prepare('UPDATE sessions SET credentials=?,email=? WHERE id=? AND owner_id=? AND expires_at>?').run(this.vault.seal(value, `session:${id}`), value.user.email, id, value.user.id, Date.now()).changes > 0; }
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
