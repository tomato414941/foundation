import { randomBytes, randomUUID } from 'node:crypto';
import { digest } from './store.mjs';
import { fail } from './errors.mjs';

export const REQUEST_TTL = 30 * 60_000;
export const REQUEST_ID = /^[A-Za-z0-9_-]{43}$/;
export const RUNTIME_KEY = /^fdn_[A-Za-z0-9_-]{43}$/;

// The public approval URL cannot authenticate a runtime. Only the hash of the
// independently generated runtime key is stored, even before user approval.
export class AccessRequests {
  constructor(store, providers) { this.store = store; this.db = store.db; this.providers = providers; }
  key(token) {
    if (typeof token !== 'string' || !RUNTIME_KEY.test(token)) fail(401, 'invalid_token', '実行環境のアクセスキーが無効です。');
    return digest(token);
  }
  get(id) {
    const row = typeof id === 'string' && REQUEST_ID.test(id) ? this.db.prepare('SELECT * FROM access_requests WHERE id=? AND expires_at>?').get(id, Date.now()) : null;
    if (!row) fail(410, 'request_expired', 'この依頼は期限切れか、無効です。AIに新しい接続リンクを依頼してください。');
    return row;
  }
  forUser(id, ownerId, pending = false) {
    const row = this.get(id);
    if (row.owner_id && row.owner_id !== ownerId) fail(404, 'not_found', 'このアカウントでは依頼を確認できません。');
    if (pending && row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    if (pending && row.agent_id && !this.db.prepare('SELECT 1 FROM agents WHERE id=? AND owner_id=? AND token_hash=?').get(row.agent_id, row.owner_id, row.token_hash)) fail(409, 'request_revoked', '依頼元の利用は停止されています。新しい接続リンクを依頼してください。');
    return row;
  }
  current(token) {
    const row = this.db.prepare('SELECT * FROM access_requests WHERE token_hash=? AND expires_at>? ORDER BY created_at DESC, rowid DESC LIMIT 1').get(this.key(token), Date.now());
    if (!row) fail(410, 'request_expired', '接続依頼がありません。新しい接続リンクを作成してください。');
    return row;
  }
  create(token, { name, provider, purpose, mode }) {
    this.providers.permission(provider, mode);
    this.store.sweep();
    const hash = this.key(token);
    const agent = this.store.authenticate(token), requesterName = agent?.name || name;
    const previous = this.db.prepare("SELECT * FROM access_requests WHERE token_hash=? AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 1").get(hash, Date.now());
    if (previous) {
      if (previous.requester_name !== requesterName || previous.provider !== provider || previous.purpose !== purpose || previous.mode !== mode) fail(409, 'request_pending', '承認待ちの依頼があります。先に現在の依頼を確認してください。');
      return previous;
    }
    if (this.db.prepare('SELECT count(*) n FROM access_requests').get().n >= 1000) fail(429, 'request_limit', '接続依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), code = randomBytes(4).toString('hex').toUpperCase();
    const now = Date.now();
    this.db.prepare('INSERT INTO access_requests (id,token_hash,requester_name,provider,purpose,mode,confirmation_code,owner_id,agent_id,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, hash, requesterName, provider, purpose, mode, code.slice(0, 4) + '-' + code.slice(4), agent?.owner_id || null, agent?.id || null, now, now + REQUEST_TTL);
    return this.get(id);
  }
  matches(row, account) {
    return account && account.provider === row.provider && this.providers.get(row.provider).matches(row.mode, account);
  }
  claim(id, ownerId) {
    const row = this.forUser(id, ownerId, true);
    this.db.prepare('UPDATE access_requests SET owner_id=? WHERE id=?').run(ownerId, row.id);
    return this.get(id);
  }
  approve(id, ownerId, accountId, code) {
    return this.store.transaction(() => {
      const row = this.forUser(id, ownerId, true);
      if (typeof code !== 'string' || code !== row.confirmation_code) fail(400, 'confirmation_required', '会話に表示された確認コードを確認してください。');
      this.providers.get(row.provider).client.check();
      const account = typeof accountId === 'string' ? this.store.account(ownerId, accountId) : null;
      if (!account || account.status !== 'connected' || !this.matches(row, account)) fail(409, 'account_unavailable', '依頼された権限で利用できるアカウントを選んでください。');
      let agentId = row.agent_id;
      if (!agentId) {
        if (this.db.prepare('SELECT 1 FROM agents WHERE token_hash=?').get(row.token_hash)) fail(409, 'request_changed', '依頼元の状態が変わりました。接続リンクを作成し直してください。');
        if (this.store.agents(ownerId).length >= 50) fail(409, 'agent_limit', '登録できる実行環境は50件までです。');
        agentId = randomUUID();
        this.db.prepare('INSERT INTO agents (id,owner_id,name,token_hash,created_at) VALUES (?,?,?,?,?)').run(agentId, ownerId, row.requester_name, row.token_hash, new Date().toISOString());
      } else {
        this.db.prepare('UPDATE agents SET generation=generation+1 WHERE id=?').run(agentId);
      }
      this.db.prepare('INSERT OR IGNORE INTO grants (agent_id,account_id) VALUES (?,?)').run(agentId, account.id);
      this.db.prepare("UPDATE access_requests SET owner_id=?,agent_id=?,account_id=?,status='approved' WHERE id=?").run(ownerId, agentId, account.id, row.id);
      return this.get(id);
    });
  }
  deny(id, ownerId) {
    const row = this.forUser(id, ownerId, true);
    this.db.prepare("UPDATE access_requests SET owner_id=?,status='denied' WHERE id=?").run(ownerId, row.id);
    return this.get(id);
  }
  cancel(token) {
    const row = this.current(token);
    if (row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    this.db.prepare("UPDATE access_requests SET status='cancelled' WHERE id=?").run(row.id);
    return this.get(row.id);
  }
  summary(row, origin) {
    let status = row.status, account;
    if (status === 'pending' && row.agent_id && !this.db.prepare('SELECT 1 FROM agents WHERE id=? AND owner_id=? AND token_hash=?').get(row.agent_id, row.owner_id, row.token_hash)) status = 'revoked';
    if (status === 'approved') {
      account = this.store.account(row.owner_id, row.account_id);
      const agent = this.db.prepare('SELECT * FROM agents WHERE id=? AND token_hash=?').get(row.agent_id, row.token_hash);
      const grant = this.db.prepare('SELECT 1 FROM grants WHERE agent_id=? AND account_id=?').get(row.agent_id, row.account_id);
      if (!agent || agent.owner_id !== row.owner_id || !grant || !this.matches(row, account) || account.status === 'disconnecting') status = 'revoked';
      else if (account.status !== 'connected') status = 'reconnect_required';
    }
    return { id: row.id, provider: row.provider, service: this.providers.describe(row.provider), permission: this.providers.permission(row.provider, row.mode), requester_name: row.requester_name, purpose: row.purpose, mode: row.mode,
      confirmation_code: row.confirmation_code, verification_uri: origin + '/connect/' + row.id,
      status, created_at: row.created_at, expires_at: row.expires_at,
      ...(status === 'approved' ? { account: { id: account.id, email: account.email, label: this.providers.get(row.provider).client.accountInfo?.(this.store.secrets(account))?.label || account.email }, agent_id: row.agent_id } : {}) };
  }
}
