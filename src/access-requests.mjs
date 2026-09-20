import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { digest } from './store.mjs';
import { fail } from './errors.mjs';

export const REQUEST_TTL = 30 * 60_000;
export const REQUEST_ID = /^[A-Za-z0-9_-]{43}$/;
export const RUNTIME_KEY = /^fdn_[A-Za-z0-9_-]{43}$/;
export const CODE_ATTEMPTS = 5;
const normalizeCode = value => typeof value === 'string' ? value.toUpperCase().replace(/[^0-9A-F]/g, '') : '';

// The public approval URL cannot authenticate a runtime. Only the hash of the
// independently generated runtime key is stored, even before user approval.
export class AccessRequests {
  constructor(store, providers) { this.store = store; this.db = store.db; this.providers = providers; }
  key(token) {
    if (typeof token !== 'string' || !RUNTIME_KEY.test(token)) fail(401, 'invalid_token', 'アクセスキーの形式が無効です。');
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
  create(token, { name, provider, purpose, mode, details }) {
    this.providers.permission(provider, mode);
    const encoded = JSON.stringify(this.providers.details(provider, details));
    this.store.sweep();
    const hash = this.key(token);
    const agent = this.store.authenticate(token), requesterName = name;
    const previous = this.db.prepare("SELECT * FROM access_requests WHERE token_hash=? AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 1").get(hash, Date.now());
    if (previous) {
      if (previous.requester_name !== requesterName || previous.provider !== provider || previous.purpose !== purpose || previous.mode !== mode || previous.details !== encoded) fail(409, 'request_pending', '承認待ちの依頼があります。先に現在の依頼を確認してください。');
      return previous;
    }
    if (this.db.prepare('SELECT count(*) n FROM access_requests').get().n >= 1000) fail(429, 'request_limit', '接続依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), code = randomBytes(4).toString('hex').toUpperCase();
    const now = Date.now();
    this.db.prepare('INSERT INTO access_requests (id,token_hash,requester_name,provider,purpose,mode,details,confirmation_code,owner_id,agent_id,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, hash, requesterName, provider, purpose, mode, encoded, code.slice(0, 4) + '-' + code.slice(4), agent?.owner_id || null, agent?.id || null, now, now + REQUEST_TTL);
    return this.get(id);
  }
  details(row) { try { return JSON.parse(row.details || '{}'); } catch { return {}; } }
  matches(row, account) {
    return account && account.provider === row.provider && this.providers.get(row.provider).matches(row.mode, account, { ...row, details: this.details(row) });
  }
  claim(id, ownerId) {
    const row = this.forUser(id, ownerId, true);
    this.db.prepare('UPDATE access_requests SET owner_id=? WHERE id=?').run(ownerId, row.id);
    return this.get(id);
  }
  // The user types the code the runtime showed in the conversation; the approval page never displays it.
  // Wrong entries count even when the surrounding transaction rolls back.
  verifyCode(id, ownerId, code) {
    const row = this.forUser(id, ownerId, true);
    const expected = Buffer.from(row.confirmation_code.replace('-', '')), given = Buffer.from(normalizeCode(code));
    if (given.length === expected.length && timingSafeEqual(given, expected)) return row;
    const attempts = row.confirmation_attempts + 1;
    if (attempts >= CODE_ATTEMPTS) {
      this.db.prepare("UPDATE access_requests SET confirmation_attempts=?, owner_id=?, status='denied' WHERE id=?").run(attempts, ownerId, row.id);
      fail(400, 'confirmation_locked', '確認コードの入力回数が上限に達したため、この依頼を取り消しました。AIに新しい接続リンクを依頼してください。');
    }
    this.db.prepare('UPDATE access_requests SET confirmation_attempts=? WHERE id=?').run(attempts, row.id);
    fail(400, 'confirmation_required', 'AIとの会話に表示された確認コードを入力してください。');
  }
  approve(id, ownerId, accountId, code) {
    this.verifyCode(id, ownerId, code);
    return this.store.transaction(() => {
      const row = this.verifyCode(id, ownerId, code);
      this.providers.get(row.provider).client.check();
      const account = typeof accountId === 'string' ? this.store.account(ownerId, accountId) : null;
      if (!account || account.status !== 'connected' || !this.matches(row, account)) fail(409, 'account_unavailable', '依頼された権限で利用できるアカウントを選んでください。');
      let agentId = row.agent_id;
      if (!agentId) {
        if (this.db.prepare('SELECT 1 FROM agents WHERE token_hash=?').get(row.token_hash)) fail(409, 'request_changed', '依頼元の状態が変わりました。接続リンクを作成し直してください。');
        if (this.store.agents(ownerId).length >= 50) fail(409, 'agent_limit', '登録できるアクセスキーは50件までです。');
        agentId = randomUUID();
        this.db.prepare('INSERT INTO agents (id,owner_id,name,token_hash,created_at) VALUES (?,?,?,?,?)').run(agentId, ownerId, row.requester_name, row.token_hash, new Date().toISOString());
      } else {
        // An approved request also confirms the account's current name.
        this.db.prepare('UPDATE agents SET generation=generation+1, name=? WHERE id=?').run(row.requester_name, agentId);
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
  summary(row, origin, { code = true } = {}) {
    let status = row.status, account;
    if (status === 'pending' && row.agent_id && !this.db.prepare('SELECT 1 FROM agents WHERE id=? AND owner_id=? AND token_hash=?').get(row.agent_id, row.owner_id, row.token_hash)) status = 'revoked';
    if (status === 'approved') {
      account = this.store.account(row.owner_id, row.account_id);
      const agent = this.db.prepare('SELECT * FROM agents WHERE id=? AND token_hash=?').get(row.agent_id, row.token_hash);
      const grant = this.db.prepare('SELECT 1 FROM grants WHERE agent_id=? AND account_id=?').get(row.agent_id, row.account_id);
      if (!agent || agent.owner_id !== row.owner_id || !grant || !this.matches(row, account) || account.status === 'disconnecting') status = 'revoked';
      else if (account.status !== 'connected') status = 'reconnect_required';
    }
    const registered = row.agent_id ? this.db.prepare('SELECT name FROM agents WHERE id=? AND token_hash=?').get(row.agent_id, row.token_hash) : undefined;
    return { id: row.id, provider: row.provider, service: this.providers.describe(row.provider), permission: this.providers.permission(row.provider, row.mode), requester_name: row.requester_name, purpose: row.purpose, mode: row.mode, details: this.details(row), ...(registered ? { agent_name: registered.name } : {}),
      ...(code ? { confirmation_code: row.confirmation_code } : {}), verification_uri: origin + '/connect/' + row.id,
      status, created_at: row.created_at, expires_at: row.expires_at,
      ...(status === 'approved' ? { account: { id: account.id, email: account.email, label: this.providers.get(row.provider).client.accountInfo?.(this.store.secrets(account))?.label || account.email }, agent_id: row.agent_id } : {}) };
  }
}
