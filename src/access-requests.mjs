import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { digest } from './store.mjs';
import { fail } from './errors.mjs';

export const REQUEST_TTL = 30 * 60_000, MAX_REQUEST_TTL = 24 * 60 * 60_000;
export const REQUEST_ID = /^[A-Za-z0-9_-]{43}$/;
export const RUNTIME_KEY = /^fdn_[A-Za-z0-9_-]{43}$/;
export const CODE_ATTEMPTS = 5;
const normalizeCode = value => typeof value === 'string' ? value.toUpperCase().replace(/[^0-9A-F]/g, '') : '';

// The public approval URL cannot authenticate a runtime. Only the hash of the
// independently generated runtime key is stored, even before user approval.
export class AccessRequests {
  constructor(store, adapters) { this.store = store; this.db = store.db; this.adapters = adapters; }
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
  // The runtime writes the guidance the owner reads on the approval page; Foundation only frames it as the AI's words.
  // The runtime chooses how long the link stays open (default 30 minutes, at most a day): a phone user may need time for the other service.
  create(token, { name, adapter, purpose, details, guidance = '', validMinutes = 30 }) {
    this.adapters.get(adapter);
    if (!Number.isInteger(validMinutes) || validMinutes < 1 || validMinutes * 60_000 > MAX_REQUEST_TTL) fail(400, 'invalid_validity', '有効期間は1〜1440分で指定してください。');
    if (typeof guidance !== 'string' || guidance.length > 2000 || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(guidance)) fail(400, 'invalid_guidance', '案内は2000文字以内で入力してください。');
    guidance = guidance.replace(/\r\n?/g, '\n').trim();
    const encoded = JSON.stringify(this.adapters.details(adapter, details));
    this.store.sweep();
    const hash = this.key(token);
    // A registered key is known by the name its owner gave it; what the runtime calls itself matters only the first time.
    const agent = this.store.authenticate(token), requesterName = agent?.name || name;
    const previous = this.db.prepare("SELECT * FROM access_requests WHERE token_hash=? AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 1").get(hash, Date.now());
    if (previous) {
      if (previous.requester_name !== requesterName || previous.adapter !== adapter || previous.purpose !== purpose || previous.details !== encoded || previous.guidance !== guidance || previous.expires_at - previous.created_at !== validMinutes * 60_000) fail(409, 'request_pending', '承認待ちの依頼があります。先に現在の依頼を確認してください。');
      return previous;
    }
    if (this.db.prepare('SELECT count(*) n FROM access_requests').get().n >= 1000) fail(429, 'request_limit', '接続依頼が混み合っています。しばらく待ってからお試しください。');
    // A code confirms that a new key is the owner's. A key already approved asks only for a registration, so it gets none.
    const id = randomBytes(32).toString('base64url'), code = agent ? '' : randomBytes(4).toString('hex').toUpperCase();
    const now = Date.now();
    this.db.prepare('INSERT INTO access_requests (id,token_hash,requester_name,adapter,purpose,details,guidance,confirmation_code,owner_id,agent_id,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, hash, requesterName, adapter, purpose, encoded, guidance, code && code.slice(0, 4) + '-' + code.slice(4), agent?.owner_id || null, agent?.id || null, now, now + validMinutes * 60_000);
    return this.get(id);
  }
  details(row) { return JSON.parse(row.details); }
  // Everything that happens at the approval URL passes through this server. It is written down as it
  // happens, unjudged, so the runtime can read what its owner ran into. Inputs are never recorded.
  record(id, event, detail = {}) {
    let row;
    try { row = this.get(id); } catch { return; }
    const events = this.eventsOf(row);
    const entry = { at: Date.now(), event: String(event).slice(0, 40) };
    for (const key of ['adapter', 'code']) if (detail[key] != null) entry[key] = String(detail[key]).slice(0, 64);
    if (detail.message != null) entry.message = String(detail.message).slice(0, 300);
    events.push(entry);
    this.db.prepare('UPDATE access_requests SET progress=? WHERE id=?').run(JSON.stringify(events.slice(-40)), row.id);
  }
  eventsOf(row) { return row.progress ? JSON.parse(row.progress) : []; }
  // What a runtime may read about its own current request: the request as created, and the raw events since.
  runtimeView(token) {
    const row = this.current(token);
    return { ...this.summary(row, ''), events: this.eventsOf(row) };
  }
  // A request from a key the owner already approved asks for nothing but a registration: registering completes it.
  registered(id, ownerId, credentialId) {
    const row = this.forUser(id, ownerId, true);
    if (row.agent_id) this.db.prepare("UPDATE access_requests SET owner_id=?, credential_id=?, status='approved' WHERE id=?").run(ownerId, credentialId, row.id);
    else this.db.prepare('UPDATE access_requests SET owner_id=?, credential_id=? WHERE id=?').run(ownerId, credentialId, row.id);
    return this.get(id);
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
    if (!row.confirmation_code) fail(409, 'request_changed', 'このアクセスキーは承認済みです。');
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
  // Approval is the owner acknowledging the key as theirs: once, with the code. From then on the key uses every credential the owner has.
  approve(id, ownerId, code) {
    this.verifyCode(id, ownerId, code);
    return this.store.transaction(() => {
      const row = this.verifyCode(id, ownerId, code);
      if (row.agent_id) fail(409, 'request_changed', 'このアクセスキーは承認済みです。');
      if (this.db.prepare('SELECT 1 FROM agents WHERE token_hash=?').get(row.token_hash)) fail(409, 'request_changed', '依頼元の状態が変わりました。接続リンクを作成し直してください。');
      if (this.store.agents(ownerId).length >= 50) fail(409, 'agent_limit', '登録できるアクセスキーは50件までです。');
      const agentId = randomUUID();
      this.db.prepare('INSERT INTO agents (id,owner_id,name,token_hash,created_at) VALUES (?,?,?,?,?)').run(agentId, ownerId, row.requester_name, row.token_hash, new Date().toISOString());
      this.db.prepare("UPDATE access_requests SET owner_id=?,agent_id=?,status='approved' WHERE id=?").run(ownerId, agentId, row.id);
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
    let status = row.status, credential;
    if (status === 'pending' && row.agent_id && !this.db.prepare('SELECT 1 FROM agents WHERE id=? AND owner_id=? AND token_hash=?').get(row.agent_id, row.owner_id, row.token_hash)) status = 'revoked';
    if (status === 'approved') {
      const agent = this.db.prepare('SELECT * FROM agents WHERE id=? AND token_hash=?').get(row.agent_id, row.token_hash);
      credential = row.credential_id ? this.store.credential(row.owner_id, row.credential_id) : null;
      if (!agent || agent.owner_id !== row.owner_id) status = 'revoked';
      else if (credential && credential.status === 'disconnecting') credential = null;
      else if (credential && credential.status !== 'connected') status = 'reconnect_required';
    }
    const registered = row.agent_id ? this.db.prepare('SELECT name FROM agents WHERE id=? AND token_hash=?').get(row.agent_id, row.token_hash) : undefined;
    const details = this.details(row);
    return { id: row.id, adapter: this.adapters.describe(row.adapter, details), requester_name: row.requester_name, purpose: row.purpose, details, guidance: row.guidance || '', ...(registered ? { agent_name: registered.name } : {}),
      ...(code && row.confirmation_code ? { confirmation_code: row.confirmation_code } : {}), verification_uri: origin + '/connect/' + row.id,
      status, created_at: row.created_at, expires_at: row.expires_at, ...(row.credential_id ? { credential_id: row.credential_id } : {}),
      ...(status === 'approved' ? { agent_id: row.agent_id, ...(credential ? { credential: { id: credential.id, service: credential.service, subject: credential.subject, label: this.adapters.get(credential.adapter).client.facts?.(this.store.secret(credential))?.label || credential.subject } } : {}) } : {}) };
  }
}
