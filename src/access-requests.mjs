import { randomBytes } from 'node:crypto';
import { digest } from './store.mjs';
import { fail } from './errors.mjs';
import { declarations } from './secrets.mjs';

export const REQUEST_TTL = 30 * 60_000, MAX_REQUEST_TTL = 24 * 60 * 60_000;
export const REQUEST_ID = /^[A-Za-z0-9_-]{43}$/;
export const RUNTIME_KEY = /^fdn_[A-Za-z0-9_-]{43}$/;
export const CODE_ATTEMPTS = 5;

// What an approved key asks its owner for. Only the hash of the key is stored.
export class AccessRequests {
  constructor(store, adapters) { this.store = store; this.db = store.db; this.adapters = adapters; }
  kindOf(row) { return row.adapter ? 'connect' : 'store'; }
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
    if (pending && !this.db.prepare('SELECT 1 FROM keys WHERE id=? AND owner_id=? AND token_hash=?').get(row.key_id, row.owner_id, row.token_hash)) fail(409, 'request_revoked', '依頼元の利用は停止されています。新しい接続リンクを依頼してください。');
    return row;
  }
  current(token) {
    const row = this.db.prepare('SELECT * FROM access_requests WHERE token_hash=? AND expires_at>? ORDER BY created_at DESC, rowid DESC LIMIT 1').get(this.key(token), Date.now());
    if (!row) fail(410, 'request_expired', '接続依頼がありません。新しい接続リンクを作成してください。');
    return row;
  }
  // A request is one of two kinds (a key not yet approved asks for approval through KeyRequests instead):
  //   connect   an approved key asks for an acquisition Foundation performs itself, through one adapter
  //   store     an approved key asks its owner to put something into storage: the key says where it goes and
  //             how it should be handed over, and writes the instructions; Foundation knows nothing else
  // The runtime writes the purpose and guidance; Foundation only frames them as the AI's words, and chooses
  // nothing about the service involved. The runtime decides how long the link stays open (at most a day).
  create(token, { adapter, store, purpose = '', details, guidance = '', validMinutes = 30 }) {
    if (!Number.isInteger(validMinutes) || validMinutes < 1 || validMinutes * 60_000 > MAX_REQUEST_TTL) fail(400, 'invalid_validity', '有効期間は1〜1440分で指定してください。');
    if (typeof guidance !== 'string' || guidance.length > 2000 || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(guidance)) fail(400, 'invalid_guidance', '案内は2000文字以内で入力してください。');
    guidance = guidance.replace(/\r\n?/g, '\n').trim();
    this.store.sweep();
    const hash = this.key(token);
    // A key is known by the name its owner gave it.
    const key = this.store.authenticate(token), requesterName = key?.name;
    if (!key) fail(409, 'approval_required', 'このアクセスキーはまだ承認されていません。先に POST /v1/keys (foundation connect) で承認を依頼してください。');
    if (adapter === undefined && store === undefined) fail(400, 'nothing_requested', '接続方法 (adapter) か、保管するものの申告 (store) を指定してください。');
    if (adapter !== undefined && store !== undefined) fail(400, 'invalid_request', '接続方法と保管の申告は同時に指定できません。');
    const kind = adapter ?? null;
    const encoded = JSON.stringify(store !== undefined ? declarations(store) : []);
    if (adapter !== undefined) this.adapters.get(adapter);
    // One open request per key at a time. A request left open by an earlier approval of the key, since revoked, does not count.
    const previous = this.db.prepare("SELECT * FROM access_requests WHERE token_hash=? AND status='pending' AND expires_at>? AND key_id=? ORDER BY created_at DESC LIMIT 1").get(hash, Date.now(), key.id);
    if (previous) {
      if (previous.requester_name !== requesterName || previous.adapter !== kind || previous.purpose !== purpose || previous.details !== encoded || previous.guidance !== guidance || previous.expires_at - previous.created_at !== validMinutes * 60_000) fail(409, 'request_pending', '承認待ちの依頼があります。先に現在の依頼を確認してください。');
      return previous;
    }
    if (this.db.prepare('SELECT count(*) n FROM access_requests').get().n >= 1000) fail(429, 'request_limit', '接続依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), now = Date.now();
    this.db.prepare('INSERT INTO access_requests (id,token_hash,requester_name,adapter,purpose,details,guidance,owner_id,key_id,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, hash, requesterName, kind, purpose, encoded, guidance, key.owner_id, key.id, now, now + validMinutes * 60_000);
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
  // A request that asked for something is complete when that something exists.
  registered(id, ownerId, where) {
    const row = this.forUser(id, ownerId, true);
    this.db.prepare("UPDATE access_requests SET owner_id=?, credential_id=?, status='approved' WHERE id=?").run(ownerId, where, row.id);
    return this.get(id);
  }
  claim(id, ownerId) {
    const row = this.forUser(id, ownerId, true);
    this.db.prepare('UPDATE access_requests SET owner_id=? WHERE id=?').run(ownerId, row.id);
    return this.get(id);
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
    const kind = this.kindOf(row);
    let status = row.status, result;
    const key = this.db.prepare('SELECT name FROM keys WHERE id=? AND owner_id=? AND token_hash=?').get(row.key_id, row.owner_id, row.token_hash);
    if (!key && ['pending', 'approved'].includes(status)) status = 'revoked';
    if (status === 'approved') {
      result = kind === 'connect' && row.credential_id ? this.store.acquisition(row.owner_id, row.credential_id) : null;
      if (result && result.status === 'disconnecting') result = null;
      else if (result && result.status !== 'connected') status = 'reconnect_required';
    }
    // What a store request asks for goes out once, as `store`. There is no second copy under another name,
    // and a request that asks for nothing to be stored carries no declaration at all.
    return { id: row.id, kind, ...(row.adapter ? { adapter: this.adapters.describe(row.adapter) } : {}),
      ...(kind === 'store' ? { store: this.details(row) } : {}),
      requester_name: row.requester_name, purpose: row.purpose, guidance: row.guidance || '', ...(key ? { key_name: key.name } : {}),
      verification_uri: origin + '/connect/' + row.id,
      status, created_at: row.created_at, expires_at: row.expires_at, ...(row.credential_id ? { credential_id: row.credential_id } : {}),
      ...(status === 'approved' ? { key_id: row.key_id, ...(result ? { result: { prefix: result.prefix, label: result.label } } : {}), ...(kind === 'store' && row.credential_id ? { result: { path: row.credential_id } } : {}) } : {}) };
  }
}
