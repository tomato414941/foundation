import { randomBytes } from 'node:crypto';
import { digest } from './store.mjs';
import { fail } from './errors.mjs';
import { declarations } from './secrets.mjs';

export const MAX_REQUEST_TTL = 24 * 60 * 60_000;
export const REQUEST_ID = /^[A-Za-z0-9_-]{43}$/;
export const RUNTIME_KEY = /^fdn_[A-Za-z0-9_-]{43}$/;
export const CODE_ATTEMPTS = 5;
const PENDING_MAX = 10, STEPS_MAX = 20, STEP_LENGTH = 500;

// What an approved key asks its owner for, one of two kinds:
//   connect   an acquisition Foundation performs itself, through one adapter
//   store     something the owner puts into storage: the key says where it goes, and writes the steps the owner
//             follows; Foundation knows nothing else about the service
// The key writes the purpose and the steps; Foundation only frames them as the AI's words. The key decides how long
// the link stays open (at most a day), and may have several open at once. Only the hash of the key is stored.
export class Requests {
  constructor(store, adapters) { this.store = store; this.db = store.db; this.adapters = adapters; }
  kindOf(row) { return row.adapter ? 'connect' : 'store'; }
  key(token) {
    if (typeof token !== 'string' || !RUNTIME_KEY.test(token)) fail(401, 'invalid_token', 'アクセスキーの形式が無効です。');
    return digest(token);
  }
  get(id) {
    const row = typeof id === 'string' && REQUEST_ID.test(id) ? this.db.prepare('SELECT * FROM requests WHERE id=? AND expires_at>?').get(id, Date.now()) : null;
    if (!row) fail(410, 'request_expired', 'この依頼は期限切れか、無効です。AIに新しい依頼を作ってもらってください。');
    return row;
  }
  forUser(id, ownerId, pending = false) {
    const row = this.get(id);
    if (row.owner_id !== ownerId) fail(404, 'not_found', 'このアカウントでは依頼を確認できません。');
    if (pending && row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    if (pending && !this.keyOf(row)) fail(409, 'request_revoked', '依頼元の利用は停止されています。新しい依頼を作ってもらってください。');
    return row;
  }
  // A key sees only what it asked for itself.
  forKey(token, id) {
    const row = this.get(id);
    if (row.token_hash !== this.key(token)) fail(404, 'not_found', '依頼が見つかりません。');
    return row;
  }
  keyOf(row) { return this.db.prepare('SELECT name FROM keys WHERE id=? AND owner_id=? AND token_hash=?').get(row.key_id, row.owner_id, row.token_hash); }
  create(token, { adapter, store, purpose = '', steps = [], validMinutes = 30 }) {
    if (!Number.isInteger(validMinutes) || validMinutes < 1 || validMinutes * 60_000 > MAX_REQUEST_TTL) fail(400, 'invalid_validity', '有効期間は1〜1440分で指定してください。');
    if (!Array.isArray(steps) || steps.length > STEPS_MAX || steps.some(step => typeof step !== 'string' || !step.trim() || step.length > STEP_LENGTH || /[\x00-\x1f\x7f]/.test(step))) {
      fail(400, 'invalid_steps', `手順は${STEPS_MAX}件までの文字列の配列で、1件${STEP_LENGTH}文字以内・改行なしで指定してください。`);
    }
    const written = JSON.stringify(steps.map(step => step.trim()));
    this.store.sweep();
    const hash = this.key(token);
    const key = this.store.authenticate(token);
    if (!key) fail(409, 'approval_required', 'このアクセスキーはまだ承認されていません。先に POST /v1/keys (foundation connect) で承認を依頼してください。');
    if (adapter === undefined && store === undefined) fail(400, 'nothing_requested', '接続方法 (adapter) か、保管するものの申告 (store) を指定してください。');
    if (adapter !== undefined && store !== undefined) fail(400, 'invalid_request', '接続方法と保管の申告は同時に指定できません。');
    const kind = adapter ?? null;
    const encoded = JSON.stringify(store !== undefined ? declarations(store) : []);
    if (adapter !== undefined) this.adapters.get(adapter);
    // Asking again for exactly the same thing, while it is open, is the same request.
    const same = this.db.prepare("SELECT * FROM requests WHERE token_hash=? AND key_id=? AND status='pending' AND expires_at>? AND adapter IS ? AND purpose=? AND details=? AND steps=? AND expires_at-created_at=?")
      .get(hash, key.id, Date.now(), kind, purpose, encoded, written, validMinutes * 60_000);
    if (same) return same;
    if (this.db.prepare("SELECT count(*) n FROM requests WHERE token_hash=? AND status='pending' AND expires_at>?").get(hash, Date.now()).n >= PENDING_MAX) fail(409, 'too_many_pending', `同時に開いておける依頼は${PENDING_MAX}件までです。不要な依頼を取り消してください。`);
    if (this.db.prepare('SELECT count(*) n FROM requests').get().n >= 1000) fail(429, 'request_limit', '依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), now = Date.now();
    this.db.prepare('INSERT INTO requests (id,token_hash,key_id,owner_id,requester_name,adapter,purpose,details,steps,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, hash, key.id, key.owner_id, key.name, kind, purpose, encoded, written, now, now + validMinutes * 60_000);
    return this.get(id);
  }
  list(token, status) {
    return this.db.prepare('SELECT * FROM requests WHERE token_hash=? AND expires_at>? AND (? IS NULL OR status=?) ORDER BY created_at, rowid').all(this.key(token), Date.now(), status ?? null, status ?? null);
  }
  details(row) { return JSON.parse(row.details); }
  // Everything that happens at the request's page passes through this server. It is written down as it happens,
  // unjudged, so the key can read what its owner ran into. Inputs are never recorded.
  record(id, event, detail = {}) {
    let row;
    try { row = this.get(id); } catch { return; }
    const entry = { at: Date.now(), event: String(event).slice(0, 40) };
    for (const name of ['adapter', 'code']) if (detail[name] != null) entry[name] = String(detail[name]).slice(0, 64);
    if (detail.message != null) entry.message = String(detail.message).slice(0, 300);
    this.db.prepare('UPDATE requests SET progress=? WHERE id=?').run(JSON.stringify([...this.eventsOf(row), entry].slice(-40)), row.id);
  }
  eventsOf(row) { return row.progress ? JSON.parse(row.progress) : []; }
  // A request is done when what it asked for exists.
  done(id, ownerId, where) {
    const row = this.forUser(id, ownerId, true);
    this.db.prepare("UPDATE requests SET credential_id=?, status='done' WHERE id=?").run(where, row.id);
    return this.get(id);
  }
  deny(id, ownerId) {
    const row = this.forUser(id, ownerId, true);
    this.db.prepare("UPDATE requests SET status='denied' WHERE id=?").run(row.id);
    return this.get(id);
  }
  cancel(token, id) {
    const row = this.forKey(token, id);
    if (row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    this.db.prepare("UPDATE requests SET status='cancelled' WHERE id=?").run(row.id);
    return this.get(row.id);
  }
  summary(row, origin, { events = false } = {}) {
    const kind = this.kindOf(row), key = this.keyOf(row);
    let status = row.status, result;
    if (!key && ['pending', 'done'].includes(status)) status = 'revoked';
    if (status === 'done') {
      result = kind === 'connect' && row.credential_id ? this.store.acquisition(row.owner_id, row.credential_id) : null;
      if (result && result.status === 'disconnecting') result = null;
      else if (result && result.status !== 'connected') status = 'reconnect_required';
    }
    return { id: row.id, kind, ...(row.adapter ? { adapter: this.adapters.describe(row.adapter) } : {}),
      ...(kind === 'store' ? { store: this.details(row) } : {}),
      requester_name: row.requester_name, purpose: row.purpose, steps: JSON.parse(row.steps), ...(key ? { key_name: key.name } : {}),
      verification_uri: origin + '/requests/' + row.id,
      status, created_at: row.created_at, expires_at: row.expires_at,
      ...(status === 'done' ? { result: kind === 'store' ? { names: JSON.parse(row.credential_id) } : result ? { connection_id: result.id, label: result.label } : {} } : {}),
      ...(events ? { events: this.eventsOf(row) } : {}) };
  }
}
