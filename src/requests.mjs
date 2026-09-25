import { randomBytes } from 'node:crypto';
import { fail } from './errors.mjs';
import { requestInput, requestResult } from './request-input.mjs';
import { REQUEST_ID, requestKey, validity, progress, events } from './request-state.mjs';

const PENDING_MAX = 10, STEPS_MAX = 20, STEP_LENGTH = 500;

// An approved key asks its owner to connect a service or save values. Completion is a
// fact about this exchange, not a projection of the current state of the resulting resource.
export class Requests {
  constructor(store, keys) { this.store = store; this.db = store.db; this.keys = keys; }
  key(token) { return requestKey(token); }
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
  forKey(token, id) {
    const key = this.keys.find(token);
    if (!key) fail(401, 'not_approved', 'このアクセスキーはまだ承認されていないか、失効しています。');
    const row = this.get(id);
    if (row.token_hash !== this.key(token) || row.key_id !== key.id || row.owner_id !== key.owner_id) fail(404, 'not_found', '依頼が見つかりません。');
    return row;
  }
  keyOf(row) {
    const key = this.keys.byHash(row.token_hash);
    return key?.id === row.key_id && key.owner_id === row.owner_id ? key : undefined;
  }
  create(token, { kind, input, purpose = '', steps = [], validMinutes = 30 }) {
    const ttl = validity(validMinutes), definition = requestInput(kind, input);
    if (!Array.isArray(steps) || steps.length > STEPS_MAX || steps.some(step => typeof step !== 'string' || !step.trim() || step.length > STEP_LENGTH || /[\x00-\x1f\x7f]/.test(step))) {
      fail(400, 'invalid_steps', '手順は20件までの文字列の配列で、1件500文字以内・改行なしで指定してください。');
    }
    const written = JSON.stringify(steps.map(step => step.trim())), encoded = JSON.stringify(definition);
    this.store.sweep();
    const hash = this.key(token), key = this.keys.find(token);
    if (!key) fail(401, 'not_approved', 'このアクセスキーはまだ承認されていないか、失効しています。');
    const same = this.db.prepare("SELECT * FROM requests WHERE token_hash=? AND key_id=? AND status='pending' AND expires_at>? AND kind=? AND input=? AND purpose=? AND steps=? AND expires_at-created_at=?")
      .get(hash, key.id, Date.now(), kind, encoded, purpose, written, ttl);
    if (same) return same;
    if (this.db.prepare("SELECT count(*) n FROM requests WHERE token_hash=? AND status='pending' AND expires_at>?").get(hash, Date.now()).n >= PENDING_MAX) fail(409, 'too_many_pending', '同時に開いておける依頼は10件までです。不要な依頼を取り消してください。');
    if (this.db.prepare('SELECT count(*) n FROM requests').get().n >= 1000) fail(429, 'request_limit', '依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), now = Date.now();
    this.db.prepare('INSERT INTO requests (id,token_hash,key_id,owner_id,requester_name,kind,input,purpose,steps,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, hash, key.id, key.owner_id, key.name, kind, encoded, purpose, written, now, now + ttl);
    return this.get(id);
  }
  list(token, status) {
    const key = this.keys.find(token);
    if (!key) fail(401, 'not_approved', 'このアクセスキーは失効しています。');
    return this.db.prepare('SELECT * FROM requests WHERE token_hash=? AND key_id=? AND owner_id=? AND expires_at>? AND (? IS NULL OR status=?) ORDER BY created_at,rowid')
      .all(this.key(token), key.id, key.owner_id, Date.now(), status ?? null, status ?? null);
  }
  input(row) { return JSON.parse(row.input); }
  record(id, event, detail) {
    let row;
    try { row = this.get(id); } catch { return; }
    this.db.prepare('UPDATE requests SET progress=? WHERE id=?').run(progress(row.progress, event, detail), row.id);
  }
  done(id, ownerId, value) {
    const row = this.forUser(id, ownerId, true), result = requestResult(row.kind, value);
    this.db.prepare("UPDATE requests SET result=?,status='done' WHERE id=?").run(JSON.stringify(result), row.id);
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
    return this.get(id);
  }
  cancelForKey(ownerId, keyId) {
    const rows = this.db.prepare("SELECT * FROM requests WHERE owner_id=? AND key_id=? AND status='pending' AND expires_at>?").all(ownerId, keyId, Date.now());
    for (const row of rows) {
      this.db.prepare("UPDATE requests SET status='cancelled',reason='requester_revoked' WHERE id=?").run(row.id);
      this.record(row.id, 'cancelled', { code: 'requester_revoked' });
    }
    return rows.map(row => this.get(row.id));
  }
  summary(row, { includeEvents = false } = {}) {
    return { id: row.id, kind: row.kind, input: this.input(row), requester_name: row.requester_name,
      purpose: row.purpose, steps: JSON.parse(row.steps), status: row.status,
      created_at: row.created_at, expires_at: row.expires_at,
      ...(row.reason ? { reason: row.reason } : {}),
      ...(row.status === 'done' ? { result: JSON.parse(row.result) } : {}),
      ...(includeEvents ? { events: events(row.progress) } : {}) };
  }
}
