import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fail } from './errors.mjs';
import { requestResult } from './request-input.mjs';
import { REQUEST_ID, CODE_ATTEMPTS, validity, progress, events } from './request-state.mjs';

const PENDING_MAX = 10, STEPS_MAX = 20, STEP_LENGTH = 500;
// A code a person reads and types (RFC 8628): consonants only, so nothing is mistaken for another and no word is spelled.
const CODE_LETTERS = 'BCDFGHJKLMNPQRSTVWXZ';
const userCode = () => Array.from(randomBytes(8), byte => CODE_LETTERS[byte % CODE_LETTERS.length]).join('');
const normalizeCode = value => typeof value === 'string' ? value.toUpperCase().replace(/[^0-9A-Z]/g, '') : '';

// One principal asks another for what it cannot do itself, described as authorization details (RFC 9396): a relation
// drawn to it, secrets kept, a service connected, an app registered. Who is asked is named when known, and answers
// where they are (as in CIBA); a principal nobody knows yet asks whoever opens its link and types its code (as in
// RFC 8628). Being granted is a fact about this exchange, not a projection of the current state of what resulted.
export class Requests {
  constructor(store) { this.store = store; this.db = store.db; }
  get(id) {
    const row = typeof id === 'string' && REQUEST_ID.test(id) ? this.db.prepare('SELECT * FROM requests WHERE id=? AND expires_at>?').get(id, Date.now()) : null;
    if (!row) fail(410, 'expired_token', 'この依頼は期限切れか、無効です。新しい依頼を作ってもらってください。');
    return row;
  }
  // The one asked reads and answers it. A request addressed to nobody yet is answered by whoever opens it.
  forTo(id, principalId, pending = false) {
    const row = this.get(id);
    if (row.to_id !== null && row.to_id !== principalId) fail(404, 'not_found', 'このアカウントでは依頼を確認できません。');
    if (pending && row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    return row;
  }
  forFrom(id, fromId) {
    const row = this.get(id);
    if (row.from_id !== fromId) fail(404, 'not_found', '依頼が見つかりません。');
    return row;
  }
  create(fromId, { type, detail, requesterName = '', bindingMessage = '', steps = [], validMinutes = 30, toId = null, code: coded = false }) {
    const ttl = validity(validMinutes);
    if (!Array.isArray(steps) || steps.length > STEPS_MAX || steps.some(step => typeof step !== 'string' || !step.trim() || step.length > STEP_LENGTH || /[\x00-\x1f\x7f]/.test(step))) {
      fail(400, 'invalid_steps', '手順は20件までの文字列の配列で、1件500文字以内・改行なしで指定してください。');
    }
    const written = JSON.stringify(steps.map(step => step.trim())), encoded = JSON.stringify(detail);
    this.store.sweep();
    const same = this.db.prepare("SELECT * FROM requests WHERE from_id=? AND to_id IS ? AND status='pending' AND expires_at>? AND type=? AND detail=? AND binding_message=? AND steps=? AND expires_at-created_at=?")
      .get(fromId, toId, Date.now(), type, encoded, bindingMessage, written, ttl);
    if (same) return same;
    if (this.db.prepare("SELECT count(*) n FROM requests WHERE from_id=? AND status='pending' AND expires_at>?").get(fromId, Date.now()).n >= PENDING_MAX) fail(409, 'too_many_pending', '同時に開いておける依頼は10件までです。');
    if (this.db.prepare('SELECT count(*) n FROM requests').get().n >= 1000) fail(429, 'request_limit', '依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), now = Date.now();
    // First contact carries a code: whoever answers types what the asker shows, so the one who answers is the one the
    // asker is talking to.
    const code = coded ? userCode() : null;
    this.db.prepare('INSERT INTO requests (id,from_id,to_id,type,detail,requester_name,binding_message,steps,user_code,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(id, fromId, toId, type, encoded, requesterName, bindingMessage, written, code && code.slice(0, 4) + '-' + code.slice(4), now, now + ttl);
    return this.get(id);
  }
  list(fromId, status) {
    return this.db.prepare('SELECT * FROM requests WHERE from_id=? AND expires_at>? AND (? IS NULL OR status=?) ORDER BY created_at,rowid')
      .all(fromId, Date.now(), status ?? null, status ?? null);
  }
  listTo(toId, status) {
    return this.db.prepare('SELECT * FROM requests WHERE to_id=? AND expires_at>? AND (? IS NULL OR status=?) ORDER BY created_at,rowid')
      .all(toId, Date.now(), status ?? null, status ?? null);
  }
  detail(row) { return JSON.parse(row.detail); }
  record(id, event, detail) {
    let row;
    try { row = this.get(id); } catch { return; }
    this.db.prepare('UPDATE requests SET progress=? WHERE id=?').run(progress(row.progress, event, detail), row.id);
  }
  done(id, toId, value) {
    const row = this.forTo(id, toId, true), result = requestResult(row.type, value);
    this.db.prepare("UPDATE requests SET result=?,to_id=?,status='granted' WHERE id=?").run(JSON.stringify(result), toId, row.id);
    return this.get(id);
  }
  deny(id, toId) {
    const row = this.forTo(id, toId, true);
    this.db.prepare("UPDATE requests SET to_id=?,status='denied' WHERE id=?").run(toId, row.id);
    return this.get(id);
  }
  cancel(fromId, id) {
    const row = this.forFrom(id, fromId);
    if (row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    this.db.prepare("UPDATE requests SET status='cancelled' WHERE id=?").run(row.id);
    return this.get(id);
  }
  cancelFrom(fromId, reason = 'requester_revoked', toId = null) {
    const rows = this.db.prepare("SELECT * FROM requests WHERE from_id=? AND status='pending' AND expires_at>? AND (? IS NULL OR to_id=?)").all(fromId, Date.now(), toId, toId);
    for (const row of rows) {
      this.db.prepare("UPDATE requests SET status='cancelled',reason=? WHERE id=?").run(reason, row.id);
      this.record(row.id, 'cancelled', { code: reason });
    }
    return rows.map(row => this.get(row.id));
  }
  // The code the requester showed, typed by the one asked. Wrong entries count even when the surrounding
  // transaction rolls back; five of them close the request.
  verifyCode(id, toId, code) {
    const row = this.forTo(id, toId, true);
    if (!row.user_code) fail(409, 'wrong_kind', 'この依頼に確認コードはありません。');
    const expected = Buffer.from(normalizeCode(row.user_code)), given = Buffer.from(normalizeCode(code));
    if (given.length === expected.length && timingSafeEqual(given, expected)) return row;
    const attempts = row.attempts + 1;
    if (attempts >= CODE_ATTEMPTS) {
      this.db.prepare("UPDATE requests SET attempts=?,to_id=?,status='denied',reason='confirmation_locked' WHERE id=?").run(attempts, toId, row.id);
      fail(400, 'confirmation_locked', '確認コードの入力回数が上限に達したため、この依頼を取り消しました。新しい依頼を作ってもらってください。');
    }
    this.db.prepare('UPDATE requests SET attempts=? WHERE id=?').run(attempts, row.id);
    fail(400, 'confirmation_required', '会話に表示された確認コードを入力してください。');
  }
  summary(row, { includeEvents = false, includeCode = false } = {}) {
    return { id: row.id, authorization_details: [{ type: row.type, ...this.detail(row) }], from: row.from_id, to: row.to_id,
      binding_message: row.binding_message, steps: JSON.parse(row.steps), status: row.status,
      ...(includeCode && row.user_code ? { user_code: row.user_code } : {}),
      created_at: row.created_at, expires_at: row.expires_at, expires_in: Math.max(0, Math.round((row.expires_at - Date.now()) / 1000)),
      ...(row.reason ? { reason: row.reason } : {}),
      ...(row.status === 'granted' ? { result: JSON.parse(row.result) } : {}),
      ...(includeEvents ? { events: events(row.progress) } : {}) };
  }
}
