import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fail } from './errors.mjs';
import { requestInput, requestResult } from './request-input.mjs';
import { REQUEST_ID, CODE_ATTEMPTS, validity, progress, events } from './request-state.mjs';

const PENDING_MAX = 10, STEPS_MAX = 20, STEP_LENGTH = 500;
const normalizeCode = value => typeof value === 'string' ? value.toUpperCase().replace(/[^0-9A-F]/g, '') : '';

// One principal asks another for what it cannot reach itself: to act for them (actor), to keep something for
// it (store), or to connect a service (connect). Who is asked is named when known; a principal that is not
// yet anyone's asks whoever will have it. Completion is a fact about this exchange, not a projection of the
// current state of the resulting resource.
export class Requests {
  constructor(store) { this.store = store; this.db = store.db; }
  get(id) {
    const row = typeof id === 'string' && REQUEST_ID.test(id) ? this.db.prepare('SELECT * FROM requests WHERE id=? AND expires_at>?').get(id, Date.now()) : null;
    if (!row) fail(410, 'request_expired', 'この依頼は期限切れか、無効です。新しい依頼を作ってもらってください。');
    return row;
  }
  // The one asked reads and answers it. An actor request addressed to nobody yet is answered by whoever opens it.
  forTo(id, principalId, pending = false) {
    const row = this.get(id);
    if (row.to_id !== null && row.to_id !== principalId) fail(404, 'not_found', 'このアカウントでは依頼を確認できません。');
    if (row.to_id === null && row.kind !== 'actor') fail(404, 'not_found', 'このアカウントでは依頼を確認できません。');
    if (pending && row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    return row;
  }
  forFrom(id, fromId) {
    const row = this.get(id);
    if (row.from_id !== fromId) fail(404, 'not_found', '依頼が見つかりません。');
    return row;
  }
  create(fromId, { kind, input, purpose = '', steps = [], validMinutes = 30, toId = null }) {
    const ttl = validity(validMinutes), definition = requestInput(kind, input);
    if (!Array.isArray(steps) || steps.length > STEPS_MAX || steps.some(step => typeof step !== 'string' || !step.trim() || step.length > STEP_LENGTH || /[\x00-\x1f\x7f]/.test(step))) {
      fail(400, 'invalid_steps', '手順は20件までの文字列の配列で、1件500文字以内・改行なしで指定してください。');
    }
    if (kind !== 'actor' && toId === null) fail(400, 'invalid_request', '誰に頼むかを指定してください。');
    const written = JSON.stringify(steps.map(step => step.trim())), encoded = JSON.stringify(definition);
    this.store.sweep();
    const same = this.db.prepare("SELECT * FROM requests WHERE from_id=? AND to_id IS ? AND status='pending' AND expires_at>? AND kind=? AND input=? AND purpose=? AND steps=? AND expires_at-created_at=?")
      .get(fromId, toId, Date.now(), kind, encoded, purpose, written, ttl);
    if (same) return same;
    if (kind === 'actor' && this.db.prepare("SELECT 1 FROM requests WHERE from_id=? AND kind='actor' AND status='pending' AND expires_at>?").get(fromId, Date.now())) fail(409, 'request_pending', '承認待ちの依頼があります。先に現在の依頼を確認してください。');
    if (this.db.prepare("SELECT count(*) n FROM requests WHERE from_id=? AND status='pending' AND expires_at>?").get(fromId, Date.now()).n >= PENDING_MAX) fail(409, 'too_many_pending', '同時に開いておける依頼は10件までです。');
    if (this.db.prepare('SELECT count(*) n FROM requests').get().n >= 1000) fail(429, 'request_limit', '依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), now = Date.now();
    const code = kind === 'actor' ? randomBytes(4).toString('hex').toUpperCase() : null;
    this.db.prepare('INSERT INTO requests (id,from_id,to_id,kind,input,purpose,steps,code,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run(id, fromId, toId, kind, encoded, purpose, written, code && code.slice(0, 4) + '-' + code.slice(4), now, now + ttl);
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
  input(row) { return JSON.parse(row.input); }
  record(id, event, detail) {
    let row;
    try { row = this.get(id); } catch { return; }
    this.db.prepare('UPDATE requests SET progress=? WHERE id=?').run(progress(row.progress, event, detail), row.id);
  }
  done(id, toId, value) {
    const row = this.forTo(id, toId, true), result = requestResult(row.kind, value);
    this.db.prepare("UPDATE requests SET result=?,to_id=?,status='done' WHERE id=?").run(JSON.stringify(result), toId, row.id);
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
  cancelFrom(fromId, reason = 'requester_revoked') {
    const rows = this.db.prepare("SELECT * FROM requests WHERE from_id=? AND status='pending' AND expires_at>?").all(fromId, Date.now());
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
    if (row.kind !== 'actor') fail(409, 'wrong_kind', 'この依頼に確認コードはありません。');
    const expected = Buffer.from(row.code.replace('-', '')), given = Buffer.from(normalizeCode(code));
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
    return { id: row.id, kind: row.kind, from: row.from_id, to: row.to_id, input: this.input(row),
      purpose: row.purpose, steps: JSON.parse(row.steps), status: row.status,
      ...(includeCode && row.code ? { confirmation_code: row.code } : {}),
      created_at: row.created_at, expires_at: row.expires_at,
      ...(row.reason ? { reason: row.reason } : {}),
      ...(row.status === 'done' ? { result: JSON.parse(row.result) } : {}),
      ...(includeEvents ? { events: events(row.progress) } : {}) };
  }
}
