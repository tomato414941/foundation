import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fail } from './errors.mjs';
import { REQUEST_ID, CODE_ATTEMPTS, requestKey, validity, progress, events } from './request-state.mjs';

const normalizeCode = value => typeof value === 'string' ? value.toUpperCase().replace(/[^0-9A-F]/g, '') : '';

// A key not yet known asks its owner to accept it. The owner types the code the runtime showed in the
// conversation, and from then on the key uses everything the owner keeps. The public URL cannot
// authenticate a runtime, so only the hash of the independently generated key is stored.
export class KeyRequests {
  constructor(store, keys) { this.store = store; this.db = store.db; this.keys = keys; }
  key(token) { return requestKey(token); }
  get(id) {
    const row = typeof id === 'string' && REQUEST_ID.test(id) ? this.db.prepare('SELECT * FROM key_requests WHERE id=? AND expires_at>?').get(id, Date.now()) : null;
    if (!row) fail(410, 'request_expired', 'この依頼は期限切れか、無効です。AIに新しい接続リンクを依頼してください。');
    return row;
  }
  forUser(id, ownerId, pending = false) {
    const row = this.get(id);
    if (row.owner_id && row.owner_id !== ownerId) fail(404, 'not_found', 'このアカウントでは依頼を確認できません。');
    if (pending && row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    return row;
  }
  current(token) {
    const row = this.db.prepare('SELECT * FROM key_requests WHERE token_hash=? AND expires_at>? ORDER BY created_at DESC, rowid DESC LIMIT 1').get(this.key(token), Date.now());
    if (!row) fail(410, 'request_expired', '承認の依頼がありません。新しく依頼してください。');
    return row;
  }
  // One open request per key. Asking again with the same name and validity returns it; anything else is refused.
  create(token, { name, validMinutes = 30 }) {
    const ttl = validity(validMinutes);
    this.store.sweep();
    const hash = this.key(token);
    if (this.keys.find(token)) fail(409, 'already_approved', 'このアクセスキーは承認済みです。');
    const previous = this.db.prepare("SELECT * FROM key_requests WHERE token_hash=? AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 1").get(hash, Date.now());
    if (previous) {
      if (previous.name !== name || previous.expires_at - previous.created_at !== ttl) fail(409, 'request_pending', '承認待ちの依頼があります。先に現在の依頼を確認してください。');
      return previous;
    }
    if (this.db.prepare('SELECT count(*) n FROM key_requests').get().n >= 1000) fail(429, 'request_limit', '接続依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), code = randomBytes(4).toString('hex').toUpperCase(), now = Date.now();
    this.db.prepare('INSERT INTO key_requests (id,token_hash,name,confirmation_code,created_at,expires_at) VALUES (?,?,?,?,?,?)')
      .run(id, hash, name, code.slice(0, 4) + '-' + code.slice(4), now, now + ttl);
    return this.get(id);
  }
  // Everything that happens at the approval URL is written down as it happens, so the runtime can read what
  // its owner ran into. Inputs are never recorded.
  record(id, event, detail = {}) {
    let row;
    try { row = this.get(id); } catch { return; }
    this.db.prepare('UPDATE key_requests SET progress=? WHERE id=?').run(progress(row.progress, event, detail), row.id);
  }
  eventsOf(row) { return events(row.progress); }
  runtimeView(token, origin) {
    const row = this.current(token);
    return { ...this.summary(row, origin), events: this.eventsOf(row) };
  }
  // Wrong entries count even when the surrounding transaction rolls back.
  verifyCode(id, ownerId, code) {
    const row = this.forUser(id, ownerId, true);
    const expected = Buffer.from(row.confirmation_code.replace('-', '')), given = Buffer.from(normalizeCode(code));
    if (given.length === expected.length && timingSafeEqual(given, expected)) return row;
    const attempts = row.confirmation_attempts + 1;
    if (attempts >= CODE_ATTEMPTS) {
      this.db.prepare("UPDATE key_requests SET confirmation_attempts=?, owner_id=?, status='denied' WHERE id=?").run(attempts, ownerId, row.id);
      fail(400, 'confirmation_locked', '確認コードの入力回数が上限に達したため、この依頼を取り消しました。AIに新しい接続リンクを依頼してください。');
    }
    this.db.prepare('UPDATE key_requests SET confirmation_attempts=? WHERE id=?').run(attempts, row.id);
    fail(400, 'confirmation_required', 'AIとの会話に表示された確認コードを入力してください。');
  }
  approve(id, ownerId, code) {
    this.verifyCode(id, ownerId, code);
    return this.store.transaction(() => {
      const row = this.verifyCode(id, ownerId, code);
      if (this.keys.byHash(row.token_hash)) fail(409, 'request_changed', '依頼元の状態が変わりました。接続リンクを作成し直してください。');
      const key = this.keys.grant(ownerId, row.name, row.token_hash);
      this.db.prepare("UPDATE key_requests SET owner_id=?,key_id=?,status='done' WHERE id=?").run(ownerId, key.id, row.id);
      return this.get(id);
    });
  }
  deny(id, ownerId) {
    const row = this.forUser(id, ownerId, true);
    this.db.prepare("UPDATE key_requests SET owner_id=?,status='denied' WHERE id=?").run(ownerId, row.id);
    return this.get(id);
  }
  cancel(token) {
    const row = this.current(token);
    if (row.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    this.db.prepare("UPDATE key_requests SET status='cancelled' WHERE id=?").run(row.id);
    return this.get(row.id);
  }
  summary(row, origin, { code = true } = {}) {
    return { id: row.id, kind: 'approve', input: { name: row.name }, name: row.name, requester_name: row.name,
      ...(code ? { confirmation_code: row.confirmation_code } : {}), verification_uri: origin + '/key-requests/' + row.id,
      status: row.status, created_at: row.created_at, expires_at: row.expires_at,
      ...(row.status === 'done' ? { result: { key_id: row.key_id }, key_id: row.key_id } : {}) };
  }
}
