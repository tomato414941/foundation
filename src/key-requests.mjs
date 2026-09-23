import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { digest } from './store.mjs';
import { fail } from './errors.mjs';
import { MAX_REQUEST_TTL, REQUEST_ID, RUNTIME_KEY, CODE_ATTEMPTS } from './requests.mjs';

const normalizeCode = value => typeof value === 'string' ? value.toUpperCase().replace(/[^0-9A-F]/g, '') : '';

// A key not yet known asks its owner to accept it. The owner types the code the runtime showed in the
// conversation, and from then on the key uses everything the owner keeps. The public URL cannot
// authenticate a runtime, so only the hash of the independently generated key is stored.
export class KeyRequests {
  constructor(store) { this.store = store; this.db = store.db; }
  key(token) {
    if (typeof token !== 'string' || !RUNTIME_KEY.test(token)) fail(401, 'invalid_token', 'アクセスキーの形式が無効です。');
    return digest(token);
  }
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
    if (!Number.isInteger(validMinutes) || validMinutes < 1 || validMinutes * 60_000 > MAX_REQUEST_TTL) fail(400, 'invalid_validity', '有効期間は1〜1440分で指定してください。');
    this.store.sweep();
    const hash = this.key(token);
    if (this.store.authenticate(token)) fail(409, 'already_approved', 'このアクセスキーは承認済みです。');
    const previous = this.db.prepare("SELECT * FROM key_requests WHERE token_hash=? AND status='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 1").get(hash, Date.now());
    if (previous) {
      if (previous.name !== name || previous.expires_at - previous.created_at !== validMinutes * 60_000) fail(409, 'request_pending', '承認待ちの依頼があります。先に現在の依頼を確認してください。');
      return previous;
    }
    if (this.db.prepare('SELECT count(*) n FROM key_requests').get().n >= 1000) fail(429, 'request_limit', '接続依頼が混み合っています。しばらく待ってからお試しください。');
    const id = randomBytes(32).toString('base64url'), code = randomBytes(4).toString('hex').toUpperCase(), now = Date.now();
    this.db.prepare('INSERT INTO key_requests (id,token_hash,name,confirmation_code,created_at,expires_at) VALUES (?,?,?,?,?,?)')
      .run(id, hash, name, code.slice(0, 4) + '-' + code.slice(4), now, now + validMinutes * 60_000);
    return this.get(id);
  }
  // Everything that happens at the approval URL is written down as it happens, so the runtime can read what
  // its owner ran into. Inputs are never recorded.
  record(id, event, detail = {}) {
    let row;
    try { row = this.get(id); } catch { return; }
    const entry = { at: Date.now(), event: String(event).slice(0, 40) };
    if (detail.code != null) entry.code = String(detail.code).slice(0, 64);
    if (detail.message != null) entry.message = String(detail.message).slice(0, 300);
    this.db.prepare('UPDATE key_requests SET progress=? WHERE id=?').run(JSON.stringify([...this.eventsOf(row), entry].slice(-40)), row.id);
  }
  eventsOf(row) { return row.progress ? JSON.parse(row.progress) : []; }
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
      if (this.db.prepare('SELECT 1 FROM keys WHERE token_hash=?').get(row.token_hash)) fail(409, 'request_changed', '依頼元の状態が変わりました。接続リンクを作成し直してください。');
      if (this.store.keys(ownerId).length >= 50) fail(409, 'key_limit', '登録できるアクセスキーは50件までです。');
      const keyId = randomUUID();
      this.db.prepare('INSERT INTO keys (id,owner_id,name,token_hash,created_at) VALUES (?,?,?,?,?)').run(keyId, ownerId, row.name, row.token_hash, new Date().toISOString());
      this.db.prepare("UPDATE key_requests SET owner_id=?,key_id=?,status='approved' WHERE id=?").run(ownerId, keyId, row.id);
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
    let status = row.status;
    if (status === 'approved' && !this.db.prepare('SELECT 1 FROM keys WHERE id=? AND owner_id=? AND token_hash=?').get(row.key_id, row.owner_id, row.token_hash)) status = 'revoked';
    return { id: row.id, name: row.name, ...(code ? { confirmation_code: row.confirmation_code } : {}), verification_uri: origin + '/keys/' + row.id,
      status, created_at: row.created_at, expires_at: row.expires_at, ...(status === 'approved' ? { key_id: row.key_id } : {}) };
  }
}
