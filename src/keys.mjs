import { randomBytes, randomUUID } from 'node:crypto';
import { digest } from './crypto.mjs';
import { fail } from './errors.mjs';

export const RUNTIME_KEY = /^fdn_[A-Za-z0-9_-]{43}$/;
const columns = 'id,owner_id,name,created_at,last_used_at';

// Permission to use one owner's resources. Authentication does not imply delivery of a value.
export class Keys {
  constructor(store) { this.store = store; this.db = store.db; }
  list(ownerId) { return this.db.prepare(`SELECT ${columns} FROM keys WHERE owner_id=? ORDER BY created_at,id`).all(ownerId); }
  get(ownerId, id) { return this.db.prepare(`SELECT ${columns} FROM keys WHERE owner_id=? AND id=?`).get(ownerId, id); }
  create(ownerId, name, token = 'fdn_' + randomBytes(32).toString('base64url')) {
    if (!RUNTIME_KEY.test(token)) fail(400, 'invalid_token', 'アクセスキーの形式が無効です。');
    return { ...this.grant(ownerId, name, digest(token)), token };
  }
  grant(ownerId, name, tokenHash) {
    if (this.list(ownerId).length >= 50) fail(409, 'key_limit', '登録できるアクセスキーは50件までです。');
    const id = randomUUID();
    this.db.prepare('INSERT INTO keys (id,owner_id,name,token_hash,created_at) VALUES (?,?,?,?,?)')
      .run(id, ownerId, name, tokenHash, new Date().toISOString());
    return this.get(ownerId, id);
  }
  byHash(hash) { return this.db.prepare(`SELECT ${columns} FROM keys WHERE token_hash=?`).get(hash); }
  find(token) {
    if (typeof token !== 'string' || !RUNTIME_KEY.test(token)) return;
    return this.byHash(digest(token));
  }
  authenticate(token) {
    const key = this.find(token);
    if (key) {
      key.last_used_at = new Date().toISOString();
      this.db.prepare('UPDATE keys SET last_used_at=? WHERE id=?').run(key.last_used_at, key.id);
    }
    return key;
  }
  requireCurrent(key) {
    if (!this.get(key.owner_id, key.id)) fail(401, 'not_approved', 'このアクセスキーは失効しています。');
    return key;
  }
  remove(ownerId, id) { return this.db.prepare('DELETE FROM keys WHERE owner_id=? AND id=?').run(ownerId, id).changes > 0; }
  rename(ownerId, id, name) {
    if (!this.db.prepare('UPDATE keys SET name=? WHERE owner_id=? AND id=?').run(name, ownerId, id).changes) fail(404, 'not_found', 'アクセスキーが見つかりません。');
  }
}
