import { randomBytes, randomUUID } from 'node:crypto';
import { digest } from './crypto.mjs';
import { fail } from './errors.mjs';

export const RUNTIME_KEY = /^fdn_[A-Za-z0-9_-]{43}$/;
// A key is a principal that acts for its holder. Its name lives with the principal, its secret with its credential.
const SELECT = `SELECT k.id, k.owner_id, p.name, k.created_at, c.last_used_at FROM keys k
  JOIN principals p ON p.id=k.id LEFT JOIN credentials c ON c.principal_id=k.id AND c.kind='key'`;

// Permission to use one owner's resources. Authentication does not imply delivery of a value.
export class Keys {
  constructor(store) { this.store = store; this.db = store.db; }
  list(ownerId) { return this.db.prepare(`${SELECT} WHERE k.owner_id=? ORDER BY k.created_at,k.id`).all(ownerId); }
  get(ownerId, id) { return this.db.prepare(`${SELECT} WHERE k.owner_id=? AND k.id=?`).get(ownerId, id); }
  create(ownerId, name, token = 'fdn_' + randomBytes(32).toString('base64url')) {
    if (!RUNTIME_KEY.test(token)) fail(400, 'invalid_token', 'アクセスキーの形式が無効です。');
    return { ...this.grant(ownerId, name, digest(token)), token };
  }
  grant(ownerId, name, tokenHash) {
    if (this.list(ownerId).length >= 50) fail(409, 'key_limit', '登録できるアクセスキーは50件までです。');
    const id = randomUUID(), now = new Date().toISOString();
    return this.store.transaction(() => {
      this.db.prepare('INSERT INTO principals (id,name,created_at) VALUES (?,?,?)').run(id, name, now);
      this.db.prepare("INSERT INTO credentials (hash,principal_id,kind,created_at) VALUES (?,?,'key',?)").run(tokenHash, id, now);
      this.db.prepare('INSERT INTO keys (id,owner_id,created_at) VALUES (?,?,?)').run(id, ownerId, now);
      return this.get(ownerId, id);
    });
  }
  byHash(hash) { return this.db.prepare(`${SELECT} WHERE c.hash=?`).get(hash); }
  find(token) {
    if (typeof token !== 'string' || !RUNTIME_KEY.test(token)) return;
    return this.byHash(digest(token));
  }
  authenticate(token) {
    const key = this.find(token);
    if (key) {
      key.last_used_at = new Date().toISOString();
      this.db.prepare("UPDATE credentials SET last_used_at=? WHERE principal_id=? AND kind='key'").run(key.last_used_at, key.id);
    }
    return key;
  }
  requireCurrent(key) {
    if (!this.get(key.owner_id, key.id)) fail(401, 'not_approved', 'このアクセスキーは失効しています。');
    return key;
  }
  // The key goes with its principal: the credential follows by cascade.
  remove(ownerId, id) {
    return this.store.transaction(() => this.db.prepare('SELECT 1 FROM keys WHERE owner_id=? AND id=?').get(ownerId, id)
      ? this.db.prepare('DELETE FROM principals WHERE id=?').run(id).changes > 0 : false);
  }
  rename(ownerId, id, name) {
    if (!this.db.prepare('UPDATE principals SET name=? WHERE id=(SELECT id FROM keys WHERE owner_id=? AND id=?)').run(name, ownerId, id).changes) fail(404, 'not_found', 'アクセスキーが見つかりません。');
  }
}
