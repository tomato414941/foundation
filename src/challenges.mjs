import { randomBytes } from 'node:crypto';
import { digest } from './crypto.mjs';

const SECRET = /^[A-Za-z0-9_-]{43}$/;
// How many may wait at once, for each purpose.
export const PENDING_MAX = 1000;
export const randomSecret = () => randomBytes(32).toString('base64url');

// Single-use values given out to be given back, as proof of something: that one receives at an address. Only their
// digests are kept. A handle lets the browser that asked find what it is waiting for; it proves nothing.
export class Challenges {
  constructor(store, { secret = randomSecret, now = Date.now } = {}) { Object.assign(this, { store, db: store.db, secret, now }); }
  issue(purpose, subject, { handle, data = {}, ttl }) {
    const now = this.now();
    // The table is bounded for each purpose. When one is full, its oldest waiting ones give way: nobody is refused for
    // what others asked, and the most a flood costs anyone is asking again.
    this.db.prepare('DELETE FROM challenges WHERE expires_at<=?').run(now);
    const over = this.db.prepare('SELECT count(*) n FROM challenges WHERE purpose=?').get(purpose).n - PENDING_MAX + 1;
    if (over > 0) this.db.prepare('DELETE FROM challenges WHERE id IN (SELECT id FROM challenges WHERE purpose=? ORDER BY created_at, rowid LIMIT ?)').run(purpose, over);
    const secret = this.secret(subject);
    this.db.prepare('INSERT OR REPLACE INTO challenges (id,purpose,subject,handle,data,created_at,expires_at) VALUES (?,?,?,?,?,?,?)')
      .run(digest(secret), purpose, subject, handle ? digest(handle) : null, JSON.stringify(data), now, now + ttl);
    return secret;
  }
  // The newest one still open for a subject, to space out how often it is asked for.
  latest(purpose, subject) { return this.row(this.db.prepare('SELECT * FROM challenges WHERE purpose=? AND subject=? AND expires_at>? ORDER BY created_at DESC LIMIT 1').get(purpose, subject, this.now())); }
  waiting(handle) {
    if (typeof handle !== 'string' || !SECRET.test(handle)) return;
    return this.row(this.db.prepare('SELECT * FROM challenges WHERE handle=? AND expires_at>? ORDER BY created_at DESC LIMIT 1').get(digest(handle), this.now()));
  }
  // Giving one back spends it, whether or not what it proves is then accepted.
  take(purpose, secret) {
    if (typeof secret !== 'string' || !SECRET.test(secret)) return;
    return this.row(this.db.prepare('DELETE FROM challenges WHERE id=? AND purpose=? AND expires_at>? RETURNING *').get(digest(secret), purpose, this.now()));
  }
  forget(handle) { if (typeof handle === 'string' && SECRET.test(handle)) this.db.prepare('DELETE FROM challenges WHERE handle=?').run(digest(handle)); }
  row(row) { return row ? { ...row, data: JSON.parse(row.data) } : undefined; }
}
