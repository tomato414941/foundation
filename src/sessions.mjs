import { randomBytes } from 'node:crypto';
import { digest } from './crypto.mjs';

const TOKEN = /^[A-Za-z0-9_-]{43}$/;

export class Sessions {
  constructor(store) { this.store = store; this.db = store.db; this.vault = store.vault; }
  create(value) {
    this.store.sweep();
    const token = randomBytes(32).toString('base64url'), id = digest(token);
    this.db.prepare('DELETE FROM sessions WHERE owner_id=? AND id IN (SELECT id FROM sessions WHERE owner_id=? ORDER BY expires_at DESC LIMIT -1 OFFSET 19)').run(value.user.id, value.user.id);
    // Whoever logs in is a principal from then on, known here by the id their login gave them.
    this.db.prepare('INSERT OR IGNORE INTO principals (id,name,created_at) VALUES (?,?,?)').run(value.user.id, '', new Date().toISOString());
    this.db.prepare('INSERT INTO sessions VALUES (?,?,?,?,?)').run(id, value.user.id, value.user.email, this.vault.seal(value, `session:${id}`), Date.now() + 14 * 86400_000);
    return token;
  }
  get(token) {
    if (typeof token !== 'string' || !TOKEN.test(token)) return;
    const row = this.db.prepare('SELECT * FROM sessions WHERE id=? AND expires_at>?').get(digest(token), Date.now());
    return row ? { ...row, value: this.vault.open(row.secret, `session:${row.id}`) } : undefined;
  }
  update(id, value) { return this.db.prepare('UPDATE sessions SET secret=?,email=? WHERE id=? AND owner_id=? AND expires_at>?').run(this.vault.seal(value, `session:${id}`), value.user.email, id, value.user.id, Date.now()).changes > 0; }
  remove(token) { if (typeof token === 'string') this.db.prepare('DELETE FROM sessions WHERE id=?').run(digest(token)); }
}

// A short-lived, single-use authorization exchange, bound to its browser session.
export class OAuthFlows {
  constructor(store) { this.store = store; this.db = store.db; this.vault = store.vault; }
  begin(sessionId, payload) {
    this.store.sweep();
    this.db.prepare('DELETE FROM oauth_flows WHERE session_id=?').run(sessionId);
    const state = randomBytes(32).toString('base64url'), id = digest(state);
    this.db.prepare('INSERT INTO oauth_flows VALUES (?,?,?,?)').run(id, sessionId, this.vault.seal(payload, `oauth:${sessionId}:${id}`), Date.now() + 600_000);
    return state;
  }
  take(sessionId, state) {
    if (typeof state !== 'string' || !TOKEN.test(state)) return;
    const id = digest(state);
    const row = this.db.prepare('DELETE FROM oauth_flows WHERE id=? AND session_id=? AND expires_at>? RETURNING payload').get(id, sessionId, Date.now());
    return row ? this.vault.open(row.payload, `oauth:${sessionId}:${id}`) : undefined;
  }
  // A flow the holder completes by hand may take a wrong answer first; it stays until an answer is right.
  peek(sessionId, state) {
    if (typeof state !== 'string' || !TOKEN.test(state)) return;
    const id = digest(state);
    const row = this.db.prepare('SELECT payload FROM oauth_flows WHERE id=? AND session_id=? AND expires_at>?').get(id, sessionId, Date.now());
    return row ? this.vault.open(row.payload, `oauth:${sessionId}:${id}`) : undefined;
  }
  drop(sessionId, state) { this.db.prepare('DELETE FROM oauth_flows WHERE id=? AND session_id=?').run(digest(state), sessionId); }
}
