import { randomBytes } from 'node:crypto';
import { digest } from './crypto.mjs';

const TOKEN = /^[A-Za-z0-9_-]{43}$/;

// What proving who one is leaves, the same for every principal: which proof (an email reached, a WebAuthn signature),
// which address or credential it was, and when. An operation that wants a fresher or stronger proof asks again.
export const SESSION_TTL = 14 * 86400_000;
// A session handed over as a bearer token, to a program rather than a browser, lasts an hour; the program proves
// itself again after that.
export const TOKEN_TTL = 3600_000;
const SESSIONS_MAX = 20;
export class Sessions {
  constructor(store) { this.store = store; this.db = store.db; }
  create(principalId, { proof, ref }, { ttl = SESSION_TTL } = {}) {
    this.store.sweep();
    const token = randomBytes(32).toString('base64url'), id = digest(token), now = Date.now();
    this.db.prepare(`DELETE FROM sessions WHERE principal_id=? AND id IN (SELECT id FROM sessions WHERE principal_id=? ORDER BY expires_at DESC LIMIT -1 OFFSET ${SESSIONS_MAX - 1})`).run(principalId, principalId);
    this.db.prepare('INSERT INTO sessions (id,principal_id,proof,proof_ref,proved_at,created_at,expires_at) VALUES (?,?,?,?,?,?,?)').run(id, principalId, proof, ref, now, now, now + ttl);
    return token;
  }
  get(token) {
    if (typeof token !== 'string' || !TOKEN.test(token)) return;
    return this.db.prepare('SELECT * FROM sessions WHERE id=? AND expires_at>?').get(digest(token), Date.now());
  }
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
  // A flow the owner completes by hand may take a wrong answer first; it stays until an answer is right.
  peek(sessionId, state) {
    if (typeof state !== 'string' || !TOKEN.test(state)) return;
    const id = digest(state);
    const row = this.db.prepare('SELECT payload FROM oauth_flows WHERE id=? AND session_id=? AND expires_at>?').get(id, sessionId, Date.now());
    return row ? this.vault.open(row.payload, `oauth:${sessionId}:${id}`) : undefined;
  }
  drop(sessionId, state) { this.db.prepare('DELETE FROM oauth_flows WHERE id=? AND session_id=?').run(digest(state), sessionId); }
}
