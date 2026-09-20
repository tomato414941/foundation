import { createHash, randomBytes } from 'node:crypto';
import { fail } from './errors.mjs';

export const LOGIN_TTL = 60 * 60_000;
const RESEND_WAIT = 60_000;
const digest = (value) => createHash('sha256').update(value).digest('hex');

// Browser-bound PKCE state lives only in memory until login, cancellation or expiry.
export class EmailLogins {
  constructor({ now = Date.now } = {}) { this.now = now; this.pending = new Map(); this.cooldowns = new Map(); }
  sweep() {
    const now = this.now();
    for (const [key, row] of this.pending) if (row.expires_at <= now) this.pending.delete(key);
    for (const [key, until] of this.cooldowns) if (until <= now) this.cooldowns.delete(key);
  }
  reserve(email) {
    this.sweep();
    const now = this.now(), emailKey = digest(email);
    if (this.cooldowns.has(emailKey)) fail(429, 'link_cooldown', '送信から1分ほど待って、もう一度お試しください。');
    if (this.pending.size >= 1000 || this.cooldowns.size >= 1000) fail(429, 'login_rate_limit', 'しばらく待ってからお試しください。');
    const token = randomBytes(32).toString('base64url');
    const row = { email, expires_at: now + LOGIN_TTL, resend_at: now + RESEND_WAIT, storage: new Map(), attempts: 0, sending: true, verifying: false };
    this.cooldowns.set(emailKey, row.resend_at);
    this.pending.set(digest(token), row);
    return { token, row };
  }
  sent(token, previous) {
    const row = this.pending.get(digest(token));
    if (!row || row.expires_at <= this.now()) fail(401, 'login_expired', 'もう一度、ログイン用のメールを送信してください。');
    row.sending = false;
    this.cancel(previous);
  }
  get(token) {
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return;
    const row = this.pending.get(digest(token));
    if (row?.expires_at <= this.now()) { this.cancel(token); return; }
    if (row && !row.sending) return row;
  }
  summary(token) {
    const row = this.get(token);
    return row ? { email: row.email, expires_at: row.expires_at, resend_at: row.resend_at } : null;
  }
  begin(token) {
    const row = this.get(token);
    if (!row) fail(401, 'login_expired', 'もう一度、ログイン用のメールを送信してください。');
    if (row.verifying) fail(409, 'login_busy', '確認中です。少し待ってからお試しください。');
    if (row.attempts >= 5) { this.cancel(token); fail(401, 'login_expired', 'もう一度、ログイン用のメールを送信してください。'); }
    row.attempts++; row.verifying = true;
    return row;
  }
  release(token, row) { if (this.get(token) === row) row.verifying = false; }
  consume(token, row) {
    if (this.get(token) !== row) return false;
    this.cancel(token);
    this.cooldowns.delete(digest(row.email));
    return true;
  }
  cancel(token) { if (typeof token === 'string') this.pending.delete(digest(token)); }
}
