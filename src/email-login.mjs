import { createHash, randomBytes } from 'node:crypto';
import { fail } from './errors.mjs';

export const LOGIN_TTL = 15 * 60_000;
const RESEND_WAIT = 60_000;
const digest = (value) => createHash('sha256').update(value).digest('hex');

// Delivery status is only for the resend screen. The emailed key is verified by Supabase.
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
    const row = { email, expires_at: now + LOGIN_TTL, resend_at: now + RESEND_WAIT, sending: true };
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
  cancel(token) { if (typeof token === 'string') this.pending.delete(digest(token)); }
}
