import { createHmac, randomBytes } from 'node:crypto';
import { fail } from './errors.mjs';
import { prepare as prepareFetch, send as sendFetch } from './fetch.mjs';

// What a principal that hands its own users to Foundation needs to say about itself: where its page is
// (return), where to send a user when a link is no good (refresh), and where it hears that a request finished
// (webhook, signed). As with Stripe. Nothing here is a holding or a line; it is the principal's own setup.
const now = () => new Date().toISOString();
const token = prefix => prefix + randomBytes(32).toString('base64url');

export function returnUrl(value) {
  let url;
  try { url = new URL(value); } catch { fail(400, 'invalid_return_url', '戻り先は https:// で始まるURLで指定してください。'); }
  const local = url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !local) || url.username || url.password || url.hash || url.href.length > 500) fail(400, 'invalid_return_url', '戻り先は https:// で始まるURLで指定してください。');
  return url.href;
}

export class Settings {
  constructor(store, principals) { this.store = store; this.db = store.db; this.principals = principals; }
  get(principalId) {
    const row = this.db.prepare('SELECT principal_id,return_url,refresh_url,webhook_url,created_at FROM settings WHERE principal_id=?').get(principalId);
    return row ? { ...row, notifies: Boolean(row.webhook_url) } : undefined;
  }
  // Set once and replaced whole. The signing secret is shown once, here.
  put(principalId, { returnUrl: target, refreshUrl, webhookUrl }) {
    const back = returnUrl(target), refresh = refreshUrl ? returnUrl(refreshUrl) : back;
    if (webhookUrl) prepareFetch({ url: webhookUrl, method: 'POST' });
    const signing = webhookUrl ? token('whsec_') : null;
    this.db.prepare('INSERT OR REPLACE INTO settings (principal_id,return_url,refresh_url,webhook_url,webhook_secret,created_at) VALUES (?,?,?,?,?,?)')
      .run(principalId, back, refresh, webhookUrl || null, signing && this.store.vault.seal(signing, 'settings:' + principalId), now());
    return { ...this.get(principalId), ...(signing ? { webhook_secret: signing } : {}) };
  }
  remove(principalId) { return this.db.prepare('DELETE FROM settings WHERE principal_id=?').run(principalId).changes > 0; }
  // The principal that hands this one around: an owner with settings. Such a user opens requests on that
  // principal's page, which knows who they are.
  handlerOf(principalId) {
    for (const ownerId of this.principals.ownersOf(principalId)) {
      const found = this.db.prepare('SELECT * FROM settings WHERE principal_id=?').get(ownerId);
      if (found) return { ...found, alias: this.principals.has(ownerId, 'owner', 'principal', principalId) && this.db.prepare("SELECT alias FROM relations WHERE subject_id=? AND relation='owner' AND object_type='principal' AND object_id=?").get(ownerId, principalId)?.alias };
    }
  }
  returnUrlFor(principalId) { return this.handlerOf(principalId)?.return_url; }
  // Where the page sends someone back: after the request is finished (return), or when the link was no good (refresh).
  // Both name the request, so the handler knows which one; neither says anything else.
  backFor(request) {
    if (!request.to_id) return;
    const found = this.handlerOf(request.to_id);
    if (!found) return;
    const withRequest = (url, extra = {}) => { const next = new URL(url); next.searchParams.set('foundation_request', request.id); for (const [k, v] of Object.entries(extra)) next.searchParams.set(k, v); return next.href; };
    return { name: this.principals.get(found.principal_id)?.name ?? '', return_url: withRequest(found.return_url, { foundation_status: request.status }), refresh_url: withRequest(found.refresh_url || found.return_url) };
  }
  sign(secret, body, at = Math.floor(Date.now() / 1000)) {
    return `t=${at},v1=${createHmac('sha256', secret).update(at + '.' + body).digest('hex')}`;
  }
  // A signed event to the handler's webhook, Stripe style: Foundation-Signature: t=<seconds>,v1=<HMAC-SHA256 of "t.body">.
  // Sent from here like any other outbound request (public HTTPS only), retried a few times, never blocking the caller.
  notify(principalId, type, payload, outbound = {}) {
    const found = this.handlerOf(principalId);
    if (!found?.webhook_url || !found.webhook_secret) return;
    const secret = this.store.vault.open(found.webhook_secret, 'settings:' + found.principal_id);
    const body = JSON.stringify({ id: 'evt_' + randomBytes(16).toString('hex'), type, created: Math.floor(Date.now() / 1000), principal: principalId, alias: found.alias ?? null, data: payload });
    const attempt = async (left, wait) => {
      try {
        const answer = await sendFetch(prepareFetch({ url: found.webhook_url, method: 'POST', headers: { 'content-type': 'application/json', 'foundation-signature': this.sign(secret, body) }, body }, outbound.ownHosts ?? []), new Map(), outbound);
        if (answer.status >= 200 && answer.status < 300) return;
      } catch {}
      if (left > 0) setTimeout(() => void attempt(left - 1, wait * 6), wait).unref?.();
    };
    return attempt(3, outbound.retryDelay ?? 5_000);
  }
}
