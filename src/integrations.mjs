import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { digest } from './crypto.mjs';
import { fail } from './errors.mjs';
import { prepare as prepareFetch, send as sendFetch } from './fetch.mjs';

// An app holding a Foundation account for each of its own users, so that they never
// sign up here. The product's credential reaches no account's contents: it makes accounts, issues and revokes
// their keys, hands one of its users to one request through a single-use link, and reads what they use.
// Everything else about an account is exactly what it is for anyone: its keys are ordinary keys.
export const INTEGRATION_TOKEN = /^fdni_[A-Za-z0-9_-]{43}$/;
const EXTERNAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/;
const LINK_TTL = 10 * 60_000, LINKED_TTL = 30 * 60_000;
const now = () => new Date().toISOString();
const token = prefix => prefix + randomBytes(32).toString('base64url');

export function returnUrl(value) {
  let url;
  try { url = new URL(value); } catch { fail(400, 'invalid_return_url', '戻り先は https:// で始まるURLで指定してください。'); }
  const local = url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !local) || url.username || url.password || url.hash || url.href.length > 500) fail(400, 'invalid_return_url', '戻り先は https:// で始まるURLで指定してください（# は使えません）。');
  return url.href;
}

export class Integrations {
  constructor(store, keys) { this.store = store; this.db = store.db; this.keys = keys; }
  // The owner registers a product; its credential is shown once.
  // As with Stripe: where the product's page is (return), where to send its user when a link cannot be used
  // (refresh, the same page unless given), and where it hears that a request finished (webhook, signed).
  register(ownerId, { name, returnUrl: target, refreshUrl, webhookUrl }) {
    if (this.list(ownerId).length >= 10) fail(409, 'integration_limit', '登録できるアプリは10件までです。');
    const back = returnUrl(target), refresh = refreshUrl ? returnUrl(refreshUrl) : back;
    if (webhookUrl) prepareFetch({ url: webhookUrl, method: 'POST' });
    const id = randomUUID(), secret = token('fdni_'), signing = webhookUrl ? token('whsec_') : null;
    this.db.prepare('INSERT INTO integrations (id,owner_id,name,token_hash,return_url,refresh_url,webhook_url,webhook_secret,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(id, ownerId, name, digest(secret), back, refresh, webhookUrl || null, signing && this.store.vault.seal(signing, 'integration:' + id), now());
    return { ...this.list(ownerId).find(row => row.id === id), token: secret, ...(signing ? { webhook_secret: signing } : {}) };
  }
  list(ownerId) {
    return this.db.prepare('SELECT i.id,i.name,i.return_url,i.refresh_url,i.webhook_url,i.created_at,i.last_used_at,(SELECT count(*) FROM accounts a WHERE a.integration_id=i.id) AS accounts FROM integrations i WHERE owner_id=? ORDER BY created_at,id').all(ownerId);
  }
  // Removing a product stops its credential. The accounts it made stay with the people they belong to.
  remove(ownerId, id) {
    if (!this.db.prepare('DELETE FROM integrations WHERE owner_id=? AND id=?').run(ownerId, id).changes) fail(404, 'not_found', 'アプリの登録が見つかりません。');
  }
  authenticate(value) {
    if (typeof value !== 'string' || !INTEGRATION_TOKEN.test(value)) return;
    const row = this.db.prepare('SELECT * FROM integrations WHERE token_hash=?').get(digest(value));
    if (row) this.db.prepare('UPDATE integrations SET last_used_at=? WHERE id=?').run(now(), row.id);
    return row;
  }
  externalId(value) {
    if (typeof value !== 'string' || !EXTERNAL_ID.test(value)) fail(400, 'invalid_external_id', 'アプリ側の利用者IDは英数字で始まる120文字までで指定してください。');
    return value;
  }
  // One account per user of the product. Asking again for the same user returns the same account.
  ensure(integration, externalId) {
    const external = this.externalId(externalId);
    const found = this.db.prepare('SELECT * FROM accounts WHERE integration_id=? AND external_id=?').get(integration.id, external);
    if (found) return found;
    if (this.db.prepare('SELECT count(*) n FROM accounts WHERE integration_id=?').get(integration.id).n >= 100_000) fail(409, 'account_limit', '作成できるアカウントの上限に達しました。');
    const id = randomUUID();
    this.db.prepare('INSERT INTO accounts (id,integration_id,external_id,created_at) VALUES (?,?,?,?)').run(id, integration.id, external, now());
    return this.db.prepare('SELECT * FROM accounts WHERE id=?').get(id);
  }
  account(integration, externalId) {
    const found = this.db.prepare('SELECT * FROM accounts WHERE integration_id=? AND external_id=?').get(integration.id, this.externalId(externalId));
    if (!found) fail(404, 'not_found', 'アカウントが見つかりません。');
    return found;
  }
  view(account) { return { id: account.id, external_id: account.external_id, created_at: account.created_at, keys: this.keys.list(account.id) }; }
  // Where a request made by one of these accounts is opened: the product's own page, which knows who its user is.
  returnUrlFor(ownerId) {
    return this.db.prepare('SELECT i.return_url FROM accounts a JOIN integrations i ON i.id=a.integration_id WHERE a.id=?').get(ownerId)?.return_url;
  }
  integrationOf(ownerId) {
    return this.db.prepare('SELECT i.*, a.external_id FROM accounts a JOIN integrations i ON i.id=a.integration_id WHERE a.id=?').get(ownerId);
  }
  // Where the page sends someone back: after the request is finished (return), or when the link was no good (refresh).
  // Both name the request, so the product knows which one; neither says anything else.
  backFor(request) {
    const found = this.integrationOf(request.owner_id);
    if (!found) return;
    const withRequest = (url, extra = {}) => { const next = new URL(url); next.searchParams.set('foundation_request', request.id); for (const [k, v] of Object.entries(extra)) next.searchParams.set(k, v); return next.href; };
    return { name: found.name, return_url: withRequest(found.return_url, { foundation_status: request.status }), refresh_url: withRequest(found.refresh_url || found.return_url) };
  }
  // A signed event to the product's webhook, Stripe style: Foundation-Signature: t=<seconds>,v1=<HMAC-SHA256 of "t.body">.
  // Sent from here like any other outbound request (public HTTPS only), retried a few times, never blocking the caller.
  sign(secret, body, at = Math.floor(Date.now() / 1000)) {
    return `t=${at},v1=${createHmac('sha256', secret).update(at + '.' + body).digest('hex')}`;
  }
  notify(ownerId, type, payload, outbound = {}) {
    const found = this.integrationOf(ownerId);
    if (!found?.webhook_url || !found.webhook_secret) return;
    const secret = this.store.vault.open(found.webhook_secret, 'integration:' + found.id);
    const body = JSON.stringify({ id: 'evt_' + randomBytes(16).toString('hex'), type, created: Math.floor(Date.now() / 1000), account: found.external_id, data: payload });
    const attempt = async (left, wait) => {
      try {
        const answer = await sendFetch(prepareFetch({ url: found.webhook_url, method: 'POST', headers: { 'content-type': 'application/json', 'foundation-signature': this.sign(secret, body) }, body }, outbound.ownHosts || []), new Map(), outbound);
        if (answer.status >= 200 && answer.status < 300) return;
      } catch {}
      if (left > 0) setTimeout(() => void attempt(left - 1, wait * 6), wait).unref?.();
    };
    return attempt(3, outbound.retryDelay ?? 5_000);
  }
  // Everything the account holds goes with it. What sits in the object space is the caller's to clear.
  deleteAccount(integration, externalId) {
    const account = this.account(integration, externalId);
    this.store.transaction(() => {
      for (const table of ['secrets', 'keys', 'requests', 'connections', 'request_links']) this.db.prepare(`DELETE FROM ${table} WHERE owner_id=?`).run(account.id);
      this.db.prepare('DELETE FROM accounts WHERE id=?').run(account.id);
    });
    return account;
  }
  // A single-use link to one request of one of this product's accounts. It carries nothing but that request.
  link(integration, request, externalId) {
    const account = this.db.prepare('SELECT * FROM accounts WHERE id=? AND integration_id=?').get(request.owner_id, integration.id);
    if (!account || (externalId !== undefined && account.external_id !== this.externalId(externalId))) fail(404, 'not_found', '依頼が見つかりません。');
    if (request.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    if (request.kind !== 'store') fail(409, 'link_unsupported', '接続の依頼はまだリンクで引き渡せません。');
    const secret = token('');
    this.db.prepare("INSERT INTO request_links (token_hash,request_id,owner_id,kind,expires_at) VALUES (?,?,?,'link',?)").run(digest(secret), request.id, request.owner_id, Date.now() + LINK_TTL);
    return { token: secret, expires_at: Date.now() + LINK_TTL };
  }
  // Opening the link spends it, and leaves a short session that reaches that one request and nothing else.
  claim(requestId, value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) fail(410, 'link_expired', 'このリンクは使えません。もう一度開き直してください。');
    return this.store.transaction(() => {
      const row = this.db.prepare("SELECT * FROM request_links WHERE token_hash=? AND kind='link' AND expires_at>?").get(digest(value), Date.now());
      if (!row || row.request_id !== requestId) fail(410, 'link_expired', 'このリンクは使えません。もう一度開き直してください。');
      this.db.prepare('DELETE FROM request_links WHERE token_hash=?').run(row.token_hash);
      const session = token('');
      this.db.prepare("INSERT INTO request_links (token_hash,request_id,owner_id,kind,expires_at) VALUES (?,?,?,'session',?)").run(digest(session), row.request_id, row.owner_id, Date.now() + LINKED_TTL);
      return { session, owner_id: row.owner_id, request_id: row.request_id };
    });
  }
  linked(value, requestId) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return;
    const row = this.db.prepare("SELECT * FROM request_links WHERE token_hash=? AND kind='session' AND expires_at>?").get(digest(value), Date.now());
    return row && row.request_id === requestId ? row : undefined;
  }
}
