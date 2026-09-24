import { randomBytes, randomUUID } from 'node:crypto';
import { digest } from './store.mjs';
import { fail } from './errors.mjs';

// Another product (ai-simplicity, say) holding a Foundation account for each of its own users, so that they never
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
  constructor(store) { this.store = store; this.db = store.db; }
  // The owner registers a product; its credential is shown once.
  register(ownerId, { name, returnUrl: target }) {
    if (this.list(ownerId).length >= 10) fail(409, 'integration_limit', '登録できる連携は10件までです。');
    const id = randomUUID(), secret = token('fdni_');
    this.db.prepare('INSERT INTO integrations (id,owner_id,name,token_hash,return_url,created_at) VALUES (?,?,?,?,?,?)').run(id, ownerId, name, digest(secret), returnUrl(target), now());
    return { ...this.list(ownerId).find(row => row.id === id), token: secret };
  }
  list(ownerId) {
    return this.db.prepare('SELECT i.id,i.name,i.return_url,i.created_at,i.last_used_at,(SELECT count(*) FROM accounts a WHERE a.integration_id=i.id) AS accounts FROM integrations i WHERE owner_id=? ORDER BY created_at,id').all(ownerId);
  }
  // Removing a product stops its credential. The accounts it made stay with the people they belong to.
  remove(ownerId, id) {
    if (!this.db.prepare('DELETE FROM integrations WHERE owner_id=? AND id=?').run(ownerId, id).changes) fail(404, 'not_found', '連携が見つかりません。');
  }
  authenticate(value) {
    if (typeof value !== 'string' || !INTEGRATION_TOKEN.test(value)) return;
    const row = this.db.prepare('SELECT * FROM integrations WHERE token_hash=?').get(digest(value));
    if (row) this.db.prepare('UPDATE integrations SET last_used_at=? WHERE id=?').run(now(), row.id);
    return row;
  }
  externalId(value) {
    if (typeof value !== 'string' || !EXTERNAL_ID.test(value)) fail(400, 'invalid_external_id', '製品側の利用者IDは英数字で始まる120文字までで指定してください。');
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
  view(account) { return { id: account.id, external_id: account.external_id, created_at: account.created_at, keys: this.store.keys(account.id) }; }
  // Where a request made by one of these accounts is opened: the product's own page, which knows who its user is.
  returnUrlFor(ownerId) {
    return this.db.prepare('SELECT i.return_url FROM accounts a JOIN integrations i ON i.id=a.integration_id WHERE a.id=?').get(ownerId)?.return_url;
  }
  // Everything the account holds goes with it. What sits in the object space is the caller's to clear.
  deleteAccount(integration, externalId) {
    const account = this.account(integration, externalId);
    this.store.transaction(() => {
      for (const table of ['secrets', 'keys', 'requests', 'acquisitions', 'request_links']) this.db.prepare(`DELETE FROM ${table} WHERE owner_id=?`).run(account.id);
      this.db.prepare('DELETE FROM accounts WHERE id=?').run(account.id);
    });
    return account;
  }
  // A single-use link to one request of one of this product's accounts. It carries nothing but that request.
  link(integration, request) {
    if (!this.db.prepare('SELECT 1 FROM accounts WHERE id=? AND integration_id=?').get(request.owner_id, integration.id)) fail(404, 'not_found', '依頼が見つかりません。');
    if (request.status !== 'pending') fail(409, 'request_finished', 'この依頼はすでに処理されています。');
    if (request.adapter) fail(409, 'link_unsupported', '接続の依頼はまだリンクで引き渡せません。');
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
