import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { Adapters } from './adapters.mjs';
import { acceptValues } from './schema.mjs';
import { EmailLogins, LOGIN_TTL } from './email-login.mjs';
import { AccessRequests } from './access-requests.mjs';
import { verificationResult } from './verification.mjs';
import { Files, FILE_MAX } from './files.mjs';
import { Records } from './records.mjs';
import { serviceName, keptValues, documentPath, documentBody, VALUE_BODY_MAX, DOCUMENT_BODY_MAX } from './kept.mjs';

const PUBLIC = new URL('../web/', import.meta.url);
const STATIC = new Map([['/', ['index.html', 'text/html; charset=utf-8']], ['/app.js', ['app.js', 'text/javascript; charset=utf-8']], ['/styles.css', ['styles.css', 'text/css; charset=utf-8']]]);
// The runtime CLI is served by the server it talks to, so a new machine needs
// only this origin: `curl -fsSL <origin>/cli/install.sh | sh`.
const CLI_FILES = ['runtime.mjs', 'env-name.mjs', 'guide.mjs', 'expo-runtime.mjs'];
const CLI_DIR = new URL('./', import.meta.url);
const installScript = async (origin) => (await readFile(fileURLToPath(new URL('install.sh', CLI_DIR)), 'utf8')).replace('__ORIGIN__', origin).replace('__FILES__', CLI_FILES.join(' '));
const MAX_BODY = 12_000;
const SESSION_AGE = 14 * 86400;
const LOGIN_CALLBACK = '/auth/callback';
const CONNECT_PAGE = /^\/connect\/[A-Za-z0-9_-]{43}$/;
// A value a key kept itself passed through no adapter, so Foundation has nothing to say about what it reaches.
const KEPT_ACCESS = Object.freeze({ name: '中身は確認していません', description: 'AIが自分で預けた値です。Foundationは何の値かも、何ができるかも確認していません。', restrictions: '心当たりのないものは削除してください。' });

function returnPath(value = '/') {
  if (value !== '/' && (typeof value !== 'string' || !CONNECT_PAGE.test(value))) fail(400, 'invalid_return', '接続リンクを開き直してください。');
  return value;
}

async function body(req, max = MAX_BODY) {
  if (req.headers['content-type']?.split(';')[0] !== 'application/json') fail(415, 'json_required', 'JSON形式で送信してください。');
  if (Number(req.headers['content-length']) > max) fail(413, 'body_too_large', '送信内容が大きすぎます。');
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > max) fail(413, 'body_too_large', '送信内容が大きすぎます。');
    chunks.push(chunk);
  }
  let result;
  try { result = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { fail(400, 'invalid_json', '送信内容を読み取れませんでした。'); }
  if (!result || typeof result !== 'object' || Array.isArray(result)) fail(400, 'invalid_json', '送信内容を確認してください。');
  return result;
}
// A file as sent, bytes untouched.
async function raw(req, max) {
  if (Number(req.headers['content-length']) > max) fail(413, 'file_too_large', 'ファイルは5MBまでです。');
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > max) fail(413, 'file_too_large', 'ファイルは5MBまでです。');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
// The owner's name for the group a credential belongs to; it starts from the adapter's or the request's, and may be changed.
function serviceValue(value) {
  if (typeof value !== 'string' || !value.trim() || value.trim().length > 40 || /[\x00-\x1f<>]/.test(value)) fail(400, 'invalid_service', 'サービス名は1〜40文字で入力してください。');
  return value.trim();
}
function purposeValue(value = '') {
  if (typeof value !== 'string' || value.length > 240 || /[\x00-\x1f]/.test(value)) fail(400, 'invalid_purpose', '用途は240文字以内で入力してください。');
  return value.trim();
}

export function createApp({ database = ':memory:', encryptionKey, auth, adapters: adapterList, files: fileBackend = null, publicOrigin, loginClock, trustedProxies = [] }) {
  if (!auth || !Array.isArray(adapterList)) throw new Error('Authentication and adapters are required');
  let external;
  if (publicOrigin) {
    external = new URL(publicOrigin);
    if (external.protocol !== 'https:' || external.username || external.password || external.pathname !== '/' || external.search || external.hash) throw new Error('FOUNDATION_PUBLIC_ORIGIN must be an HTTPS origin without a path');
  }
  const store = new Store(database, encryptionKey);
  // Behind a reverse proxy every socket has the proxy's address; the client is the last hop the proxy appended.
  // Only proxies the operator named are believed, otherwise the header is attacker-controlled.
  const proxies = new Set(trustedProxies);
  const clientAddress = req => {
    const socket = req.socket.remoteAddress || '';
    if (!proxies.has(socket)) return socket;
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',').map(part => part.trim()).filter(Boolean);
    return forwarded.at(-1) || socket;
  };
  const adapters = new Adapters(adapterList);
  const records = new Records(store, adapters);
  const requests = new AccessRequests(store, adapters);
  const files = new Files(store, fileBackend);
  const logins = new EmailLogins({ now: loginClock });
  const refreshing = new Map(), limits = new Map(), disconnects = new Set();
  const timer = setInterval(() => {
    store.sweep();
    logins.sweep();
    for (const [key, value] of limits) if (value.until <= Date.now()) limits.delete(key);
  }, 60_000).unref();
  function rateLimit(key, max, window = 60_000) {
    let value = limits.get(key);
    if (!value || value.until <= Date.now()) value = { count: 0, until: Date.now() + window };
    if (++value.count > max) fail(429, 'rate_limit', '操作が続いています。しばらく待ってからお試しください。');
    if (limits.size >= 2000 && !limits.has(key)) limits.delete(limits.keys().next().value);
    limits.set(key, value);
  }
  const readCookie = (req, name) => (req.headers.cookie ?? '').split(';').map((part) => part.trim()).find((part) => part.startsWith(name + '='))?.slice(name.length + 1);
  const cookieToken = (req) => readCookie(req, 'fdn_session');
  function localSession(req) {
    const value = store.session(cookieToken(req));
    if (!value) fail(401, 'login_required', 'ログインしてください。');
    return value;
  }
  async function principal(req) {
    const row = localSession(req);
    try {
      if (row.value.expires_at <= Date.now() + 60_000) {
        if (!refreshing.has(row.id)) {
          const pending = (async () => {
            const fresh = await auth.refresh(row.value.refresh_token);
            if (fresh.user.id !== row.owner_id || !store.updateSession(row.id, fresh)) fail(401, 'login_required', 'もう一度ログインしてください。');
          })();
          refreshing.set(row.id, pending);
          pending.finally(() => refreshing.delete(row.id)).catch(() => {});
        }
        await refreshing.get(row.id);
      }
      const fresh = localSession(req);
      const user = await auth.user(fresh.value.access_token);
      if (user.id !== fresh.owner_id || localSession(req).id !== row.id) fail(401, 'login_required', 'もう一度ログインしてください。');
      return { user, session: fresh };
    } catch (error) {
      if (error instanceof HttpError && error.status === 401) store.removeSession(cookieToken(req));
      throw error;
    }
  }
  const bearer = req => req.headers.authorization?.match(/^Bearer (\S+)$/)?.[1];
  function actor(req) {
    const agent = store.authenticate(bearer(req));
    if (!agent) fail(401, 'not_approved', 'このアクセスキーはまだ承認されていないか、失効しています。foundation connect で接続依頼を作り、承認後にお試しください。');
    return agent;
  }
  function requireOrigin(req, origin) {
    if (req.headers.origin !== origin) fail(403, 'origin_denied', 'この操作はFoundationの画面から行ってください。');
  }
  function credentialFor(ownerId, id) {
    const credential = store.credential(ownerId, id);
    if (!credential) fail(404, 'not_found', '認証情報が見つかりません。');
    return credential;
  }
  // A value a key kept itself: no adapter, so the routes for keeping values refuse anything else.
  function keptOnly(ownerId, id) {
    const credential = credentialFor(ownerId, id);
    if (credential.adapter) fail(404, 'not_found', '保管された値が見つかりません。');
    return credential;
  }
  const keptView = credential => ({ id: credential.id, service: credential.service, names: credential.names, kept_by: credential.kept_by, created_at: credential.created_at, updated_at: credential.updated_at });
  function stillCurrent(credential) {
    const current = credentialFor(credential.owner_id, credential.id);
    if (current.status !== 'connected' || current.generation !== credential.generation) fail(409, 'connection_changed', '認証情報の状態が変わりました。');
  }
  // A credential is named by what was verified about it, unless the owner names it.
  const credentialName = (record, subject, given) => given || String(record.facts.label || subject).slice(0, 80);
  // Everything acquisition produced, in the shape storage holds and delivery reads.
  const store_ = (adapterId, result, previous, rest) => {
    const record = records.build(adapterId, result.secret, { subject: result.subject });
    return { record, details: { adapter: adapterId, subject: result.subject, names: records.names(record), ...rest, name: credentialName(record, result.subject, rest.name) } };
  };
  const givenName = value => value === undefined || value === '' ? '' : nameValue(value, '表示名');
  // Runs a service exchange, records what was verified on the stored secret (for the owner's screens only),
  // and commits atomically. Foundation never reports these outcomes to the runtime; it learns only which credentials it can use.
  async function verifyConnection(req, session, user, operation, commit) {
    const result = await operation();
    if (req.aborted || req.socket.destroyed || localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
    const report = verificationResult(result);
    if (result.secret) result.secret.verification = report;
    return store.transaction(() => commit(result, report));
  }
  // What the owner sees of a credential: the row, what its adapter verified about it, and how it is delivered.
  function ownerView(credential) {
    const record = store.secret(credentialFor(credential.owner_id, credential.id));
    const { owner_id: _owner, generation: _generation, secret: _secret, ...row } = credential;
    const access = credential.adapter ? adapters.get(credential.adapter).access : KEPT_ACCESS;
    return { ...row, ...record.facts, expires_at: record.expires_at, expiry_known: record.expiry_known, credential_type: record.credential_type,
      access, variables: credential.names, ...(record.verification ? { verification: record.verification } : {}) };
  }
  // What a runtime sees: the same, and where to ask for delivery. Never the secret.
  function runtimeView(credential) {
    const adapter = credential.adapter ? adapters.get(credential.adapter) : null;
    const record = store.secret(credentialFor(credential.owner_id, credential.id));
    return { ...ownerView(credential), api: (adapter ? adapters.service(adapter.id, record.renewal?.details) : null)?.api || { base_url: '', documentation_url: '' },
      delivery: { method: 'POST', endpoint: '/v1/credentials/' + credential.id + '/deliver',
        revocation: adapter && adapter.canRevoke !== false ? 'Stops future delivery; tokens already delivered may remain valid until they expire or the service revokes them.' : 'Stops future delivery only. Keys already delivered remain usable until the service expires or deletes them. No artificial short expiry is applied.' } };
  }
  const server = createServer(async (req, res) => {
    const send = (status, value) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); };
    const redirect = (path) => { res.writeHead(303, { location: path }); res.end(); };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (external) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    let progressRequestId = null;
    try {
      const port = server.address()?.port;
      const allowedHosts = [`127.0.0.1:${port}`, `localhost:${port}`, ...(external ? [external.host] : [])];
      if (!allowedHosts.includes(req.headers.host)) fail(403, 'host_denied', 'このホストからは利用できません。');
      const origin = external?.origin || `http://${req.headers.host}`;
      const url = new URL(req.url, origin), path = url.pathname, method = req.method;
      const setNamedCookie = (name, value, age) => res.appendHeader('Set-Cookie', `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${external ? '; Secure' : ''}`);
      const setCookie = (value, age) => setNamedCookie('fdn_session', value, age);
      const loginToken = readCookie(req, 'fdn_login');
      if ((STATIC.has(path) || CONNECT_PAGE.test(path)) && method === 'GET') {
        if (CONNECT_PAGE.test(path)) requests.record(path.slice('/connect/'.length), 'page_opened');
        const [filename, type] = STATIC.get(CONNECT_PAGE.test(path) ? '/' : path);
        res.writeHead(200, { 'content-type': type });
        return res.end(await readFile(fileURLToPath(new URL(filename, PUBLIC))));
      }
      if (path === '/health' && method === 'GET') return send(200, { status: 'ok' });
      if (path === '/cli/install.sh' && method === 'GET') { res.writeHead(200, { 'content-type': 'text/x-shellscript; charset=utf-8' }); return res.end(await installScript(origin)); }
      const cliFile = path.match(/^\/cli\/([a-z-]+\.mjs)$/)?.[1];
      if (cliFile && CLI_FILES.includes(cliFile) && method === 'GET') { res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' }); return res.end(await readFile(fileURLToPath(new URL(cliFile, CLI_DIR)))); }
      if (path === LOGIN_CALLBACK && method === 'GET') {
        let pending, destination = logins.get(loginToken)?.returnTo || '/';
        try {
          rateLimit('login:' + clientAddress(req), 30, 600_000);
          const code = url.searchParams.get('code');
          if (url.searchParams.has('error') || url.searchParams.getAll('code').length !== 1 || !/^[A-Za-z0-9_-]{20,2048}$/.test(code || '')) fail(400, 'invalid_link', 'ログイン用のリンクを開き直してください。');
          pending = logins.begin(loginToken);
          destination = pending.returnTo || '/';
          const session = await auth.exchangeLink(code, pending.storage);
          if (session.user.email.toLowerCase() !== pending.email || !logins.consume(loginToken, pending)) {
            try { await auth.logout(session.access_token); } catch {}
            fail(401, 'login_expired', 'もう一度、ログイン用のメールを送信してください。');
          }
          store.removeSession(cookieToken(req));
          setCookie(store.createSession(session), SESSION_AGE);
          setNamedCookie('fdn_login', '', 0);
          return redirect(destination);
        } catch (error) {
          if (pending?.attempts >= 5) { logins.cancel(loginToken); setNamedCookie('fdn_login', '', 0); }
          const code = error.code === 'login_expired' ? 'expired' : error.code === 'login_busy' ? 'busy' : error.status === 429 ? 'limited' : error.status === 503 ? 'unavailable' : 'invalid';
          return redirect(destination + '?login=' + code);
        } finally { if (pending) logins.release(loginToken, pending); }
      }
      const oauthCallback = path.match(/^\/oauth\/([a-z][a-z0-9.-]{0,63})\/callback$/);
      if (oauthCallback && method === 'GET') {
        let destination = '/';
        const connectionLocation = code => destination + '?connection=' + code + (destination === '/' ? '&adapter=' + encodeURIComponent(oauthCallback[1]) : '');
        try {
          const { user, session } = await principal(req);
          if (url.searchParams.getAll('state').length !== 1 || url.searchParams.getAll('code').length > 1) fail(400, 'invalid_state', '接続をやり直してください。');
          const flow = store.takeFlow(session.id, url.searchParams.get('state'));
          if (!flow) fail(400, 'invalid_state', '接続をやり直してください。');
          if (flow.adapter !== oauthCallback[1]) fail(400, 'invalid_state', '接続をやり直してください。');
          const adapter = adapters.get(flow.adapter);
          if (flow.accessRequestId) {
            destination = '/connect/' + flow.accessRequestId;
            requests.forUser(flow.accessRequestId, user.id, true);
            progressRequestId = flow.accessRequestId;
          }
          if (url.searchParams.has('error')) {
            fail(400, 'authorization_denied', '接続先での認証は許可されませんでした。');
          }
          const code = url.searchParams.get('code');
          if (!code || code.length > 8192) fail(400, 'invalid_state', '接続をやり直してください。');
          let previous;
          if (flow.previous) {
            previous = credentialFor(user.id, flow.previous.id);
            if (previous.generation !== flow.previous.generation || previous.status === 'disconnecting') fail(409, 'connection_changed', '接続状態が変わりました。');
          }
          if (flow.accessRequestId) requests.forUser(flow.accessRequestId, user.id, true);
          await verifyConnection(req, session, user,
            () => adapter.client.exchange({ ...flow, code, range: adapter.range }, previous ? { subject: previous.subject, secret: store.secret(previous).renewal } : undefined),
            result => {
              if (flow.accessRequestId) requests.forUser(flow.accessRequestId, user.id, true);
              const held = store_(adapter.id, result, previous, { service: flow.service || adapter.service.name, name: flow.name, kept_by: flow.requestedBy });
              const id = store.register(user.id, held.details, held.record, previous);
              if (flow.accessRequestId) requests.registered(flow.accessRequestId, user.id, id);
              return id;
            });
          if (flow.accessRequestId) requests.record(flow.accessRequestId, 'connected', { adapter: adapter.id });
          return redirect(connectionLocation('connected'));
        } catch (error) {
          if (progressRequestId && error instanceof HttpError) requests.record(progressRequestId, 'connect_failed', { adapter: oauthCallback[1], code: error.code, message: error.message });
          const codes = { authorization_denied: 'denied', invalid_state: 'expired', login_required: 'expired', account_changed: 'wrong_account', already_connected: 'already_connected', scope_mismatch: 'scope', refresh_missing: 'retry', connection_changed: 'changed' };
          return redirect(connectionLocation(codes[error.code] || 'failed'));
        }
      }
      if (req.headers['sec-fetch-site'] === 'cross-site') fail(403, 'cross_site_denied', '外部サイトからの操作は許可されていません。');
      if (path === '/api/auth/config' && method === 'GET') return send(200, { available: auth.emailEnabled ?? auth.enabled, method: 'email_link', pending: logins.summary(loginToken) });
      if (path === '/api/auth/link' && method === 'POST') {
        requireOrigin(req, origin);
        const input = await body(req);
        if (typeof input.email !== 'string' || input.email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(input.email.trim())) fail(400, 'invalid_email', 'メールアドレスを確認してください。');
        const destination = returnPath(input.returnTo);
        rateLimit('link-send:' + clientAddress(req), 12, 600_000);
        const { token, row } = logins.reserve(input.email.trim().toLowerCase());
        row.returnTo = destination;
        try {
          await auth.sendLink(row.email, origin + LOGIN_CALLBACK, row.storage);
          logins.sent(token, loginToken);
          setNamedCookie('fdn_login', token, LOGIN_TTL / 1000);
          return send(202, { pending: logins.summary(token) });
        } catch (error) { logins.cancel(token); throw error; }
      }
      if (path === '/api/auth/link' && method === 'DELETE') {
        requireOrigin(req, origin);
        logins.cancel(loginToken); setNamedCookie('fdn_login', '', 0);
        return send(200, { ok: true });
      }
      if (path === '/api/session' && method === 'DELETE') {
        requireOrigin(req, origin);
        const session = store.session(cookieToken(req));
        logins.cancel(loginToken);
        store.removeSession(cookieToken(req));
        setCookie('', 0);
        setNamedCookie('fdn_login', '', 0);
        let authLogout = true;
        if (session) { try { await auth.logout(session.value.access_token); } catch { authLogout = false; } }
        return send(200, { ok: true, authLogout });
      }
      // Pairing bootstraps a runtime without a previously issued Foundation key.
      // Possessing the approval URL alone never gives access to this endpoint.
      // A runtime learns which credentials it may use from /v1/credentials. When its owner asks for help,
      // it may read its own current request raw (what was requested, and what happened at the approval URL).
      if (path === '/v1/adapters' && method === 'GET') return send(200, { adapters: adapters.ids().map(id => adapters.describe(id)) });
      if (path === '/v1/access-requests' || path === '/v1/access-requests/current') {
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        const token = req.headers.authorization?.match(/^Bearer (\S+)$/)?.[1];
        const hash = requests.key(token);
        rateLimit('request-poll:' + hash, 30);
        if (path === '/v1/access-requests' && method === 'POST') {
          const input = await body(req);
          // Only a key not yet approved introduces itself by name; an approved key is known by the name its owner keeps.
          const name = input.name === undefined ? '' : nameValue(input.name, '依頼元'), purpose = purposeValue(input.purpose);
          rateLimit('request-create:' + clientAddress(req), 12, 600_000);
          return send(201, { request: requests.summary(requests.create(token, { name, purpose, adapter: input.adapter, details: input.details, guidance: input.guidance ?? '', validMinutes: input.valid_minutes ?? 30 }), origin) });
        }
        if (path.endsWith('/current') && method === 'GET') return send(200, { request: { ...requests.runtimeView(token), verification_uri: origin + '/connect/' + requests.current(token).id } });
        if (path.endsWith('/current') && method === 'DELETE') {
          await body(req);
          const cancelled = requests.cancel(token); requests.record(cancelled.id, 'cancelled');
          return send(200, { request: requests.summary(cancelled, origin) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (path.startsWith('/api/')) {
        if (!['GET', 'HEAD'].includes(method)) requireOrigin(req, origin);
        const { user, session } = await principal(req);
        if (path === '/api/state' && method === 'GET') return send(200, { user, credentials: store.credentials(user.id).filter(row => row.adapter).map(ownerView), agents: store.agents(user.id), values: store.credentials(user.id).filter(row => !row.adapter).map(keptView), documents: store.documents(user.id), adapters: adapters.ids().map(id => adapters.describe(id)) });
        // What a key kept is the owner's: they read it, rename the group it sits in, and remove it.
        const keptRoute = path.match(/^\/api\/values\/([a-f0-9-]{36})$/);
        if (keptRoute) {
          if (method === 'GET') return send(200, { values: store.secret(keptOnly(user.id, keptRoute[1])).environment });
          if (method === 'PATCH') {
            const input = await body(req);
            const credential = keptOnly(user.id, keptRoute[1]);
            store.updateCredential(user.id, credential.id, serviceValue(input.service), serviceValue(input.service));
            return send(200, { ok: true });
          }
          if (method === 'DELETE') {
            await body(req);
            keptOnly(user.id, keptRoute[1]);
            store.removeCredential(user.id, keptRoute[1]);
            return send(200, { ok: true });
          }
        }
        const keptDocumentRoute = path.match(/^\/api\/documents\/([^/]+)\/([^/]+)$/);
        if (keptDocumentRoute) {
          const { collection, name } = documentPath(decodeURIComponent(keptDocumentRoute[1]), decodeURIComponent(keptDocumentRoute[2]));
          if (method === 'GET') {
            const document = store.document(user.id, collection, name);
            if (!document) fail(404, 'not_found', '記録が見つかりません。');
            return send(200, { document: { collection, name, body: document.body, kept_by: document.kept_by, updated_at: document.updated_at } });
          }
          if (method === 'DELETE') {
            await body(req);
            if (!store.removeDocument(user.id, collection, name)) fail(404, 'not_found', '記録が見つかりません。');
            return send(200, { ok: true });
          }
        }
        const requestRoute = path.match(/^\/api\/access-requests\/([A-Za-z0-9_-]{43})(\/(?:approve|deny))?$/);
        if (requestRoute) {
          const row = requests.forUser(requestRoute[1], user.id);
          if (!requestRoute[2] && method === 'GET') { requests.record(row.id, 'page_viewed'); return send(200, { request: requests.summary(row, origin, { code: false }) }); }
          if (method === 'POST' && requestRoute[2]) {
            const input = await body(req);
            if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
            progressRequestId = row.id;
            const result = requestRoute[2] === '/deny' ? requests.deny(row.id, user.id) : requests.approve(row.id, user.id, input.confirmationCode);
            requests.record(row.id, requestRoute[2] === '/deny' ? 'denied' : 'approved');
            return send(200, { request: requests.summary(result, origin, { code: false }) });
          }
        }
        // Registering a credential through one adapter. How the owner hands it over is the adapter's:
        // pasted values checked against its schema, a login relayed once, or an OAuth round trip.
        const connectRoute = path.match(/^\/api\/adapters\/([a-z][a-z0-9.-]{0,63})\/connect$/);
        if (connectRoute && method === 'POST') {
          const adapter = adapters.get(connectRoute[1]);
          adapter.client.check();
          rateLimit((adapter.register === 'login' ? 'login:' : 'connect:') + user.id, 10, adapter.register === 'login' ? 600_000 : 60_000);
          const input = await body(req);
          const accessRequest = input.accessRequestId === undefined ? null : requests.forUser(input.accessRequestId, user.id, true);
          progressRequestId = accessRequest?.id || null;
          if (accessRequest) requests.record(accessRequest.id, 'connect_started', { adapter: adapter.id });
          if (accessRequest && !accessRequest.adapter) fail(409, 'approval_only', 'この依頼はアクセスキーの承認だけです。認証情報の登録には使えません。');
          if (accessRequest && adapter.id !== accessRequest.adapter) fail(400, 'scope_mismatch', '依頼された接続方法で登録してください。');
          // Who asked for it, as they were called then. A registration from the dashboard was asked by no one.
          const given = givenName(input.name), requestedBy = accessRequest?.requester_name ?? '';
          const chosenService = input.service === undefined || input.service === '' ? null : serviceValue(input.service);
          if (adapter.register === 'login') {
            let result, committed = false;
            try {
              if (accessRequest) requests.claim(accessRequest.id, user.id);
              const saved = await verifyConnection(req, session, user, async () => { result = await adapter.client.login(input); return result; }, () => {
                if (accessRequest) requests.forUser(accessRequest.id, user.id, true);
                if (result.challenge) return { challenge: result.challenge };
                const held = store_(adapter.id, result, undefined, { service: chosenService || adapter.service.name, name: given, kept_by: requestedBy });
                const id = store.register(user.id, held.details, held.record);
                const done = accessRequest ? requests.registered(accessRequest.id, user.id, id) : null;
                return { connected: true, credential_id: id, ...(done ? { request: requests.summary(done, origin, { code: false }) } : {}) };
              });
              if (result.challenge) return send(202, saved);
              committed = true;
              if (accessRequest) requests.record(accessRequest.id, 'connected', { adapter: adapter.id });
              return send(200, saved);
            } finally {
              input.password = ''; input.otp = '';
              // A session the service created must not outlive a registration that did not complete. Never log service errors.
              if (result?.secret && !committed) await adapter.client.revoke(result.secret).catch(() => {});
            }
          }
          const previous = input.credentialId ? credentialFor(user.id, input.credentialId) : undefined;
          if (previous && previous.adapter !== adapter.id) fail(400, 'invalid_adapter', '接続方法が一致しません。');
          if (previous && adapter.canReconnect === false) fail(400, 'new_connection_required', '新しく登録してください。');
          if (previous?.status === 'disconnecting') fail(409, 'connection_changed', '接続の解除が進行中です。');
          if (adapter.register === 'paste') {
            // A request fixes what the runtime declared; a registration from the owner's own screen declares it there.
            const details = accessRequest ? requests.details(accessRequest) : adapters.details(adapter.id, input.details);
            const values = acceptValues(adapters.form(adapter.id, details).schema, input.values);
            input.values = null;
            if (accessRequest) requests.claim(accessRequest.id, user.id);
            const saved = await verifyConnection(req, session, user,
              () => adapter.client.importToken({ values, details }),
              (result, report) => {
                if (accessRequest) requests.forUser(accessRequest.id, user.id, true);
                const held = store_(adapter.id, result, undefined, { service: chosenService || adapters.service(adapter.id, details).name, name: given, kept_by: requestedBy });
                const id = store.register(user.id, held.details, held.record);
                if (accessRequest) requests.registered(accessRequest.id, user.id, id);
                return { connected: true, credential_id: id, verification: report };
              });
            if (accessRequest) requests.record(accessRequest.id, 'connected', { adapter: adapter.id });
            return send(200, saved);
          }
          const verifier = randomBytes(32).toString('base64url');
          const redirectUri = origin + '/oauth/' + adapter.id + '/callback';
          if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
          if (accessRequest) requests.claim(accessRequest.id, user.id);
          const flow = { adapter: adapter.id, name: given, service: chosenService, requestedBy, verifier, redirectUri, accessRequestId: accessRequest?.id, previous: previous ? { id: previous.id, generation: previous.generation } : null };
          const state = store.addFlow(session.id, flow);
          return send(200, { url: adapter.client.authorize({ state, verifier, redirectUri, range: adapter.range, email: previous?.subject }) });
        }
        const credentialRoute = path.match(/^\/api\/credentials\/([a-f0-9-]{36})$/);
        if (credentialRoute) {
          const credential = credentialFor(user.id, credentialRoute[1]);
          if (method === 'PATCH') {
            const input = await body(req);
            store.updateCredential(user.id, credential.id, nameValue(input.name, '表示名'), serviceValue(input.service ?? credential.service));
            return send(200, { ok: true });
          }
          if (method === 'DELETE') {
            const input = await body(req);
            if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', '接続先の許可を取り消すか選んでください。');
            const adapter = credential.adapter ? adapters.get(credential.adapter) : null, canRevoke = adapter ? (adapter.client.canRevoke?.(store.secret(credential).renewal) ?? adapter.canRevoke !== false) : false;
            if (disconnects.has(credential.id)) fail(409, 'disconnect_in_progress', '登録を解除しています。');
            disconnects.add(credential.id);
            try {
              // Deleting it here always succeeds; asking the service to revoke is an attempt whose outcome is reported.
              const previous = store.disconnect(user.id, credential.id);
              let revoked = null;
              if (input.revoke && canRevoke) {
                try { await adapter.client.revoke(store.secret(previous).renewal); revoked = true; }
                catch { revoked = false; }
              }
              store.removeCredential(user.id, credential.id);
              return send(200, { ok: true, service_revoked: revoked });
            } finally { disconnects.delete(credential.id); }
          }
        }
        if (path === '/api/agents' && method === 'POST') {
          const input = await body(req);
          return send(201, { agent: store.addAgent(user.id, nameValue(input.name)) });
        }
        const agentRoute = path.match(/^\/api\/agents\/([a-f0-9-]{36})$/);
        if (agentRoute) {
          if (method === 'DELETE') {
            store.removeAgent(user.id, agentRoute[1]);
            return send(200, { ok: true });
          }
          if (method === 'PATCH') {
            const input = await body(req);
            store.renameAgent(user.id, agentRoute[1], nameValue(input.name));
            return send(200, { ok: true });
          }
        }
      }
      if (path.startsWith('/v1/')) {
        const agent = actor(req);
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        if (path === '/v1/credentials' && method === 'GET') return send(200, { credentials: store.credentials(agent.owner_id).filter(credential => credential.adapter && credential.status !== 'disconnecting').map(runtimeView) });
        if (path === '/v1/me' && method === 'GET') return send(200, { agent: store.agentDetails(agent) });
        if (path === '/v1/me' && method === 'PATCH') {
          const input = await body(req);
          store.renameAgent(agent.owner_id, agent.id, nameValue(input.name));
          return send(200, { agent: store.agentDetails(agent) });
        }
        if (path === '/v1/me' && method === 'DELETE') {
          await body(req);
          // The key retires itself: it stops working. Connections stay with the owner.
          store.removeAgent(agent.owner_id, agent.id);
          return send(200, { ok: true });
        }
        // The file space, a tool the key may use: put a file, get a time-limited link that reads it.
        if (path === '/v1/files' && method === 'GET') return send(200, { files: files.list(agent.owner_id) });
        if (path === '/v1/files' && method === 'POST') {
          files.check();
          rateLimit('files:' + agent.id, 20);
          const minutes = url.searchParams.has('minutes') ? Number(url.searchParams.get('minutes')) : undefined;
          const content = await raw(req, FILE_MAX);
          return send(201, await files.put(agent, { name: url.searchParams.get('name'), contentType: req.headers['content-type'] || 'application/octet-stream', body: content, minutes }));
        }
        const fileRoute = path.match(/^\/v1\/files\/([A-Za-z0-9_-]{32})\/link$/);
        if (fileRoute && method === 'POST') {
          const input = await body(req);
          rateLimit('files:' + agent.id, 20);
          return send(200, await files.link(agent, fileRoute[1], input.minutes));
        }
        // Storage on its own: a key keeps values under names a command will read, with no adapter and no
        // approval behind them. They land in the same place as everything else the owner keeps.
        if (path === '/v1/vault' && method === 'GET') return send(200, { values: store.credentials(agent.owner_id).filter(row => !row.adapter).map(keptView) });
        if (path === '/v1/vault' && method === 'POST') {
          const input = await body(req, VALUE_BODY_MAX);
          rateLimit('vault:' + agent.id, 60);
          const values = keptValues(input.values, adapters.owned);
          const id = store.register(agent.owner_id, { service: serviceName(input.service), name: serviceName(input.service), names: Object.keys(values), kept_by: agent.name }, records.keep(values));
          return send(201, { value: keptView(credentialFor(agent.owner_id, id)) });
        }
        const valueRoute = path.match(/^\/v1\/vault\/([a-f0-9-]{36})$/);
        if (valueRoute && method === 'PUT') {
          const input = await body(req, VALUE_BODY_MAX);
          rateLimit('vault:' + agent.id, 60);
          const credential = keptOnly(agent.owner_id, valueRoute[1]);
          const values = keptValues(input.values, adapters.owned);
          store.saveSecret(credential, records.keep(values), Object.keys(values));
          return send(200, { value: keptView(credentialFor(agent.owner_id, credential.id)) });
        }
        if (valueRoute && method === 'DELETE') {
          await body(req);
          keptOnly(agent.owner_id, valueRoute[1]);
          store.removeCredential(agent.owner_id, valueRoute[1]);
          return send(200, { ok: true });
        }
        // Documents: the same storage, for what the key reads back whole rather than hands to a command.
        if (path === '/v1/documents' && method === 'GET') return send(200, { documents: store.documents(agent.owner_id, url.searchParams.get('collection') ?? undefined) });
        const documentRoute = path.match(/^\/v1\/documents\/([^/]+)\/([^/]+)$/);
        if (documentRoute) {
          const { collection, name } = documentPath(decodeURIComponent(documentRoute[1]), decodeURIComponent(documentRoute[2]));
          if (method === 'GET') {
            const document = store.document(agent.owner_id, collection, name);
            if (!document) fail(404, 'not_found', '記録が見つかりません。');
            const { body: content, owner_id: _owner, ...row } = document;
            return send(200, { document: { ...row, body: content } });
          }
          if (method === 'PUT') {
            const input = await body(req, DOCUMENT_BODY_MAX);
            rateLimit('documents:' + agent.id, 120);
            store.writeDocument(agent.owner_id, { collection, name, body: documentBody(input.body), keptBy: agent.name });
            return send(200, { document: store.documents(agent.owner_id, collection).find(row => row.name === name) });
          }
          if (method === 'DELETE') {
            await body(req);
            if (!store.removeDocument(agent.owner_id, collection, name)) fail(404, 'not_found', '記録が見つかりません。');
            return send(200, { ok: true });
          }
        }
        // Delivery reads storage and nothing else. When an adapter stands behind the credential it is given a
        // chance first to check or refresh it, which writes a new record; what is handed over is that record.
        const route = path.match(/^\/v1\/credentials\/([a-f0-9-]{36})\/deliver$/);
        if (route && method === 'POST') {
          await body(req);
          store.requireAccess(agent, route[1]);
          let credential = credentialFor(agent.owner_id, route[1]);
          rateLimit('issue:' + agent.id, 30);
          if (credential.adapter) {
            const adapter = adapters.get(credential.adapter);
            await adapter.client.token(records.clientStore(adapter.id), credential, false);
            actor(req);
            store.requireAccess(agent, credential.id);
            stillCurrent(credential);
            credential = credentialFor(agent.owner_id, credential.id);
          }
          const record = store.secret(credential);
          if (record.expires_at !== null && !(Number.isFinite(record.expires_at) && record.expires_at > Date.now())) fail(502, 'service_response', '認証情報の有効期限を確認できませんでした。');
          store.recordIssuance(agent, record.expires_at);
          return send(200, { credential: { id: credential.id, adapter: credential.adapter || null, service: credential.service, name: credential.name, label: record.facts.label || credential.name },
            expires_at: record.expires_at, expires_in: record.expires_at === null ? null : Math.max(0, Math.floor((record.expires_at - Date.now()) / 1000)),
            delivery: records.delivery(record), ...(record.facts.key_info ? { key_info: record.facts.key_info } : {}), ...(record.verification ? { verification: record.verification } : {}) });
        }
      }
      fail(404, 'not_found', '指定された操作が見つかりません。');
    } catch (error) {
      if (!(error instanceof HttpError)) console.error(new Date().toISOString(), req.method, req.url, error);
      if (progressRequestId && error instanceof HttpError && !res.headersSent) requests.record(progressRequestId, 'connect_failed', { code: error.code, message: error.message });
      if (!res.headersSent) send(error instanceof HttpError ? error.status : 500, { error: { code: error instanceof HttpError ? error.code : 'internal_error', message: error instanceof HttpError ? error.message : '処理を完了できませんでした。' }, ...(error instanceof HttpError && error.extra ? error.extra : {}) });
      else res.end();
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  return {
    server, store,
    async close() {
      clearInterval(timer);
      if (server.listening) await new Promise((resolve) => { server.close(resolve); server.closeIdleConnections(); });
      store.close();
    },
  };
}
