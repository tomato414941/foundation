import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store, digest } from './store.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { Adapters } from './adapters.mjs';
import { EmailLogins, LOGIN_TTL } from './email-login.mjs';
import { Requests } from './requests.mjs';
import { KeyRequests } from './key-requests.mjs';
import { Integrations } from './integrations.mjs';
import { Acquisitions } from './acquisitions.mjs';
import { Secrets, SECRET_MAX, SECRET_COUNT_MAX, SECRET_TOTAL_MAX, secretName } from './secrets.mjs';
import { Objects, S3Space, OBJECT_MAX } from './objects.mjs';
import { respond } from './mcp.mjs';
import { prepare as prepareFetch, send as sendFetch, FETCH_BODY_MAX } from './fetch.mjs';
import { FUNCTIONS, outputNames, saveOutputs, deliveredOutputs } from './functions.mjs';
import { guide } from '../cli/guide.mjs';

const VERSION = createRequire(import.meta.url)('../package.json').version;

const PUBLIC = new URL('../web/', import.meta.url);
// The owner's pages. Each is the same shell; the script decides what to show from the path.
const PAGES = ['/', '/secrets', '/connections', '/objects', '/keys', '/functions', '/developers', '/account'];
const STATIC = new Map([['/', ['index.html', 'text/html; charset=utf-8']], ['/secrets', ['index.html', 'text/html; charset=utf-8']], ['/objects', ['index.html', 'text/html; charset=utf-8']], ['/functions', ['index.html', 'text/html; charset=utf-8']], ['/developers', ['index.html', 'text/html; charset=utf-8']], ['/account', ['index.html', 'text/html; charset=utf-8']], ['/connections', ['index.html', 'text/html; charset=utf-8']], ['/keys', ['index.html', 'text/html; charset=utf-8']], ['/app.js', ['app.js', 'text/javascript; charset=utf-8']], ['/styles.css', ['styles.css', 'text/css; charset=utf-8']]]);
const MAX_BODY = 12_000;
const SESSION_AGE = 14 * 86400;
const LOGIN_CALLBACK = '/login/callback';
const REQUEST_PAGE = /^\/requests\/[A-Za-z0-9_-]{43}$/, KEY_PAGE = /^\/key-requests\/[A-Za-z0-9_-]{43}$/;
// A value a key kept itself passed through no adapter, so Foundation has nothing to say about what it reaches.
const KEPT_ACCESS = Object.freeze({ name: '中身は確認していません', description: 'AIが自分で預けた値です。Foundationは何の値かも、何ができるかも確認していません。', restrictions: '心当たりのないものは削除してください。' });
// A revision of the encrypted record, never a fingerprint of the plaintext value.
const secretTag = row => '"' + digest(JSON.stringify([row.id, row.name, row.content, row.readable, row.updated_at])) + '"';

function returnPath(value = '/') {
  if (!PAGES.includes(value) && (typeof value !== 'string' || !(REQUEST_PAGE.test(value) || KEY_PAGE.test(value)))) fail(400, 'invalid_return', '接続リンクを開き直してください。');
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
// Bytes as they were sent, untouched.
async function raw(req, max) {
  const tooLarge = () => fail(413, 'too_large', `送信できるのは${Math.floor(max / (1024 * 1024))}MBまでです。`);
  if (Number(req.headers['content-length']) > max) tooLarge();
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > max) tooLarge();
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

export function createApp({ database = ':memory:', encryptionKey, auth, adapters: adapterList, space: spaceBackend = null, publicOrigin, owners: ownerList = [], loginClock, trustedProxies = [], outbound = {} }) {
  if (!auth || !Array.isArray(adapterList)) throw new Error('Authentication and adapters are required');
  let external;
  if (publicOrigin) {
    external = new URL(publicOrigin);
    if (external.protocol !== 'https:' || external.username || external.password || external.pathname !== '/' || external.search || external.hash) throw new Error('FOUNDATION_PUBLIC_ORIGIN must be an HTTPS origin without a path');
  }
  // Who may become an owner here. Empty means anyone who can log in, which is only safe while nobody else can reach it.
  const owners = ownerList.length ? new Set(ownerList.map(value => value.trim().toLowerCase()).filter(Boolean)) : null;
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
  const secrets = new Secrets(store);
  const objects = new Objects(spaceBackend);
  const acquisitions = new Acquisitions(store, adapters);
  const requests = new Requests(store, adapters), keyRequests = new KeyRequests(store), integrations = new Integrations(store);
  // A request made by an account another product holds is opened on that product's page, which knows who its user is.
  requests.returnUrlFor = ownerId => integrations.returnUrlFor(ownerId);
  const ownHosts = () => [...(external ? [external.hostname] : []), '127.0.0.1', 'localhost'];
  requests.onChange = row => void integrations.notify(row.owner_id, 'request.' + row.status, { request: requests.summary(row, external?.origin || '') }, { ...outbound, ownHosts: ownHosts() });
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
    const key = store.authenticate(bearer(req));
    if (!key) fail(401, 'not_approved', 'このアクセスキーはまだ承認されていないか、失効しています。foundation connect (POST /v1/keys) で承認を依頼し、承認後にお試しください。');
    return key;
  }
  function requireOrigin(req, origin) {
    if (req.headers.origin !== origin) fail(403, 'origin_denied', 'この操作はFoundationの画面から行ってください。');
  }
  // Connection identity, provider details and available outputs; never private renewal state.
  const runtimeAcquisition = row => {
    const adapter = adapters.get(row.adapter);
    const facts = store.acquisitionState(row).facts;
    return { id: row.id, connector: row.adapter, service: adapter.service, label: facts.label || row.label, status: row.status, facts,
      access: adapter.access, api: adapter.service?.api || { base_url: '', documentation_url: '' },
      outputs: adapter.variables };
  };
  function acquisitionFor(ownerId, id) {
    if (typeof id !== 'string' || !id || id.length > 200 || /[\x00-\x1f\x7f]/.test(id)) fail(400, 'invalid_connection', '接続IDを指定してください。');
    const row = store.acquisition(ownerId, id);
    if (!row) fail(404, 'not_found', '接続が見つかりません。');
    return row;
  }
  // Runs a service exchange and commits it atomically, checking that the same person is still here.
  async function verifyConnection(req, session, user, operation, commit) {
    const result = await operation();
    if (req.aborted || req.socket.destroyed || localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
    return store.transaction(() => commit(result));
  }
  // Connection metadata and available outputs, independent of saved values.
  function acquisitionView(row) {
    const adapter = adapters.get(row.adapter), state = store.acquisitionState(row);
    const { owner_id: _owner, state: _state, adapter: connector, ...rest } = row;
    return { ...rest, connector, ...state.facts, expires_at: state.expires_at, access: adapter.access, service: adapter.service,
      outputs: adapter.variables,
      ...(adapter.revocationNote ? { revocation_note: adapter.revocationNote } : {}),
      can_reconnect: adapter.canReconnect !== false, can_revoke: adapter.canRevoke !== false, available: adapter.client.enabled };
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
      if ((STATIC.has(path) || REQUEST_PAGE.test(path) || KEY_PAGE.test(path)) && method === 'GET') {
        if (REQUEST_PAGE.test(path)) requests.record(path.slice('/requests/'.length), 'page_opened');
        if (KEY_PAGE.test(path)) keyRequests.record(path.slice('/key-requests/'.length), 'page_opened');
        const [filename, type] = STATIC.get(STATIC.has(path) ? path : '/');
        res.writeHead(200, { 'content-type': type });
        return res.end(await readFile(fileURLToPath(new URL(filename, PUBLIC))));
      }
      if (path === '/health' && method === 'GET') return send(200, { status: 'ok' });
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
        const connectionLocation = code => destination + '?connection=' + code + (destination === '/' ? '&connector=' + encodeURIComponent(oauthCallback[1]) : '');
        try {
          const { user, session } = await principal(req);
          if (url.searchParams.getAll('state').length !== 1 || url.searchParams.getAll('code').length > 1) fail(400, 'invalid_state', '接続をやり直してください。');
          const flow = store.takeFlow(session.id, url.searchParams.get('state'));
          if (!flow) fail(400, 'invalid_state', '接続をやり直してください。');
          if (flow.adapter !== oauthCallback[1]) fail(400, 'invalid_state', '接続をやり直してください。');
          const adapter = adapters.get(flow.adapter);
          if (flow.requestId) {
            destination = '/requests/' + flow.requestId;
            requests.forUser(flow.requestId, user.id, true);
            progressRequestId = flow.requestId;
          }
          if (url.searchParams.has('error')) {
            fail(400, 'authorization_denied', '接続先での認証は許可されませんでした。');
          }
          const code = url.searchParams.get('code');
          if (!code || code.length > 8192) fail(400, 'invalid_state', '接続をやり直してください。');
          let previous;
          if (flow.previous) {
            previous = acquisitionFor(user.id, flow.previous.id);
            if (previous.generation !== flow.previous.generation || previous.status === 'disconnecting') fail(409, 'connection_changed', '接続状態が変わりました。');
          }
          if (flow.requestId) requests.forUser(flow.requestId, user.id, true);
          await verifyConnection(req, session, user,
            () => adapter.client.exchange({ ...flow, code, range: adapter.range }, previous ? { subject: previous.subject, secret: store.acquisitionState(previous).renewal } : undefined),
            result => {
              if (flow.requestId) requests.forUser(flow.requestId, user.id, true);
              const saved = acquisitions.save(user.id, adapter.id, result, { keptBy: flow.requestedBy, previous });
              if (flow.requestId) requests.done(flow.requestId, user.id, saved.id);
              return saved.id;
            });
          if (flow.requestId) requests.record(flow.requestId, 'connected', { connector: adapter.id });
          return redirect(connectionLocation('connected'));
        } catch (error) {
          if (progressRequestId && error instanceof HttpError) requests.record(progressRequestId, 'connect_failed', { connector: oauthCallback[1], code: error.code, message: error.message });
          const codes = { authorization_denied: 'denied', invalid_state: 'expired', login_required: 'expired', account_changed: 'wrong_account', already_connected: 'already_connected', scope_mismatch: 'scope', refresh_missing: 'retry', connection_changed: 'changed' };
          return redirect(connectionLocation(codes[error.code] || 'failed'));
        }
      }
      if (req.headers['sec-fetch-site'] === 'cross-site') fail(403, 'cross_site_denied', '外部サイトからの操作は許可されていません。');
      // One tree, three ways in. A bearer token, when sent, is what speaks: an access key, or an app's credential.
      // Without one the browser speaks, through its session cookie or a product's single-use link, and every
      // change it asks for must come from Foundation's own pages. Cookies are never read beside a token.
      const token = bearer(req), browser = token === undefined;
      if (browser && !['GET', 'HEAD'].includes(method) && !(path === '/v1/keys' && method === 'POST' && !cookieToken(req))) requireOrigin(req, origin);
      if (!browser && req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
      if (path === '/v1/login' && method === 'GET') return send(200, { available: auth.emailEnabled ?? auth.enabled, method: 'email_link', pending: logins.summary(loginToken) });
      if (path === '/v1/login' && method === 'POST') {
        const input = await body(req);
        if (typeof input.email !== 'string' || input.email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(input.email.trim())) fail(400, 'invalid_email', 'メールアドレスを確認してください。');
        // Reachable from anywhere means anyone who finds the URL could otherwise make themselves an owner here.
        if (owners && !owners.has(input.email.trim().toLowerCase())) fail(403, 'not_invited', 'このアドレスではご利用いただけません。');
        const destination = returnPath(input.return_to);
        rateLimit('link-send:' + clientAddress(req), 12, 600_000);
        const { token: pendingToken, row } = logins.reserve(input.email.trim().toLowerCase());
        row.returnTo = destination;
        try {
          await auth.sendLink(row.email, origin + LOGIN_CALLBACK, row.storage);
          logins.sent(pendingToken, loginToken);
          setNamedCookie('fdn_login', pendingToken, LOGIN_TTL / 1000);
          return send(202, { pending: logins.summary(pendingToken) });
        } catch (error) { logins.cancel(pendingToken); throw error; }
      }
      if (path === '/v1/login' && method === 'DELETE') {
        logins.cancel(loginToken); setNamedCookie('fdn_login', '', 0);
        return send(200, { ok: true });
      }
      if (path === '/v1/session' && method === 'DELETE') {
        const session = store.session(cookieToken(req));
        logins.cancel(loginToken);
        store.removeSession(cookieToken(req));
        setCookie('', 0);
        setNamedCookie('fdn_login', '', 0);
        let authLogout = true;
        if (session) { try { await auth.logout(session.value.access_token); } catch { authLogout = false; } }
        return send(200, { ok: true, authLogout });
      }
      // The ways this server can connect a service itself. Public: a key not yet approved reads it too.
      if (path === '/v1/connectors' && method === 'GET') return send(200, { connectors: adapters.ids().map(id => adapters.describe(id)) });
      // A key not yet approved asks its owner to accept it. It may arrive with no key at all: an agent that cannot
      // generate a secret of its own is issued one here, returned once and never again. While it waits, it may read
      // its own request raw (what it asked, and what happened at the page), or cancel it. Once approved, the same
      // place is the key itself: what it is called, a new name, or its own retirement.
      if ((path === '/v1/keys' && method === 'POST' && !(browser && cookieToken(req))) || path === '/v1/keys/current') {
        const issued = token === undefined && path === '/v1/keys' ? 'fdn_' + randomBytes(32).toString('base64url') : undefined;
        const spoken = issued ?? token;
        rateLimit('request-poll:' + keyRequests.key(spoken), 30);
        if (path === '/v1/keys') {
          const input = await body(req);
          rateLimit('request-create:' + clientAddress(req), 12, 600_000);
          const row = keyRequests.create(spoken, { name: nameValue(input.name, '依頼元'), validMinutes: input.valid_minutes ?? 30 });
          return send(201, { ...(issued ? { key: issued } : {}), request: keyRequests.summary(row, origin) });
        }
        const key = store.authenticate(spoken);
        if (method === 'GET') {
          // A key the owner or an app made directly never asked; it has itself, and no request. One whose
          // request was approved but which no longer exists has been revoked, and hears so.
          let request = null;
          try { request = keyRequests.runtimeView(spoken, origin); } catch (error) { if (!(error instanceof HttpError)) throw error; }
          if (!key && (!request || request.status === 'approved')) fail(401, 'not_approved', 'このアクセスキーはまだ承認されていないか、失効しています。foundation connect (POST /v1/keys) で承認を依頼し、承認後にお試しください。');
          return send(200, { ...(key ? { key: store.keyDetails(key) } : {}), request });
        }
        if (method === 'PATCH') {
          const input = await body(req);
          store.renameKey(actor(req).owner_id, actor(req).id, nameValue(input.name));
          return send(200, { key: store.keyDetails(actor(req)) });
        }
        if (method === 'DELETE') {
          await body(req);
          // An approved key retires itself: it stops working, and connections stay with the owner. One still
          // waiting withdraws its request instead.
          if (key) { store.removeKey(key.owner_id, key.id); return send(200, { ok: true }); }
          const cancelled = keyRequests.cancel(spoken); keyRequests.record(cancelled.id, 'cancelled');
          return send(200, { request: keyRequests.summary(cancelled, origin) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // What an approved key asks its owner for: something to keep, or a connection Foundation makes itself. A key
      // reads each of its own requests raw (what it asked, and what happened at its page), and may cancel one.
      const requestRoute = path.match(/^\/v1\/requests(?:\/([A-Za-z0-9_-]{43})(\/done|\/deny)?)?$/);
      if (requestRoute && !browser) {
        if (requestRoute[2]) fail(404, 'not_found', '指定された操作が見つかりません。');
        rateLimit('request-poll:' + requests.key(token), 30);
        const id = requestRoute[1];
        if (!id && method === 'POST') {
          const input = await body(req);
          rateLimit('request-create:' + clientAddress(req), 12, 600_000);
          const row = requests.create(token, { purpose: purposeValue(input.purpose), adapter: input.connector, store: input.store, steps: input.steps ?? [], validMinutes: input.valid_minutes ?? 30 });
          return send(201, { request: requests.summary(row, origin) });
        }
        if (!id && method === 'GET') {
          const status = url.searchParams.get('status');
          if (status !== null && !['pending', 'done', 'denied', 'cancelled'].includes(status)) fail(400, 'invalid_status', 'status は pending / done / denied / cancelled のいずれかです。');
          return send(200, { requests: requests.list(token, status).map(row => requests.summary(row, origin)) });
        }
        if (id && method === 'GET') return send(200, { request: requests.summary(requests.forKey(token, id), origin, { events: true }) });
        if (id && method === 'DELETE') {
          await body(req);
          const cancelled = requests.cancel(token, id); requests.record(cancelled.id, 'cancelled');
          return send(200, { request: requests.summary(cancelled, origin) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // A product's user arrives with a single-use link to one request. Spending it leaves a short session,
      // scoped by cookie path and by the server to that request's own routes, and to nothing else.
      // Where the page may send a product's user back: that product's own pages for this request, and nothing else.
      const backRoute = path.match(/^\/v1\/request-links\/([A-Za-z0-9_-]{43})$/);
      if (backRoute && method === 'GET') {
        const back = integrations.backFor(requests.get(backRoute[1]));
        if (!back) fail(404, 'not_found', '戻り先はありません。');
        return send(200, { back });
      }
      if (path === '/v1/request-links/claim' && method === 'POST') {
        const input = await body(req);
        rateLimit('link:' + clientAddress(req), 20, 600_000);
        const claimed = integrations.claim(input.request_id, input.link);
        requests.record(claimed.request_id, 'link_opened');
        res.appendHeader('Set-Cookie', `fdn_link=${claimed.session}; HttpOnly; SameSite=Strict; Path=/v1/requests/${claimed.request_id}; Max-Age=1800${external ? '; Secure' : ''}`);
        return send(200, { ok: true });
      }
      // What an app calls, with its own credential: accounts for its users, keys for them, and the link that
      // hands one user to one request. It reaches no account's contents.
      if (path.startsWith('/v1/accounts/') || path === '/v1/request-links') {
        const integration = integrations.authenticate(token);
        if (!integration) fail(401, 'not_an_app', 'このアプリキーは無効です。');
        rateLimit('app:' + integration.id, 300);
        const accountRoute = path.match(/^\/v1\/accounts\/([^/]+)(?:\/(keys|usage)(?:\/([a-f0-9-]{36}))?)?$/);
        if (accountRoute) {
          const externalId = decodeURIComponent(accountRoute[1]), part = accountRoute[2], keyId = accountRoute[3];
          if (!part && method === 'PUT') { await body(req); return send(200, { account: integrations.view(integrations.ensure(integration, externalId)) }); }
          if (!part && method === 'GET') return send(200, { account: integrations.view(integrations.account(integration, externalId)) });
          if (!part && method === 'DELETE') {
            await body(req);
            const removed = integrations.deleteAccount(integration, externalId);
            if (objects.enabled) {
              let cursor;
              do { const page = await objects.list(removed.id, '', cursor); for (const item of page.objects) await objects.remove(removed.id, item.key); cursor = page.cursor; } while (cursor);
            }
            return send(200, { ok: true });
          }
          const account = integrations.account(integration, externalId);
          // A key for the account, one per place the app runs its user's agent. Replacing one revokes the old.
          if (part === 'keys' && !keyId && method === 'POST') {
            const input = await body(req);
            if (input.replaces !== undefined && !store.keys(account.id).some(item => item.id === input.replaces)) fail(404, 'not_found', '置き換えるキーが見つかりません。');
            return store.transaction(() => {
              if (input.replaces !== undefined) store.removeKey(account.id, input.replaces);
              return send(201, { key: store.addKey(account.id, nameValue(input.name ?? integration.name, 'キー')) });
            });
          }
          if (part === 'keys' && keyId && method === 'DELETE') {
            await body(req);
            if (!store.keys(account.id).some(item => item.id === keyId)) fail(404, 'not_found', 'キーが見つかりません。');
            store.removeKey(account.id, keyId);
            return send(200, { ok: true });
          }
          if (part === 'usage' && method === 'GET') {
            const space = objects.enabled ? await objects.usage(account.id) : null;
            return send(200, { usage: { secrets: store.usage(account.id), objects: space ? { count: space.count, bytes: space.bytes } : null } });
          }
        }
        if (path === '/v1/request-links' && method === 'POST') {
          const input = await body(req);
          // Naming the user too (external_id) lets the app refuse a request that is not that user's.
          const made = integrations.link(integration, requests.get(input.request_id), input.external_id);
          return send(201, { url: origin + '/requests/' + input.request_id + '#link=' + made.token, expires_at: made.expires_at });
        }
        fail(404, 'not_found', '指定された操作が見つかりません。');
      }
      // The MCP door. It carries no capability of its own: a tool call is the same request to the same
      // API, made with the same key. Agents whose harness connects them to nothing else arrive here.
      if (path === '/mcp') {
        if (method !== 'POST') fail(405, 'method_not_allowed', 'MCPのエンドポイントはPOSTのみです。');
        const caller = actor(req);
        rateLimit('mcp:' + caller.id, 120);
        const authorization = req.headers.authorization;
        const answer = await respond(await body(req), req.headers, {
          serverInfo: { name: 'foundation', version: VERSION },
          guide: () => guide(adapters.ids().map(id => adapters.describe(id))),
          call: async ({ method: verb, path: target, body: payload }) => {
            const response = await fetch(`http://127.0.0.1:${port}${target}`, {
              method: verb, redirect: 'error', signal: AbortSignal.timeout(20_000),
              headers: { authorization, ...(payload === undefined ? {} : { 'content-type': 'application/json' }) },
              ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
            });
            return { ok: response.ok, text: await response.text() };
          },
        });
        if (answer.body === null) { res.writeHead(answer.status); return res.end(); }
        return send(answer.status, answer.body);
      }
      if (!path.startsWith('/v1/')) fail(404, 'not_found', '指定された操作が見つかりません。');
      // From here, who is asking: the owner at their browser (or a product's user, on the one request they were
      // handed), or an approved key. Both reach the same owner's things, addressed the same way.
      const link = browser && requestRoute ? integrations.linked(readCookie(req, 'fdn_link'), requestRoute[1]) : undefined;
      const caller = browser ? null : actor(req);
      const { user, session } = caller ? { user: { id: caller.owner_id, email: null }, session: null }
        : link ? { user: { id: link.owner_id, email: null, linked: true }, session: null } : await principal(req);
      const ownerId = user.id;
      if (requestRoute) {
        const row = requests.forUser(requestRoute[1], ownerId, requestRoute[2] === '/done');
        if (!requestRoute[2] && method === 'GET') { requests.record(row.id, 'page_viewed'); return send(200, { request: requests.summary(row, origin) }); }
        // The owner chooses each saved name. The requested read permissions still apply to its value.
        if (requestRoute[2] === '/done' && method === 'POST') {
          if (requests.kindOf(row) !== 'store') fail(409, 'wrong_kind', 'この依頼は保管の依頼ではありません。');
          // Several things asked for together are kept together: all of them, or none.
          const asked = requests.details(row);
          const input = await body(req, SECRET_MAX * asked.length);
          const entries = input.entries;
          if (!Array.isArray(entries) || entries.length !== asked.length || entries.some(entry => !entry || typeof entry.content !== 'string' || entry.content === '')) fail(400, 'invalid_values', '入力内容を確認してください。');
          const names = entries.map(entry => secretName(entry.name));
          if (new Set(names).size !== names.length) fail(400, 'duplicate_names', '保存名が重複しています。別の名前を入力してください。');
          progressRequestId = row.id;
          return store.transaction(() => {
            requests.forUser(row.id, ownerId, true);
            const occupied = names.find(name => store.secret(ownerId, name));
            if (occupied !== undefined) fail(409, 'name_taken', `「${occupied}」はすでに使われています。別の保存名を入力してください。`);
            for (const [at, one] of asked.entries()) {
              secrets.put(ownerId, { name: names[at], content: Buffer.from(entries[at].content, 'utf8'), secret: one.secret });
            }
            requests.done(row.id, ownerId, JSON.stringify(names));
            requests.record(row.id, 'stored');
            return send(200, { stored: true, names });
          });
        }
        if (requestRoute[2] === '/deny' && method === 'POST') {
          await body(req);
          if (!user.linked && localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
          progressRequestId = row.id;
          const result = requests.deny(row.id, ownerId);
          requests.record(row.id, 'denied');
          return send(200, { request: requests.summary(result, origin) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (user.linked) fail(401, 'login_required', 'ログインしてください。');
      // The owner's screen, in one answer.
      if (path === '/v1/state' && method === 'GET' && browser) return send(200, { user, secrets: secrets.list(ownerId), connections: store.acquisitions(ownerId).map(acquisitionView), keys: store.keys(ownerId), apps: integrations.list(ownerId), functions: FUNCTIONS, invocations: store.invocations(ownerId), connectors: adapters.ids().map(id => adapters.describe(id)) });
      // Everything, in one file, for the owner alone. Lending someone a place to keep things means they
      // can take them away again; without this the promise is words. Keys are included in full, because
      // a copy that leaves the secrets behind is not a copy.
      if (path === '/v1/export' && method === 'GET') {
        if (!browser) fail(403, 'owner_only', 'この操作は持ち主の画面からだけ行えます。');
        const kept = secrets.list(ownerId).map(row => {
          const full = secrets.at(ownerId, row.name);
          return { ...row, content: store.secretContent(full).toString('base64'), encoding: 'base64' };
        });
        const value = { exported_at: new Date().toISOString(), owner: user.email, origin,
          secrets: kept, connections: store.acquisitions(ownerId).map(acquisitionView), keys: store.keys(ownerId) };
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8',
          'content-disposition': `attachment; filename="foundation-${new Date().toISOString().slice(0, 10)}.json"` });
        return res.end(JSON.stringify(value, null, 2));
      }
      // The owner accepts a new key with the code the runtime showed, or turns it away.
      const keyRequestRoute = path.match(/^\/v1\/key-requests\/([A-Za-z0-9_-]{43})(\/(?:approve|deny))?$/);
      if (keyRequestRoute && browser) {
        const row = keyRequests.forUser(keyRequestRoute[1], ownerId);
        if (!keyRequestRoute[2] && method === 'GET') { keyRequests.record(row.id, 'page_viewed'); return send(200, { request: keyRequests.summary(row, origin, { code: false }) }); }
        if (method === 'POST' && keyRequestRoute[2]) {
          const input = await body(req);
          if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
          let result;
          try { result = keyRequestRoute[2] === '/deny' ? keyRequests.deny(row.id, ownerId) : keyRequests.approve(row.id, ownerId, input.confirmation_code); }
          catch (error) { if (error instanceof HttpError) keyRequests.record(row.id, 'connect_failed', { code: error.code, message: error.message }); throw error; }
          keyRequests.record(row.id, keyRequestRoute[2] === '/deny' ? 'denied' : 'approved');
          return send(200, { request: keyRequests.summary(result, origin, { code: false }) });
        }
      }
      // The keys the owner approved, and ones they make themselves, without asking an agent to ask them.
      if (path === '/v1/keys' && browser) {
        if (method === 'GET') return send(200, { keys: store.keys(ownerId) });
        if (method === 'POST') {
          const input = await body(req);
          return send(201, { key: store.addKey(ownerId, nameValue(input.name)) });
        }
      }
      const keyRoute = path.match(/^\/v1\/keys\/([a-f0-9-]{36})$/);
      if (keyRoute && browser) {
        if (method === 'DELETE') { store.removeKey(ownerId, keyRoute[1]); return send(200, { ok: true }); }
        if (method === 'PATCH') {
          const input = await body(req);
          store.renameKey(ownerId, keyRoute[1], nameValue(input.name));
          return send(200, { ok: true });
        }
      }
      // Apps: other products that hold accounts for their own users. Each credential is shown once, here.
      if (path === '/v1/apps' && browser && method === 'GET') return send(200, { apps: integrations.list(ownerId) });
      if (path === '/v1/apps' && browser && method === 'POST') {
        const input = await body(req);
        return send(201, { app: integrations.register(ownerId, { name: nameValue(input.name, 'アプリ'), returnUrl: input.return_url, refreshUrl: input.refresh_url || undefined, webhookUrl: input.webhook_url || undefined }) });
      }
      const appRoute = path.match(/^\/v1\/apps\/([a-f0-9-]{36})$/);
      if (appRoute && browser && method === 'DELETE') { await body(req); integrations.remove(ownerId, appRoute[1]); return send(200, { ok: true }); }
      // Connections: services Foundation connected itself. The owner sees everything about them; a key sees
      // what it needs to use one. Making one starts the service's own login; removing one may also revoke there.
      if (path === '/v1/connections' && method === 'GET') {
        return send(200, { connections: browser ? store.acquisitions(ownerId).map(acquisitionView)
          : store.acquisitions(ownerId).filter(row => row.status !== 'disconnecting').map(runtimeAcquisition) });
      }
      if (path === '/v1/connections' && method === 'POST' && browser) {
        const input = await body(req);
        const adapter = adapters.get(input.connector);
        adapter.client.check();
        rateLimit('connect:' + ownerId, 10, 60_000);
        const request = input.request_id === undefined ? null : requests.forUser(input.request_id, ownerId, true);
        progressRequestId = request?.id || null;
        if (request) requests.record(request.id, 'connect_started', { connector: adapter.id });
        if (request && !request.adapter) fail(409, 'approval_only', 'この依頼はこの接続方法のものではありません。');
        if (request && adapter.id !== request.adapter) fail(400, 'scope_mismatch', '依頼された接続方法で登録してください。');
        // Who asked for it, as they were called then. One started from the dashboard was asked by no one.
        const requestedBy = request?.requester_name ?? '';
        const previous = input.connection_id === undefined ? undefined : acquisitionFor(ownerId, input.connection_id);
        if (previous && previous.adapter !== adapter.id) fail(400, 'invalid_connector', '接続方法が一致しません。');
        if (previous && adapter.canReconnect === false) fail(400, 'new_connection_required', '新しく登録してください。');
        if (previous?.status === 'disconnecting') fail(409, 'connection_changed', '接続の解除が進行中です。');
        const verifier = randomBytes(32).toString('base64url');
        const redirectUri = origin + '/oauth/' + adapter.id + '/callback';
        if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
        const flow = { adapter: adapter.id, requestedBy, verifier, redirectUri, requestId: request?.id, previous: previous ? { id: previous.id, generation: previous.generation } : null };
        const state = store.addFlow(session.id, flow);
        return send(200, { url: adapter.client.authorize({ state, verifier, redirectUri, range: adapter.range, email: previous?.subject }) });
      }
      const connectionRoute = path.match(/^\/v1\/connections\/(.+)$/);
      if (connectionRoute && browser && method === 'DELETE') {
        const acquisition = acquisitionFor(ownerId, decodeURIComponent(connectionRoute[1]));
        const input = await body(req);
        if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', '接続先の許可を取り消すか選んでください。');
        const adapter = adapters.get(acquisition.adapter);
        const canRevoke = adapter.client.canRevoke?.(store.acquisitionState(acquisition).renewal) ?? adapter.canRevoke !== false;
        if (disconnects.has(acquisition.id)) fail(409, 'disconnect_in_progress', '登録を解除しています。');
        disconnects.add(acquisition.id);
        try {
          // Removing it here always succeeds; asking the service to revoke is an attempt whose outcome is reported.
          const previous = store.disconnect(ownerId, acquisition.id);
          let revoked = null;
          if (input.revoke && canRevoke) {
            try { await adapter.client.revoke(store.acquisitionState(previous).renewal); revoked = true; }
            catch { revoked = false; }
          }
          store.removeAcquisition(ownerId, acquisition.id);
          return send(200, { ok: true, service_revoked: revoked });
        } finally { disconnects.delete(acquisition.id); }
      }
      // What this owner is using, and what they may use. Lending has a cost, so both sides can see it.
      if (path === '/v1/usage' && method === 'GET') {
        const kept = store.usage(ownerId);
        const space = objects.enabled ? await objects.usage(ownerId) : null;
        return send(200, { secrets: { ...kept, count_max: SECRET_COUNT_MAX, bytes_max: SECRET_TOTAL_MAX },
          objects: space ? { count: space.count, bytes: space.bytes, count_max: space.count_max, bytes_max: space.bytes_max } : null });
      }
      // The owner's own space of objects. Lent from Foundation's bucket while the owner has none of
      // their own; the same calls reach a bucket of theirs once one is connected.
      if (path === '/v1/objects' && method === 'GET') {
        objects.check();
        if (caller) rateLimit('objects:' + caller.id, 60);
        return send(200, await objects.list(ownerId, url.searchParams.get('prefix') ?? '', url.searchParams.get('cursor') ?? undefined));
      }
      const objectRoute = path.match(/^\/v1\/objects\/(.+?)(\/link)?$/);
      if (objectRoute) {
        objects.check();
        if (caller) rateLimit('objects:' + caller.id, 60);
        const key = decodeURIComponent(objectRoute[1]);
        if (objectRoute[2]) {
          if (method !== 'POST') fail(405, 'method_not_allowed', 'この操作は利用できません。');
          const input = await body(req);
          return send(200, await objects.link(ownerId, key, input.minutes));
        }
        if (method === 'PUT') {
          const content = await raw(req, OBJECT_MAX);
          return send(200, await objects.put(ownerId, key, content, req.headers['content-type'] || 'application/octet-stream'));
        }
        if (method === 'GET') {
          const found = await objects.get(ownerId, key);
          res.writeHead(200, { 'content-type': found.contentType, 'content-length': found.content.length,
            'content-disposition': `attachment; filename="object.bin"; filename*=UTF-8''${encodeURIComponent(key.split('/').pop()).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16))}` });
          return res.end(found.content);
        }
        if (method === 'DELETE') { await body(req); await objects.remove(ownerId, key); return send(200, { ok: true }); }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // What is kept, by name. A name is any text, so it travels as ?name=: a path would fold "." and ".." away.
      if (path === '/v1/secrets' && method === 'GET' && !url.searchParams.has('name')) return send(200, { secrets: secrets.list(ownerId, url.searchParams.get('prefix') ?? undefined) });
      if (path === '/v1/secrets' && url.searchParams.has('name')) {
        const target = url.searchParams.get('name');
        if (method === 'GET') {
          // The owner reads anything of theirs; a key reads only what was left readable to it.
          const { row, content } = browser ? (() => { const row = secrets.at(ownerId, target); return { row, content: store.secretContent(row) }; })() : secrets.read(ownerId, target);
          res.setHeader('etag', secretTag(row));
          res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': content.length, 'content-disposition': `attachment; filename="secret.bin"; filename*=UTF-8''${encodeURIComponent(row.name).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16))}` });
          return res.end(content);
        }
        if (method === 'PUT') {
          if (caller) rateLimit('secrets:' + caller.id, 120);
          const content = await raw(req, SECRET_MAX);
          if (!content.length) fail(400, 'invalid_values', '入力内容を確認してください。');
          // What the owner keeps is secret unless they say otherwise; what a key keeps stays readable to it unless it asks.
          const saved = store.transaction(() => {
            const match = req.headers['if-match'];
            const current = match === undefined ? null : store.secret(ownerId, secretName(target));
            if (match !== undefined && (!current || match !== secretTag(current))) fail(412, 'secret_changed', 'ほかの操作で変更されています。開き直して確認してください。');
            const saved = secrets.put(ownerId, { name: target, content,
              secret: current ? !current.readable : browser ? url.searchParams.get('secret') !== 'false' : url.searchParams.get('secret') === 'true' });
            res.setHeader('etag', secretTag(secrets.at(ownerId, target)));
            return saved;
          });
          return send(200, { secret: saved });
        }
        // Rename without returning or changing the stored value.
        if (method === 'PATCH' && browser) {
          const input = await body(req);
          return send(200, { secret: secrets.rename(ownerId, target, { name: input.name }) });
        }
        if (method === 'DELETE') {
          await body(req);
          secrets.remove(ownerId, target);
          return send(200, { ok: true });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (!caller) fail(404, 'not_found', '指定された操作が見つかりません。');
      // Reading a saved value never invokes provider code or updates another value.
      if (path === '/v1/deliveries' && method === 'POST') {
        const input = await body(req);
        rateLimit('issue:' + caller.id, 30);
        const names = Array.isArray(input.names) ? input.names : [];
        for (const item of names) store.requireAccess(caller, secretName(typeof item === 'string' ? item : item?.name));
        const delivery = secrets.deliver(caller.owner_id, names);
        store.recordIssuance(caller, null);
        return send(200, { delivery, expires_at: null, expires_in: null });
      }
      if (path === '/v1/functions' && method === 'GET') return send(200, { functions: FUNCTIONS });
      if (path === '/v1/functions/connection.credentials' && method === 'POST') {
        const input = await body(req);
        rateLimit('issue:' + caller.id, 30);
        const connection = acquisitionFor(caller.owner_id, input.connection_id);
        const outputs = outputNames(input.save, adapters.get(connection.adapter).variables);
        let result;
        try { result = await acquisitions.obtain(connection); }
        catch (error) { store.recordInvocation(caller.owner_id, { key: caller, fn: 'connection.credentials', target: connection.label, status: 'failed', detail: error.code || 'error' }); throw error; }
        const expires_at = result.state.expires_at;
        if (expires_at !== null && !(Number.isFinite(expires_at) && expires_at > Date.now())) fail(502, 'service_response', '有効期限を確認できませんでした。');
        store.transaction(() => {
          actor(req);
          // A rotated refresh token must survive even if saving a caller-selected copy
          // fails (for example, a storage quota). The private connection state is separate.
          store.saveState(connection, result.state);
        });
        const saved = outputs ? saveOutputs(secrets, caller.owner_id, outputs, result.values) : null;
        const output = saved ? { saved } : { delivery: deliveredOutputs(result.values) };
        store.recordIssuance(caller, expires_at);
        store.recordInvocation(caller.owner_id, { key: caller, fn: 'connection.credentials', target: connection.label, status: 'ok', detail: saved ? '保管: ' + saved.map(item => item.name).join(', ') : '渡した' });
        return send(200, { ...output, facts: result.state.facts, expires_at,
          expires_in: expires_at === null ? null : Math.max(0, Math.floor((expires_at - Date.now()) / 1000)) });
      }
      if (path === '/v1/functions/http.request' && method === 'POST') {
        const input = await body(req, FETCH_BODY_MAX * 2);
        rateLimit('fetch:' + caller.id, 30);
        const ownHosts = [url.hostname, ...(external ? [external.hostname] : [])];
        const prepared = prepareFetch(input, ownHosts);
        const bindings = input.bindings ?? {};
        if (!bindings || typeof bindings !== 'object' || Array.isArray(bindings)) fail(400, 'invalid_input', 'bindings は入力名と保存名の組で指定してください。');
        const names = prepared.names.map(slot => secretName(Object.hasOwn(bindings, slot) ? bindings[slot] : slot));
        for (const name of names) store.requireAccess(caller, name);
        const outputs = input.save === undefined ? null : outputNames({ response: input.save }, ['response']);
        const values = new Map(prepared.names.map((slot, at) => {
          const content = store.secretContent(secrets.at(caller.owner_id, names[at])), text = content.toString('utf8');
          if (!Buffer.from(text, 'utf8').equals(content)) fail(400, 'not_text', '指定された入力は文字列ではないため、リクエストには入れられません。');
          return [slot, text];
        }));
        let response;
        try { response = await sendFetch(prepared, values, { ...outbound, ownHosts }); }
        catch (error) { store.recordInvocation(caller.owner_id, { key: caller, fn: 'http.request', target: prepared.method + ' ' + prepared.url.hostname, status: 'failed', detail: error.code || 'error' }); throw error; }
        actor(req);
        store.recordInvocation(caller.owner_id, { key: caller, fn: 'http.request', target: prepared.method + ' ' + prepared.url.hostname, status: 'ok', detail: 'HTTP ' + response.status + (names.length ? '、入力 ' + names.length + '件' : '') + (input.save === undefined ? '' : '、応答を保管') });
        const saved = outputs ? saveOutputs(secrets, caller.owner_id, outputs,
          new Map([['response', { content: Buffer.from(response.body, response.body_encoding === 'base64' ? 'base64' : 'utf8') }]])) : null;
        store.recordIssuance(caller, null);
        return send(200, saved ? { response: { status: response.status, headers: response.headers }, saved } : { response });
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
