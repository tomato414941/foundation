import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { Adapters } from './adapters.mjs';
import { EmailLogins, LOGIN_TTL } from './email-login.mjs';
import { Requests } from './requests.mjs';
import { KeyRequests } from './key-requests.mjs';
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
const PAGES = ['/', '/secrets', '/objects'];
const STATIC = new Map([['/', ['index.html', 'text/html; charset=utf-8']], ['/secrets', ['index.html', 'text/html; charset=utf-8']], ['/objects', ['index.html', 'text/html; charset=utf-8']], ['/app.js', ['app.js', 'text/javascript; charset=utf-8']], ['/styles.css', ['styles.css', 'text/css; charset=utf-8']]]);
const MAX_BODY = 12_000;
const SESSION_AGE = 14 * 86400;
const LOGIN_CALLBACK = '/auth/callback';
const REQUEST_PAGE = /^\/requests\/[A-Za-z0-9_-]{43}$/, KEY_PAGE = /^\/keys\/[A-Za-z0-9_-]{43}$/;
// A value a key kept itself passed through no adapter, so Foundation has nothing to say about what it reaches.
const KEPT_ACCESS = Object.freeze({ name: '中身は確認していません', description: 'AIが自分で預けた値です。Foundationは何の値かも、何ができるかも確認していません。', restrictions: '心当たりのないものは削除してください。' });

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
  const requests = new Requests(store, adapters), keyRequests = new KeyRequests(store);
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
    return { id: row.id, adapter: row.adapter, service: adapter.service, label: row.label, status: row.status,
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
    const { owner_id: _owner, state: _state, ...rest } = row;
    return { ...rest, ...state.facts, expires_at: state.expires_at, access: adapter.access, service: adapter.service,
      outputs: adapter.variables,
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
        if (KEY_PAGE.test(path)) keyRequests.record(path.slice('/keys/'.length), 'page_opened');
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
        const connectionLocation = code => destination + '?connection=' + code + (destination === '/' ? '&adapter=' + encodeURIComponent(oauthCallback[1]) : '');
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
          if (flow.requestId) requests.record(flow.requestId, 'connected', { adapter: adapter.id });
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
        // Reachable from anywhere means anyone who finds the URL could otherwise make themselves an owner here.
        if (owners && !owners.has(input.email.trim().toLowerCase())) fail(403, 'not_invited', 'このアドレスではご利用いただけません。');
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
      // A runtime learns which connections it may use from /v1/acquisitions. When its owner asks for help,
      // it may read its own current request raw (what was requested, and what happened at the approval URL).
      if (path === '/v1/adapters' && method === 'GET') return send(200, { adapters: adapters.ids().map(id => adapters.describe(id)) });
      // A key not yet approved asks its owner to accept it. It may arrive with no key at all: an agent that cannot
      // generate a secret of its own is issued one here, returned once and never again. While it waits, it may read
      // its own request raw (what it asked, and what happened at the page), or cancel it.
      if (path === '/v1/keys' || path === '/v1/keys/current') {
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        const given = bearer(req);
        const issued = given === undefined && path === '/v1/keys' && method === 'POST' ? 'fdn_' + randomBytes(32).toString('base64url') : undefined;
        const token = issued ?? given;
        rateLimit('request-poll:' + keyRequests.key(token), 30);
        if (path === '/v1/keys' && method === 'POST') {
          const input = await body(req);
          rateLimit('request-create:' + clientAddress(req), 12, 600_000);
          const row = keyRequests.create(token, { name: nameValue(input.name, '依頼元'), validMinutes: input.valid_minutes ?? 30 });
          return send(201, { ...(issued ? { key: issued } : {}), request: keyRequests.summary(row, origin) });
        }
        if (path === '/v1/keys/current' && method === 'GET') return send(200, { request: keyRequests.runtimeView(token, origin) });
        if (path === '/v1/keys/current' && method === 'DELETE') {
          await body(req);
          const cancelled = keyRequests.cancel(token); keyRequests.record(cancelled.id, 'cancelled');
          return send(200, { request: keyRequests.summary(cancelled, origin) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // What an approved key asks its owner for: something to keep, or a connection Foundation makes itself. A key
      // reads each of its own requests raw (what it asked, and what happened at its page), and may cancel one.
      const requestRoute = path.match(/^\/v1\/requests(?:\/([A-Za-z0-9_-]{43}))?$/);
      if (requestRoute) {
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        const token = bearer(req);
        rateLimit('request-poll:' + requests.key(token), 30);
        const id = requestRoute[1];
        if (!id && method === 'POST') {
          const input = await body(req);
          rateLimit('request-create:' + clientAddress(req), 12, 600_000);
          const row = requests.create(token, { purpose: purposeValue(input.purpose), adapter: input.adapter, store: input.store, steps: input.steps ?? [], validMinutes: input.valid_minutes ?? 30 });
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
      if (path.startsWith('/api/')) {
        if (!['GET', 'HEAD'].includes(method)) requireOrigin(req, origin);
        const { user, session } = await principal(req);
        if (path === '/api/state' && method === 'GET') return send(200, { user, secrets: secrets.list(user.id), acquisitions: store.acquisitions(user.id).map(acquisitionView), keys: store.keys(user.id), adapters: adapters.ids().map(id => adapters.describe(id)) });
        // What a key kept is the owner's: they read it, rename the group it sits in, and remove it.
        // The same space the keys use, from the owner's own screen: what is there, and putting, taking
        // and removing one thing. The owner is the one paying for it, so they must be able to clear it.
        if (path === '/api/objects' && method === 'GET') {
          if (!objects.enabled) return send(200, { available: false, objects: [], usage: null });
          const space = await objects.usage(user.id);
          return send(200, { available: true, objects: space.objects,
            usage: { count: space.count, bytes: space.bytes, count_max: space.count_max, bytes_max: space.bytes_max } });
        }
        const ownObject = path.match(/^\/api\/objects\/(.+?)(\/link)?$/);
        if (ownObject) {
          const key = decodeURIComponent(ownObject[1]);
          if (ownObject[2] && method === 'POST') return send(200, await objects.link(user.id, key, (await body(req)).minutes));
          if (method === 'PUT') {
            const content = await raw(req, OBJECT_MAX);
            return send(200, await objects.put(user.id, key, content, req.headers['content-type'] || 'application/octet-stream'));
          }
          if (method === 'GET') {
            const found = await objects.get(user.id, key);
            res.writeHead(200, { 'content-type': found.contentType, 'content-length': found.content.length,
              'content-disposition': `attachment; filename="${key.split('/').pop()}"` });
            return res.end(found.content);
          }
          if (method === 'DELETE') { await body(req); await objects.remove(user.id, key); return send(200, { ok: true }); }
          fail(405, 'method_not_allowed', 'この操作は利用できません。');
        }
        // Everything, in one file, for the owner alone. Lending someone a place to keep things means they
        // can take them away again; without this the promise is words. Keys are included in full, because
        // a copy that leaves the secrets behind is not a copy.
        if (path === '/api/export' && method === 'GET') {
          const kept = secrets.list(user.id).map(row => {
            const full = secrets.at(user.id, row.name);
            return { ...row, content: store.secretContent(full).toString('base64'), encoding: 'base64' };
          });
          const value = { exported_at: new Date().toISOString(), owner: user.email, origin,
            secrets: kept, acquisitions: store.acquisitions(user.id).map(acquisitionView), keys: store.keys(user.id) };
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8',
            'content-disposition': `attachment; filename="foundation-${new Date().toISOString().slice(0, 10)}.json"` });
          return res.end(JSON.stringify(value, null, 2));
        }
        const ownSecret = path === '/api/secrets' && url.searchParams.has('name')
          ? [null, url.searchParams.get('name')] : path.match(/^\/api\/secrets\/(.+)$/);
        const ownName = ownSecret && (path === '/api/secrets' ? ownSecret[1] : decodeURIComponent(ownSecret[1]));
        if (ownSecret) {
          if (method === 'GET') {
            const row = secrets.at(user.id, ownName);
            const content = store.secretContent(row);
            res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': content.length, 'content-disposition': `attachment; filename="secret.bin"; filename*=UTF-8''${encodeURIComponent(row.name).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16))}` });
            return res.end(content);
          }
          // The owner puts something there themselves, without asking an agent to ask them for it.
          if (method === 'PUT') {
            const content = await raw(req, SECRET_MAX);
            if (!content.length) fail(400, 'invalid_values', '入力内容を確認してください。');
            return send(200, { secret: secrets.put(user.id, { name: ownName, content,
              secret: url.searchParams.get('secret') !== 'false' }) });
          }
          // Rename without returning or changing the stored value.
          if (method === 'PATCH') {
            const input = await body(req);
            const moved = secrets.rename(user.id, ownName, { name: input.name });
            return send(200, { secret: moved });
          }
          if (method === 'DELETE') {
            await body(req);
            secrets.remove(user.id, ownName);
            return send(200, { ok: true });
          }
        }
        // The owner fulfils a storage request: what they typed becomes the entry the key asked for, exactly
        // where and how the key declared it. Foundation adds nothing and checks nothing about the content.
        const storeRoute = path.match(/^\/api\/requests\/([A-Za-z0-9_-]{43})\/store$/);
        if (storeRoute && method === 'POST') {
          const row = requests.forUser(storeRoute[1], user.id, true);
          if (requests.kindOf(row) !== 'store') fail(409, 'wrong_kind', 'この依頼は保管の依頼ではありません。');
          // Several things asked for together are kept together: all of them, or none.
          const asked = requests.details(row);
          const input = await body(req, SECRET_MAX * asked.length);
          const given = input.contents && typeof input.contents === 'object' && !Array.isArray(input.contents) ? input.contents : null;
          if (!given || asked.some(one => typeof given[one.name] !== 'string' || given[one.name] === '')) fail(400, 'invalid_values', '入力内容を確認してください。');
          progressRequestId = row.id;
          return store.transaction(() => {
            requests.forUser(row.id, user.id, true);
            for (const one of asked) {
              secrets.put(user.id, { name: one.name, content: Buffer.from(given[one.name], 'utf8'), secret: one.secret });
            }
            requests.done(row.id, user.id, JSON.stringify(asked.map(one => one.name)));
            requests.record(row.id, 'stored');
            return send(200, { stored: true, names: asked.map(one => one.name) });
          });
        }
        const ownerRequest = path.match(/^\/api\/requests\/([A-Za-z0-9_-]{43})(\/deny)?$/);
        if (ownerRequest) {
          const row = requests.forUser(ownerRequest[1], user.id);
          if (!ownerRequest[2] && method === 'GET') { requests.record(row.id, 'page_viewed'); return send(200, { request: requests.summary(row, origin) }); }
          if (method === 'POST' && ownerRequest[2]) {
            await body(req);
            if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
            progressRequestId = row.id;
            const result = requests.deny(row.id, user.id);
            requests.record(row.id, 'denied');
            return send(200, { request: requests.summary(result, origin) });
          }
        }
        // The owner accepts a new key with the code the runtime showed, or turns it away.
        const keyRequestRoute = path.match(/^\/api\/key-requests\/([A-Za-z0-9_-]{43})(\/(?:approve|deny))?$/);
        if (keyRequestRoute) {
          const row = keyRequests.forUser(keyRequestRoute[1], user.id);
          if (!keyRequestRoute[2] && method === 'GET') { keyRequests.record(row.id, 'page_viewed'); return send(200, { request: keyRequests.summary(row, origin, { code: false }) }); }
          if (method === 'POST' && keyRequestRoute[2]) {
            const input = await body(req);
            if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
            let result;
            try { result = keyRequestRoute[2] === '/deny' ? keyRequests.deny(row.id, user.id) : keyRequests.approve(row.id, user.id, input.confirmationCode); }
            catch (error) { if (error instanceof HttpError) keyRequests.record(row.id, 'connect_failed', { code: error.code, message: error.message }); throw error; }
            keyRequests.record(row.id, keyRequestRoute[2] === '/deny' ? 'denied' : 'approved');
            return send(200, { request: keyRequests.summary(result, origin, { code: false }) });
          }
        }
        // Starting an acquisition Foundation performs itself: an OAuth round trip, or a login relayed once.
        const connectRoute = path.match(/^\/api\/adapters\/([a-z][a-z0-9.-]{0,63})\/connect$/);
        if (connectRoute && method === 'POST') {
          const adapter = adapters.get(connectRoute[1]);
          adapter.client.check();
          rateLimit('connect:' + user.id, 10, 60_000);
          const input = await body(req);
          const request = input.requestId === undefined ? null : requests.forUser(input.requestId, user.id, true);
          progressRequestId = request?.id || null;
          if (request) requests.record(request.id, 'connect_started', { adapter: adapter.id });
          if (request && !request.adapter) fail(409, 'approval_only', 'この依頼はこの接続方法のものではありません。');
          if (request && adapter.id !== request.adapter) fail(400, 'scope_mismatch', '依頼された接続方法で登録してください。');
          // Who asked for it, as they were called then. One started from the dashboard was asked by no one.
          const requestedBy = request?.requester_name ?? '';
          const previous = input.connection_id === undefined ? undefined : acquisitionFor(user.id, input.connection_id);
          if (previous && previous.adapter !== adapter.id) fail(400, 'invalid_adapter', '接続方法が一致しません。');
          if (previous && adapter.canReconnect === false) fail(400, 'new_connection_required', '新しく登録してください。');
          if (previous?.status === 'disconnecting') fail(409, 'connection_changed', '接続の解除が進行中です。');
          const verifier = randomBytes(32).toString('base64url');
          const redirectUri = origin + '/oauth/' + adapter.id + '/callback';
          if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
          const flow = { adapter: adapter.id, requestedBy, verifier, redirectUri, requestId: request?.id, previous: previous ? { id: previous.id, generation: previous.generation } : null };
          const state = store.addFlow(session.id, flow);
          return send(200, { url: adapter.client.authorize({ state, verifier, redirectUri, range: adapter.range, email: previous?.subject }) });
        }
        const acquisitionRoute = path.match(/^\/api\/acquisitions\/(.+)$/);
        if (acquisitionRoute && method === 'DELETE') {
          const acquisition = acquisitionFor(user.id, decodeURIComponent(acquisitionRoute[1]));
          const input = await body(req);
          if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', '接続先の許可を取り消すか選んでください。');
          const adapter = adapters.get(acquisition.adapter);
          const canRevoke = adapter.client.canRevoke?.(store.acquisitionState(acquisition).renewal) ?? adapter.canRevoke !== false;
          if (disconnects.has(acquisition.id)) fail(409, 'disconnect_in_progress', '登録を解除しています。');
          disconnects.add(acquisition.id);
          try {
            // Removing it here always succeeds; asking the service to revoke is an attempt whose outcome is reported.
            const previous = store.disconnect(user.id, acquisition.id);
            let revoked = null;
            if (input.revoke && canRevoke) {
              try { await adapter.client.revoke(store.acquisitionState(previous).renewal); revoked = true; }
              catch { revoked = false; }
            }
            store.removeAcquisition(user.id, acquisition.id);
            return send(200, { ok: true, service_revoked: revoked });
          } finally { disconnects.delete(acquisition.id); }
        }
        if (path === '/api/keys' && method === 'POST') {
          const input = await body(req);
          return send(201, { key: store.addKey(user.id, nameValue(input.name)) });
        }
        const keyRoute = path.match(/^\/api\/keys\/([a-f0-9-]{36})$/);
        if (keyRoute) {
          if (method === 'DELETE') {
            store.removeKey(user.id, keyRoute[1]);
            return send(200, { ok: true });
          }
          if (method === 'PATCH') {
            const input = await body(req);
            store.renameKey(user.id, keyRoute[1], nameValue(input.name));
            return send(200, { ok: true });
          }
        }
      }
      // The MCP door. It carries no capability of its own: a tool call is the same request to the same
      // API, made with the same key. Agents whose harness connects them to nothing else arrive here.
      if (path === '/mcp') {
        if (method !== 'POST') fail(405, 'method_not_allowed', 'MCPのエンドポイントはPOSTのみです。');
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
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
      if (path.startsWith('/v1/')) {
        const caller = actor(req);
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        if (path === '/v1/acquisitions' && method === 'GET') return send(200, { acquisitions: store.acquisitions(caller.owner_id).filter(row => row.status !== 'disconnecting').map(runtimeAcquisition) });
        if (path === '/v1/me' && method === 'GET') return send(200, { key: store.keyDetails(caller) });
        if (path === '/v1/me' && method === 'PATCH') {
          const input = await body(req);
          store.renameKey(caller.owner_id, caller.id, nameValue(input.name));
          return send(200, { key: store.keyDetails(caller) });
        }
        if (path === '/v1/me' && method === 'DELETE') {
          await body(req);
          // The key retires itself: it stops working. Connections stay with the owner.
          store.removeKey(caller.owner_id, caller.id);
          return send(200, { ok: true });
        }
        // A URL for something that can only take a URL. Only here because not every owner has cloud
        // storage of their own; one who does should use it directly instead.
        // What this owner is using, and what they may use. Lending has a cost, so both sides can see it.
        if (path === '/v1/usage' && method === 'GET') {
          const kept = store.usage(caller.owner_id);
          const space = objects.enabled ? await objects.usage(caller.owner_id) : null;
          return send(200, { secrets: { ...kept, count_max: SECRET_COUNT_MAX, bytes_max: SECRET_TOTAL_MAX },
            objects: space ? { count: space.count, bytes: space.bytes, count_max: space.count_max, bytes_max: space.bytes_max } : null });
        }
        // The owner's own space of objects. Lent from Foundation's bucket while the owner has none of
        // their own; the same calls reach a bucket of theirs once one is connected.
        if (path === '/v1/objects' && method === 'GET') {
          objects.check();
          rateLimit('objects:' + caller.id, 60);
          return send(200, await objects.list(caller.owner_id, url.searchParams.get('prefix') ?? '', url.searchParams.get('cursor') ?? undefined));
        }
        const objectRoute = path.match(/^\/v1\/objects\/(.+?)(\/link)?$/);
        if (objectRoute) {
          objects.check();
          rateLimit('objects:' + caller.id, 60);
          const key = decodeURIComponent(objectRoute[1]);
          if (objectRoute[2]) {
            if (method !== 'POST') fail(405, 'method_not_allowed', 'この操作は利用できません。');
            const input = await body(req);
            return send(200, await objects.link(caller.owner_id, key, input.minutes));
          }
          if (method === 'PUT') {
            const content = await raw(req, OBJECT_MAX);
            return send(200, await objects.put(caller.owner_id, key, content, req.headers['content-type'] || 'application/octet-stream'));
          }
          if (method === 'GET') {
            const found = await objects.get(caller.owner_id, key);
            res.writeHead(200, { 'content-type': found.contentType });
            return res.end(found.content);
          }
          if (method === 'DELETE') { await body(req); await objects.remove(caller.owner_id, key); return send(200, { ok: true }); }
          fail(405, 'method_not_allowed', 'この操作は利用できません。');
        }
        // Storage identifies bytes by an opaque name. Query parameters preserve names such as ".." too.
        if (path === '/v1/secrets' && method === 'GET' && !url.searchParams.has('name')) return send(200, { secrets: secrets.list(caller.owner_id, url.searchParams.get('prefix') ?? undefined) });
        const secretRoute = path === '/v1/secrets' && url.searchParams.has('name')
          ? [null, url.searchParams.get('name')] : path.match(/^\/v1\/secrets\/(.+)$/);
        if (secretRoute) {
          const target = path === '/v1/secrets' ? secretRoute[1] : decodeURIComponent(secretRoute[1]);
          if (method === 'PUT') {
            rateLimit('secrets:' + caller.id, 120);
            const content = await raw(req, SECRET_MAX);
            return send(200, { secret: secrets.put(caller.owner_id, { name: target, content,
              secret: url.searchParams.get('secret') === 'true' }) });
          }
          if (method === 'GET') {
            const { row, content } = secrets.read(caller.owner_id, target);
            res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': content.length });
            return res.end(content);
          }
          if (method === 'DELETE') {
            await body(req);
            secrets.remove(caller.owner_id, target);
            return send(200, { ok: true });
          }
        }
        // Reading a saved value never invokes provider code or updates another value.
        if (path === '/v1/deliver' && method === 'POST') {
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
          const result = await acquisitions.obtain(connection);
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
          return send(200, { ...output, expires_at,
            expires_in: expires_at === null ? null : Math.max(0, Math.floor((expires_at - Date.now()) / 1000)) });
        }
        // The existing fetch endpoint invokes the same built-in operation as its catalog entry.
        if (['/v1/fetch', '/v1/functions/http.request'].includes(path) && method === 'POST') {
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
          const response = await sendFetch(prepared, values, { ...outbound, ownHosts });
          actor(req);
          const saved = outputs ? saveOutputs(secrets, caller.owner_id, outputs,
            new Map([['response', { content: Buffer.from(response.body, response.body_encoding === 'base64' ? 'base64' : 'utf8') }]])) : null;
          store.recordIssuance(caller, null);
          return send(200, saved ? { response: { status: response.status, headers: response.headers }, saved } : { response });
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
