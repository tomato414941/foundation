import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { Adapters } from './adapters.mjs';
import { EmailLogins, LOGIN_TTL } from './email-login.mjs';
import { AccessRequests } from './access-requests.mjs';
import { Acquisitions } from './acquisitions.mjs';
import { Entries, ENTRY_MAX, entryPath } from './entries.mjs';
import { Files, FILE_MAX } from './files.mjs';
import { Objects, S3Space, OBJECT_MAX } from './objects.mjs';
import { respond } from './mcp.mjs';
import { guide } from './guide.mjs';

const VERSION = createRequire(import.meta.url)('../package.json').version;

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

export function createApp({ database = ':memory:', encryptionKey, auth, adapters: adapterList, files: fileBackend = null, space: spaceBackend = null, publicOrigin, owners: ownerList = [], loginClock, trustedProxies = [] }) {
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
  const entries = new Entries(store, adapters.owned);
  const files = new Files(store, fileBackend);
  const objects = new Objects(spaceBackend);
  const acquisitions = new Acquisitions(store, adapters);
  const requests = new AccessRequests(store, adapters);
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
  // What a key sees of an acquisition: what it keeps and where, never what it holds.
  const runtimeAcquisition = row => {
    const adapter = adapters.get(row.adapter);
    return { prefix: row.prefix, adapter: row.adapter, service: adapter.service, label: row.label, status: row.status,
      access: adapter.access, api: adapter.service?.api || { base_url: '', documentation_url: '' },
      entries: store.entries(row.owner_id, row.prefix).map(entry => ({ path: entry.path, env: entry.env, filename: entry.filename, session: entry.session })) };
  };
  function acquisitionFor(ownerId, prefix) {
    const row = store.acquisition(ownerId, prefix);
    if (!row) fail(404, 'not_found', '接続が見つかりません。');
    return row;
  }
  // Runs a service exchange and commits it atomically, checking that the same person is still here.
  async function verifyConnection(req, session, user, operation, commit) {
    const result = await operation();
    if (req.aborted || req.socket.destroyed || localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
    return store.transaction(() => commit(result));
  }
  // What the owner sees of an acquisition: what it is, whose account, and what it keeps under its prefix.
  function acquisitionView(row) {
    const adapter = adapters.get(row.adapter), state = store.acquisitionState(row);
    const { owner_id: _owner, state: _state, ...rest } = row;
    return { ...rest, ...state.facts, expires_at: state.expires_at, access: adapter.access, service: adapter.service,
      entries: store.entries(row.owner_id, row.prefix).map(entry => entry.path),
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
            previous = acquisitionFor(user.id, flow.previous.prefix);
            if (previous.generation !== flow.previous.generation || previous.status === 'disconnecting') fail(409, 'connection_changed', '接続状態が変わりました。');
          }
          if (flow.accessRequestId) requests.forUser(flow.accessRequestId, user.id, true);
          await verifyConnection(req, session, user,
            () => adapter.client.exchange({ ...flow, code, range: adapter.range }, previous ? { subject: previous.subject, secret: store.acquisitionState(previous).renewal } : undefined),
            result => {
              if (flow.accessRequestId) requests.forUser(flow.accessRequestId, user.id, true);
              const saved = acquisitions.save(user.id, adapter.id, result, { keptBy: flow.requestedBy, previous });
              if (flow.accessRequestId) requests.registered(flow.accessRequestId, user.id, saved.prefix);
              return saved.prefix;
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
      // A runtime learns which credentials it may use from /v1/credentials. When its owner asks for help,
      // it may read its own current request raw (what was requested, and what happened at the approval URL).
      if (path === '/v1/adapters' && method === 'GET') return send(200, { adapters: adapters.ids().map(id => adapters.describe(id)) });
      if (path === '/v1/access-requests' || path === '/v1/access-requests/current') {
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        // A first request may arrive with no key at all: an agent that cannot generate a secret of its own is
        // issued one here, returned once and never again. One that has a key keeps using it.
        const given = req.headers.authorization?.match(/^Bearer (\S+)$/)?.[1];
        const issued = given === undefined && path === '/v1/access-requests' && method === 'POST' ? 'fdn_' + randomBytes(32).toString('base64url') : undefined;
        const token = issued ?? given;
        const hash = requests.key(token);
        rateLimit('request-poll:' + hash, 30);
        if (path === '/v1/access-requests' && method === 'POST') {
          const input = await body(req);
          // Only a key not yet approved introduces itself by name; an approved key is known by the name its owner keeps.
          const name = input.name === undefined ? '' : nameValue(input.name, '依頼元'), purpose = purposeValue(input.purpose);
          rateLimit('request-create:' + clientAddress(req), 12, 600_000);
          const row = requests.create(token, { name, purpose, adapter: input.adapter, store: input.store, details: input.details, guidance: input.guidance ?? '', validMinutes: input.valid_minutes ?? 30 });
          return send(201, { ...(issued ? { key: issued } : {}), request: requests.summary(row, origin) });
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
        if (path === '/api/state' && method === 'GET') return send(200, { user, entries: entries.list(user.id), acquisitions: store.acquisitions(user.id).map(acquisitionView), agents: store.agents(user.id), adapters: adapters.ids().map(id => adapters.describe(id)) });
        // What a key kept is the owner's: they read it, rename the group it sits in, and remove it.
        // Everything, in one file, for the owner alone. Lending someone a place to keep things means they
        // can take them away again; without this the promise is words. Keys are included in full, because
        // a copy that leaves the secrets behind is not a copy.
        if (path === '/api/export' && method === 'GET') {
          const kept = entries.list(user.id).map(row => {
            const full = entries.entry(user.id, row.path);
            return { ...row, content: store.entryContent(full).toString('base64'), encoding: 'base64' };
          });
          const value = { exported_at: new Date().toISOString(), owner: user.email, origin,
            entries: kept, acquisitions: store.acquisitions(user.id).map(acquisitionView), agents: store.agents(user.id) };
          res.writeHead(200, { 'content-type': 'application/json; charset=utf-8',
            'content-disposition': `attachment; filename="foundation-${new Date().toISOString().slice(0, 10)}.json"` });
          return res.end(JSON.stringify(value, null, 2));
        }
        const ownEntry = path.match(/^\/api\/entries\/(.+)$/);
        if (ownEntry) {
          if (method === 'GET') {
            const row = entries.entry(user.id, decodeURIComponent(ownEntry[1]));
            const content = store.entryContent(row);
            res.writeHead(200, { 'content-type': row.media_type, 'content-length': content.length, 'content-disposition': `attachment; filename="${row.path.split('/').pop()}"` });
            return res.end(content);
          }
          if (method === 'DELETE') {
            await body(req);
            entries.remove(user.id, decodeURIComponent(ownEntry[1]));
            return send(200, { ok: true });
          }
        }
        // The owner fulfils a storage request: what they typed becomes the entry the key asked for, exactly
        // where and how the key declared it. Foundation adds nothing and checks nothing about the content.
        const storeRoute = path.match(/^\/api\/access-requests\/([A-Za-z0-9_-]{43})\/store$/);
        if (storeRoute && method === 'POST') {
          const row = requests.forUser(storeRoute[1], user.id, true);
          if (requests.kindOf(row) !== 'store') fail(409, 'wrong_kind', 'この依頼は保管の依頼ではありません。');
          const asked = requests.details(row);
          const input = await body(req, ENTRY_MAX);
          if (typeof input.content !== 'string' || input.content === '') fail(400, 'invalid_values', '入力内容を確認してください。');
          progressRequestId = row.id;
          return store.transaction(() => {
            requests.forUser(row.id, user.id, true);
            entries.put(user.id, { path: asked.path, content: Buffer.from(input.content, 'utf8'), type: asked.type, env: asked.env, filename: asked.filename, secret: asked.secret, keptBy: row.requester_name });
            requests.registered(row.id, user.id, asked.path);
            requests.record(row.id, 'stored');
            return send(200, { stored: true, path: asked.path });
          });
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
        // Starting an acquisition Foundation performs itself: an OAuth round trip, or a login relayed once.
        const connectRoute = path.match(/^\/api\/adapters\/([a-z][a-z0-9.-]{0,63})\/connect$/);
        if (connectRoute && method === 'POST') {
          const adapter = adapters.get(connectRoute[1]);
          adapter.client.check();
          rateLimit((adapter.register === 'login' ? 'login:' : 'connect:') + user.id, 10, adapter.register === 'login' ? 600_000 : 60_000);
          const input = await body(req);
          const accessRequest = input.accessRequestId === undefined ? null : requests.forUser(input.accessRequestId, user.id, true);
          progressRequestId = accessRequest?.id || null;
          if (accessRequest) requests.record(accessRequest.id, 'connect_started', { adapter: adapter.id });
          if (accessRequest && !accessRequest.adapter) fail(409, 'approval_only', 'この依頼はこの接続方法のものではありません。');
          if (accessRequest && adapter.id !== accessRequest.adapter) fail(400, 'scope_mismatch', '依頼された接続方法で登録してください。');
          // Who asked for it, as they were called then. One started from the dashboard was asked by no one.
          const requestedBy = accessRequest?.requester_name ?? '';
          if (adapter.register === 'login') {
            let result, committed = false;
            try {
              if (accessRequest) requests.claim(accessRequest.id, user.id);
              const saved = await verifyConnection(req, session, user, async () => { result = await adapter.client.login(input); return result; }, () => {
                if (accessRequest) requests.forUser(accessRequest.id, user.id, true);
                if (result.challenge) return { challenge: result.challenge };
                const saved = acquisitions.save(user.id, adapter.id, result, { keptBy: requestedBy });
                const done = accessRequest ? requests.registered(accessRequest.id, user.id, saved.prefix) : null;
                return { connected: true, prefix: saved.prefix, ...(done ? { request: requests.summary(done, origin, { code: false }) } : {}) };
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
          const previous = input.prefix ? acquisitionFor(user.id, entryPath(input.prefix)) : undefined;
          if (previous && previous.adapter !== adapter.id) fail(400, 'invalid_adapter', '接続方法が一致しません。');
          if (previous && adapter.canReconnect === false) fail(400, 'new_connection_required', '新しく登録してください。');
          if (previous?.status === 'disconnecting') fail(409, 'connection_changed', '接続の解除が進行中です。');
          const verifier = randomBytes(32).toString('base64url');
          const redirectUri = origin + '/oauth/' + adapter.id + '/callback';
          if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
          if (accessRequest) requests.claim(accessRequest.id, user.id);
          const flow = { adapter: adapter.id, requestedBy, verifier, redirectUri, accessRequestId: accessRequest?.id, previous: previous ? { prefix: previous.prefix, generation: previous.generation } : null };
          const state = store.addFlow(session.id, flow);
          return send(200, { url: adapter.client.authorize({ state, verifier, redirectUri, range: adapter.range, email: previous?.subject }) });
        }
        const acquisitionRoute = path.match(/^\/api\/acquisitions\/(.+)$/);
        if (acquisitionRoute && method === 'DELETE') {
          const acquisition = acquisitionFor(user.id, entryPath(decodeURIComponent(acquisitionRoute[1])));
          const input = await body(req);
          if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', '接続先の許可を取り消すか選んでください。');
          const adapter = adapters.get(acquisition.adapter);
          const canRevoke = adapter.client.canRevoke?.(store.acquisitionState(acquisition).renewal) ?? adapter.canRevoke !== false;
          if (disconnects.has(acquisition.id)) fail(409, 'disconnect_in_progress', '登録を解除しています。');
          disconnects.add(acquisition.id);
          try {
            // Removing it here always succeeds; asking the service to revoke is an attempt whose outcome is reported.
            const previous = store.disconnect(user.id, acquisition.prefix);
            let revoked = null;
            if (input.revoke && canRevoke) {
              try { await adapter.client.revoke(store.acquisitionState(previous).renewal); revoked = true; }
              catch { revoked = false; }
            }
            store.removeAcquisition(user.id, acquisition.prefix);
            return send(200, { ok: true, service_revoked: revoked });
          } finally { disconnects.delete(acquisition.id); }
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
      // The MCP door. It carries no capability of its own: a tool call is the same request to the same
      // API, made with the same key. Agents whose harness connects them to nothing else arrive here.
      if (path === '/mcp') {
        if (method !== 'POST') fail(405, 'method_not_allowed', 'MCPのエンドポイントはPOSTのみです。');
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        const agent = actor(req);
        rateLimit('mcp:' + agent.id, 120);
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
        const agent = actor(req);
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        if (path === '/v1/acquisitions' && method === 'GET') return send(200, { acquisitions: store.acquisitions(agent.owner_id).filter(row => row.status !== 'disconnecting').map(runtimeAcquisition) });
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
        // A URL for something that can only take a URL. Only here because not every owner has cloud
        // storage of their own; one who does should use it directly instead.
        // The owner's own space of objects. Lent from Foundation's bucket while the owner has none of
        // their own; the same calls reach a bucket of theirs once one is connected.
        if (path === '/v1/objects' && method === 'GET') {
          objects.check();
          rateLimit('objects:' + agent.id, 60);
          return send(200, await objects.list(agent.owner_id, url.searchParams.get('prefix') ?? '', url.searchParams.get('cursor') ?? undefined));
        }
        const objectRoute = path.match(/^\/v1\/objects\/(.+?)(\/link)?$/);
        if (objectRoute) {
          objects.check();
          rateLimit('objects:' + agent.id, 60);
          const key = decodeURIComponent(objectRoute[1]);
          if (objectRoute[2]) {
            if (method !== 'POST') fail(405, 'method_not_allowed', 'この操作は利用できません。');
            const input = await body(req);
            return send(200, await objects.link(agent.owner_id, key, input.minutes));
          }
          if (method === 'PUT') {
            const content = await raw(req, OBJECT_MAX);
            return send(200, await objects.put(agent.owner_id, key, content, req.headers['content-type'] || 'application/octet-stream'));
          }
          if (method === 'GET') {
            const found = await objects.get(agent.owner_id, key);
            res.writeHead(200, { 'content-type': found.contentType });
            return res.end(found.content);
          }
          if (method === 'DELETE') { await body(req); await objects.remove(agent.owner_id, key); return send(200, { ok: true }); }
          fail(405, 'method_not_allowed', 'この操作は利用できません。');
        }
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
        // Storage: bytes at a path the key chose, with no adapter, no request and no approval behind them.
        // Foundation never reads them; what it was told at writing time is all it knows.
        if (path === '/v1/entries' && method === 'GET') return send(200, { entries: entries.list(agent.owner_id, url.searchParams.get('prefix') ?? undefined) });
        const entryRoute = path.match(/^\/v1\/entries\/(.+)$/);
        if (entryRoute) {
          const target = decodeURIComponent(entryRoute[1]);
          if (method === 'PUT') {
            rateLimit('entries:' + agent.id, 120);
            const content = await raw(req, ENTRY_MAX);
            const ifVersion = url.searchParams.has('if_version') ? Number(url.searchParams.get('if_version')) : undefined;
            if (ifVersion !== undefined && !Number.isInteger(ifVersion)) fail(400, 'invalid_version', '版は整数で指定してください。');
            return send(200, { entry: entries.put(agent.owner_id, { path: target, content, type: req.headers['content-type'],
              env: url.searchParams.get('env'), filename: url.searchParams.get('filename'), secret: url.searchParams.get('secret') === 'true', keptBy: agent.name }, ifVersion) });
          }
          if (method === 'GET') {
            const { row, content } = entries.read(agent.owner_id, target);
            res.writeHead(200, { 'content-type': row.media_type, 'content-length': content.length });
            return res.end(content);
          }
          if (method === 'DELETE') {
            await body(req);
            entries.remove(agent.owner_id, target);
            return send(200, { ok: true });
          }
        }
        // What a command receives: the bytes, under the names they were kept with. Anything an acquisition
        // keeps current is brought up to date first; after that, delivery reads storage and nothing else.
        if (path === '/v1/deliver' && method === 'POST') {
          const input = await body(req);
          rateLimit('issue:' + agent.id, 30);
          const paths = Array.isArray(input.paths) ? input.paths : [];
          for (const path of paths) store.requireAccess(agent, entryPath(path));
          const pending = new Map();
          for (const path of paths) {
            const acquisition = store.acquisitionFor(agent.owner_id, entryPath(path));
            if (acquisition && acquisition.status === 'connected') pending.set(acquisition.prefix, acquisition);
          }
          for (const acquisition of pending.values()) await acquisitions.refresh(acquisition);
          actor(req);
          for (const path of paths) store.requireAccess(agent, entryPath(path));
          const expiry = [...pending.values()].map(acquisition => store.acquisitionState(store.acquisition(agent.owner_id, acquisition.prefix)).expires_at).filter(value => value !== null);
          for (const value of expiry) if (!(Number.isFinite(value) && value > Date.now())) fail(502, 'service_response', '有効期限を確認できませんでした。');
          const expires_at = expiry.length ? Math.min(...expiry) : null;
          store.recordIssuance(agent, expires_at);
          return send(200, { delivery: entries.deliver(agent.owner_id, paths), expires_at,
            expires_in: expires_at === null ? null : Math.max(0, Math.floor((expires_at - Date.now()) / 1000)) });
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
