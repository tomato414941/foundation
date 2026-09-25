import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { digest } from './crypto.mjs';
import { Principals, KEY, LINK } from './principals.mjs';
import { Sessions, OAuthFlows } from './sessions.mjs';
import { RequestActions } from './request-actions.mjs';
import { requestDefinition, requestView } from './http-requests.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { Connectors } from './connectors.mjs';
import { EmailLogins, LOGIN_TTL } from './email-login.mjs';
import { Requests } from './requests.mjs';
import { Settings } from './settings.mjs';
import { Records } from './records.mjs';
import { Connections } from './connections.mjs';
import { Secrets, SECRET_MAX, SECRET_COUNT_MAX, SECRET_TOTAL_MAX, secretName } from './secrets.mjs';
import { Objects, OBJECT_MAX } from './objects.mjs';
import { respond } from './mcp.mjs';
import { FETCH_BODY_MAX } from './fetch.mjs';
import { FUNCTIONS, Functions } from './functions.mjs';
import { guide } from '../cli/guide.mjs';
import { Authorization } from './authorization.mjs';

const VERSION = createRequire(import.meta.url)('../package.json').version;

const PUBLIC = new URL('../web/', import.meta.url);
// The owner's pages. Each is the same shell; the script decides what to show from the path.
const PAGES = ['/', '/secrets', '/connections', '/objects', '/principals', '/functions', '/account'];
const STATIC = new Map(PAGES.map(page => [page, ['index.html', 'text/html; charset=utf-8']]));
STATIC.set('/app.js', ['app.js', 'text/javascript; charset=utf-8']);
STATIC.set('/request-view.js', ['request-view.js', 'text/javascript; charset=utf-8']);
STATIC.set('/styles.css', ['styles.css', 'text/css; charset=utf-8']);
const MAX_BODY = 12_000;
const SESSION_AGE = 14 * 86400;
const LOGIN_CALLBACK = '/login/callback';
const LINK_TTL = 10 * 60_000, LINKED_TTL = 30 * 60_000;
const REQUEST_PAGE = /^\/requests\/[A-Za-z0-9_-]{43}$/;
const PRINCIPAL_ID = /^[A-Za-z0-9-]{1,64}$/;
// A revision of the encrypted record, never a fingerprint of the plaintext value.
const secretTag = row => '"' + digest(JSON.stringify([row.id, row.name, row.content, row.updated_at])) + '"';

function returnPath(value = '/') {
  if (!PAGES.includes(value) && (typeof value !== 'string' || !REQUEST_PAGE.test(value))) fail(400, 'invalid_return', '接続リンクを開き直してください。');
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
function purposeValue(value = '') {
  if (typeof value !== 'string' || value.length > 240 || /[\x00-\x1f]/.test(value)) fail(400, 'invalid_purpose', '用途は240文字以内で入力してください。');
  return value.trim();
}
function principalId(value) {
  if (typeof value !== 'string' || !PRINCIPAL_ID.test(value)) fail(400, 'invalid_principal', '相手の指定を確認してください。');
  return value;
}

export function createApp({ database = ':memory:', encryptionKey, auth, connectors: connectorList, space: spaceBackend = null, publicOrigin, owners: ownerList = [], loginClock, trustedProxies = [], outbound = {} }) {
  if (!auth || !Array.isArray(connectorList)) throw new Error('Authentication and connectors are required');
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
  const connectors = new Connectors(connectorList);
  const secrets = new Secrets(store);
  const objects = new Objects(spaceBackend, store);
  const connections = new Connections(store, connectors);
  const principals = new Principals(store), sessions = new Sessions(store), flows = new OAuthFlows(store);
  const requests = new Requests(store), settings = new Settings(store, principals), records = new Records(store);
  const authorization = new Authorization(principals);
  // One held thing, of whatever kind, by its id.
  const holding = id => {
    const row = typeof id === 'string' ? store.db.prepare('SELECT id,holder_id,kind,name,size,type,created_at,updated_at FROM holdings WHERE id=?').get(id) : undefined;
    if (!row) fail(404, 'not_found', '保管されたものが見つかりません。');
    return row;
  };
  const functions = new Functions({ connections, secrets, outbound });
  const ownHosts = () => [...(external ? [external.hostname] : []), '127.0.0.1', 'localhost'];
  const viewRequest = (row, origin, options) => requestView({ requests, connectors, principals, settings }, row, origin, options);
  const requestActions = new RequestActions({ store, requests, secrets, connections, principals, records,
    changed: row => { if (row.to_id) void settings.notify(row.to_id, 'request.' + row.status, { request: viewRequest(row, external?.origin || '') }, { ...outbound, ownHosts: ownHosts() }); } });
  const logins = new EmailLogins({ now: loginClock });
  const refreshing = new Map(), limits = new Map(), disconnects = new Set();
  const timer = setInterval(() => {
    store.sweep();
    principals.sweep();
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
    const value = sessions.get(cookieToken(req));
    if (!value) fail(401, 'login_required', 'ログインしてください。');
    return value;
  }
  async function loggedIn(req) {
    const row = localSession(req);
    try {
      if (row.value.expires_at <= Date.now() + 60_000) {
        if (!refreshing.has(row.id)) {
          const pending = (async () => {
            const fresh = await auth.refresh(row.value.refresh_token);
            if (fresh.user.id !== row.owner_id || !sessions.update(row.id, fresh)) fail(401, 'login_required', 'もう一度ログインしてください。');
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
      if (error instanceof HttpError && error.status === 401) sessions.remove(cookieToken(req));
      throw error;
    }
  }
  const bearer = req => req.headers.authorization?.match(/^Bearer (\S+)$/)?.[1];
  function requireOrigin(req, origin) {
    if (req.headers.origin !== origin) fail(403, 'origin_denied', 'この操作はFoundationの画面から行ってください。');
  }
  // Authorization may take time. Check the browser again before committing any result.
  async function verifyConnection(req, session, operation, commit) {
    const result = await operation();
    if (req.aborted || req.socket.destroyed || localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
    return commit(result);
  }
  const notApproved = () => fail(401, 'not_approved', 'このキーはまだ誰の代わりにも動けないか、失効しています。foundation connect（POST /v1/requests kind actor）で承認を依頼し、承認後にお試しください。');
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
      const setNamedCookie = (name, value, age, cookiePath = '/') => res.appendHeader('Set-Cookie', `${name}=${value}; HttpOnly; SameSite=${cookiePath === '/' ? 'Lax' : 'Strict'}; Path=${cookiePath}; Max-Age=${age}${external ? '; Secure' : ''}`);
      const setCookie = (value, age) => setNamedCookie('fdn_session', value, age);
      const loginToken = readCookie(req, 'fdn_login');
      if ((STATIC.has(path) || REQUEST_PAGE.test(path)) && method === 'GET') {
        if (REQUEST_PAGE.test(path)) requests.record(path.slice('/requests/'.length), 'page_opened');
        // The page and its script are the same for everyone, so a browser keeps them and only asks whether
        // they changed. What the API answers stays no-store.
        const [filename, type] = STATIC.get(STATIC.has(path) ? path : '/');
        const content = await readFile(fileURLToPath(new URL(filename, PUBLIC))), tag = '"' + digest(content).slice(0, 32) + '"';
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('ETag', tag);
        if (req.headers['if-none-match'] === tag) { res.writeHead(304); return res.end(); }
        res.writeHead(200, { 'content-type': type });
        return res.end(content);
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
          sessions.remove(cookieToken(req));
          setCookie(sessions.create(session), SESSION_AGE);
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
          const { user, session } = await loggedIn(req);
          if (url.searchParams.getAll('state').length !== 1 || url.searchParams.getAll('code').length > 1) fail(400, 'invalid_state', '接続をやり直してください。');
          const flow = flows.take(session.id, url.searchParams.get('state'));
          if (!flow) fail(400, 'invalid_state', '接続をやり直してください。');
          if (flow.connector !== oauthCallback[1]) fail(400, 'invalid_state', '接続をやり直してください。');
          const connector = connectors.get(flow.connector);
          if (flow.requestId) {
            destination = '/requests/' + flow.requestId;
            requests.forTo(flow.requestId, user.id, true);
            progressRequestId = flow.requestId;
          }
          if (url.searchParams.has('error')) fail(400, 'authorization_denied', '接続先での認証は許可されませんでした。');
          const code = url.searchParams.get('code');
          if (!code || code.length > 8192) fail(400, 'invalid_state', '接続をやり直してください。');
          let previous;
          if (flow.previous) {
            previous = connections.at(user.id, flow.previous.id);
            if (previous.generation !== flow.previous.generation || previous.status === 'disconnecting') fail(409, 'connection_changed', '接続状態が変わりました。');
          }
          if (flow.requestId) requests.forTo(flow.requestId, user.id, true);
          await verifyConnection(req, session,
            () => connector.authorization.complete({ code, verifier: flow.verifier, redirectUri: flow.redirectUri }, connections.context(previous)),
            result => requestActions.connect(flow.requestId, user.id, connector.id, result, { keptBy: flow.requestedBy, previous }));
          return redirect(connectionLocation('connected'));
        } catch (error) {
          if (progressRequestId && error instanceof HttpError) requests.record(progressRequestId, 'connect_failed', { connector: oauthCallback[1], code: error.code, message: error.message });
          const codes = { authorization_denied: 'denied', invalid_state: 'expired', login_required: 'expired', account_changed: 'wrong_account', already_connected: 'already_connected', scope_mismatch: 'scope', refresh_missing: 'retry', connection_changed: 'changed', service_response: 'failed' };
          return redirect(connectionLocation(codes[error.code] || 'failed'));
        }
      }
      if (req.headers['sec-fetch-site'] === 'cross-site') fail(403, 'cross_site_denied', '外部サイトからの操作は許可されていません。');
      const requestRoute = path.match(/^\/v1\/requests(?:\/([A-Za-z0-9_-]{43})(\/done|\/deny)?)?$/);
      // One tree, one question. A bearer token, when sent, says which principal speaks. Without one the browser
      // speaks, through its login session or the short credential a single-use link left, and every change it
      // asks for must come from Foundation's own pages. Cookies are never read beside a token.
      const token = bearer(req), browser = req.headers.authorization === undefined;
      if (!browser && !token) fail(401, 'invalid_token', 'Bearer形式のキーを指定してください。');
      const anonymousAsk = browser && requestRoute && !requestRoute[1] && method === 'POST' && !cookieToken(req);
      if (browser && !['GET', 'HEAD'].includes(method) && !anonymousAsk) requireOrigin(req, origin);
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
        const session = sessions.get(cookieToken(req));
        logins.cancel(loginToken);
        sessions.remove(cookieToken(req));
        setCookie('', 0);
        setNamedCookie('fdn_login', '', 0);
        let authLogout = true;
        if (session) { try { await auth.logout(session.value.access_token); } catch { authLogout = false; } }
        return send(200, { ok: true, authLogout });
      }
      // The ways this server can connect a service itself. Public: a key not yet approved reads it too.
      if (path === '/v1/connectors' && method === 'GET') return send(200, { connectors: connectors.ids().map(id => connectors.describe(id)) });
      // Where the page sends someone back after a request: the handler's page for it. Public, and says nothing else.
      const returnRoute = path.match(/^\/v1\/requests\/([A-Za-z0-9_-]{43})\/return$/);
      if (returnRoute && method === 'GET') {
        const back = settings.backFor(requests.get(returnRoute[1]));
        if (!back) fail(404, 'not_found', '戻り先はありません。');
        return send(200, { back });
      }
      // Spending a single-use link: the one in the URL is gone, and a short credential for the browser takes its
      // place, sent as a cookie that reaches that one request's routes and nothing else.
      if (path === '/v1/credentials/exchange' && method === 'POST') {
        const input = await body(req);
        rateLimit('link:' + clientAddress(req), 20, 600_000);
        const made = principals.exchange(input.link);
        const requestId = made.scope?.startsWith('request:') ? made.scope.slice('request:'.length) : null;
        if (!requestId || requestId !== input.request_id) fail(410, 'link_expired', 'このリンクは使えません。元の画面から開き直してください。');
        requests.record(requestId, 'link_opened');
        setNamedCookie('fdn_link', made.token, LINKED_TTL / 1000, '/v1/requests/' + requestId);
        return send(200, { ok: true });
      }
      // Who is asking. A token names a principal by its credential; a browser is the person who logged in, or the
      // one a link handed to a single request. A token nobody knows may still ask to act for someone: that is how
      // a new key introduces itself, and it becomes a principal by asking.
      let subject, session = null, user = null;
      const known = browser ? undefined : principals.authenticate(token);
      if (anonymousAsk || (!browser && !known)) {
        // A key nobody knows, or no key at all, may still ask to act for someone: that is how a new key introduces
        // itself, and it becomes a principal by asking. One that cannot make a secret of its own is issued one, once.
        if (!anonymousAsk && !(requestRoute && !requestRoute[1] && method === 'POST' && KEY.test(token))) notApproved();
        const input = await body(req);
        const definition = requestDefinition(input);
        if (definition.kind !== 'actor') notApproved();
        rateLimit('request-create:' + clientAddress(req), 12, 600_000);
        const secret = anonymousAsk ? 'fdn_' + randomBytes(32).toString('base64url') : token;
        const made = store.transaction(() => {
          // A new principal each time a token nobody knows asks: whatever an earlier principal with the same secret
          // was told or given stays with that earlier one.
          const principal = principals.ensure(randomUUID(), nameValue(definition.input?.name, '依頼元'));
          principals.issue(principal.id, { kind: 'key', token: secret });
          return principal;
        });
        const row = requestActions.ask(made.id, { kind: 'actor', input: definition.input, purpose: purposeValue(input.purpose), steps: input.steps ?? [], validMinutes: input.valid_minutes ?? 30 });
        return send(201, { ...(anonymousAsk ? { key: secret } : {}), request: viewRequest(row, origin, { code: true }) });
      }
      if (!browser) subject = { id: known.principal.id, credential: known.credential };
      else {
        const linkToken = requestRoute?.[1] ? readCookie(req, 'fdn_link') : undefined;
        const linked = linkToken && LINK.test(linkToken) ? principals.authenticate(linkToken) : undefined;
        if (linked?.credential.scope === 'request:' + requestRoute?.[1]) subject = { id: linked.principal.id, credential: linked.credential };
        else {
          ({ user, session } = await loggedIn(req));
          principals.ensure(user.id);
          subject = { id: user.id, credential: { kind: 'session', id: session.id } };
        }
      }
      const self = principals.get(subject.id);
      // In whose name. Someone acting for exactly one other acts for them unless they say otherwise; anyone else is
      // taken to mean themselves.
      const actsFor = principals.actsFor(subject.id);
      const asked = url.searchParams.get('as');
      const holderId = asked ? principalId(asked) : actsFor.length === 1 ? actsFor[0].id : subject.id;
      let asked_ = null;
      const permit = (name, type, id, holder = type === 'principal' ? id : holderId) => {
        asked_ = { subject, action: { name }, resource: { type, ...(id === undefined ? {} : { id }), holder } };
        if (authorization.allowed(asked_).decision) return;
        if (subject.credential.kind === 'link') fail(401, 'login_required', 'ログインしてください。');
        if (subject.credential.kind === 'key' && holder !== subject.id && !principals.relationsOf(subject.id).length) notApproved();
        fail(403, 'forbidden', 'この操作は許可されていません。');
      };
      // Reading an upload may outlive its authorization. Recheck before committing any change: the credential,
      // and the same question the route asked before reading.
      const still = () => {
        if (subject.credential.kind === 'session') { if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。'); }
        else if (!principals.credentials(subject.id).some(row => row.id === subject.credential.id)) fail(401, 'not_approved', 'このキーは失効しています。');
        if (asked_ ? !authorization.allowed(asked_).decision : holderId !== subject.id && !principals.has(subject.id, 'actor', 'principal', holderId) && !principals.has(subject.id, 'owner', 'principal', holderId)) fail(401, 'not_approved', 'この相手の代わりには動けません。');
      };
      const inputBody = async max => { const input = await body(req, max); still(); return input; };
      const inputBytes = async max => { const input = await raw(req, max); still(); return input; };
      const limit = (name, max) => rateLimit(name + ':' + subject.id, max);

      // Requests: what one principal asks of another, and what the one asked does about it.
      if (requestRoute) {
        const id = requestRoute[1], action = requestRoute[2];
        if (!id && method === 'POST') {
          const input = await body(req);
          rateLimit('request-create:' + clientAddress(req), 12, 600_000);
          const definition = requestDefinition(input);
          if (definition.kind === 'connect') connectors.get(definition.input?.connector);
          const toId = definition.kind === 'actor' ? (input.to === undefined ? null : principalId(input.to)) : input.to === undefined ? holderId : principalId(input.to);
          if (toId !== null && !principals.get(toId)) fail(404, 'not_found', '相手が見つかりません。');
          if (definition.kind !== 'actor') permit('list', 'secret', undefined, toId);
          const row = requestActions.ask(subject.id, { ...definition, toId, purpose: purposeValue(input.purpose), steps: input.steps ?? [], validMinutes: input.valid_minutes ?? 30 });
          return send(201, { request: viewRequest(row, origin, { code: definition.kind === 'actor' }) });
        }
        if (!id && method === 'GET') {
          const status = url.searchParams.get('status');
          if (status !== null && !['pending', 'done', 'denied', 'cancelled'].includes(status)) fail(400, 'invalid_status', 'status は pending / done / denied / cancelled のいずれかです。');
          limit('request-poll', 30);
          const mine = url.searchParams.get('to') === 'me';
          return send(200, { requests: (mine ? requests.listTo(subject.id, status) : requests.list(subject.id, status)).map(row => viewRequest(row, origin)) });
        }
        const row = requests.get(id);
        const asker = row.from_id === subject.id;
        if (!action && method === 'GET') {
          limit('request-poll', 30);
          if (asker) return send(200, { request: viewRequest(row, origin, { events: true, code: row.status === 'pending' }) });
          requests.forTo(id, subject.id);
          permit('read', 'request', id, row.to_id ?? subject.id);
          requests.record(row.id, 'page_viewed');
          return send(200, { request: viewRequest(row, origin) });
        }
        if (!action && method === 'DELETE') {
          await body(req);
          permit('cancel', 'request', id, row.from_id);
          return send(200, { request: viewRequest(requestActions.cancel(subject.id, id), origin) });
        }
        if (action === '/done' && method === 'POST') {
          const pending = requests.forTo(id, subject.id, true);
          permit('done', 'request', id, row.to_id ?? subject.id);
          progressRequestId = pending.id;
          if (pending.kind === 'store') {
            const input = await inputBody(SECRET_MAX * requests.input(pending).fields.length);
            return send(200, { stored: true, ...requestActions.save(id, subject.id, input.entries) });
          }
          if (pending.kind === 'actor') {
            const input = await inputBody();
            return send(200, { request: viewRequest(requestActions.approve(id, subject.id, input.confirmation_code), origin) });
          }
          fail(409, 'wrong_kind', 'この依頼はページから完了するものではありません。');
        }
        if (action === '/deny' && method === 'POST') {
          requests.forTo(id, subject.id, true);
          permit('deny', 'request', id, row.to_id ?? subject.id);
          await inputBody();
          progressRequestId = row.id;
          return send(200, { request: viewRequest(requestActions.deny(id, subject.id), origin) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (subject.credential.kind === 'link') fail(401, 'login_required', 'ログインしてください。');
      // Principals: oneself, and those one owns.
      if (path === '/v1/principals/me') {
        if (method === 'GET') return send(200, { principal: self, acts_for: actsFor, owners: principals.ownersOf(subject.id), credentials: principals.credentials(subject.id), requests: requests.list(subject.id, 'pending').map(row => viewRequest(row, origin, { code: true })) });
        if (method === 'PATCH') { const input = await inputBody(); return send(200, { principal: principals.rename(subject.id, nameValue(input.name)) }); }
        // Leaving: a principal takes itself away, its open requests with it. What it acted for stays where it was.
        if (method === 'DELETE') {
          await inputBody();
          const cancelled = store.transaction(() => { const rows = requests.cancelFrom(subject.id, 'requester_left'); principals.remove(subject.id); return rows; });
          for (const row of cancelled) requestActions.changed(row);
          return send(200, { ok: true });
        }
      }
      if (path === '/v1/principals' && method === 'GET') { permit('list', 'principal', undefined, subject.id); return send(200, { principals: principals.owned(subject.id) }); }
      // Making a principal. One that is to act for its maker, and to carry a key, can be asked for in the same
      // breath; that is what making oneself a key is.
      if (path === '/v1/principals' && method === 'POST') {
        const input = await inputBody();
        const alias = input.alias === undefined ? undefined : nameValue(input.alias);
        const { made, issued } = store.transaction(() => {
          const made = principals.create(subject.id, { name: input.name === undefined ? (alias ?? '相手') : nameValue(input.name), alias });
          if (input.actor === true) principals.relate(made.id, 'actor', 'principal', subject.id);
          const issued = input.credential === 'key' ? principals.issue(made.id, { kind: 'key' }) : null;
          return { made, issued };
        });
        records.write(subject.id, 'principal.created', 'principal', made.id, { alias: alias ?? null, actor: input.actor === true, credential: issued ? 'key' : null });
        return send(201, { principal: { ...made, alias: alias ?? null, credentials: principals.credentials(made.id), acts_for: principals.actsFor(made.id) }, ...(issued ? { token: issued.token, credential: { id: issued.id, kind: 'key' } } : {}) });
      }
      const principalRoute = path.match(/^\/v1\/principals\/([A-Za-z0-9-]{1,64})(?:\/(credentials|settings)(?:\/([a-f0-9-]{36}))?)?$/);
      if (principalRoute) {
        const id = principalRoute[1] === 'me' ? subject.id : principalRoute[1], part = principalRoute[2], credentialId = principalRoute[3];
        const target = principals.at(id);
        if (!part) {
          if (method === 'GET') { permit('read', 'principal', id); return send(200, { principal: { ...target, credentials: principals.credentials(id), acts_for: principals.actsFor(id), owners: principals.ownersOf(id) } }); }
          if (method === 'PATCH') { permit('rename', 'principal', id); const input = await inputBody(); return send(200, { principal: principals.rename(id, nameValue(input.name)) }); }
          if (method === 'DELETE') {
            permit('remove', 'principal', id);
            await inputBody();
            requestActions.removePrincipal(subject.id, id);
            if (objects.enabled) {
              let cursor;
              do { const page = await objects.list(id, '', cursor); for (const item of page.objects) await objects.remove(id, item.key); cursor = page.cursor; } while (cursor);
            }
            return send(200, { ok: true });
          }
        }
        if (part === 'credentials') {
          if (!credentialId && method === 'GET') { permit('read', 'principal', id); return send(200, { credentials: principals.credentials(id) }); }
          if (!credentialId && method === 'POST') {
            permit('issue-credential', 'principal', id);
            const input = await inputBody();
            const kind = input.kind ?? 'key';
            if (kind === 'link') {
              // A link reaches one request, and only one the principal is asked to answer.
              if (typeof input.request_id !== 'string') fail(400, 'invalid_scope', 'リンクにする依頼を指定してください。');
              const row = requests.forTo(input.request_id, id, true);
              if (row.kind !== 'store') fail(409, 'link_unsupported', '接続の依頼はまだリンクで引き渡せません。');
              const made = principals.issue(id, { kind: 'link', scope: 'request:' + row.id, expiresIn: LINK_TTL });
              records.write(subject.id, 'credential.issued', 'principal', id, { kind: 'link', request: row.id });
              return send(201, { credential: { id: made.id, kind: made.kind, scope: made.scope, expires_at: made.expires_at }, url: origin + '/requests/' + row.id + '#link=' + made.token, expires_at: made.expires_at });
            }
            const made = store.transaction(() => {
              if (input.replaces !== undefined && !principals.revoke(id, input.replaces)) fail(404, 'not_found', '置き換える資格情報が見つかりません。');
              return principals.issue(id, { kind: 'key' });
            });
            records.write(subject.id, 'credential.issued', 'principal', id, { kind: 'key', replaced: input.replaces ?? null });
            return send(201, { credential: { id: made.id, kind: made.kind, created_at: made.created_at }, token: made.token });
          }
          if (credentialId && method === 'DELETE') {
            permit('revoke-credential', 'principal', id);
            await inputBody();
            if (!principals.revoke(id, credentialId)) fail(404, 'not_found', '資格情報が見つかりません。');
            records.write(subject.id, 'credential.revoked', 'principal', id, { credential: credentialId });
            return send(200, { ok: true });
          }
        }
        if (part === 'settings' && !credentialId) {
          permit('settings', 'principal', id);
          if (method === 'GET') return send(200, { settings: settings.get(id) ?? null });
          if (method === 'PUT') {
            const input = await inputBody();
            const made = settings.put(id, { returnUrl: input.return_url, refreshUrl: input.refresh_url || undefined, webhookUrl: input.webhook_url || undefined });
            records.write(subject.id, 'settings.changed', 'principal', id, {});
            return send(200, { settings: made });
          }
          if (method === 'DELETE') { await inputBody(); settings.remove(id); return send(200, { ok: true }); }
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // Lines between principals, and onto what is held. One may draw a line onto oneself or onto what one owns,
      // and never one that gives more than one has.
      if (path === '/v1/relations') {
        if (method === 'GET') return send(200, { relations: principals.relationsOf(subject.id) });
        const input = await inputBody();
        const subjectId = input.subject === undefined ? subject.id : principalId(input.subject);
        if (typeof input.relation !== 'string' || typeof input.object_type !== 'string' || typeof input.object_id !== 'string') fail(400, 'invalid_relation', '関係の指定を確認してください。');
        // Ownership comes from making or approving, never from a line drawn here. Onto a held thing the holder draws
        // viewer or editor, to anyone; between principals one draws actor, for oneself or for what one owns.
        // Anyone may step off a line they are on themselves.
        const declining = method === 'DELETE' && subjectId === subject.id;
        if (input.object_type === 'principal') {
          if (input.relation !== 'actor') fail(400, 'invalid_relation', '関係の種類を確認してください。');
          if (!declining) {
            if (subjectId !== subject.id && !principals.has(subject.id, 'owner', 'principal', subjectId)) fail(403, 'forbidden', 'この操作は許可されていません。');
            permit('relate', 'principal', input.object_id);
          }
        } else if (input.object_type === 'holding') {
          if (!['viewer', 'editor'].includes(input.relation)) fail(400, 'invalid_relation', '関係の種類を確認してください。');
          if (!declining) {
            const held = holding(input.object_id);
            permit('share', held.kind, held.id, held.holder_id);
            principals.at(subjectId);
          }
        } else fail(400, 'invalid_relation', '関係の種類を確認してください。');
        if (method === 'POST') {
          principals.relate(subjectId, input.relation, input.object_type, input.object_id, { scope: input.scope === undefined ? undefined : String(input.scope) });
          records.write(subject.id, 'relation.added', input.object_type, input.object_id, { subject: subjectId, relation: input.relation });
          return send(201, { ok: true });
        }
        if (method === 'DELETE') {
          principals.unrelate(subjectId, input.relation, input.object_type, input.object_id);
          records.write(subject.id, 'relation.removed', input.object_type, input.object_id, { subject: subjectId, relation: input.relation });
          return send(200, { ok: true });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // Held things by id: the same thing whoever holds it, reached along the lines drawn onto it.
      if (path === '/v1/holdings' && method === 'GET') { permit('list', 'holding', undefined, subject.id); return send(200, { holdings: principals.shownTo(subject.id) }); }
      const holdingRoute = path.match(/^\/v1\/holdings\/([a-f0-9-]{36})(\/content)?$/);
      if (holdingRoute) {
        const held = holding(holdingRoute[1]);
        if (!holdingRoute[2] && method === 'GET') {
          permit('read', held.kind, held.id, held.holder_id);
          return send(200, { holding: { ...held, ...(held.holder_id === subject.id ? { lines: principals.linesOnto(held.id) } : {}) } });
        }
        if (holdingRoute[2] && method === 'GET') {
          permit('read', held.kind, held.id, held.holder_id);
          if (held.kind === 'secret') {
            const content = secrets.content(secrets.byId(held.id));
            res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': content.length });
            return res.end(content);
          }
          if (held.kind === 'object') {
            const found = await objects.read(objects.byId(held.id));
            still();
            res.writeHead(200, { 'content-type': found.contentType, 'content-length': found.content.length });
            return res.end(found.content);
          }
          fail(405, 'method_not_allowed', 'この操作は利用できません。');
        }
        if (holdingRoute[2] && method === 'PUT') {
          permit('write', held.kind, held.id, held.holder_id);
          if (held.kind === 'secret') {
            const content = await inputBytes(SECRET_MAX);
            if (!content.length) fail(400, 'invalid_values', '入力内容を確認してください。');
            return send(200, { secret: secrets.write(secrets.byId(held.id), content) });
          }
          if (held.kind === 'object') {
            const content = await inputBytes(OBJECT_MAX);
            const saved = await objects.write(objects.byId(held.id), content, req.headers['content-type'] || 'application/octet-stream');
            still();
            return send(200, saved);
          }
          fail(405, 'method_not_allowed', 'この操作は利用できません。');
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (path === '/v1/records' && method === 'GET') { permit('list', 'record', undefined, subject.id); return send(200, { records: records.listFor(subject.id, principals.actorsOf(subject.id).map(row => row.id)) }); }
      // The holder's screen, in one answer.
      if (path === '/v1/overview' && method === 'GET') {
        permit('read', 'overview');
        return send(200, { user: { id: subject.id, email: user?.email ?? null }, principal: self, secrets: secrets.list(holderId), connections: connections.list(holderId).map(row => connections.view(row, { owner: true })),
          principals: principals.owned(holderId), actors: principals.actorsOf(holderId), requests: requests.listTo(holderId, 'pending').map(row => viewRequest(row, origin)),
          functions: FUNCTIONS, connectors: connectors.ids().map(id => connectors.describe(id)), settings: settings.get(holderId) ?? null });
      }
      // Everything, in one file, for the holder alone. Lending someone a place to keep things means they
      // can take them away again; without this the promise is words.
      if (path === '/v1/export' && method === 'GET') {
        permit('read', 'export');
        const kept = secrets.list(holderId).map(row => {
          const full = secrets.at(holderId, row.name);
          return { ...row, content: secrets.content(full).toString('base64'), encoding: 'base64' };
        });
        const value = { exported_at: new Date().toISOString(), owner: user?.email ?? null, origin,
          secrets: kept, connections: connections.list(holderId).map(row => connections.view(row, { owner: true })), principals: principals.owned(holderId) };
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8',
          'content-disposition': `attachment; filename="foundation-${new Date().toISOString().slice(0, 10)}.json"` });
        return res.end(JSON.stringify(value, null, 2));
      }
      // Connections: services Foundation connected itself. The holder sees everything about them; whoever acts
      // for them sees what they need to use one. Making one starts the service's own login; removing one may also revoke there.
      if (path === '/v1/connections' && method === 'GET') {
        permit('list', 'connection');
        return send(200, { connections: subject.id === holderId ? connections.list(holderId).map(row => connections.view(row, { owner: true }))
          : connections.list(holderId).filter(row => row.status !== 'disconnecting').map(row => connections.view(row)) });
      }
      if (path === '/v1/connections' && method === 'POST') {
        permit('create', 'connection');
        const input = await inputBody();
        const connector = connectors.get(input.connector);
        if (connector.authorization.kind !== 'oauth') fail(400, 'unsupported_authorization', 'この接続方法には対応していません。');
        limit('connect', 10);
        const request = input.request_id === undefined ? null : requests.forTo(input.request_id, holderId, true);
        progressRequestId = request?.id || null;
        if (request) requests.record(request.id, 'connect_started', { connector: connector.id });
        if (request && request.kind !== 'connect') fail(409, 'approval_only', 'この依頼はこの接続方法のものではありません。');
        if (request && connector.id !== requests.input(request).connector) fail(400, 'scope_mismatch', '依頼された接続方法で登録してください。');
        // Who asked for it, as they were called then. One started from the dashboard was asked by no one.
        const requestedBy = request ? principals.get(request.from_id)?.name ?? '' : '';
        const previous = input.connection_id === undefined ? undefined : connections.at(holderId, input.connection_id);
        if (previous && previous.connector !== connector.id) fail(400, 'invalid_connector', '接続方法が一致しません。');
        if (previous && connector.canReconnect === false) fail(400, 'new_connection_required', '新しく登録してください。');
        if (previous?.status === 'disconnecting') fail(409, 'connection_changed', '接続の解除が進行中です。');
        const verifier = randomBytes(32).toString('base64url');
        const redirectUri = origin + '/oauth/' + connector.id + '/callback';
        if (!session) fail(401, 'login_required', 'ログインしてください。');
        still();
        const flow = { connector: connector.id, requestedBy, verifier, redirectUri, requestId: request?.id, previous: previous ? { id: previous.id, generation: previous.generation } : null };
        const state = flows.begin(session.id, flow);
        return send(200, { url: await connector.authorization.begin({ state, verifier, redirectUri }, connections.context(previous)) });
      }
      const connectionRoute = path.match(/^\/v1\/connections\/(.+)$/);
      if (connectionRoute && method === 'DELETE') {
        permit('remove', 'connection', decodeURIComponent(connectionRoute[1]));
        const connection = connections.at(holderId, decodeURIComponent(connectionRoute[1]));
        const input = await inputBody();
        if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', '接続先の許可を取り消すか選んでください。');
        const connector = connectors.get(connection.connector);
        const canRevoke = typeof connector.revoke === 'function';
        if (disconnects.has(connection.id)) fail(409, 'disconnect_in_progress', '登録を解除しています。');
        disconnects.add(connection.id);
        try {
          // Removing it here always succeeds; asking the service to revoke is an attempt whose outcome is reported.
          const previous = connections.disconnect(holderId, connection.id);
          let revoked = null;
          if (input.revoke && canRevoke) {
            try { await connector.revoke(connections.context(previous).privateState); revoked = true; }
            catch { revoked = false; }
          }
          connections.remove(holderId, connection.id);
          records.write(subject.id, 'connection.removed', 'connection', connection.id, { revoked });
          return send(200, { ok: true, service_revoked: revoked });
        } finally { disconnects.delete(connection.id); }
      }
      // What this holder is using, and what they may use. Lending has a cost, so both sides can see it.
      if (path === '/v1/usage' && method === 'GET') {
        permit('read', 'usage');
        const kept = secrets.usage(holderId);
        const space = objects.enabled ? await objects.usage(holderId) : null;
        still();
        return send(200, { secrets: { ...kept, count_max: SECRET_COUNT_MAX, bytes_max: SECRET_TOTAL_MAX },
          objects: space ? { count: space.count, bytes: space.bytes, count_max: space.count_max, bytes_max: space.bytes_max } : null });
      }
      // The holder's own space of objects. Lent from Foundation's bucket while the holder has none of
      // their own; the same calls reach a bucket of theirs once one is connected.
      if (path === '/v1/objects' && method === 'GET') {
        permit('list', 'object');
        objects.check();
        limit('objects', 60);
        const listed = await objects.list(holderId, url.searchParams.get('prefix') ?? '', url.searchParams.get('cursor') ?? undefined);
        still();
        return send(200, listed);
      }
      const objectRoute = path.match(/^\/v1\/objects\/(.+?)(\/link)?$/);
      if (objectRoute) {
        objects.check();
        limit('objects', 60);
        const key = decodeURIComponent(objectRoute[1]);
        if (objectRoute[2]) {
          if (method !== 'POST') fail(405, 'method_not_allowed', 'この操作は利用できません。');
          permit('link', 'object', objects.find(holderId, key)?.id);
          const input = await inputBody();
          const link = await objects.link(holderId, key, input.minutes);
          still();
          return send(200, link);
        }
        if (method === 'PUT') {
          permit('write', 'object', objects.find(holderId, key)?.id);
          const content = await inputBytes(OBJECT_MAX);
          const saved = await objects.put(holderId, key, content, req.headers['content-type'] || 'application/octet-stream');
          still();
          return send(200, saved);
        }
        if (method === 'GET') {
          permit('read', 'object', objects.find(holderId, key)?.id);
          const found = await objects.get(holderId, key);
          still();
          res.writeHead(200, { 'content-type': found.contentType, 'content-length': found.content.length,
            'content-disposition': `attachment; filename="object.bin"; filename*=UTF-8''${encodeURIComponent(key.split('/').pop()).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16))}` });
          return res.end(found.content);
        }
        if (method === 'DELETE') { permit('remove', 'object', objects.find(holderId, key)?.id); await inputBody(); await objects.remove(holderId, key); still(); return send(200, { ok: true }); }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // What is kept, by name. A name is any text, so it travels as ?name=: a path would fold "." and ".." away.
      if (path === '/v1/secrets' && method === 'GET' && !url.searchParams.has('name')) { permit('list', 'secret'); return send(200, { secrets: secrets.list(holderId, url.searchParams.get('prefix') ?? undefined) }); }
      if (path === '/v1/secrets' && url.searchParams.has('name')) {
        const target = url.searchParams.get('name'), held = secrets.find(holderId, target)?.id;
        if (method === 'GET') {
          // Whoever may list may learn that a name is not there.
          if (held === undefined) { permit('list', 'secret'); fail(404, 'not_found', '保管されたものが見つかりません。'); }
          permit('read', 'secret', held);
          const row = secrets.at(holderId, target), content = secrets.content(row);
          res.setHeader('etag', secretTag(row));
          res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': content.length, 'content-disposition': `attachment; filename="secret.bin"; filename*=UTF-8''${encodeURIComponent(row.name).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16))}` });
          return res.end(content);
        }
        if (method === 'PUT') {
          permit('write', 'secret', held);
          limit('secrets', 120);
          const content = await inputBytes(SECRET_MAX);
          if (!content.length) fail(400, 'invalid_values', '入力内容を確認してください。');
          // A thing made for the holder by someone else is one its maker may read and write: a line says so.
          const saved = store.transaction(() => {
            const match = req.headers['if-match'];
            const current = match === undefined ? null : secrets.find(holderId, secretName(target));
            if (match !== undefined && (!current || match !== secretTag(current))) fail(412, 'secret_changed', 'ほかの操作で変更されています。開き直して確認してください。');
            const saved = secrets.put(holderId, { name: target, content });
            if (held === undefined && subject.id !== holderId) principals.relate(subject.id, 'editor', 'holding', saved.id);
            res.setHeader('etag', secretTag(secrets.at(holderId, target)));
            return saved;
          });
          return send(200, { secret: saved });
        }
        // Rename without returning or changing the stored value.
        if (method === 'PATCH') {
          permit('rename', 'secret', held);
          const input = await inputBody();
          return send(200, { secret: secrets.rename(holderId, target, { name: input.name }) });
        }
        if (method === 'DELETE') {
          permit('remove', 'secret', held);
          await inputBody();
          secrets.remove(holderId, target);
          return send(200, { ok: true });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // Reading a saved value never invokes provider code or updates another value.
      if (path === '/v1/deliveries' && method === 'POST') {
        permit('create', 'delivery');
        const input = await inputBody();
        limit('issue', 30);
        const names = Array.isArray(input.names) ? input.names : [];
        const delivery = secrets.deliver(holderId, names);
        records.write(subject.id, 'delivery', 'principal', holderId, { names: names.map(item => typeof item === 'string' ? item : item?.name).filter(Boolean) });
        return send(200, { delivery, expires_at: null, expires_in: null });
      }
      if (path === '/v1/functions' && method === 'GET') { permit('list', 'function'); return send(200, { functions: FUNCTIONS }); }
      if (path === '/v1/functions/connection.credentials' && method === 'POST') {
        permit('invoke', 'function', 'connection.credentials');
        const input = await inputBody();
        limit('issue', 30);
        const result = await functions.credentials({ holderId, still }, input);
        records.write(subject.id, 'function', 'principal', holderId, { function: 'connection.credentials', connection: input.connection_id, saved: result.saved?.map(item => item.name) ?? null });
        return send(200, result);
      }
      if (path === '/v1/functions/http.request' && method === 'POST') {
        permit('invoke', 'function', 'http.request');
        const input = await inputBody(FETCH_BODY_MAX * 2);
        limit('fetch', 30);
        const result = await functions.request({ holderId, still }, input, [url.hostname, ...(external ? [external.hostname] : [])]);
        records.write(subject.id, 'function', 'principal', holderId, { function: 'http.request', target: String(input.url).slice(0, 200), status: result.response?.status ?? null });
        return send(200, result);
      }
      // The MCP door. It carries no capability of its own: a tool call is the same request to the same
      // API, made with the same key. Agents whose harness connects them to nothing else arrive here.
      if (path === '/mcp') {
        if (method !== 'POST') fail(405, 'method_not_allowed', 'MCPのエンドポイントはPOSTのみです。');
        limit('mcp', 120);
        const authorization = req.headers.authorization;
        const answer = await respond(await body(req), req.headers, {
          serverInfo: { name: 'foundation', version: VERSION },
          guide: () => guide(connectors.ids().map(id => connectors.describe(id))),
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
      fail(404, 'not_found', '指定された操作が見つかりません。');
    } catch (error) {
      if (!(error instanceof HttpError)) console.error(new Date().toISOString(), req.method, req.url, error);
      if (progressRequestId && error instanceof HttpError && !res.headersSent) requests.record(progressRequestId, 'connect_failed', { code: error.code, message: error.message });
      if (!res.headersSent) send(error instanceof HttpError ? error.status : 500, { error: { code: error instanceof HttpError ? error.code : 'internal_error', message: error instanceof HttpError ? error.message : '処理を完了できませんでした。' } });
      else res.end();
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  return {
    server, store, secrets, connections, principals, sessions, flows, requests, requestActions, settings, records,
    async close() {
      clearInterval(timer);
      if (server.listening) await new Promise((resolve) => { server.close(resolve); server.closeIdleConnections(); });
      store.close();
    },
  };
}
