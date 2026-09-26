import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { digest } from './crypto.mjs';
import { Principals, LINK } from './principals.mjs';
import { Sessions, OAuthFlows } from './sessions.mjs';
import { RequestActions } from './request-actions.mjs';
import { requestDefinition, requestView } from './http-requests.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { Connectors } from './connectors.mjs';
import { EmailLogins, LOGIN_TTL } from './email-login.mjs';
import { Requests } from './requests.mjs';
import { Settings } from './settings.mjs';
import { Records } from './records.mjs';
import { Grants, GRANT_MAX, GRANT_COUNT_MAX, GRANT_TOTAL_MAX, METHODS } from './grants.mjs';
import { Objects, OBJECT_MAX } from './objects.mjs';
import { Holdings, KINDS } from './holdings.mjs';
import { respond } from './mcp.mjs';
import { FETCH_BODY_MAX } from './fetch.mjs';
import { FUNCTIONS, Functions } from './functions.mjs';
import { guide } from '../cli/guide.mjs';
import { Authorization } from './authorization.mjs';

const VERSION = createRequire(import.meta.url)('../package.json').version;

const PUBLIC = new URL('../web/', import.meta.url);
// The owner's pages. Each is the same shell; the script decides what to show from the path.
const PAGES = ['/', '/grants', '/objects', '/principals', '/functions', '/account'];
const STATIC = new Map(PAGES.map(page => [page, ['index.html', 'text/html; charset=utf-8']]));
STATIC.set('/app.js', ['app.js', 'text/javascript; charset=utf-8']);
STATIC.set('/request-view.js', ['request-view.js', 'text/javascript; charset=utf-8']);
STATIC.set('/styles.css', ['styles.css', 'text/css; charset=utf-8']);
STATIC.set('/service-logos.svg', ['service-logos.svg', 'image/svg+xml']);
const MAX_BODY = 12_000;
const SESSION_AGE = 14 * 86400;
const LOGIN_CALLBACK = '/login/callback';
const LINK_TTL = 10 * 60_000, LINKED_TTL = 30 * 60_000;
const REQUEST_PAGE = /^\/requests\/[A-Za-z0-9_-]{43}$/;
const PRINCIPAL_ID = /^[A-Za-z0-9-]{1,64}$/;
// A revision of the encrypted record, never a fingerprint of the plaintext value.
const grantTag = row => '"' + digest(JSON.stringify([row.id, row.name, row.size, row.updated_at])) + '"';

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
  const holdings = new Holdings(store);
  const grants = new Grants(store, holdings, connectors);
  const objects = new Objects(spaceBackend, holdings, store);
  const principals = new Principals(store), sessions = new Sessions(store), flows = new OAuthFlows(store);
  const requests = new Requests(store), settings = new Settings(store, principals), records = new Records(store);
  const authorization = new Authorization(principals);
  const functions = new Functions({ grants, outbound });
  const ownHosts = () => [...(external ? [external.hostname] : []), '127.0.0.1', 'localhost'];
  const viewRequest = (row, origin, options) => requestView({ requests, connectors, principals, settings }, row, origin, options);
  const requestActions = new RequestActions({ store, requests, grants, principals, records,
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
            previous = grants.connection(user.id, flow.previous.id);
            if (previous.generation !== flow.previous.generation || previous.status === 'disconnecting') fail(409, 'connection_changed', '接続状態が変わりました。');
          }
          if (flow.requestId) requests.forTo(flow.requestId, user.id, true);
          await verifyConnection(req, session,
            () => connector.authorization.complete({ code, verifier: flow.verifier, redirectUri: flow.redirectUri }, grants.context(previous)),
            result => requestActions.connect(flow.requestId, user.id, connector.id, result, { requestedBy: flow.requestedBy, previous }));
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
      // Becoming a principal needs no credential and no login: the request carries nothing to protect.
      const becoming = path === '/v1/principals' && method === 'POST' && browser && !cookieToken(req);
      if (browser && !['GET', 'HEAD'].includes(method) && !becoming) requireOrigin(req, origin);
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
      // one a link handed to a single request.
      let subject, session = null, user = null;
      const known = browser ? undefined : principals.authenticate(token);
      // Anyone may become a principal: one row and one key, issued here and shown once. It reaches nothing until
      // someone draws it a line; what it may do never comes from the making, only from the lines.
      if (becoming) {
        const input = await body(req);
        rateLimit('principal-create:' + clientAddress(req), 12, 600_000);
        const made = store.transaction(() => {
          const principal = principals.ensure(randomUUID(), nameValue(input.name, '相手'));
          return { principal, issued: principals.issue(principal.id, { kind: 'key' }) };
        });
        return send(201, { principal: made.principal, token: made.issued.token, credential: { id: made.issued.id, kind: 'key' } });
      }
      if (!browser && !known) notApproved();
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
      // In whose name. A principal acts as itself unless it names whom it acts for (?as=<id>); whether it may is
      // the same question as any other, answered from the lines.
      const actsFor = principals.actsFor(subject.id);
      const asked = url.searchParams.get('as');
      const holderId = asked ? principalId(asked) : subject.id;
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
        if (asked_ && !authorization.allowed(asked_).decision) fail(401, 'not_approved', 'この相手の代わりには動けません。');
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
          if (definition.kind !== 'actor') permit('list', 'grant', undefined, toId);
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
            const input = await inputBody(GRANT_MAX * requests.input(pending).fields.length);
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
          const cancelled = store.transaction(() => { const rows = requests.cancelFrom(subject.id, 'requester_left'); holdings.removeAll(subject.id); principals.remove(subject.id); return rows; });
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
            if (objects.enabled) for (const row of objects.list(id)) await objects.remove(row);
            holdings.removeAll(id);
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
            const held = holdings.at(input.object_id);
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
      // Held things. Each has an id, and that is how lines, records and the calls below refer to it. A name is how
      // the holder calls one: a way to find or place a thing, not its identity. A grant says what it is and how it
      // came to be held; an object says its size and type. Neither says anything of its content here.
      const shown = row => row.kind === 'grant' ? grants.view(grants.get(row.id), { owner: subject.id === row.holder_id }) : objects.view(objects.get(row.id));
      const holdingKind = required => {
        const kind = url.searchParams.get('kind') ?? undefined;
        if ((required && kind === undefined) || (kind !== undefined && !KINDS.includes(kind))) fail(400, 'invalid_kind', 'kind は grant / object のいずれかです。');
        return kind;
      };
      if (path === '/v1/holdings' && method === 'GET') {
        if (url.searchParams.get('shown') === 'me') { permit('list', 'holding', undefined, subject.id); return send(200, { holdings: principals.shownTo(subject.id) }); }
        const kind = holdingKind(false), name = url.searchParams.get('name') ?? undefined, prefix = url.searchParams.get('prefix') ?? undefined;
        const kinds = kind ? [kind] : KINDS;
        for (const one of kinds) permit('list', one);
        if (name !== undefined) {
          const found = (kinds.includes('grant') && grants.find(holderId, name)) || (kinds.includes('object') && objects.enabled && objects.find(holderId, name));
          if (!found) fail(404, 'not_found', '保管されたものが見つかりません。');
          return send(200, { holding: shown(found) });
        }
        const rows = [];
        if (kinds.includes('grant')) {
          const wanted = url.searchParams.get('method') ?? undefined, provider = url.searchParams.get('provider') ?? undefined, tag = url.searchParams.get('tag') ?? undefined;
          if (wanted !== undefined && !METHODS.includes(wanted)) fail(400, 'invalid_method', 'method は given / authorized / delegated のいずれかです。');
          rows.push(...grants.list(holderId, { method: wanted, provider, tag, prefix }).filter(row => subject.id === holderId || row.status !== 'disconnecting'));
        }
        if (kinds.includes('object')) { if (kind === 'object') objects.check(); if (objects.enabled) { limit('objects', 60); rows.push(...objects.list(holderId, prefix ?? '')); } }
        return send(200, { holdings: rows.map(shown) });
      }
      // Placing a thing by name: the holder's name for it. The same name, same kind, replaces what is there.
      // A grant placed this way is given: the holder hands the bytes over. Connections are made at /v1/connections.
      if (path === '/v1/holdings' && method === 'PUT') {
        const kind = holdingKind(true), name = url.searchParams.get('name');
        if (name === null) fail(400, 'invalid_name', '名前を指定してください。');
        const existing = kind === 'grant' ? grants.find(holderId, name) : (objects.check(), objects.find(holderId, name));
        permit('write', kind, existing?.id);
        limit(kind === 'grant' ? 'grants' : 'objects', kind === 'grant' ? 120 : 60);
        const content = await inputBytes(kind === 'grant' ? GRANT_MAX : OBJECT_MAX);
        if (kind === 'grant' && !content.length) fail(400, 'invalid_values', '入力内容を確認してください。');
        // A thing made for the holder by someone else is one its maker may read and write: a line says so.
        const line = saved => { if (!existing && subject.id !== holderId) principals.relate(subject.id, 'editor', 'holding', saved.id); };
        if (kind === 'grant') {
          const saved = store.transaction(() => {
            const match = req.headers['if-match'];
            const current = match === undefined ? null : grants.find(holderId, name);
            if (match !== undefined && (!current || match !== grantTag(current))) fail(412, 'grant_changed', 'ほかの操作で変更されています。開き直して確認してください。');
            const saved = grants.put(holderId, { name, content, provider: url.searchParams.get('provider') ?? undefined, tags: url.searchParams.get('tags') ?? undefined });
            line(saved);
            res.setHeader('etag', grantTag(saved));
            return saved;
          });
          return send(200, { holding: shown(saved) });
        }
        const saved = await objects.put(holderId, name, content, req.headers['content-type'] || 'application/octet-stream');
        still();
        line(saved);
        return send(200, { holding: shown(saved) });
      }
      const holdingRoute = path.match(/^\/v1\/holdings\/([a-f0-9-]{36})(\/content|\/link)?$/);
      if (holdingRoute) {
        const held = holdings.at(holdingRoute[1]), part = holdingRoute[2];
        const grant = held.kind === 'grant' ? grants.get(held.id) : null, given = grant?.method === 'given';
        if (!part && method === 'GET') {
          permit('read', held.kind, held.id, held.holder_id);
          return send(200, { holding: { ...shown(held), ...(held.holder_id === subject.id ? { lines: principals.linesOnto(held.id) } : {}) } });
        }
        // Renaming changes what the holder calls it and nothing else: lines, records and the content stay. Provider
        // and tags are likewise the holder's words about a grant.
        if (!part && method === 'PATCH') {
          const input = await inputBody();
          if (input.name !== undefined) permit('rename', held.kind, held.id, held.holder_id);
          if (input.provider !== undefined || input.tags !== undefined) permit('describe', 'grant', held.id, held.holder_id);
          if (held.kind === 'object') return send(200, { holding: shown(objects.rename(objects.get(held.id), input.name)) });
          let row = grant;
          if (input.name !== undefined) row = grants.rename(row, input.name);
          row = grants.describe(row, { provider: input.provider, tags: input.tags });
          return send(200, { holding: shown(row) });
        }
        if (!part && method === 'DELETE') {
          if (grant && !given) fail(405, 'method_not_allowed', '接続の解除は /v1/connections から行います。');
          permit('remove', held.kind, held.id, held.holder_id);
          await inputBody();
          if (held.kind === 'grant') grants.remove(held); else { await objects.remove(objects.get(held.id)); still(); }
          return send(200, { ok: true });
        }
        // The content of a thing: an object's bytes, or what a given grant holds. A connected grant has nothing to
        // read; what it yields is derived when it is delivered.
        if (part === '/content' && method === 'GET') {
          if (grant && !given) fail(405, 'method_not_allowed', 'この委任に読める中身はありません。渡すには /v1/deliveries を使います。');
          permit(held.kind === 'grant' ? 'content' : 'read', held.kind, held.id, held.holder_id);
          const disposition = `attachment; filename="holding.bin"; filename*=UTF-8''${encodeURIComponent(held.name.split('/').pop()).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16))}`;
          if (given) {
            const content = grants.content(grant);
            res.setHeader('etag', grantTag(grant));
            res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': content.length, 'content-disposition': disposition });
            return res.end(content);
          }
          const found = await objects.read(objects.get(held.id));
          still();
          res.writeHead(200, { 'content-type': found.contentType, 'content-length': found.content.length, 'content-disposition': disposition });
          return res.end(found.content);
        }
        if (part === '/content' && method === 'PUT') {
          if (grant && !given) fail(405, 'method_not_allowed', 'この委任の中身は書き換えられません。');
          permit('write', held.kind, held.id, held.holder_id);
          if (given) {
            limit('grants', 120);
            const content = await inputBytes(GRANT_MAX);
            if (!content.length) fail(400, 'invalid_values', '入力内容を確認してください。');
            const saved = store.transaction(() => {
              const match = req.headers['if-match'], current = grants.get(held.id);
              if (match !== undefined && match !== grantTag(current)) fail(412, 'grant_changed', 'ほかの操作で変更されています。開き直して確認してください。');
              const saved = grants.write(current, content);
              res.setHeader('etag', grantTag(saved));
              return saved;
            });
            return send(200, { holding: shown(saved) });
          }
          limit('objects', 60);
          const content = await inputBytes(OBJECT_MAX);
          const saved = await objects.write(objects.get(held.id), content, req.headers['content-type'] || 'application/octet-stream');
          still();
          return send(200, { holding: shown(saved) });
        }
        if (part === '/link' && method === 'POST') {
          if (held.kind !== 'object') fail(405, 'method_not_allowed', 'この操作は利用できません。');
          permit('link', 'object', held.id, held.holder_id);
          const input = await inputBody();
          limit('objects', 60);
          const link = await objects.link(objects.get(held.id), input.minutes);
          still();
          return send(200, link);
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (path === '/v1/records' && method === 'GET') { permit('list', 'record', undefined, subject.id); return send(200, { records: records.list(subject.id) }); }
      // The holder's screen, in one answer.
      if (path === '/v1/overview' && method === 'GET') {
        permit('read', 'overview');
        return send(200, { user: { id: subject.id, email: user?.email ?? null }, principal: self, grants: grants.list(holderId).map(row => grants.view(row, { owner: true })), tags: grants.tagsUsed(holderId),
          principals: principals.owned(holderId), actors: principals.actorsOf(holderId), requests: requests.listTo(holderId, 'pending').map(row => viewRequest(row, origin)),
          functions: FUNCTIONS, connectors: connectors.ids().map(id => connectors.describe(id)), settings: settings.get(holderId) ?? null });
      }
      // Everything, in one file, for the holder alone. Lending someone a place to keep things means they
      // can take them away again; without this the promise is words.
      if (path === '/v1/export' && method === 'GET') {
        permit('read', 'export');
        // A given grant goes out with its bytes; a connected one with what is known of it, since what renews it is
        // Foundation's to keep and would be of no use elsewhere.
        const kept = grants.list(holderId).map(row => ({ ...grants.view(row, { owner: true }), ...(row.method === 'given' ? { content: grants.content(row).toString('base64'), encoding: 'base64' } : {}) }));
        const value = { exported_at: new Date().toISOString(), owner: user?.email ?? null, origin, grants: kept, principals: principals.owned(holderId) };
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8',
          'content-disposition': `attachment; filename="foundation-${new Date().toISOString().slice(0, 10)}.json"` });
        return res.end(JSON.stringify(value, null, 2));
      }
      // Connections: services Foundation connected itself. The holder sees everything about them; whoever acts
      // for them sees what they need to use one. Making one starts the service's own login; removing one may also revoke there.
      if (path === '/v1/connections' && method === 'GET') {
        permit('list', 'grant');
        return send(200, { connections: subject.id === holderId ? grants.connections(holderId).map(row => grants.view(row, { owner: true }))
          : grants.connections(holderId).filter(row => row.status !== 'disconnecting').map(row => grants.view(row)) });
      }
      if (path === '/v1/connections' && method === 'POST') {
        permit('connect', 'grant');
        const input = await inputBody();
        const connector = connectors.get(input.connector);
        limit('connect', 10);
        const request = input.request_id === undefined ? null : requests.forTo(input.request_id, holderId, true);
        progressRequestId = request?.id || null;
        if (request) requests.record(request.id, 'connect_started', { connector: connector.id });
        if (request && request.kind !== 'connect') fail(409, 'approval_only', 'この依頼はこの接続方法のものではありません。');
        if (request && connector.id !== requests.input(request).connector) fail(400, 'scope_mismatch', '依頼された接続方法で登録してください。');
        // Who asked for it, as they were called then. One started from the dashboard was asked by no one.
        const requestedBy = request ? principals.get(request.from_id)?.name ?? '' : '';
        const previous = input.connection_id === undefined ? undefined : grants.connection(holderId, input.connection_id);
        if (previous && previous.connector !== connector.id) fail(400, 'invalid_connector', '接続方法が一致しません。');
        if (previous && connector.canReconnect === false) fail(400, 'new_connection_required', '新しく登録してください。');
        if (previous?.status === 'disconnecting') fail(409, 'connection_changed', '接続の解除が進行中です。');
        if (!session) fail(401, 'login_required', 'ログインしてください。');
        still();
        const flow = { connector: connector.id, requestedBy, requestId: request?.id, previous: previous ? { id: previous.id, generation: previous.generation } : null };
        // A role is made by the holder in the service's own console, then named here; what Foundation must remember
        // meanwhile (the external ID it chose) travels in the flow, and the flow lasts until the answer is right.
        if (connector.authorization.kind === 'role') {
          const started = await connector.authorization.begin({ origin }, grants.context(previous));
          still();
          const state = flows.begin(session.id, { ...flow, kind: 'role', memo: started.memo ?? null });
          return send(200, { url: started.url, state, complete: { fields: started.fields ?? [] } });
        }
        const verifier = randomBytes(32).toString('base64url');
        const redirectUri = origin + '/oauth/' + connector.id + '/callback';
        const state = flows.begin(session.id, { ...flow, verifier, redirectUri });
        return send(200, { url: await connector.authorization.begin({ state, verifier, redirectUri }, grants.context(previous)) });
      }
      if (path === '/v1/connections/complete' && method === 'POST') {
        permit('connect', 'grant');
        const input = await inputBody();
        if (!session) fail(401, 'login_required', 'ログインしてください。');
        limit('connect', 10);
        const flow = flows.peek(session.id, input.state);
        if (!flow || flow.kind !== 'role') fail(400, 'invalid_state', '接続をやり直してください。');
        const connector = connectors.get(flow.connector);
        const previous = flow.previous ? grants.connection(holderId, flow.previous.id) : undefined;
        if (previous && previous.generation !== flow.previous.generation) fail(409, 'connection_changed', '接続状態が変わりました。');
        if (flow.requestId) { requests.forTo(flow.requestId, holderId, true); progressRequestId = flow.requestId; }
        const fields = input.fields && typeof input.fields === 'object' && !Array.isArray(input.fields) ? input.fields : {};
        const saved = await verifyConnection(req, session,
          () => connector.authorization.complete({ fields, memo: flow.memo }, grants.context(previous)),
          result => requestActions.connect(flow.requestId, holderId, connector.id, result, { requestedBy: flow.requestedBy, previous }));
        flows.drop(session.id, input.state);
        return send(200, { connection: grants.view(saved, { owner: true }) });
      }
      const connectionRoute = path.match(/^\/v1\/connections\/(.+)$/);
      if (connectionRoute && method === 'DELETE') {
        permit('disconnect', 'grant', decodeURIComponent(connectionRoute[1]));
        const connection = grants.connection(holderId, decodeURIComponent(connectionRoute[1]));
        const input = await inputBody();
        if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', '接続先の許可を取り消すか選んでください。');
        const connector = connectors.get(connection.connector);
        const canRevoke = typeof connector.revoke === 'function';
        if (disconnects.has(connection.id)) fail(409, 'disconnect_in_progress', '登録を解除しています。');
        disconnects.add(connection.id);
        try {
          // Removing it here always succeeds; asking the service to revoke is an attempt whose outcome is reported.
          const previous = grants.disconnect(holderId, connection.id);
          let revoked = null;
          if (input.revoke && canRevoke) {
            try { await connector.revoke(grants.context(previous).privateState); revoked = true; }
            catch { revoked = false; }
          }
          grants.remove(previous);
          records.write(subject.id, 'connection.removed', 'grant', connection.id, { revoked });
          return send(200, { ok: true, service_revoked: revoked });
        } finally { disconnects.delete(connection.id); }
      }
      // What this holder is using, and what they may use. Lending has a cost, so both sides can see it.
      if (path === '/v1/usage' && method === 'GET') {
        permit('read', 'usage');
        const kept = grants.usage(holderId);
        const space = objects.enabled ? await objects.usage(holderId) : null;
        still();
        return send(200, { grants: { ...kept, count_max: GRANT_COUNT_MAX, bytes_max: GRANT_TOTAL_MAX },
          objects: space ? { count: space.count, bytes: space.bytes, count_max: space.count_max, bytes_max: space.bytes_max } : null });
      }
      // Delivering derives what each grant yields now: a given one its bytes, a connected one what its connector
      // obtains. This is the one place a stored thing reaches a provider.
      if (path === '/v1/deliveries' && method === 'POST') {
        permit('create', 'delivery');
        const input = await inputBody();
        limit('issue', 30);
        const names = Array.isArray(input.names) ? input.names : [];
        const { delivery, expires_at } = await grants.deliver(holderId, names);
        still();
        records.write(subject.id, 'delivery', 'principal', holderId, { names: names.map(item => typeof item === 'string' ? item : item?.name).filter(Boolean) });
        return send(200, { delivery, expires_at, expires_in: expires_at === null ? null : Math.max(0, Math.floor((expires_at - Date.now()) / 1000)) });
      }
      if (path === '/v1/functions' && method === 'GET') { permit('list', 'function'); return send(200, { functions: FUNCTIONS }); }
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
          // The tool names whom the caller acts for when it is exactly one and the call did not say.
          call: async ({ method: verb, path: target, body: payload }) => {
            const named = actsFor.length === 1 && !/[?&]as=/.test(target) ? target + (target.includes('?') ? '&' : '?') + 'as=' + encodeURIComponent(actsFor[0].id) : target;
            const response = await fetch(`http://127.0.0.1:${port}${named}`, {
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
    server, store, holdings, grants, objects, principals, sessions, flows, requests, requestActions, settings, records,
    async close() {
      clearInterval(timer);
      if (server.listening) await new Promise((resolve) => { server.close(resolve); server.closeIdleConnections(); });
      store.close();
    },
  };
}
