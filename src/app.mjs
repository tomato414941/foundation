import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { digest } from './crypto.mjs';
import { Principals } from './principals.mjs';
import { Sessions, OAuthFlows } from './sessions.mjs';
import { RequestActions } from './request-actions.mjs';
import { requestDefinition, requestView } from './http-requests.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { EmailLogins, LOGIN_TTL } from './email-login.mjs';
import { Requests } from './requests.mjs';
import { Settings } from './settings.mjs';
import { AuditLog } from './audit-log.mjs';
import { scopeList, requestedScopes } from './scopes.mjs';
import { appReference } from './request-input.mjs';
import { Apps, FOUNDATION_APP, takesApps } from './apps.mjs';
import { Credentials } from './credentials.mjs';
import { Secrets, SECRET_MAX, SECRET_COUNT_MAX, SECRET_TOTAL_MAX } from './secrets.mjs';
import { Inputs } from './inputs.mjs';
import { Services } from './services.mjs';
import { Objects, OBJECT_MAX } from './objects.mjs';
import { Environments } from './environments.mjs';
import { Resources, KINDS } from './resources.mjs';
import { respond } from './mcp.mjs';
import { FETCH_BODY_MAX } from './fetch.mjs';
import { FUNCTIONS, Functions } from './functions.mjs';
import { guide } from '../cli/guide.mjs';
import { Authorization, reaches } from './authorization.mjs';
import { pages, pageTitle, workspaceView, pendingView } from '../web/workspace-view.js';

const VERSION = createRequire(import.meta.url)('../package.json').version;

const PUBLIC = new URL('../web/', import.meta.url);
const PAGES = Object.keys(pages);
const STATIC = new Map(PAGES.map(page => [page, ['index.html', 'text/html; charset=utf-8']]));
STATIC.set('/login/confirm', ['index.html', 'text/html; charset=utf-8']);
STATIC.set('/app.js', ['app.js', 'text/javascript; charset=utf-8']);
STATIC.set('/request-view.js', ['request-view.js', 'text/javascript; charset=utf-8']);
STATIC.set('/workspace-view.js', ['workspace-view.js', 'text/javascript; charset=utf-8']);
STATIC.set('/styles.css', ['styles.css', 'text/css; charset=utf-8']);
STATIC.set('/service-logos.svg', ['service-logos.svg', 'image/svg+xml']);
const MAX_BODY = 12_000;
const SESSION_AGE = 14 * 86400;
const LOGIN_CONFIRM = '/login/confirm';
const LINK_TTL = 10 * 60_000, LINKED_TTL = 30 * 60_000;
const REQUEST_PAGE = /^\/requests\/[A-Za-z0-9_-]{43}$/;
const PRINCIPAL_ID = /^[A-Za-z0-9-]{1,64}$/;
// A revision of the encrypted record, never a fingerprint of the plaintext value.
const secretTag = row => '"' + digest(JSON.stringify([row.id, row.name, row.size, row.updated_at])) + '"';

function returnPath(value = '/') {
  const invalid = () => fail(400, 'invalid_return', 'リンクを開き直してください。');
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || /[\\\s]/.test(value)) invalid();
  const url = new URL(value, 'https://foundation.invalid');
  if (url.origin !== 'https://foundation.invalid' || (!PAGES.includes(url.pathname) && !REQUEST_PAGE.test(url.pathname))) invalid();
  if ([...url.searchParams.keys()].some(key => url.pathname !== '/objects' || key !== 'prefix')) invalid();
  return url.pathname + url.search + url.hash;
}

function loginEmail(value) {
  if (typeof value !== 'string' || value.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(value.trim())) fail(400, 'invalid_email', 'メールアドレスを確認してください。');
  return value.trim().toLowerCase();
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
  if (typeof value !== 'string' || value.length > 240 || /[\x00-\x1f]/.test(value)) fail(400, 'invalid_purpose', '目的は240文字以内で入力してください。');
  return value.trim();
}
function principalId(value) {
  if (typeof value !== 'string' || !PRINCIPAL_ID.test(value)) fail(400, 'invalid_principal', '相手の指定を確認してください。');
  return value;
}

export function createApp({ database = ':memory:', encryptionKey, auth, services: catalog, serviceFetcher, space: spaceBackend = null, publicOrigin, owners: ownerList = [], loginClock, trustedProxies = [], outbound = {}, runner = null, compute = {} }) {
  if (!auth || !Array.isArray(catalog)) throw new Error('Authentication and services are required');
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
  const resources = new Resources(store);
  const principals = new Principals(store), sessions = new Sessions(store), flows = new OAuthFlows(store);
  const authorization = new Authorization(principals);
  const services = new Services(store, resources, catalog, { authorization, ...(serviceFetcher ? { fetcher: serviceFetcher } : {}) });
  const apps = new Apps(store, resources, services), credentials = new Credentials(store, resources, services, apps);
  const secrets = new Secrets(store, resources), inputs = new Inputs(secrets, credentials);
  const objects = new Objects(spaceBackend, resources, store);
  const requests = new Requests(store), settings = new Settings(store, principals), auditLog = new AuditLog(store);
  const environments = new Environments({ store, resources, principals, runner, limits: compute });
  const functions = new Functions({ secrets, inputs, outbound });
  const ownHosts = () => [...(external ? [external.hostname] : []), '127.0.0.1', 'localhost'];
  const viewRequest = (row, origin, options) => requestView({ requests, services, principals, settings, credentials, apps }, row, origin, options);
  const requestActions = new RequestActions({ store, requests, secrets, credentials, services, apps, principals, authorization, auditLog,
    changed: row => { if (row.to_id) void settings.notify(row.to_id, 'request.' + row.status, { request: viewRequest(row, external?.origin || '') }, { ...outbound, ownHosts: ownHosts() }); } });
  const logins = new EmailLogins({ now: loginClock });
  const refreshing = new Map(), limits = new Map(), disconnects = new Set();
  const timer = setInterval(() => {
    store.sweep();
    principals.sweep();
    void environments.sweep().catch(error => console.error(new Date().toISOString(), 'environment sweep', error));
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
        const [filename, type] = STATIC.get(STATIC.has(path) ? path : '/');
        let content = await readFile(fileURLToPath(new URL(filename, PUBLIC)));
        if (filename === 'index.html') {
          const ownerFrame = PAGES.includes(path) && Boolean(sessions.get(cookieToken(req)));
          if (ownerFrame || path !== '/') {
            content = content.toString().replace(/<div id="app">[\s\S]*?<div id="notice"/, () => `<div id="app">${ownerFrame ? workspaceView(path, { pending: true }) : pendingView(path)}</div>\n  <div id="notice"`)
              .replace('<title>Foundation</title>', `<title>${pageTitle(path)}</title>`);
          }
          res.setHeader('Cache-Control', path === LOGIN_CONFIRM ? 'no-store' : 'private, no-store');
          res.writeHead(200, { 'content-type': type });
          return res.end(content);
        }
        const tag = '"' + digest(content).slice(0, 32) + '"';
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('ETag', tag);
        if (req.headers['if-none-match'] === tag) { res.writeHead(304); return res.end(); }
        res.writeHead(200, { 'content-type': type });
        return res.end(content);
      }
      if (path === '/health' && method === 'GET') return send(200, { status: 'ok' });
      if (path === '/start' && (method === 'GET' || method === 'HEAD')) {
        const instructions = [
          'CONNECT THIS AI TO FOUNDATION', '',
          'Server: ' + origin,
          'This is a public guide, not an access key or an approval. The owner approves access separately.', '',
          'Use the CLI quick start below if you can run shell commands. Do the setup in your own environment.',
          'Without a shell, use the HTTP instructions in WHO YOU ARE below and keep your key in private storage.',
          'Never ask the owner to paste credentials into chat.', '',
          '1. Use the existing foundation CLI, or install it with Node.js 24 or later:',
          '   npm install -g @tomato414941/foundation',
          '2. Connect with a name the owner will recognize:',
          '   foundation connect ' + origin + ' --name "<your name>"',
          '   An existing approved key is reused. If already approved, skip to step 4.',
          '3. Show the owner the returned request.verification_uri and request.confirmation_code.',
          '   Ask them to open the URL, check your name and permissions, and approve with the code.',
          '   Never approve on their behalf. Do not print or copy the private key file into the conversation.',
          '4. After they approve, check:',
          '   foundation api GET /v1/principals/me',
          '   Confirm acts_for contains the intended owner; if it does not, approval is not complete.',
          '5. Read the API guide below and continue with the owner\'s actual task.',
          '   Connecting alone does not authorize unrelated changes or access to external services.', '',
          guide(services.catalogView()),
        ].join('\n');
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        return res.end(method === 'HEAD' ? undefined : instructions);
      }
      if (path === '/login/callback' && method === 'GET') return redirect('/?login=invalid');
      // Every OAuth consent comes back here: the state names the flow, and the flow the service and the app.
      if (path === '/oauth/callback' && method === 'GET') {
        let destination = '/services', flowService = null;
        const location = code => destination + '?result=' + code + (destination === '/services' && flowService ? '&service=' + encodeURIComponent(flowService) : '');
        try {
          const { user, session } = await loggedIn(req);
          if (url.searchParams.getAll('state').length !== 1 || url.searchParams.getAll('code').length > 1) fail(400, 'invalid_state', '接続をやり直してください。');
          const flow = flows.take(session.id, url.searchParams.get('state'));
          if (!flow || flow.kind) fail(400, 'invalid_state', '接続をやり直してください。');
          flowService = flow.service;
          // The same app that asked for consent exchanges the code: Foundation's, or one someone holds.
          const active = apps.scheme(flow.service, flow.app);
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
            previous = credentials.forService(user.id, flow.previous.id);
            if (previous.generation !== flow.previous.generation || previous.status === 'disconnecting') fail(409, 'credential_changed', '接続の状態が変わりました。');
          }
          if (flow.requestId) requests.forTo(flow.requestId, user.id, true);
          const previousContext = credentials.context(previous);
          const completion = await verifyConnection(req, session,
            () => active.authorization.complete({ code, verifier: flow.verifier, redirectUri: flow.redirectUri }, previousContext),
            result => {
              const changes = previous ? active.authorization.changes?.(result, previousContext) : undefined;
              if (changes?.length) {
                if (flow.requestId) requests.forTo(flow.requestId, user.id, true);
                const current = credentials.reconnection(user.id, flow.service, 'oauth', previous.id);
                if (current.generation !== previous.generation) fail(409, 'credential_changed', '接続の状態が変わりました。');
                credentials.nextState(result);
                const { credentials: produced, ...kept } = result;
                const state = flows.begin(session.id, { kind: 'confirmation', service: flow.service, scheme: 'oauth', requestId: flow.requestId,
                  requestedBy: flow.requestedBy, previous: flow.previous, result: kept, changes, scopes: flow.scopes ?? null, app: flow.app ?? null });
                if (flow.requestId) requests.record(flow.requestId, 'connect_review', { service: flow.service });
                return { confirmation: state };
              }
              requestActions.connect(flow.requestId, user.id, flow.service, 'oauth', result, { requestedBy: flow.requestedBy, previous, scopes: flow.scopes ?? null, app: flow.app ?? null });
            });
          if (completion?.confirmation) return redirect(location('review') + '&state=' + completion.confirmation);
          return redirect(location('connected'));
        } catch (error) {
          if (progressRequestId && error instanceof HttpError) requests.record(progressRequestId, 'connect_failed', { service: flowService, code: error.code, message: error.message });
          const codes = { authorization_denied: 'denied', invalid_state: 'expired', login_required: 'expired', account_changed: 'wrong_account', scope_mismatch: 'scope', refresh_missing: 'retry', credential_changed: 'changed', service_response: 'failed' };
          return redirect(location(codes[error.code] || 'failed'));
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
        const email = loginEmail(input?.email);
        // Reachable from anywhere means anyone who finds the URL could otherwise make themselves an owner here.
        if (owners && !owners.has(email)) fail(403, 'not_invited', 'このアドレスではご利用いただけません。');
        const destination = returnPath(input.return_to);
        rateLimit('link-send:' + clientAddress(req), 12, 600_000);
        const { token: pendingToken, row } = logins.reserve(email);
        try {
          const redirectUri = origin + LOGIN_CONFIRM + (destination === '/' ? '' : '?' + new URLSearchParams({ return_to: destination }));
          await auth.sendLink(row.email, redirectUri);
          logins.sent(pendingToken, loginToken);
          setNamedCookie('fdn_login', pendingToken, LOGIN_TTL / 1000);
          return send(202, { pending: logins.summary(pendingToken) });
        } catch (error) { logins.cancel(pendingToken); throw error; }
      }
      if (path === '/v1/login/verify' && method === 'POST') {
        requireOrigin(req, origin);
        rateLimit('login:' + clientAddress(req), 30, 600_000);
        const input = await body(req), email = loginEmail(input?.email), destination = returnPath(input.return_to);
        if (typeof input.token_hash !== 'string' || !/^[A-Za-z0-9_-]{20,2048}$/.test(input.token_hash)) fail(400, 'invalid_link', 'リンクが無効です。最新のメールのリンクを開いてください。');
        if (owners && !owners.has(email)) fail(403, 'not_invited', 'このアドレスではご利用いただけません。');
        // The displayed account is untrusted until the provider returns the matching identity.
        // Merely opening the confirmation page never consumes the key or changes a session.
        let session;
        try { session = await auth.verifyLink(input.token_hash); }
        catch (error) {
          if (error instanceof HttpError) throw error;
          fail(503, 'auth_unavailable', 'ログインサービスに接続できません。しばらく待ってからお試しください。');
        }
        if (session.user.email.toLowerCase() !== email || req.aborted || req.socket.destroyed) {
          try { await auth.logout(session.access_token); } catch {}
          fail(401, 'invalid_link', 'リンクが無効です。最新のメールのリンクを開いてください。');
        }
        const next = sessions.create(session);
        sessions.remove(cookieToken(req));
        setCookie(next, SESSION_AGE);
        logins.cancel(loginToken);
        setNamedCookie('fdn_login', '', 0);
        return send(200, { ok: true, return_to: destination });
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
      // The services Foundation knows, and how it comes to hold a credential for each. Public: a key not yet
      // approved reads it too.
      if (path === '/v1/services' && method === 'GET') return send(200, { services: services.catalogView() });
      // Where the page sends someone back after a request: the handler's page for it. Public, and says nothing else.
      const returnRoute = path.match(/^\/v1\/requests\/([A-Za-z0-9_-]{43})\/return$/);
      if (returnRoute && method === 'GET') {
        const back = settings.backFor(requests.get(returnRoute[1]));
        if (!back) fail(404, 'not_found', '戻り先はありません。');
        return send(200, { back });
      }
      // Spending a single-use link: the one in the URL is gone, and a short link for the browser takes its place,
      // sent as a cookie that reaches that one request's routes and nothing else.
      if (path === '/v1/links/exchange' && method === 'POST') {
        const input = await body(req);
        rateLimit('link:' + clientAddress(req), 20, 600_000);
        const made = principals.exchangeLink(input.link, input.request_id, LINKED_TTL);
        requests.record(made.request_id, 'link_opened');
        setNamedCookie('fdn_link', made.token, LINKED_TTL / 1000, '/v1/requests/' + made.request_id);
        return send(200, { ok: true });
      }
      // Who is asking, and what they came in by (via). A token is an access key; a browser is the person who logged in,
      // or the one a request link handed to a single request.
      let subject, session = null, user = null;
      const known = browser ? undefined : principals.authenticateKey(token);
      // Anyone may become a principal: one row and one key, issued here and shown once. It reaches nothing until
      // someone draws it a line; what it may do never comes from the making, only from the lines.
      if (becoming) {
        const input = await body(req);
        rateLimit('principal-create:' + clientAddress(req), 12, 600_000);
        const made = store.transaction(() => {
          const principal = principals.ensure(randomUUID(), nameValue(input.name, '相手'));
          return { principal, issued: principals.issueKey(principal.id) };
        });
        return send(201, { principal: made.principal, token: made.issued.token, key: { id: made.issued.id } });
      }
      if (!browser && !known) notApproved();
      if (!browser) subject = { id: known.principal.id, via: { kind: 'key', id: known.key.id, ...(known.key.environment ? { environment: known.key.environment } : {}) } };
      else {
        const linked = requestRoute?.[1] ? principals.authenticateLink(readCookie(req, 'fdn_link'), requestRoute[1]) : undefined;
        if (linked) subject = { id: linked.principal.id, via: { kind: 'link', ...linked.link } };
        else {
          ({ user, session } = await loggedIn(req));
          principals.ensure(user.id);
          subject = { id: user.id, via: { kind: 'session', id: session.id } };
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
        if (subject.via.kind === 'link') fail(401, 'login_required', 'ログインしてください。');
        if (subject.via.kind === 'key' && holder !== subject.id && !principals.relationsOf(subject.id).length) notApproved();
        fail(403, 'forbidden', 'この操作は許可されていません。');
      };
      // Reading an upload may outlive its authorization. Recheck before committing any change: what the subject came in
      // by, and the same question the route asked before reading.
      const still = () => {
        if (subject.via.kind === 'session') { if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。'); }
        else if (subject.via.kind === 'link') { if (!principals.hasLink(subject.id, subject.via.id)) fail(401, 'login_required', 'このリンクは使えません。元の画面から開き直してください。'); }
        else if (!principals.hasKey(subject.id, subject.via.id)) fail(401, 'not_approved', 'このキーは失効しています。');
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
          const toId = definition.kind === 'actor' ? (input.to === undefined ? null : principalId(input.to)) : input.to === undefined ? holderId : principalId(input.to);
          if (toId !== null && !principals.get(toId)) fail(404, 'not_found', '相手が見つかりません。');
          if (definition.kind !== 'actor') permit('list', definition.kind === 'store' ? 'secret' : 'credential', undefined, toId);
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
          if (pending.kind === 'app') {
            if (!session) fail(401, 'login_required', 'ログインしてください。');
            const input = await inputBody();
            return send(200, { registered: true, ...requestActions.registerApp(id, subject.id, input) });
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
      if (subject.via.kind === 'link') fail(401, 'login_required', 'ログインしてください。');
      // Principals: oneself, and those one owns.
      if (path === '/v1/principals/me') {
        if (method === 'GET') return send(200, { principal: self, ...(subject.via.kind === 'key' ? { key: { id: subject.via.id, ...(subject.via.environment ? { environment: subject.via.environment } : {}) } } : {}), acts_for: actsFor, owners: principals.ownersOf(subject.id), keys: principals.keys(subject.id), requests: requests.list(subject.id, 'pending').map(row => viewRequest(row, origin, { code: true })) });
        if (method === 'PATCH') { const input = await inputBody(); return send(200, { principal: principals.rename(subject.id, nameValue(input.name)) }); }
        // Leaving: a principal takes itself away, its open requests with it. What it acted for stays where it was.
        if (method === 'DELETE') {
          await inputBody();
          await environments.removeAll(subject.id);
          const cancelled = store.transaction(() => { const rows = requests.cancelFrom(subject.id, 'requester_left'); resources.removeAll(subject.id); principals.remove(subject.id); return rows; });
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
          const issued = input.key === true ? principals.issueKey(made.id) : null;
          return { made, issued };
        });
        auditLog.write(subject.id, 'principal.created', 'principal', made.id, { alias: alias ?? null, actor: input.actor === true, key: Boolean(issued) });
        return send(201, { principal: { ...made, alias: alias ?? null, keys: principals.keys(made.id), acts_for: principals.actsFor(made.id) }, ...(issued ? { token: issued.token, key: { id: issued.id, kind: 'key' } } : {}) });
      }
      const principalRoute = path.match(/^\/v1\/principals\/([A-Za-z0-9-]{1,64})(?:\/(keys|links|settings|access|compute)(?:\/([a-f0-9-]{36}))?)?$/);
      if (principalRoute) {
        const id = principalRoute[1] === 'me' ? subject.id : principalRoute[1], part = principalRoute[2], keyId = principalRoute[3];
        const target = principals.at(id);
        if (part === 'access' && !keyId && method === 'DELETE') {
          permit('relate', 'principal', holderId);
          if (id === holderId) fail(400, 'invalid_principal', '自分自身のアクセスは取り消せません。');
          await inputBody();
          requestActions.revokeAccess(holderId, id);
          return send(200, { ok: true });
        }
        if (!part) {
          if (method === 'GET') { permit('read', 'principal', id); return send(200, { principal: { ...target, keys: principals.keys(id), acts_for: principals.actsFor(id), owners: principals.ownersOf(id) } }); }
          if (method === 'PATCH') { permit('rename', 'principal', id); const input = await inputBody(); return send(200, { principal: principals.rename(id, nameValue(input.name)) }); }
          if (method === 'DELETE') {
            permit('remove', 'principal', id);
            await inputBody();
            requestActions.removePrincipal(subject.id, id);
            if (objects.enabled) for (const row of objects.list(id)) await objects.remove(row);
            await environments.removeAll(id);
            resources.removeAll(id);
            return send(200, { ok: true });
          }
        }
        if (part === 'keys') {
          if (!keyId && method === 'GET') { permit('read', 'principal', id); return send(200, { keys: principals.keys(id) }); }
          if (!keyId && method === 'POST') {
            permit('issue-key', 'principal', id);
            const input = await inputBody();
            const made = store.transaction(() => {
              if (input.replaces !== undefined && !principals.revokeKey(id, input.replaces)) fail(404, 'not_found', '置き換えるキーが見つかりません。');
              return principals.issueKey(id);
            });
            auditLog.write(subject.id, 'key.issued', 'principal', id, { replaced: input.replaces ?? null });
            return send(201, { key: { id: made.id, created_at: made.created_at }, token: made.token });
          }
          if (keyId && method === 'DELETE') {
            permit('revoke-key', 'principal', id);
            await inputBody();
            if (!principals.revokeKey(id, keyId)) fail(404, 'not_found', 'キーが見つかりません。');
            auditLog.write(subject.id, 'key.revoked', 'principal', id, { key: keyId });
            return send(200, { ok: true });
          }
        }
        // A request link: handed to the principal asked, to answer that one request without a login.
        if (part === 'links' && !keyId && method === 'POST') {
          permit('issue-link', 'principal', id);
          const input = await inputBody();
          if (typeof input.request_id !== 'string') fail(400, 'invalid_request', 'リンクにする依頼を指定してください。');
          const row = requests.forTo(input.request_id, id, true);
          if (row.kind !== 'store') fail(409, 'link_unsupported', '接続の依頼はまだリンクで引き渡せません。');
          const made = principals.issueLink(id, row.id, LINK_TTL);
          auditLog.write(subject.id, 'link.issued', 'principal', id, { request: row.id });
          return send(201, { link: { id: made.id, request_id: made.request_id, expires_at: made.expires_at }, url: origin + '/requests/' + row.id + '#link=' + made.token, expires_at: made.expires_at });
        }
        // Computing this principal spent this month and may spend; its owner bounds it.
        if (part === 'compute' && !keyId) {
          if (method === 'GET') { permit('read', 'usage', undefined, id); return send(200, { compute: environments.usage(id) }); }
          if (method === 'PUT') {
            permit('limit', 'principal', id);
            const input = await inputBody();
            const made = environments.setLimit(id, input.monthly_seconds);
            auditLog.write(subject.id, 'compute.limited', 'principal', id, { monthly_seconds: input.monthly_seconds });
            return send(200, { compute: made });
          }
        }
        if (part === 'settings' && !keyId) {
          permit('settings', 'principal', id);
          if (method === 'GET') return send(200, { settings: settings.get(id) ?? null });
          if (method === 'PUT') {
            const input = await inputBody();
            const made = settings.put(id, { returnUrl: input.return_url, refreshUrl: input.refresh_url || undefined, webhookUrl: input.webhook_url || undefined });
            auditLog.write(subject.id, 'settings.changed', 'principal', id, {});
            return send(200, { settings: made });
          }
          if (method === 'DELETE') { await inputBody(); settings.remove(id); return send(200, { ok: true }); }
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // Lines: the one record of what a principal was given. A line names a role or one action and points at a
      // principal or a resource. It is drawn by one who may give lines there and may take there all it reaches; it is
      // taken back by one who may give lines there, or given up by the one it was drawn to. Owning is never drawn.
      if (path === '/v1/relations') {
        if (method === 'GET') return send(200, { relations: principals.relationsOf(subject.id) });
        if (method !== 'POST' && method !== 'DELETE') fail(405, 'method_not_allowed', 'この操作は利用できません。');
        const input = await inputBody();
        const subjectId = input.subject === undefined ? subject.id : principalId(input.subject);
        if (typeof input.relation !== 'string' || !['principal', 'resource'].includes(input.object_type) || typeof input.object_id !== 'string') fail(400, 'invalid_relation', '関係の指定を確認してください。');
        const object = input.object_type === 'principal' ? { id: principals.at(input.object_id).id } : resources.at(input.object_id);
        if (!reaches(input.relation, input.object_type, object.kind)) fail(400, 'invalid_relation', '関係の種類を確認してください。');
        principals.at(subjectId);
        if (method === 'POST') {
          if (!authorization.mayGive(subject.id, input.relation, input.object_type, object)) fail(403, 'forbidden', 'この操作は許可されていません。');
          principals.relate(subjectId, input.relation, input.object_type, input.object_id);
          auditLog.write(subject.id, 'relation.added', input.object_type, input.object_id, { subject: subjectId, relation: input.relation });
          return send(201, { ok: true });
        }
        if (subjectId !== subject.id) {
          if (input.object_type === 'principal') permit('relate', 'principal', object.id);
          else permit('share', object.kind, object.id, object.holder_id);
        }
        principals.unrelate(subjectId, input.relation, input.object_type, input.object_id);
        auditLog.write(subject.id, 'relation.removed', input.object_type, input.object_id, { subject: subjectId, relation: input.relation });
        return send(200, { ok: true });
      }
      // Lent machines. An environment is a resource: opened by the holder or whoever acts for them, reached by its id,
      // shared along lines, and able to reach nothing of Foundation's unless given an identity it may act as.
      const passable = identity => {
        if (identity === undefined || identity === null) return null;
        const id = principalId(identity);
        principals.at(id);
        permit('pass', 'principal', id);
        return id;
      };
      if (path === '/v1/environments' && method === 'GET') { permit('list', 'environment'); return send(200, { environments: environments.list(holderId).map(row => environments.view(row)) }); }
      if ((path === '/v1/environments' || path === '/v1/runs') && method === 'POST') {
        permit('open', 'environment');
        environments.check();
        limit('environments', 20);
        const input = await inputBody(1024 * 1024 + 20_000);
        const identity = passable(input.identity);
        const run = path === '/v1/runs';
        const opened = await environments.open(holderId, { ...input, identity, ...(run ? { lifetime: { ...(input.lifetime ?? {}), end: 'exit' } } : {}) }, origin);
        auditLog.write(subject.id, 'environment.opened', 'resource', opened.id, { identity, size: opened.size, lifetime: opened.lifetime });
        if (!run) return send(201, { environment: environments.view(opened) });
        const started = environments.run(opened, subject.id, input);
        auditLog.write(subject.id, 'environment.command', 'resource', opened.id, { command: String(input.command?.[0] ?? '').slice(0, 100) });
        const answered = await environments.answer(opened.id, started.id, 20_000);
        return send(answered.status === 'running' ? 202 : 200, { environment: environments.view(environments.get(opened.id)), command: answered });
      }
      const environmentRoute = path.match(/^\/v1\/(environments|resources)\/([a-f0-9-]{36})(?:\/commands(?:\/([a-f0-9-]{36}))?)?$/);
      const environmentHeld = environmentRoute && (environmentRoute[1] === 'environments' || (!path.includes('/commands') && resources.get(environmentRoute[2])?.kind === 'environment'))
        ? environments.at(environmentRoute[2]) : null;
      if (environmentHeld && (environmentRoute[1] === 'environments' || method === 'DELETE')) {
        const held = environmentHeld, commands = path.endsWith('/commands') || Boolean(environmentRoute[3]);
        if (!commands && method === 'GET') { permit('read', 'environment', held.id, held.holder_id); return send(200, { environment: environments.view(held) }); }
        if (!commands && method === 'PATCH') {
          permit('identity', 'environment', held.id, held.holder_id);
          const input = await inputBody();
          if (!Object.hasOwn(input, 'identity')) fail(400, 'invalid_identity', 'identity を指定してください（外すときは null）。');
          const identity = passable(input.identity);
          const changed = identity ? await environments.attach(held, identity) : await environments.detach(held);
          auditLog.write(subject.id, identity ? 'environment.identity' : 'environment.identity_removed', 'resource', held.id, { identity });
          return send(200, { environment: environments.view(changed) });
        }
        if (!commands && method === 'DELETE') {
          permit('remove', 'environment', held.id, held.holder_id);
          await inputBody();
          await environments.remove(held);
          auditLog.write(subject.id, 'environment.closed', 'resource', held.id, {});
          return send(200, { ok: true });
        }
        if (commands && !environmentRoute[3] && method === 'POST') {
          permit('exec', 'environment', held.id, held.holder_id);
          const input = await inputBody(1024 * 1024 + 20_000);
          const started = environments.run(held, subject.id, input);
          auditLog.write(subject.id, 'environment.command', 'resource', held.id, { command: String(input.command?.[0] ?? '').slice(0, 100) });
          const answered = await environments.answer(held.id, started.id, 20_000);
          return send(answered.status === 'running' ? 202 : 200, { command: answered });
        }
        if (commands && environmentRoute[3] && method === 'GET') {
          permit('read', 'environment', held.id, held.holder_id);
          return send(200, { command: environments.command(held.id, environmentRoute[3]) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // Resources. Each has an id, and that is how lines, the audit log and the calls below refer to it. A name is
      // how the holder calls one: a way to find or place a thing, not its identity. A credential says what it is
      // and where it works; an object says its size and type; neither says anything of its content here.
      const shown = row => row.kind === 'credential' ? credentials.view(credentials.get(row.id), { owner: subject.id === row.holder_id })
        : row.kind === 'secret' ? secrets.view(secrets.get(row.id))
        : row.kind === 'app' ? apps.view(apps.get(row.id), { owner: subject.id === row.holder_id })
        : row.kind === 'service' ? services.view(services.row(row.id), { owner: subject.id === row.holder_id })
        : row.kind === 'environment' ? environments.view(environments.get(row.id)) : objects.view(objects.get(row.id));
      const resourceKind = required => {
        const kind = url.searchParams.get('kind') ?? undefined;
        if ((required && kind === undefined) || (kind !== undefined && !KINDS.includes(kind))) fail(400, 'invalid_kind', 'kind は secret / credential / object / app / service / environment のいずれかです。');
        return kind;
      };
      if (path === '/v1/resources' && method === 'GET') {
        if (url.searchParams.get('shown') === 'me') { permit('list', 'resource', undefined, subject.id); return send(200, { resources: principals.shownTo(subject.id) }); }
        const kind = resourceKind(false), name = url.searchParams.get('name') ?? undefined, prefix = url.searchParams.get('prefix') ?? undefined;
        const kinds = kind ? [kind] : KINDS;
        for (const one of kinds) permit('list', one);
        if (name !== undefined) {
          const found = (kinds.includes('secret') && secrets.find(holderId, name)) || (kinds.includes('object') && objects.enabled && objects.find(holderId, name))
            || (kinds.includes('service') && services.find(holderId, name)) || (kinds.includes('app') && apps.find(holderId, name));
          if (!found) fail(404, 'not_found', '見つかりません。');
          return send(200, { resource: shown(found) });
        }
        const rows = [];
        if (kinds.includes('secret')) rows.push(...secrets.list(holderId, { prefix }));
        if (kinds.includes('credential')) {
          const service = url.searchParams.get('service') ?? undefined;
          rows.push(...credentials.list(holderId, { service, prefix }).filter(row => subject.id === holderId || row.status !== 'disconnecting'));
        }
        if (kinds.includes('object')) { if (kind === 'object') objects.check(); if (objects.enabled) { limit('objects', 60); rows.push(...objects.list(holderId, prefix ?? '')); } }
        if (kinds.includes('app')) rows.push(...apps.list(holderId), ...apps.lent(holderId));
        if (kinds.includes('service')) rows.push(...services.list(holderId), ...services.lent(holderId));
        if (kinds.includes('environment')) rows.push(...environments.list(holderId));
        // Apps are listed with those Foundation offers, which anyone may connect through and nobody holds.
        return send(200, { resources: [...rows.map(shown), ...(kind === 'app' ? apps.offeredAll() : [])] });
      }
      // Placing a thing by name: the holder's name for it. The same name, same kind, replaces what is there. A
      // secret placed this way is the holder's bytes. Managed authorizations are made at /v1/credentials.
      if (path === '/v1/resources' && method === 'PUT') {
        const kind = resourceKind(true), name = url.searchParams.get('name');
        if (name === null) fail(400, 'invalid_name', '名前を指定してください。');
        // An app is registered by its holder, as values: which service, its client ID and secret. The same name
        // again gives it new values, and its credentials go on through it.
        if (kind === 'app') {
          const existing = apps.find(holderId, name);
          permit('write', 'app', existing?.id);
          limit('apps', 30);
          const input = await inputBody();
          services.get(input.service, holderId);
          const saved = apps.put(holderId, { ...input, name });
          auditLog.write(subject.id, existing ? 'app.changed' : 'app.created', 'resource', saved.id, { service: saved.service });
          return send(200, { resource: shown(saved) });
        }
        // A service is described as its definition; it holds nothing secret.
        if (kind === 'service') {
          const existing = services.find(holderId, name);
          permit('write', 'service', existing?.id);
          limit('services', 30);
          const input = await inputBody();
          const saved = store.transaction(() => {
            if (req.headers['if-none-match'] === '*' && services.find(holderId, name)) fail(412, 'name_taken', '同じ名前のサービスがあります。一覧から選んでください。');
            return services.put(holderId, name, input);
          });
          auditLog.write(subject.id, existing ? 'service.changed' : 'service.created', 'resource', saved.id, {});
          return send(200, { resource: shown(saved) });
        }
        if (!['secret', 'object'].includes(kind)) fail(405, 'method_not_allowed', 'この操作は利用できません。');
        const existing = kind === 'secret' ? secrets.find(holderId, name) : (objects.check(), objects.find(holderId, name));
        permit('write', kind, existing?.id);
        limit(kind === 'secret' ? 'secrets' : 'objects', kind === 'secret' ? 120 : 60);
        const content = await inputBytes(kind === 'secret' ? SECRET_MAX : OBJECT_MAX);
        if (kind === 'secret' && !content.length) fail(400, 'invalid_values', '入力内容を確認してください。');
        // A thing made for the holder by someone else is one its maker may read and write: a line says so.
        const line = saved => { if (!existing && subject.id !== holderId) principals.relate(subject.id, 'editor', 'resource', saved.id); };
        if (kind === 'secret') {
          const saved = store.transaction(() => {
            const match = req.headers['if-match'];
            const current = match === undefined ? null : secrets.find(holderId, name);
            if (match !== undefined && (!current || match !== secretTag(current))) fail(412, 'secret_changed', 'ほかの操作で変更されています。開き直して確認してください。');
            const saved = secrets.put(holderId, { name, content });
            line(saved);
            res.setHeader('etag', secretTag(saved));
            return saved;
          });
          return send(200, { resource: shown(saved) });
        }
        const saved = await objects.put(holderId, name, content, req.headers['content-type'] || 'application/octet-stream');
        still();
        line(saved);
        return send(200, { resource: shown(saved) });
      }
      const resourceRoute = path.match(/^\/v1\/resources\/([a-f0-9-]{36})(\/content|\/link)?$/);
      if (resourceRoute) {
        const held = resources.at(resourceRoute[1]), part = resourceRoute[2];
        const credential = held.kind === 'credential' ? credentials.get(held.id) : null, secret = held.kind === 'secret' ? secrets.get(held.id) : null;
        // An app: renamed by its holder; given new values by its holder or an editor; removed by its holder, which
        // stops the credentials made through it. Its secret is never read back, by anyone.
        if (held.kind === 'app') {
          const app = apps.at(held.id);
          if (part) fail(405, 'method_not_allowed', 'アプリの秘密は読み出せません。');
          if (method === 'PATCH') {
            const input = await inputBody();
            const { name, ...values } = input;
            let row = app;
            if (name !== undefined) { permit('rename', 'app', app.id, app.holder_id); row = apps.rename(row, name); }
            if (Object.keys(values).length) {
              permit('write', 'app', app.id, app.holder_id);
              row = apps.write(row, values);
              auditLog.write(subject.id, 'app.changed', 'resource', app.id, { service: app.service });
            }
            return send(200, { resource: shown(row) });
          }
          if (method === 'DELETE') {
            permit('remove', 'app', app.id, app.holder_id);
            const input = await inputBody(), dependents = apps.dependents(app);
            // Removing an app stops what was connected through it; that is said, and agreed to, first.
            if (dependents.length && input.confirm !== true) {
              fail(409, 'app_in_use', `このアプリで作った接続が${dependents.length}件あります。削除すると、つなぎ直すまで使えなくなります。`,
                { credentials: dependents.length, yours: dependents.filter(row => row.holder_id === app.holder_id).map(row => ({ id: row.id, name: row.name })) });
            }
            apps.remove(app);
            auditLog.write(subject.id, 'app.removed', 'resource', app.id, { service: app.service, credentials_stopped: dependents.length });
            return send(200, { ok: true, credentials_stopped: dependents.length });
          }
        }
        // A service a holder described: its definition is read, replaced and renamed; it is removed once nothing
        // refers to it.
        if (held.kind === 'service') {
          const row = services.row(held.id);
          if (part) fail(405, 'method_not_allowed', 'この操作は利用できません。');
          if (method === 'PUT') {
            permit('write', 'service', row.id, row.holder_id);
            const saved = services.write(row, await inputBody());
            auditLog.write(subject.id, 'service.changed', 'resource', row.id, {});
            return send(200, { resource: shown(saved) });
          }
          if (method === 'PATCH') {
            const input = await inputBody();
            if (Object.keys(input).some(key => !['name', 'auth_schemes'].includes(key)) || !Object.keys(input).length) fail(400, 'invalid_fields', '変更する項目を確認してください。');
            if (input.name !== undefined) permit('rename', 'service', row.id, row.holder_id);
            if (input.auth_schemes !== undefined) permit('write', 'service', row.id, row.holder_id);
            const saved = store.transaction(() => {
              let current = services.row(row.id);
              if (input.name !== undefined) current = services.rename(current, input.name);
              if (input.auth_schemes !== undefined) current = services.addSchemes(current, input.auth_schemes);
              return current;
            });
            if (input.auth_schemes !== undefined) auditLog.write(subject.id, 'service.changed', 'resource', row.id, {});
            return send(200, { resource: shown(saved) });
          }
          if (method === 'DELETE') {
            permit('remove', 'service', row.id, row.holder_id);
            await inputBody();
            services.remove(row);
            auditLog.write(subject.id, 'service.removed', 'resource', row.id, {});
            return send(200, { ok: true });
          }
        }
        if (!part && method === 'GET') {
          permit('read', held.kind, held.id, held.holder_id);
          return send(200, { resource: { ...shown(held), ...(held.holder_id === subject.id ? { lines: principals.linesOnto(held.id) } : {}) } });
        }
        // Renaming changes what the holder calls it and nothing else: lines, the audit log and the content stay.
        if (!part && method === 'PATCH') {
          const input = await inputBody();
          permit('rename', held.kind, held.id, held.holder_id);
          if (held.kind === 'object') return send(200, { resource: shown(objects.rename(objects.get(held.id), input.name)) });
          if (secret) return send(200, { resource: shown(secrets.rename(secret, input.name)) });
          return send(200, { resource: shown(credentials.rename(credential, input.name)) });
        }
        // Removing a credential for a service disconnects it: Foundation stops obtaining from it and, when asked,
        // asks the service to revoke it. Removing always succeeds; the revocation's outcome is reported.
        if (!part && method === 'DELETE' && credential) {
          permit('disconnect', 'credential', held.id, held.holder_id);
          const input = await inputBody();
          if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', 'サービス側の許可を取り消すか選んでください。');
          let scheme = null;
          try { scheme = credentials.schemeFor(credential); } catch {}
          if (disconnects.has(credential.id)) fail(409, 'disconnect_in_progress', '接続を解除しています。');
          disconnects.add(credential.id);
          try {
            const previous = credentials.disconnect(held.holder_id, credential.id);
            let revoked = null;
            if (input.revoke && typeof scheme?.revoke === 'function') {
              try { await scheme.revoke(credentials.context(previous).privateState); revoked = true; }
              catch { revoked = false; }
            }
            credentials.remove(previous);
            auditLog.write(subject.id, 'credential.removed', 'credential', credential.id, { service: credential.service, revoked });
            return send(200, { ok: true, service_revoked: revoked });
          } finally { disconnects.delete(credential.id); }
        }
        if (!part && method === 'DELETE') {
          permit('remove', held.kind, held.id, held.holder_id);
          await inputBody();
          if (secret) secrets.remove(secret); else { await objects.remove(objects.get(held.id)); still(); }
          return send(200, { ok: true });
        }
        // The content of a thing: an object's bytes, or a secret's. A credential for a service has nothing to read;
        // what it yields is derived when it is injected.
        if (part === '/content' && method === 'GET') {
          if (credential) fail(405, 'method_not_allowed', 'この接続に読める中身はありません。使うには /v1/injections を使います。');
          permit(secret ? 'content' : 'read', held.kind, held.id, held.holder_id);
          const disposition = `attachment; filename="resource.bin"; filename*=UTF-8''${encodeURIComponent(held.name.split('/').pop()).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16))}`;
          if (secret) {
            const content = secrets.content(secret);
            res.setHeader('etag', secretTag(secret));
            res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': content.length, 'content-disposition': disposition });
            return res.end(content);
          }
          const found = await objects.read(objects.get(held.id));
          still();
          res.writeHead(200, { 'content-type': found.contentType, 'content-length': found.content.length, 'content-disposition': disposition });
          return res.end(found.content);
        }
        if (part === '/content' && method === 'PUT') {
          if (credential) fail(405, 'method_not_allowed', 'この接続の中身は書き換えられません。');
          permit('write', held.kind, held.id, held.holder_id);
          if (secret) {
            limit('secrets', 120);
            const content = await inputBytes(SECRET_MAX);
            if (!content.length) fail(400, 'invalid_values', '入力内容を確認してください。');
            const saved = store.transaction(() => {
              const match = req.headers['if-match'], current = secrets.get(held.id);
              if (!current) fail(404, 'not_found', '見つかりません。');
              if (match !== undefined && match !== secretTag(current)) fail(412, 'secret_changed', 'ほかの操作で変更されています。開き直して確認してください。');
              const saved = secrets.write(current, content);
              res.setHeader('etag', secretTag(saved));
              return saved;
            });
            return send(200, { resource: shown(saved) });
          }
          limit('objects', 60);
          const content = await inputBytes(OBJECT_MAX);
          const saved = await objects.write(objects.get(held.id), content, req.headers['content-type'] || 'application/octet-stream');
          still();
          return send(200, { resource: shown(saved) });
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
      if (path === '/v1/audit-log' && method === 'GET') { permit('list', 'audit_log', undefined, subject.id); return send(200, { entries: auditLog.list(subject.id) }); }
      // The holder's screen, in one answer.
      if (path === '/v1/overview' && method === 'GET') {
        permit('read', 'overview');
        return send(200, { user: { id: subject.id, email: user?.email ?? null }, principal: self, secrets: secrets.list(holderId).map(row => secrets.view(row)), credentials: credentials.list(holderId).map(row => credentials.view(row, { owner: true })),
          apps: [...apps.list(holderId).map(row => apps.view(row, { owner: true })), ...apps.lent(holderId).map(row => apps.view(row)), ...apps.offeredAll()],
          services: [...services.list(holderId).map(row => services.view(row, { owner: true })), ...services.lent(holderId).map(row => services.view(row))],
          catalog: services.catalogView(), principals: principals.owned(holderId), actors: principals.actorsOf(holderId),
          requests: requests.listTo(holderId, 'pending').map(row => viewRequest(row, origin)), functions: FUNCTIONS, settings: settings.get(holderId) ?? null });
      }
      // Everything, in one file, for the holder alone. Lending someone a place to keep things means they can take
      // them away again; without this the promise is words.
      if (path === '/v1/export' && method === 'GET') {
        permit('read', 'export');
        // A secret goes out with its bytes; a credential for a service with what is known of it, since what renews
        // it is Foundation's to keep and would be of no use elsewhere. A described service goes out as its definition.
        const kept = secrets.list(holderId).map(row => ({ ...secrets.view(row), content: secrets.content(row).toString('base64'), encoding: 'base64' }));
        const value = { exported_at: new Date().toISOString(), owner: user?.email ?? null, origin, secrets: kept, credentials: credentials.list(holderId).map(row => credentials.view(row, { owner: true })),
          services: services.list(holderId).map(row => ({ id: row.id, name: row.name, definition: JSON.parse(row.definition) })), principals: principals.owned(holderId) };
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8',
          'content-disposition': `attachment; filename="foundation-${new Date().toISOString().slice(0, 10)}.json"` });
        return res.end(JSON.stringify(value, null, 2));
      }
      // Connecting: a credential for a service, by one of its schemes. OAuth goes to the service's consent screen
      // and comes back at /oauth/callback; a role is made in the service's console and named here; a token is
      // handed over here. The credential it makes is a resource like any other: listed and removed at
      // /v1/resources.
      if (path === '/v1/credentials/confirmation' && ['GET', 'POST', 'DELETE'].includes(method)) {
        permit('connect', 'credential');
        if (!session) fail(401, 'login_required', 'ログインしてください。');
        const state = method === 'GET' ? url.searchParams.get('state') : (await inputBody()).state;
        const flow = flows.peek(session.id, state);
        if (!flow || flow.kind !== 'confirmation') fail(400, 'invalid_state', '接続をやり直してください。');
        progressRequestId = flow.requestId || null;
        if (method === 'DELETE') { flows.drop(session.id, state); return send(200, { ok: true }); }
        const previous = credentials.reconnection(holderId, flow.service, flow.scheme, flow.previous.id);
        if (previous.generation !== flow.previous.generation) fail(409, 'credential_changed', '接続の状態が変わりました。');
        if (flow.requestId) requests.forTo(flow.requestId, holderId, true);
        if (method === 'GET') return send(200, { credential: credentials.view(previous, { owner: true }), changes: flow.changes });
        still();
        const saved = requestActions.connect(flow.requestId, holderId, flow.service, flow.scheme, flow.result, { requestedBy: flow.requestedBy, previous, scopes: flow.scopes ?? null, app: flow.app ?? null });
        flows.drop(session.id, state);
        return send(200, { credential: credentials.view(saved, { owner: true }) });
      }
      if (path === '/v1/credentials' && method === 'POST') {
        permit('connect', 'credential');
        const input = await inputBody();
        limit('connect', 10);
        const request = input.request_id === undefined ? null : requests.forTo(input.request_id, holderId, true);
        progressRequestId = request?.id || null;
        const asked = request ? requests.input(request) : null;
        if (request && request.kind !== 'connect') fail(409, 'approval_only', 'この依頼は接続の依頼ではありません。');
        // The service, the scheme, the scopes and the app are the request's when there is one: what the holder saw is
        // what happens.
        const { ref, definition } = services.get(asked ? asked.service : input.service, holderId);
        const schemeId = asked ? asked.auth_scheme : input.auth_scheme ?? Object.keys(definition.auth_schemes)[0];
        if (request && input.service !== undefined && input.service !== ref) fail(400, 'scope_mismatch', '依頼されたサービスで接続してください。');
        const scheme = services.scheme(ref, schemeId);
        if (request) requests.record(request.id, 'connect_started', { service: ref });
        // Who asked for it, as they were called then. One started from the page was asked by no one.
        const requestedBy = request ? principals.get(request.from_id)?.name ?? '' : subject.id === holderId ? '' : self.name;
        const target = asked ? asked.credential_id : input.credential_id;
        if (request && input.credential_id !== undefined && input.credential_id !== target) fail(409, 'credential_changed', '依頼された接続を選んでください。');
        const previous = target === undefined ? undefined : credentials.reconnection(holderId, ref, schemeId, target);
        if (!session) fail(401, 'login_required', 'ログインしてください。');
        const previousState = previous ? credentials.state(previous) : null;
        const scopes = requestedScopes(scheme, asked ? asked.scopes ?? [] : scopeList(input.scopes), previousState);
        // Reconnecting keeps the app the credential was made through unless another is named.
        const named = asked ? asked.app : appReference(input.app);
        if (named !== undefined && !takesApps(scheme)) fail(400, 'app_unsupported', 'この接続方法はアプリを通しません。');
        const appId = takesApps(scheme) ? named ?? previous?.app_id ?? FOUNDATION_APP : null;
        if (appId && appId !== FOUNDATION_APP) permit('use', 'app', appId, apps.at(appId).holder_id);
        const active = schemeId === 'oauth' ? apps.scheme(ref, appId) : scheme;
        still();
        const flow = { service: ref, requestedBy, requestId: request?.id, previous: previous ? { id: previous.id, generation: previous.generation } : null, scopes, app: appId };
        // A role is made by the holder in the service's own console, then named here; what Foundation must remember
        // meanwhile (the external ID it chose) travels in the flow, and the flow lasts until the answer is right.
        if (schemeId === 'role') {
          const started = await active.authorization.begin({ origin }, credentials.context(previous));
          still();
          const state = flows.begin(session.id, { ...flow, kind: 'role', memo: started.memo ?? null });
          return send(200, { url: started.url, state, complete: { fields: started.fields ?? [] } });
        }
        const verifier = randomBytes(32).toString('base64url');
        const redirectUri = origin + '/oauth/callback';
        const state = flows.begin(session.id, { ...flow, verifier, redirectUri });
        return send(200, { url: await active.authorization.begin({ state, verifier, redirectUri, scopes }, credentials.context(previous)) });
      }
      if (path === '/v1/credentials/complete' && method === 'POST') {
        permit('connect', 'credential');
        const input = await inputBody();
        if (!session) fail(401, 'login_required', 'ログインしてください。');
        limit('connect', 10);
        const flow = flows.peek(session.id, input.state);
        if (!flow || flow.kind !== 'role') fail(400, 'invalid_state', '接続をやり直してください。');
        const scheme = services.scheme(flow.service, 'role');
        const previous = flow.previous ? credentials.forService(holderId, flow.previous.id) : undefined;
        if (previous && previous.generation !== flow.previous.generation) fail(409, 'credential_changed', '接続の状態が変わりました。');
        if (flow.requestId) { requests.forTo(flow.requestId, holderId, true); progressRequestId = flow.requestId; }
        const fields = input.fields && typeof input.fields === 'object' && !Array.isArray(input.fields) ? input.fields : {};
        const saved = await verifyConnection(req, session,
          () => scheme.authorization.complete({ fields, memo: flow.memo }, credentials.context(previous)),
          result => requestActions.connect(flow.requestId, holderId, flow.service, 'role', result, { requestedBy: flow.requestedBy, previous }));
        flows.drop(session.id, input.state);
        return send(200, { credential: credentials.view(saved, { owner: true }) });
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
      // Injecting derives what each credential yields now: a secret its bytes, one for a service what its scheme
      // obtains. This is the one place a credential reaches a service.
      if (path === '/v1/injections' && method === 'POST') {
        permit('create', 'injection');
        const input = await inputBody();
        limit('issue', 30);
        const names = Array.isArray(input.names) ? input.names : [];
        const { injection, expires_at } = await inputs.inject(holderId, names);
        still();
        // Handed into a lent machine: what it prints is cleaned of these.
        if (subject.via.environment) environments.reveal(subject.via.environment, [...Object.values(injection.environment), ...injection.files.map(file => Buffer.from(file.content, 'base64').toString('utf8'))]);
        auditLog.write(subject.id, 'injection', 'principal', holderId, { names: names.map(item => typeof item === 'string' ? item : item?.name).filter(Boolean) });
        return send(200, { injection, expires_at, expires_in: expires_at === null ? null : Math.max(0, Math.floor((expires_at - Date.now()) / 1000)) });
      }
      if (path === '/v1/functions' && method === 'GET') { permit('list', 'function'); return send(200, { functions: FUNCTIONS }); }
      if (path === '/v1/functions/http.request' && method === 'POST') {
        permit('invoke', 'function', 'http.request');
        const input = await inputBody(FETCH_BODY_MAX * 2);
        limit('fetch', 30);
        const result = await functions.request({ holderId, still }, input, [url.hostname, ...(external ? [external.hostname] : [])]);
        auditLog.write(subject.id, 'function', 'principal', holderId, { function: 'http.request', target: String(input.url).slice(0, 200), status: result.response?.status ?? null });
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
          guide: () => guide(services.catalogView()),
          // The tool names whom the caller acts for when it is exactly one and the call did not say.
          call: async ({ method: verb, path: target, body: payload, body_encoding }) => {
            const named = actsFor.length === 1 && !/[?&]as=/.test(target) ? target + (target.includes('?') ? '&' : '?') + 'as=' + encodeURIComponent(actsFor[0]) : target;
            const response = await fetch(`http://127.0.0.1:${port}${named}`, {
              method: verb, redirect: 'error', signal: AbortSignal.timeout(20_000),
              headers: { authorization, ...(payload === undefined ? {} : { 'content-type': body_encoding === 'json' ? 'application/json' : 'application/octet-stream' }) },
              ...(payload === undefined ? {} : { body: body_encoding === 'base64' ? Buffer.from(payload, 'base64') : body_encoding === 'text' ? payload : JSON.stringify(payload) }),
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
      if (!res.headersSent) send(error instanceof HttpError ? error.status : 500, { error: { code: error instanceof HttpError ? error.code : 'internal_error', message: error instanceof HttpError ? error.message : '処理を完了できませんでした。',
        ...(error instanceof HttpError && error.extra ? error.extra : {}) } });
      else res.end();
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  return {
    server, store, resources, services, secrets, credentials, inputs, apps, objects, environments, principals, sessions, flows, requests, requestActions, settings, auditLog,
    async close() {
      clearInterval(timer);
      if (server.listening) await new Promise((resolve) => { server.close(resolve); server.closeIdleConnections(); });
      store.close();
    },
  };
}
