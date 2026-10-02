import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { digest } from './crypto.mjs';
import { Principals } from './principals.mjs';
import { Sessions, OAuthFlows, TOKEN_TTL } from './sessions.mjs';
import { WebauthnCredentials } from './webauthn.mjs';
import { Payments, Stripe } from './payments.mjs';
import { Emails } from './emails.mjs';
import { Challenges, randomSecret } from './challenges.mjs';
import { RequestActions } from './request-actions.mjs';
import { requestView, INTERVAL } from './http-requests.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { Requests } from './requests.mjs';
import { Settings } from './settings.mjs';
import { AuditLog } from './audit-log.mjs';
import { scopeList, requestedScopes } from './scopes.mjs';
import { appReference, requestDetails } from './request-input.mjs';
import { Apps, FOUNDATION_APP, takesApps } from './apps.mjs';
import { Connections } from './connections.mjs';
import { Secrets, SECRET_MAX, SECRET_COUNT_MAX, SECRET_TOTAL_MAX } from './secrets.mjs';
import { Keys, bytes as keyBytes } from './keys.mjs';
import { principalName } from './names.mjs';
import { Merge } from './merge.mjs';
import { Inputs } from './inputs.mjs';
import { Services } from './services.mjs';
import { Objects, OBJECT_MAX } from './objects.mjs';
import { Environments } from './environments.mjs';
import { Resources, KINDS } from './resources.mjs';
import { respond } from './mcp.mjs';
import { FETCH_BODY_MAX } from './fetch.mjs';
import { FUNCTIONS, Functions } from './functions.mjs';
import { matchRoute, openapi, validateBody } from './api.mjs';
import { serveDocs } from './api-docs.mjs';
import { Authorization, reaches } from './authorization.mjs';
import { pages, brand, languagePicker, pageTitle, workspaceView, pendingView } from '../web/workspace-view.js';
import { createI18n, isLocale, resolveLocale } from '../web/i18n.js';
import { IMPORT_MAP, escapeHtml, localizeErrorMessage } from './web-i18n.mjs';

const require = createRequire(import.meta.url);
const VERSION = require('../package.json').version;
const I18NEXT = require.resolve('i18next/package.json').replace(/package\.json$/, 'dist/esm/i18next.js');
const IMPORT_MAP_HASH = Buffer.from(digest(IMPORT_MAP), 'hex').toString('base64');

const PUBLIC = new URL('../web/', import.meta.url);
const PAGES = Object.keys(pages);
const STATIC = new Map(PAGES.map(page => [page, ['index.html', 'text/html; charset=utf-8']]));
STATIC.set('/signin/confirm', ['index.html', 'text/html; charset=utf-8']);
STATIC.set('/app.js', ['app.js', 'text/javascript; charset=utf-8']);
for (const filename of ['i18n.js', 'service-i18n.js', 'locales/shared.js', 'locales/client.js', 'locales/server.js', 'locales/services.js']) {
  STATIC.set('/' + filename, [filename, 'text/javascript; charset=utf-8']);
}
STATIC.set('/vendor/i18next.js', [I18NEXT, 'text/javascript; charset=utf-8']);
STATIC.set('/request-view.js', ['request-view.js', 'text/javascript; charset=utf-8']);
STATIC.set('/workspace-view.js', ['workspace-view.js', 'text/javascript; charset=utf-8']);
STATIC.set('/sealing.js', ['sealing.js', 'text/javascript; charset=utf-8']);
STATIC.set('/styles.css', ['styles.css', 'text/css; charset=utf-8']);
STATIC.set('/service-logos.svg', ['service-logos.svg', 'image/svg+xml']);
// The logo as images, for browsers that do not take the page's SVG icon (Safari asks for these by name).
STATIC.set('/favicon.ico', ['favicon.png', 'image/png']);
STATIC.set('/favicon.png', ['favicon.png', 'image/png']);
STATIC.set('/apple-touch-icon.png', ['apple-touch-icon.png', 'image/png']);
const MAX_BODY = 12_000;
const SESSION_AGE = 14 * 86400;
const SIGNIN_CONFIRM = '/signin/confirm';
// An emailed sign-in link lasts a quarter of an hour, and another is sent no sooner than a minute after the last.
const SIGNIN_TTL = 15 * 60_000, RESEND_WAIT = 60_000;
const LINK_TTL = 10 * 60_000, LINKED_TTL = 30 * 60_000;
const REQUEST_PAGE = /^\/requests\/[A-Za-z0-9_-]{43}$/;
const PRINCIPAL_ID = /^[A-Za-z0-9-]{1,64}$/;
// A revision of the encrypted record, never a fingerprint of the plaintext value.
const secretTag = row => '"' + digest(JSON.stringify([row.id, row.name, row.size, row.updated_at])) + '"';
// A secret's bytes as the client sealed them (content: iv, tag and ciphertext, so at least 29 bytes for one byte
// kept), or as they are (plain), for Foundation's principal to seal where it is the owner's agent.
function sealedInput(input) {
  const plain = input?.plain !== undefined, content = keyBytes(plain ? input.plain : input?.content);
  if (!content || (!plain && content.length < 29)) fail(400, 'invalid_values', '入力内容を確認してください。');
  if (content.length > SECRET_MAX) fail(413, 'too_large', '1件あたり1MBまでです。');
  return { content, plain };
}

function returnPath(value = '/') {
  const invalid = () => fail(400, 'invalid_return', 'リンクを開き直してください。');
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || /[\\\s]/.test(value)) invalid();
  const url = new URL(value, 'https://foundation.invalid');
  if (url.origin !== 'https://foundation.invalid' || (!PAGES.includes(url.pathname) && !REQUEST_PAGE.test(url.pathname))) invalid();
  if ([...url.searchParams.keys()].some(key => url.pathname !== '/objects' || key !== 'prefix')) invalid();
  return url.pathname + url.search + url.hash;
}

// What a sign-in link says, in the email that carries it.
function signinMessage(link) {
  const href = link.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  return { subject: 'Foundationへのサインイン', text: `Foundationにサインイン\n${link}\n\nリンクは15分間有効です。心当たりがない場合は、このメールを無視してください。`,
    html: `<p><a href="${href}">Foundationにサインイン</a></p>\n<p>リンクは15分間有効です。心当たりがない場合は、このメールを無視してください。</p>` };
}

function signinEmail(value) {
  if (typeof value !== 'string' || value.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(value.trim())) fail(400, 'invalid_email', 'メールアドレスを確認してください。');
  return value.trim().toLowerCase();
}

async function readBody(req, max = MAX_BODY) {
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

export function createApp({ database = ':memory:', encryptionKey, mailer, services: catalog, serviceFetcher, space: spaceBackend = null, publicOrigin, challengeSecret, stripe = new Stripe(), trustedProxies = [], outbound = {}, runner = null, compute = {}, requestInterval = INTERVAL }) {
  if (!mailer || !Array.isArray(catalog)) throw new Error('A mailer and services are required');
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
  const resources = new Resources(store);
  const principals = new Principals(store), sessions = new Sessions(store), flows = new OAuthFlows(store), emails = new Emails(store);
  const challenges = new Challenges(store, challengeSecret ? { secret: challengeSecret } : {}), webauthn = new WebauthnCredentials(store, challenges);
  const authorization = new Authorization(principals, resources);
  const services = new Services(store, resources, catalog, { authorization, ...(serviceFetcher ? { fetcher: serviceFetcher } : {}) });
  const apps = new Apps(store, resources, services), connections = new Connections(store, resources, services, apps);
  const keys = new Keys(store), secrets = new Secrets(store, resources, keys);
  // Opening a secret to use it in Foundation's name: only for a owner that made Foundation's principal its agent.
  const agentFor = ownerId => { if (!authorization.can(keys.agentId, 'inject', 'principal', { id: ownerId })) fail(403, 'foundation_not_agent', 'Foundation はこの持ち主の代わりに動く許可がありません。'); };
  const opener = row => { agentFor(row.owner_id); return secrets.open(row); };
  const inputs = new Inputs(secrets, connections, opener);
  const payments = new Payments(store, stripe);
  const objects = new Objects(spaceBackend, resources, store, payments);
  const requests = new Requests(store), settings = new Settings(store, principals), auditLog = new AuditLog(store);
  const environments = new Environments({ store, resources, principals, payments, runner, limits: compute });
  const functions = new Functions({ secrets, inputs, outbound });
  const ownHosts = () => [...(external ? [external.hostname] : []), '127.0.0.1', 'localhost'];
  const viewRequest = (row, origin, options) => requestView({ requests, services, principals, settings, connections, apps, resources, keys, authorization }, row, origin, { interval: requestInterval, ...options });
  const requestActions = new RequestActions({ store, requests, secrets, connections, services, apps, principals, authorization, auditLog,
    changed: row => { if (row.to_id) void settings.notify(row.to_id, 'request.' + row.status, { request: viewRequest(row, external?.origin || '') }, { ...outbound, ownHosts: ownHosts() }); } });
  const merge = new Merge({ store, db: store.db, resources, secrets, connections, apps, services, objects, environments, principals, webauthn, keys, requests, challenges, auditLog });
  const limits = new Map(), disconnects = new Set();
  const timer = setInterval(() => {
    store.sweep();
    principals.sweep();
    void environments.sweep().catch(error => console.error(new Date().toISOString(), 'environment sweep', error));
    // What payers store, once a day, and whatever is recorded and not yet sent to Stripe.
    if (objects.enabled) for (const payer of payments.payers()) payments.stored(payer, objects.usage(payer).bytes, Date.now());
    void payments.send()?.catch(error => console.error(new Date().toISOString(), 'meter events', error));
    for (const [key, value] of limits) if (value.until <= Date.now()) limits.delete(key);
  }, 60_000).unref();
  // When each asker last looked at each of its requests, to answer slow_down.
  const polled = new Map();
  function rateLimit(key, max, window = 60_000) {
    let value = limits.get(key);
    if (!value || value.until <= Date.now()) value = { count: 0, until: Date.now() + window };
    if (++value.count > max) fail(429, 'rate_limit', '操作が続いています。しばらく待ってからお試しください。');
    if (limits.size >= 2000 && !limits.has(key)) limits.delete(limits.keys().next().value);
    limits.set(key, value);
  }
  const readCookie = (req, name) => (req.headers.cookie ?? '').split(';').map((part) => part.trim()).find((part) => part.startsWith(name + '='))?.slice(name.length + 1);
  const cookieToken = (req) => readCookie(req, 'fdn_session');
  function signedIn(req) {
    const session = sessions.get(cookieToken(req));
    if (!session) fail(401, 'signin_required', 'サインインしてください。');
    return session;
  }
  const bearer = req => req.headers.authorization?.match(/^Bearer (\S+)$/)?.[1];
  function requireOrigin(req, origin) {
    if (req.headers.origin !== origin) fail(403, 'origin_denied', 'この操作はFoundationの画面から行ってください。');
  }
  // Authorization may take time. Check the browser again before committing any result.
  async function verifyConnection(req, session, operation, commit) {
    const result = await operation();
    if (req.aborted || req.socket.destroyed || signedIn(req).id !== session.id) fail(401, 'signin_required', 'サインインしてください。');
    return commit(result);
  }
  const notApproved = () => fail(401, 'not_approved', 'このキーはまだ誰の代わりにも動けないか、失効しています。foundation connect（POST /v1/requests で relation actor を依頼）で承認を依頼し、承認後にお試しください。');
  const server = createServer(async (req, res) => {
    const locale = resolveLocale({ cookie: req.headers.cookie, acceptLanguage: req.headers['accept-language'] });
    const t = createI18n(locale).t;
    // JSON messages change only when the Web client explicitly opts in. Cookies and
    // Accept-Language alone never change the public API's historical message contract.
    const webLocale = req.headers['x-foundation-locale'];
    const webT = isLocale(webLocale) ? (webLocale === locale ? t : createI18n(webLocale).t) : null;
    const send = (status, value) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); };
    const redirect = (path) => { res.writeHead(303, { location: path }); res.end(); };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (external) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' 'sha256-${IMPORT_MAP_HASH}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`);
    let progressRequestId = null;
    try {
      const port = server.address()?.port;
      const allowedHosts = [`127.0.0.1:${port}`, `localhost:${port}`, ...(external ? [external.host] : [])];
      if (!allowedHosts.includes(req.headers.host)) fail(403, 'host_denied', 'このホストからは利用できません。');
      const origin = external?.origin || `http://${req.headers.host}`;
      const url = new URL(req.url, origin), path = url.pathname, method = req.method;
      const route = matchRoute(path, method), at = route?.name;
      const body = async (request, max) => {
        const input = await readBody(request, max);
        validateBody(route, input, url.searchParams.get('kind'));
        return input;
      };
      if (path === '/openapi.json' && ['GET', 'HEAD'].includes(method)) {
        res.setHeader('Link', '</docs>; rel="service-doc"; type="text/html"');
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
        return res.end(method === 'HEAD' ? undefined : JSON.stringify(openapi(origin, VERSION)));
      }
      if (await serveDocs(req, res, path)) return;
      const setNamedCookie = (name, value, age, cookiePath = '/') => res.appendHeader('Set-Cookie', `${name}=${value}; HttpOnly; SameSite=${cookiePath === '/' ? 'Lax' : 'Strict'}; Path=${cookiePath}; Max-Age=${age}${external ? '; Secure' : ''}`);
      const setCookie = (value, age) => setNamedCookie('fdn_session', value, age);
      const signinHandle = readCookie(req, 'fdn_signin');
      if ((STATIC.has(path) || REQUEST_PAGE.test(path)) && method === 'GET') {
        if (REQUEST_PAGE.test(path)) requests.record(path.slice('/requests/'.length), 'page_opened');
        const [filename, type] = STATIC.get(STATIC.has(path) ? path : '/');
        let content = await readFile(filename === I18NEXT ? I18NEXT : fileURLToPath(new URL(filename, PUBLIC)));
        if (filename === 'index.html') {
          const ownerFrame = PAGES.includes(path) && Boolean(sessions.get(cookieToken(req)));
          const frame = ownerFrame ? workspaceView(path, { pending: true, t, locale })
            : path !== '/' ? pendingView(path, { t, locale })
              : `<div class="workspace signin-shell"><header class="topbar">${brand(t)}${languagePicker(t, locale)}</header><main class="signin-main"><h1>Foundation</h1><footer id="public-info" class="public-info"><a href="/docs" data-i18n="server.docs.api">${escapeHtml(t('server.docs.api'))}</a></footer></main></div>`;
          const slots = { locale, title: escapeHtml(pageTitle(path, t)), importmap: IMPORT_MAP,
            app: frame, noscript: escapeHtml(t('server.noscript.signin')) };
          content = content.toString().replace(/\{\{foundation-(locale|title|importmap|app|noscript)\}\}/g, (_, key) => slots[key]);
          res.setHeader('Content-Language', locale);
          res.setHeader('Vary', 'Accept-Language, Cookie');
          res.setHeader('Cache-Control', path === SIGNIN_CONFIRM ? 'no-store' : 'private, no-store');
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
      if (at === 'health' && method === 'GET') return send(200, { status: 'ok' });
      if (!route && path !== '/mcp') fail(404, 'not_found', '指定された操作が見つかりません。');
      // What Stripe says of a subscription, signed with this endpoint's secret: it is believed for that, not for who sent it.
      if (at === 'paymentEvents' && method === 'POST') {
        if (!stripe.enabled) fail(404, 'not_found', '指定された操作が見つかりません。');
        const chunks = [];
        let length = 0;
        for await (const chunk of req) { length += chunk.length; if (length > 512_000) fail(413, 'body_too_large', '送信内容が大きすぎます。'); chunks.push(chunk); }
        payments.changed(stripe.verify(Buffer.concat(chunks).toString('utf8'), req.headers['stripe-signature']));
        return send(200, { received: true });
      }
      // Every OAuth consent comes back here: the state names the flow, and the flow the service and the app.
      if (at === 'oauthCallback' && method === 'GET') {
        let destination = '/services', flowService = null;
        const location = code => destination + '?result=' + code + (destination === '/services' && flowService ? '&service=' + encodeURIComponent(flowService) : '');
        try {
          const session = signedIn(req), owner = session.principal_id;
          if (url.searchParams.getAll('state').length !== 1 || url.searchParams.getAll('code').length > 1) fail(400, 'invalid_state', '接続をやり直してください。');
          const flow = flows.take(session.id, url.searchParams.get('state'));
          if (!flow || flow.kind) fail(400, 'invalid_state', '接続をやり直してください。');
          flowService = flow.service;
          // The same app that asked for consent exchanges the code: Foundation's, or one someone holds.
          const active = apps.scheme(flow.service, flow.app);
          if (flow.requestId) {
            destination = '/requests/' + flow.requestId;
            requests.forTo(flow.requestId, owner, true);
            progressRequestId = flow.requestId;
          }
          if (url.searchParams.has('error')) fail(400, 'authorization_denied', '接続先での認証は許可されませんでした。');
          const code = url.searchParams.get('code');
          if (!code || code.length > 8192) fail(400, 'invalid_state', '接続をやり直してください。');
          let previous;
          if (flow.previous) {
            previous = connections.forService(owner, flow.previous.id);
            if (previous.generation !== flow.previous.generation || previous.status === 'disconnecting') fail(409, 'connection_changed', '接続の状態が変わりました。');
          }
          if (flow.requestId) requests.forTo(flow.requestId, owner, true);
          const previousContext = connections.context(previous);
          const completion = await verifyConnection(req, session,
            () => active.authorization.complete({ code, verifier: flow.verifier, redirectUri: flow.redirectUri }, previousContext),
            result => {
              const changes = previous ? active.authorization.changes?.(result, previousContext) : undefined;
              if (changes?.length) {
                if (flow.requestId) requests.forTo(flow.requestId, owner, true);
                const current = connections.reconnection(owner, flow.service, 'oauth', previous.id);
                if (current.generation !== previous.generation) fail(409, 'connection_changed', '接続の状態が変わりました。');
                connections.nextState(result);
                const { credentials: produced, ...kept } = result;
                const state = flows.begin(session.id, { kind: 'confirmation', service: flow.service, scheme: 'oauth', requestId: flow.requestId,
                  requestedBy: flow.requestedBy, previous: flow.previous, result: kept, changes, scopes: flow.scopes ?? null, app: flow.app ?? null });
                if (flow.requestId) requests.record(flow.requestId, 'connect_review', { service: flow.service });
                return { confirmation: state };
              }
              requestActions.connect(flow.requestId, owner, flow.service, 'oauth', result, { requestedBy: flow.requestedBy, previous, scopes: flow.scopes ?? null, app: flow.app ?? null });
            });
          if (completion?.confirmation) return redirect(location('review') + '&state=' + completion.confirmation);
          return redirect(location('connected'));
        } catch (error) {
          if (progressRequestId && error instanceof HttpError) requests.record(progressRequestId, 'connect_failed', { service: flowService, code: error.code, message: error.message });
          const codes = { authorization_denied: 'denied', invalid_state: 'expired', signin_required: 'expired', account_changed: 'wrong_account', scope_mismatch: 'scope', refresh_missing: 'retry', connection_changed: 'changed', service_response: 'failed' };
          return redirect(location(codes[error.code] || 'failed'));
        }
      }
      if (req.headers['sec-fetch-site'] === 'cross-site') fail(403, 'cross_site_denied', '外部サイトからの操作は許可されていません。');
      const requestRoute = route?.group === 'requests' ? route.params : null;
      // One tree, one question. A bearer token, when sent, says which principal speaks. Without one the browser
      // speaks, through its signin session or the short connection a single-use link left, and every change it
      // asks for must come from Foundation's own pages. Cookies are never read beside a token.
      const token = bearer(req), browser = req.headers.authorization === undefined;
      if (!browser && !token) fail(401, 'invalid_token', 'Bearer形式のキーを指定してください。');
      // Becoming a principal needs no connection and no signin: the request carries nothing to protect.
      const becoming = at === 'principals' && method === 'POST' && browser && !cookieToken(req);
      // Proving oneself by WebAuthn carries nothing to protect either; a browser's session is still asked its origin there.
      const proving = ['webauthnSigninOptions', 'webauthnSignin', 'principalOptions'].includes(at);
      if (browser && !['GET', 'HEAD'].includes(method) && !becoming && !proving) requireOrigin(req, origin);
      if (!browser && req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
      // Signing in by email: a single-use link is sent to the address, and opening it proves receiving there. The
      // browser that asked keeps only a handle, to show what it is waiting for; the link works in any browser.
      const waitingFor = handle => {
        const row = challenges.waiting(handle);
        return row ? { email: row.subject, expires_at: row.expires_at, resend_at: row.created_at + RESEND_WAIT } : null;
      };
      if (at === 'signin' && method === 'GET') return send(200, { available: mailer.enabled, method: 'email_link', pending: waitingFor(signinHandle) });
      if (at === 'signin' && method === 'POST') {
        const input = await body(req);
        const email = signinEmail(input?.email);
        const destination = returnPath(input.return_to);
        rateLimit('link-send:' + clientAddress(req), 12, 600_000);
        const last = challenges.latest('email', email);
        if (last && last.created_at + RESEND_WAIT > Date.now()) fail(429, 'link_cooldown', '送信から1分ほど待って、もう一度お試しください。');
        if (!mailer.enabled) fail(503, 'email_unavailable', '現在サインインを利用できません。');
        const handle = randomSecret();
        const secret = challenges.issue('email', email, { handle, ttl: SIGNIN_TTL });
        const link = origin + SIGNIN_CONFIRM + (destination === '/' ? '' : '?' + new URLSearchParams({ return_to: destination })) + '#' + new URLSearchParams({ token: secret, email });
        try { await mailer.send({ to: email, ...signinMessage(link) }); }
        catch (error) { challenges.take('email', secret); throw error; }
        challenges.forget(signinHandle);
        setNamedCookie('fdn_signin', handle, SIGNIN_TTL / 1000);
        return send(202, { pending: waitingFor(handle) });
      }
      if (at === 'verifySignin' && method === 'POST') {
        requireOrigin(req, origin);
        rateLimit('signin:' + clientAddress(req), 30, 600_000);
        const input = await body(req), email = signinEmail(input?.email), destination = returnPath(input.return_to);
        if (typeof input.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(input.token)) fail(400, 'invalid_link', 'リンクが無効です。最新のメールのリンクを開いてください。');
        // Giving the link back spends it. Merely opening the confirmation page does not; the page asks first.
        const proof = challenges.take('email', input.token);
        if (!proof || proof.subject !== email || req.aborted || req.socket.destroyed) fail(401, 'invalid_link', 'リンクが無効か、有効期限が切れています。最新のメールのリンクを開いてください。');
        // An address proven for the first time is a new principal's; one proven before is its principal's again.
        const principalId = store.transaction(() => {
          const known = emails.principalOf(email);
          if (known) return known;
          const made = principals.ensure(randomUUID());
          emails.add(made.id, email);
          return made.id;
        });
        const next = sessions.create(principalId, { proof: 'email', ref: email });
        sessions.remove(cookieToken(req));
        setCookie(next, SESSION_AGE);
        challenges.forget(signinHandle);
        setNamedCookie('fdn_signin', '', 0);
        return send(200, { ok: true, return_to: destination });
      }
      // Signing in by WebAuthn, from anywhere: a browser gets its session as a cookie, a program as an hour's token.
      // Options for a credential that, once registered, makes its principal.
      if (at === 'principalOptions' && method === 'POST') {
        const input = await body(req);
        rateLimit('principal-create:' + clientAddress(req), 12, 600_000);
        // The passkey's label where it is kept: the name given, or one drawn here (names.mjs), which the client then
        // gives the principal it makes, so the device and Foundation call it the same thing.
        return send(200, { options: await webauthn.registration(randomUUID(), { origin, userName: input?.name === undefined ? principalName() : nameValue(input.name), creating: true }) });
      }
      if (at === 'webauthnSigninOptions' && method === 'POST') {
        rateLimit('webauthn-options:' + clientAddress(req), 60, 600_000);
        return send(200, { options: await webauthn.authentication({ origin }) });
      }
      if (at === 'webauthnSignin' && method === 'POST') {
        rateLimit('signin:' + clientAddress(req), 30, 600_000);
        const input = await body(req), asToken = input?.session === 'token';
        if (!asToken) requireOrigin(req, origin);
        const destination = asToken ? '/' : returnPath(input?.return_to);
        const proven = await webauthn.authenticate(input?.credential, { origin });
        if (asToken) {
          const token = sessions.create(proven.principalId, { proof: 'webauthn', ref: proven.credentialId }, { ttl: TOKEN_TTL });
          return send(200, { token, expires_at: Date.now() + TOKEN_TTL });
        }
        const next = sessions.create(proven.principalId, { proof: 'webauthn', ref: proven.credentialId });
        sessions.remove(cookieToken(req));
        setCookie(next, SESSION_AGE);
        return send(200, { ok: true, return_to: destination });
      }
      if (at === 'signin' && method === 'DELETE') {
        challenges.forget(signinHandle); setNamedCookie('fdn_signin', '', 0);
        return send(200, { ok: true });
      }
      if (at === 'session' && method === 'DELETE') {
        challenges.forget(signinHandle);
        sessions.remove(cookieToken(req));
        setCookie('', 0);
        setNamedCookie('fdn_signin', '', 0);
        return send(200, { ok: true });
      }
      // The services Foundation knows, and how it comes to hold a connection for each. Public: a key not yet
      // approved reads it too.
      if (at === 'catalog' && method === 'GET') return send(200, { services: services.catalogView() });
      // Where the page sends someone back after a request: the handler's page for it. Public, and says nothing else.
      if (at === 'return' && method === 'GET') {
        const back = settings.backFor(requests.get(route.params.requestId));
        if (!back) fail(404, 'not_found', '戻り先はありません。');
        return send(200, { back });
      }
      // Spending a single-use link: the one in the URL is gone, and a short link for the browser takes its place,
      // sent as a cookie that reaches that one request's routes and nothing else.
      if (at === 'exchangeLink' && method === 'POST') {
        const input = await body(req);
        rateLimit('link:' + clientAddress(req), 20, 600_000);
        const made = principals.exchangeLink(input.link, input.request_id, LINKED_TTL);
        requests.record(made.request_id, 'link_opened');
        setNamedCookie('fdn_link', made.token, LINKED_TTL / 1000, '/v1/requests/' + made.request_id);
        return send(200, { ok: true });
      }
      // Who is asking, and what they came in by (via). A token is an access key; a browser is the person who logged in,
      // or the one a request link handed to a single request.
      let subject, session = null;
      const known = browser ? undefined : principals.authenticateKey(token);
      // Anyone may become a principal: one row, with a WebAuthn credential made for it - and so a session at once, a
      // cookie for a browser or an hour's token for a program - or else one key, issued here and shown once. It reaches
      // nothing of anyone else's until someone draws it a line; what it may do never comes from the making.
      if (becoming) {
        const input = await body(req);
        rateLimit('principal-create:' + clientAddress(req), 12, 600_000);
        if (input?.webauthn_credential !== undefined) {
          const asToken = input.session === 'token', given = input.webauthn_credential, name = input.name === undefined ? '' : nameValue(input.name);
          if (!asToken) requireOrigin(req, origin);
          const destination = asToken ? '/' : returnPath(input.return_to);
          const made = await webauthn.register(given?.credential, { origin, name: given?.name, make: id => {
            principals.ensure(id, name);
            if (input.public_key !== undefined) keys.publish(id, input.public_key);
          } });
          if (given.wrap !== undefined) keys.keepWrap(made.credential.id, given.wrap);
          auditLog.write(made.principalId, 'principal.created', 'principal', made.principalId, { webauthn_credential: made.credential.id });
          const proof = { proof: 'webauthn', ref: made.credential.id }, principal = principals.get(made.principalId);
          const answer = { principal, webauthn_credential: webauthn.view(made.credential), backed_up: made.backedUp };
          if (asToken) return send(201, { ...answer, token: sessions.create(made.principalId, proof, { ttl: TOKEN_TTL }), expires_at: Date.now() + TOKEN_TTL });
          setCookie(sessions.create(made.principalId, proof), SESSION_AGE);
          return send(201, { ...answer, return_to: destination });
        }
        const made = store.transaction(() => {
          const principal = principals.ensure(randomUUID(), nameValue(input.name, '相手'));
          return { principal, issued: principals.issueKey(principal.id) };
        });
        return send(201, { principal: made.principal, token: made.issued.token, key: { id: made.issued.id } });
      }
      // A bearer token is an access key, or a session a program was given for proving itself by WebAuthn.
      const tokenSession = !browser && !known ? sessions.get(token) : undefined;
      if (!browser && !known && !tokenSession) notApproved();
      if (tokenSession) subject = { id: tokenSession.principal_id, via: { kind: 'session', id: tokenSession.id } };
      else if (!browser) subject = { id: known.principal.id, via: { kind: 'key', id: known.key.id, ...(known.key.environment ? { environment: known.key.environment } : {}) } };
      else {
        const linked = requestRoute?.requestId ? principals.authenticateLink(readCookie(req, 'fdn_link'), requestRoute.requestId) : undefined;
        if (linked) subject = { id: linked.principal.id, via: { kind: 'link', ...linked.link } };
        else {
          session = signedIn(req);
          subject = { id: session.principal_id, via: { kind: 'session', id: session.id } };
        }
      }
      const self = principals.get(subject.id);
      // In whose name. A principal acts as itself unless it names whom it acts for (?as=<id>); whether it may is
      // the same question as any other, answered from the lines.
      const actsFor = principals.actsFor(subject.id);
      const asked = url.searchParams.get('as');
      const ownerId = asked ? principalId(asked) : subject.id;
      let asked_ = null;
      const permit = (name, type, id, owner = type === 'principal' ? id : ownerId) => {
        asked_ = { subject, action: { name }, resource: { type, ...(id === undefined ? {} : { id }), owner } };
        if (authorization.allowed(asked_).decision) return;
        if (subject.via.kind === 'link') fail(401, 'signin_required', 'サインインしてください。');
        if (!browser && owner !== subject.id && !principals.relationsOf(subject.id).length) notApproved();
        fail(403, 'forbidden', 'この操作は許可されていません。');
      };
      // Reading an upload may outlive its authorization. Recheck before committing any change: what the subject came in
      // by, and the same question the route asked before reading.
      const still = () => {
        if (subject.via.kind === 'session') { if (sessions.get(browser ? cookieToken(req) : token)?.id !== subject.via.id) fail(401, 'signin_required', 'サインインしてください。'); }
        else if (subject.via.kind === 'link') { if (!principals.hasLink(subject.id, subject.via.id)) fail(401, 'signin_required', 'このリンクは使えません。元の画面から開き直してください。'); }
        else if (!principals.hasKey(subject.id, subject.via.id)) fail(401, 'not_approved', 'このキーは失効しています。');
        if (asked_ && !authorization.allowed(asked_).decision) fail(401, 'not_approved', 'この相手の代わりには動けません。');
      };
      const inputBody = async max => { const input = await body(req, max); still(); return input; };
      const inputBytes = async max => { const input = await raw(req, max); still(); return input; };
      const limit = (name, max) => rateLimit(name + ':' + subject.id, max);

      // Requests: what one principal asks of another, and what the one asked does about it.
      if (requestRoute) {
        const id = requestRoute.requestId, action = at === 'grant' || at === 'deny' ? at : null;
        if (!id && method === 'POST') {
          const input = await body(req);
          rateLimit('request-create:' + clientAddress(req), 12, 600_000);
          const { type, detail } = requestDetails(input.authorization_details);
          // Whom it asks: the one named; for a relation onto something, whoever holds it; for a relation onto nothing,
          // nobody yet - whoever answers; otherwise the owner this principal acts as.
          const ownerOf = () => detail.object_type === 'principal' ? detail.object_id : resources.at(detail.object_id).owner_id;
          const toId = input.to !== undefined ? principalId(input.to)
            : type === 'relation' ? (detail.object_type === undefined ? null : ownerOf()) : ownerId;
          if (toId !== null && !principals.get(toId)) fail(404, 'not_found', '相手が見つかりません。');
          // Someone nobody has taken on yet may only ask whoever opens the page it hands over; naming a person would let
          // anyone put a request in front of them. Once it is on a line with someone, it is known, and may name.
          if (input.to !== undefined && !principals.relationsOf(subject.id).length) fail(403, 'unknown_requester', 'まだ誰にも承認されていないので、相手を指定した依頼は出せません。相手を指定せずに依頼し、その画面を渡してください。');
          if (type !== 'relation') permit('list', type === 'secret' ? 'secret' : 'connection', undefined, toId);
          const row = requestActions.ask(subject.id, { type, detail, toId, bindingMessage: purposeValue(input.binding_message), steps: input.steps ?? [], validMinutes: input.valid_minutes ?? 30 });
          return send(201, { request: viewRequest(row, origin, { code: true }) });
        }
        if (!id && method === 'GET') {
          const status = url.searchParams.get('status');
          if (status !== null && !['pending', 'granted', 'denied', 'cancelled'].includes(status)) fail(400, 'invalid_status', 'status は pending / granted / denied / cancelled のいずれかです。');
          limit('request-poll', 30);
          const mine = url.searchParams.get('to') === 'me';
          return send(200, { requests: (mine ? requests.listTo(subject.id, status) : requests.list(subject.id, status)).map(row => viewRequest(row, origin)) });
        }
        const row = requests.get(id);
        const asker = row.from_id === subject.id;
        if (!action && method === 'GET') {
          if (asker) {
            // The one asking looks again no more often than interval, as RFC 8628 and CIBA ask of a polling client.
            const key = subject.id + ':' + row.id, last = polled.get(key), now = Date.now();
            polled.set(key, now);
            if (row.status === 'pending' && last !== undefined && now - last < requestInterval * 1000 - 500) fail(429, 'slow_down', `${requestInterval}秒以上あけて確認してください。`);
            return send(200, { request: viewRequest(row, origin, { events: true, code: row.status === 'pending' }) });
          }
          limit('request-poll', 30);
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
        if (action === 'grant' && method === 'POST') {
          const pending = requests.forTo(id, subject.id, true);
          permit('grant', 'request', id, row.to_id ?? subject.id);
          progressRequestId = pending.id;
          if (pending.type === 'secret') {
            const input = await inputBody(SECRET_MAX * requests.detail(pending).fields.length);
            return send(200, { stored: true, ...requestActions.save(id, subject.id, input.entries) });
          }
          if (pending.type === 'relation') {
            const input = await inputBody();
            return send(200, { request: viewRequest(requestActions.grantRelation(id, subject.id, input.user_code), origin) });
          }
          if (pending.type === 'app') {
            if (!session) fail(401, 'signin_required', 'サインインしてください。');
            const input = await inputBody();
            return send(200, { registered: true, ...requestActions.registerApp(id, subject.id, input) });
          }
          fail(409, 'wrong_kind', 'この依頼は、サービスとの接続を済ませると許可されます。');
        }
        if (action === 'deny' && method === 'POST') {
          requests.forTo(id, subject.id, true);
          permit('deny', 'request', id, row.to_id ?? subject.id);
          await inputBody();
          progressRequestId = row.id;
          return send(200, { request: viewRequest(requestActions.deny(id, subject.id), origin) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (subject.via.kind === 'link') fail(401, 'signin_required', 'サインインしてください。');
      // Principals: oneself, and those one owns.
      // A principal's WebAuthn credentials: added by the principal itself, listed by whoever reads it, removed by it or its owner.
      if (at === 'webauthnCredentials' && method === 'GET') {
        permit('read', 'principal', ownerId);
        return send(200, { webauthn_credentials: webauthn.list(ownerId).map(row => webauthn.view(row)) });
      }
      if (at === 'webauthnCredentialOptions' && method === 'POST') {
        permit('add-webauthn-credential', 'principal', ownerId);
        return send(200, { options: await webauthn.registration(ownerId, { origin, userName: emails.of(ownerId)[0] || self.name || ownerId }) });
      }
      if (at === 'webauthnCredentials' && method === 'POST') {
        permit('add-webauthn-credential', 'principal', ownerId);
        const input = await inputBody();
        const made = await webauthn.register(input.credential, { origin, name: input.name, principalId: ownerId });
        if (input.wrap !== undefined) keys.keepWrap(made.credential.id, input.wrap);
        auditLog.write(subject.id, 'webauthn_credential.added', 'principal', ownerId, { credential: made.credential.id });
        return send(201, { webauthn_credential: webauthn.view(made.credential), backed_up: made.backedUp });
      }
      if (at === 'webauthnCredential' && method === 'DELETE') {
        const row = webauthn.get(route.params.credentialId);
        if (!row) fail(404, 'not_found', 'パスキーが見つかりません。');
        permit('remove-webauthn-credential', 'principal', row.principal_id);
        still();
        webauthn.remove(row);
        auditLog.write(subject.id, 'webauthn_credential.removed', 'principal', row.principal_id, { credential: row.id });
        return send(200, { ok: true });
      }
      if (at === 'webauthnCredentialWrap' && method === 'PUT') {
        const row = webauthn.get(route.params.credentialId);
        if (!row) fail(404, 'not_found', 'パスキーが見つかりません。');
        permit('add-webauthn-credential', 'principal', row.principal_id);
        const input = await inputBody();
        keys.keepWrap(row.id, input.wrapped);
        return send(200, { ok: true });
      }
      // The caller's key: the public half published once, the private half kept wrapped per credential, each given
      // back so that whichever credential is at hand unwraps it.
      if (at === 'key') {
        if (method === 'GET') return send(200, { key: keys.view(subject.id, { own: true }) });
        if (method !== 'PUT') fail(405, 'method_not_allowed', 'この操作は利用できません。');
        const input = await inputBody();
        const wraps = input.wraps === undefined ? [] : Object.entries(input.wraps);
        if (input.wraps !== undefined && (!input.wraps || typeof input.wraps !== 'object' || Array.isArray(input.wraps))) fail(400, 'invalid_wrap', '包んだ鍵を確認してください。');
        store.transaction(() => {
          keys.publish(subject.id, input.public_key);
          for (const [id, wrapped] of wraps) {
            if (webauthn.get(id)?.principal_id !== subject.id) fail(404, 'not_found', 'パスキーが見つかりません。');
            keys.keepWrap(id, wrapped);
          }
        });
        auditLog.write(subject.id, 'key.published', 'principal', subject.id, {});
        return send(200, { key: keys.view(subject.id, { own: true }) });
      }
      // Whom to seal a secret of the owner's for: the owner, and Foundation's principal when it acts for them.
      if (at === 'recipients' && method === 'GET') {
        permit('write', 'secret');
        const ids = [ownerId, ...(authorization.can(keys.agentId, 'inject', 'principal', { id: ownerId }) ? [keys.agentId] : [])];
        return send(200, { recipients: ids.map(id => ({ principal_id: id, public_key: keys.publicKeyOf(id) })).filter(item => item.public_key).map(item => ({ ...item, public_key: item.public_key.toString('base64url') })) });
      }
      // Another account made one with this: its passkey answers for it, this session for this one.
      if (at === 'mergeOptions' && method === 'POST') {
        permit('add-webauthn-credential', 'principal', subject.id);
        await inputBody();
        return send(200, { options: await webauthn.authentication({ origin, purpose: 'merge' }) });
      }
      if (at === 'mergeBegin' && method === 'POST') {
        permit('add-webauthn-credential', 'principal', subject.id);
        const input = await inputBody();
        return send(200, await merge.begin(subject.id, input.credential, { origin }));
      }
      if (at === 'mergeComplete' && method === 'POST') {
        permit('add-webauthn-credential', 'principal', subject.id);
        const input = await inputBody(SECRET_MAX);
        const done = merge.complete(subject.id, input);
        return send(200, { ...done, principal: principals.get(subject.id) });
      }
      // Paying for more than the free part: a payment method set on Stripe's page, for the principal itself.
      if (at === 'payment' && method === 'GET') {
        permit('payment', 'principal', ownerId);
        return send(200, { payment: payments.view(ownerId) });
      }
      if (at === 'paymentSetup' && method === 'POST') {
        permit('payment', 'principal', ownerId);
        await inputBody();
        return send(200, { url: await payments.setup(ownerId, { origin, email: emails.of(ownerId)[0] }) });
      }
      if (at === 'paymentComplete' && method === 'POST') {
        permit('payment', 'principal', ownerId);
        const input = await inputBody();
        const view = await payments.complete(ownerId, input.session_id);
        auditLog.write(subject.id, 'payment.set', 'principal', ownerId, {});
        return send(200, { payment: view });
      }
      if (at === 'me') {
        if (method === 'GET') return send(200, { principal: self, ...(subject.via.kind === 'key' ? { key: { id: subject.via.id, ...(subject.via.environment ? { environment: subject.via.environment } : {}) } } : {}), acts_for: actsFor, owners: principals.ownersOf(subject.id), keys: principals.keys(subject.id), requests: requests.list(subject.id, 'pending').map(row => viewRequest(row, origin, { code: true })) });
        if (method === 'PATCH') { const input = await inputBody(); return send(200, { principal: principals.rename(subject.id, nameValue(input.name)) }); }
        // Leaving: a principal takes itself away, its open requests with it. What it acted for stays where it was.
        if (method === 'DELETE') {
          await inputBody();
          await environments.removeAll(subject.id);
          const cancelled = store.transaction(() => { environments.assertRemoved(subject.id); const rows = requests.cancelFrom(subject.id, 'requester_left'); resources.removeAll(subject.id); principals.remove(subject.id); return rows; });
          for (const row of cancelled) requestActions.changed(row);
          return send(200, { ok: true });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (at === 'principals' && method === 'GET') { permit('list', 'principal', undefined, subject.id); return send(200, { principals: principals.owned(subject.id) }); }
      // Making a principal. One that is to act for its maker, and to carry a key, can be asked for in the same
      // breath; that is what making oneself a key is.
      if (at === 'principals' && method === 'POST') {
        const input = await inputBody();
        const alias = input.alias === undefined ? undefined : nameValue(input.alias);
        const { made, issued } = store.transaction(() => {
          const made = principals.create(subject.id, { name: input.name === undefined ? (alias ?? '相手') : nameValue(input.name), alias });
          if (input.agent === true) principals.relate(made.id, 'agent', 'principal', subject.id);
          const issued = input.key === true ? principals.issueKey(made.id) : null;
          return { made, issued };
        });
        auditLog.write(subject.id, 'principal.created', 'principal', made.id, { alias: alias ?? null, agent: input.agent === true, key: Boolean(issued) });
        return send(201, { principal: { ...made, alias: alias ?? null, keys: principals.keys(made.id), acts_for: principals.actsFor(made.id) }, ...(issued ? { token: issued.token, key: { id: issued.id, kind: 'key' } } : {}) });
      }
      if (route?.group === 'principals') {
        const id = route.params.principalId === 'me' ? subject.id : route.params.principalId, part = at === 'principal' ? null : at === 'accessKey' ? 'keys' : at, keyId = route.params.keyId;
        const target = principals.at(id);
        if (part === 'access' && !keyId && method === 'DELETE') {
          permit('relate', 'principal', ownerId);
          if (id === ownerId) fail(400, 'invalid_principal', '自分自身のアクセスは取り消せません。');
          await inputBody();
          requestActions.revokeAccess(ownerId, id);
          return send(200, { ok: true });
        }
        if (part === 'publicKey' && method === 'GET') return send(200, { key: keys.view(id) });
        // Owned by another from now on: by its owner, who stops being so.
        if (part === 'transferPrincipal' && method === 'POST') {
          permit('transfer', 'principal', id);
          const input = await inputBody(), to = principalId(input.to);
          const owners = principals.ownersOf(id), from = owners.includes(subject.id) ? subject.id : owners[0];
          if (from === undefined) fail(409, 'not_owned', 'この相手には持ち主がいません。');
          const moved = principals.transfer(id, from, to);
          auditLog.write(subject.id, 'principal.transferred', 'principal', id, { from, to });
          return send(200, { principal: { ...moved, keys: principals.keys(id), acts_for: principals.actsFor(id), owners: principals.ownersOf(id) } });
        }
        if (!part) {
          if (method === 'GET') { permit('read', 'principal', id); return send(200, { principal: { ...target, keys: principals.keys(id), acts_for: principals.actsFor(id), owners: principals.ownersOf(id) } }); }
          if (method === 'PATCH') { permit('rename', 'principal', id); const input = await inputBody(); return send(200, { principal: principals.rename(id, nameValue(input.name)) }); }
          if (method === 'DELETE') {
            permit('remove', 'principal', id);
            await inputBody();
            if (objects.enabled) for (const row of objects.list(id)) await objects.remove(row);
            await environments.removeAll(id);
            store.transaction(() => {
              environments.assertRemoved(id);
              requestActions.removePrincipal(subject.id, id);
              resources.removeAll(id);
            });
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
        // A request link: handed to the principal asked, to answer that one request without a signin.
        if (part === 'links' && !keyId && method === 'POST') {
          permit('issue-link', 'principal', id);
          const input = await inputBody();
          if (typeof input.request_id !== 'string') fail(400, 'invalid_request', 'リンクにする依頼を指定してください。');
          const row = requests.forTo(input.request_id, id, true);
          if (row.type !== 'secret') fail(409, 'link_unsupported', '接続の依頼はまだリンクで引き渡せません。');
          const made = principals.issueLink(id, row.id, LINK_TTL);
          auditLog.write(subject.id, 'link.issued', 'principal', id, { request: row.id });
          return send(201, { link: { id: made.id, request_id: made.request_id, expires_at: made.expires_at }, url: origin + '/requests/' + row.id + '#link=' + made.token, expires_at: made.expires_at });
        }
        // Computing this principal spent this month and may spend; its owner bounds it.
        if (part === 'compute' && !keyId) {
          if (method === 'GET') { permit('usage', 'principal', id); return send(200, { compute: environments.usage(id) }); }
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
      if (at === 'relations') {
        if (method === 'GET') return send(200, { relations: principals.relationsOf(subject.id) });
        if (method !== 'POST' && method !== 'DELETE') fail(405, 'method_not_allowed', 'この操作は利用できません。');
        const input = await inputBody();
        const subjectId = input.subject === undefined ? subject.id : principalId(input.subject);
        if (typeof input.relation !== 'string' || !['principal', 'resource'].includes(input.object_type) || typeof input.object_id !== 'string') fail(400, 'invalid_relation', '関係の指定を確認してください。');
        const object = input.object_type === 'principal' ? { id: principals.at(input.object_id).id } : resources.at(input.object_id);
        if (!reaches(input.relation, input.object_type === 'principal' ? 'principal' : object.kind)) fail(400, 'invalid_relation', '関係の種類を確認してください。');
        principals.at(subjectId);
        if (method === 'POST') {
          if (!authorization.mayGive(subject.id, input.relation, input.object_type, object)) fail(403, 'forbidden', 'この操作は許可されていません。');
          principals.relate(subjectId, input.relation, input.object_type, input.object_id);
          auditLog.write(subject.id, 'relation.added', input.object_type, input.object_id, { subject: subjectId, relation: input.relation });
          return send(201, { ok: true });
        }
        if (subjectId !== subject.id) {
          if (input.object_type === 'principal') permit('relate', 'principal', object.id);
          else permit('share', object.kind, object.id, object.owner_id);
        }
        principals.unrelate(subjectId, input.relation, input.object_type, input.object_id);
        auditLog.write(subject.id, 'relation.removed', input.object_type, input.object_id, { subject: subjectId, relation: input.relation });
        return send(200, { ok: true });
      }
      // Lent machines. An environment is a resource: opened by the owner or whoever acts for them, reached by its id,
      // shared along lines, and able to reach nothing of Foundation's unless given an identity it may act as.
      const passable = identity => {
        if (identity === undefined || identity === null) return null;
        const id = principalId(identity);
        principals.at(id);
        permit('pass', 'principal', id);
        return id;
      };
      if (at === 'environments' && method === 'GET') { permit('list', 'environment'); return send(200, { environments: environments.list(ownerId).map(row => environments.view(row)) }); }
      if ((at === 'environments' || at === 'runs') && method === 'POST') {
        permit('open', 'environment');
        environments.check();
        limit('environments', 20);
        const input = await inputBody(1024 * 1024 + 20_000);
        const identity = passable(input.identity);
        const run = at === 'runs';
        const opened = await environments.open(ownerId, { ...input, identity, ...(run ? { lifetime: { ...(input.lifetime ?? {}), end: 'exit' } } : {}) }, origin);
        auditLog.write(subject.id, 'environment.opened', 'resource', opened.id, { identity, size: opened.size, lifetime: opened.lifetime });
        if (!run) return send(201, { environment: environments.view(opened) });
        const started = environments.run(opened, subject.id, input);
        auditLog.write(subject.id, 'environment.command', 'resource', opened.id, { command: String(input.command?.[0] ?? '').slice(0, 100) });
        const answered = await environments.answer(opened.id, started.id, 20_000);
        return send(answered.status === 'running' ? 202 : 200, { environment: environments.view(environments.get(opened.id)), command: answered });
      }
      const environmentHeld = route?.group === 'environments' || (at === 'resource' && resources.get(route.params.resourceId)?.kind === 'environment')
        ? environments.at(route.params.resourceId) : null;
      if (environmentHeld && (route.group === 'environments' || method === 'DELETE')) {
        const held = environmentHeld, commands = at === 'commands' || at === 'command';
        if (!commands && method === 'GET') { permit('read', 'environment', held.id, held.owner_id); return send(200, { environment: environments.view(held) }); }
        if (!commands && method === 'PATCH') {
          permit('identity', 'environment', held.id, held.owner_id);
          const input = await inputBody();
          if (!Object.hasOwn(input, 'identity')) fail(400, 'invalid_identity', 'identity を指定してください（外すときは null）。');
          const identity = passable(input.identity);
          const changed = identity ? await environments.attach(held, identity) : await environments.detach(held);
          auditLog.write(subject.id, identity ? 'environment.identity' : 'environment.identity_removed', 'resource', held.id, { identity });
          return send(200, { environment: environments.view(changed) });
        }
        if (!commands && method === 'DELETE') {
          permit('remove', 'environment', held.id, held.owner_id);
          await inputBody();
          await environments.remove(held);
          auditLog.write(subject.id, 'environment.closed', 'resource', held.id, {});
          return send(200, { ok: true });
        }
        if (at === 'commands' && method === 'POST') {
          permit('exec', 'environment', held.id, held.owner_id);
          const input = await inputBody(1024 * 1024 + 20_000);
          const started = environments.run(held, subject.id, input);
          auditLog.write(subject.id, 'environment.command', 'resource', held.id, { command: String(input.command?.[0] ?? '').slice(0, 100) });
          const answered = await environments.answer(held.id, started.id, 20_000);
          return send(answered.status === 'running' ? 202 : 200, { command: answered });
        }
        if (at === 'command' && method === 'GET') {
          permit('read', 'environment', held.id, held.owner_id);
          return send(200, { command: environments.command(held.id, route.params.commandId) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      // Resources. Each has an id, and that is how lines, the audit log and the calls below refer to it. A name is
      // how the owner calls one: a way to find or place a thing, not its identity. A connection says what it is
      // and where it works; an object says its size and type; neither says anything of its content here.
      const shown = row => row.kind === 'connection' ? connections.view(connections.get(row.id), { owner: subject.id === row.owner_id })
        : row.kind === 'secret' ? secrets.view(secrets.get(row.id))
        : row.kind === 'app' ? apps.view(apps.get(row.id), { owner: subject.id === row.owner_id })
        : row.kind === 'service' ? services.view(services.row(row.id), { owner: subject.id === row.owner_id })
        : row.kind === 'environment' ? environments.view(environments.get(row.id)) : objects.view(objects.get(row.id));
      const resourceKind = required => {
        const kind = url.searchParams.get('kind') ?? undefined;
        if ((required && kind === undefined) || (kind !== undefined && !KINDS.includes(kind))) fail(400, 'invalid_kind', 'kind は secret / connection / object / app / service / environment のいずれかです。');
        return kind;
      };
      if (at === 'resources' && method === 'GET') {
        if (url.searchParams.get('shown') === 'me') { permit('shown', 'principal', subject.id); return send(200, { resources: principals.shownTo(subject.id) }); }
        const kind = resourceKind(false), name = url.searchParams.get('name') ?? undefined, prefix = url.searchParams.get('prefix') ?? undefined;
        const kinds = kind ? [kind] : KINDS;
        for (const one of kinds) permit('list', one);
        if (name !== undefined) {
          const found = (kinds.includes('secret') && secrets.find(ownerId, name)) || (kinds.includes('object') && objects.enabled && objects.find(ownerId, name))
            || (kinds.includes('service') && services.find(ownerId, name)) || (kinds.includes('app') && apps.find(ownerId, name));
          if (!found) fail(404, 'not_found', '見つかりません。');
          return send(200, { resource: shown(found) });
        }
        const rows = [];
        if (kinds.includes('secret')) rows.push(...secrets.list(ownerId, { prefix }));
        if (kinds.includes('connection')) {
          const service = url.searchParams.get('service') ?? undefined;
          rows.push(...connections.list(ownerId, { service, prefix }).filter(row => subject.id === ownerId || row.status !== 'disconnecting'));
        }
        if (kinds.includes('object')) { if (kind === 'object') objects.check(); if (objects.enabled) { limit('objects', 60); rows.push(...objects.list(ownerId, prefix ?? '')); } }
        if (kinds.includes('app')) rows.push(...apps.list(ownerId), ...apps.lent(ownerId));
        if (kinds.includes('service')) rows.push(...services.list(ownerId), ...services.lent(ownerId));
        if (kinds.includes('environment')) rows.push(...environments.list(ownerId));
        // Apps are listed with those Foundation offers, which anyone may connect through and nobody holds.
        return send(200, { resources: [...rows.map(shown), ...(kind === 'app' ? apps.offeredAll() : [])] });
      }
      // Placing a thing by name: the owner's name for it. The same name, same kind, replaces what is there. A
      // secret placed this way is the owner's bytes. Managed authorizations are made at /v1/connections.
      if (at === 'resources' && method === 'PUT') {
        const kind = resourceKind(true), name = url.searchParams.get('name');
        if (name === null) fail(400, 'invalid_name', '名前を指定してください。');
        // An app is registered by its owner, as values: which service, its client ID and secret. The same name
        // again gives it new values, and its connections go on through it.
        if (kind === 'app') {
          const existing = apps.find(ownerId, name);
          permit('write', 'app', existing?.id);
          limit('apps', 30);
          const input = await inputBody();
          services.get(input.service, ownerId);
          const saved = apps.put(ownerId, { ...input, name });
          auditLog.write(subject.id, existing ? 'app.changed' : 'app.created', 'resource', saved.id, { service: saved.service });
          return send(200, { resource: shown(saved) });
        }
        // A service is described as its definition; it holds nothing secret.
        if (kind === 'service') {
          const existing = services.find(ownerId, name);
          permit('write', 'service', existing?.id);
          limit('services', 30);
          const input = await inputBody();
          const saved = store.transaction(() => {
            if (req.headers['if-none-match'] === '*' && services.find(ownerId, name)) fail(412, 'name_taken', '同じ名前のサービスがあります。一覧から選んでください。');
            return services.put(ownerId, name, input);
          });
          auditLog.write(subject.id, existing ? 'service.changed' : 'service.created', 'resource', saved.id, {});
          return send(200, { resource: shown(saved) });
        }
        if (!['secret', 'object'].includes(kind)) fail(405, 'method_not_allowed', 'この操作は利用できません。');
        const existing = kind === 'secret' ? secrets.find(ownerId, name) : (objects.check(), objects.find(ownerId, name));
        permit('write', kind, existing?.id);
        limit(kind === 'secret' ? 'secrets' : 'objects', kind === 'secret' ? 120 : 60);
        // A thing made for the owner by someone else is one its maker may read and write: a line says so.
        const line = saved => { if (!existing && subject.id !== ownerId) principals.relate(subject.id, 'editor', 'resource', saved.id); };
        if (kind === 'secret') {
          const input = await inputBody(SECRET_MAX * 2), { content, plain } = sealedInput(input);
          if (plain) agentFor(ownerId);
          const saved = store.transaction(() => {
            const match = req.headers['if-match'];
            const current = match === undefined ? null : secrets.find(ownerId, name);
            if (match !== undefined && (!current || match !== secretTag(current))) fail(412, 'secret_changed', 'ほかの操作で変更されています。開き直して確認してください。');
            const saved = plain ? secrets.putAs(ownerId, { name, content }) : secrets.put(ownerId, { name, content, envelopes: input.envelopes });
            line(saved);
            res.setHeader('etag', secretTag(saved));
            return saved;
          });
          return send(200, { resource: shown(saved) });
        }
        const content = await inputBytes(OBJECT_MAX);
        const saved = await objects.put(ownerId, name, content, req.headers['content-type'] || 'application/octet-stream');
        still();
        line(saved);
        return send(200, { resource: shown(saved) });
      }
      if (route?.group === 'resources') {
        const held = resources.at(route.params.resourceId), part = at === 'content' ? '/content' : at === 'objectLink' ? '/link' : at === 'envelopes' ? '/envelopes' : at === 'transferResource' ? '/transfer' : null;
        const connection = held.kind === 'connection' ? connections.get(held.id) : null, secret = held.kind === 'secret' ? secrets.get(held.id) : null;
        // Given to another owner: by whoever may transfer it, to any principal. A lent machine is not given.
        if (part === '/transfer' && method === 'POST') {
          if (held.kind === 'environment') fail(405, 'method_not_allowed', '環境は渡せません。');
          permit('transfer', held.kind, held.id, held.owner_id);
          const input = await inputBody(), to = principals.at(principalId(input.to)).id;
          const moved = held.kind === 'secret' ? secrets.transfer(secrets.get(held.id), to, input.envelope)
            : held.kind === 'connection' ? connections.transfer(connections.get(held.id), to)
            : held.kind === 'app' ? apps.transfer(apps.get(held.id), to)
            : held.kind === 'service' ? services.transfer(services.row(held.id), to) : objects.transfer(objects.get(held.id), to);
          auditLog.write(subject.id, 'resource.transferred', 'resource', held.id, { from: held.owner_id, to });
          return send(200, { resource: shown(resources.get(held.id)) });
        }
        // An app: renamed by its owner; given new values by its owner or an editor; removed by its owner, which
        // stops the connections made through it. Its secret is never read back, by anyone.
        if (held.kind === 'app') {
          const app = apps.at(held.id);
          if (part) fail(405, 'method_not_allowed', 'アプリの秘密は読み出せません。');
          if (method === 'PATCH') {
            const input = await inputBody();
            const { name, ...values } = input;
            let row = app;
            if (name !== undefined) { permit('rename', 'app', app.id, app.owner_id); row = apps.rename(row, name); }
            if (Object.keys(values).length) {
              permit('write', 'app', app.id, app.owner_id);
              row = apps.write(row, values);
              auditLog.write(subject.id, 'app.changed', 'resource', app.id, { service: app.service });
            }
            return send(200, { resource: shown(row) });
          }
          if (method === 'DELETE') {
            permit('remove', 'app', app.id, app.owner_id);
            const input = await inputBody(), dependents = apps.dependents(app);
            // Removing an app stops what was connected through it; that is said, and agreed to, first.
            if (dependents.length && input.confirm !== true) {
              fail(409, 'app_in_use', `このアプリで作った接続が${dependents.length}件あります。削除すると、つなぎ直すまで使えなくなります。`,
                { connections: dependents.length, yours: dependents.filter(row => row.owner_id === app.owner_id).map(row => ({ id: row.id, name: row.name })) });
            }
            apps.remove(app);
            auditLog.write(subject.id, 'app.removed', 'resource', app.id, { service: app.service, connections_stopped: dependents.length });
            return send(200, { ok: true, connections_stopped: dependents.length });
          }
        }
        // A service a owner described: its definition is read, replaced and renamed; it is removed once nothing
        // refers to it.
        if (held.kind === 'service') {
          const row = services.row(held.id);
          if (part) fail(405, 'method_not_allowed', 'この操作は利用できません。');
          if (method === 'PUT') {
            permit('write', 'service', row.id, row.owner_id);
            const saved = services.write(row, await inputBody());
            auditLog.write(subject.id, 'service.changed', 'resource', row.id, {});
            return send(200, { resource: shown(saved) });
          }
          if (method === 'PATCH') {
            const input = await inputBody();
            if (Object.keys(input).some(key => !['name', 'auth_schemes'].includes(key)) || !Object.keys(input).length) fail(400, 'invalid_fields', '変更する項目を確認してください。');
            if (input.name !== undefined) permit('rename', 'service', row.id, row.owner_id);
            if (input.auth_schemes !== undefined) permit('write', 'service', row.id, row.owner_id);
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
            permit('remove', 'service', row.id, row.owner_id);
            await inputBody();
            services.remove(row);
            auditLog.write(subject.id, 'service.removed', 'resource', row.id, {});
            return send(200, { ok: true });
          }
        }
        if (!part && method === 'GET') {
          permit('read', held.kind, held.id, held.owner_id);
          return send(200, { resource: { ...shown(held), ...(held.owner_id === subject.id ? { lines: principals.linesOnto(held.id) } : {}) } });
        }
        // Renaming changes what the owner calls it and nothing else: lines, the audit log and the content stay.
        if (!part && method === 'PATCH') {
          const input = await inputBody();
          permit('rename', held.kind, held.id, held.owner_id);
          if (held.kind === 'object') return send(200, { resource: shown(objects.rename(objects.get(held.id), input.name)) });
          if (secret) return send(200, { resource: shown(secrets.rename(secret, input.name)) });
          return send(200, { resource: shown(connections.rename(connection, input.name)) });
        }
        // Removing a connection for a service disconnects it: Foundation stops obtaining from it and, when asked,
        // asks the service to revoke it. Removing always succeeds; the revocation's outcome is reported.
        if (!part && method === 'DELETE' && connection) {
          permit('disconnect', 'connection', held.id, held.owner_id);
          const input = await inputBody();
          if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', 'サービス側の許可を取り消すか選んでください。');
          let scheme = null;
          try { scheme = connections.schemeFor(connection); } catch {}
          if (disconnects.has(connection.id)) fail(409, 'disconnect_in_progress', '接続を解除しています。');
          disconnects.add(connection.id);
          try {
            const previous = connections.disconnect(held.owner_id, connection.id);
            let revoked = null;
            if (input.revoke && typeof scheme?.revoke === 'function') {
              try { await scheme.revoke(connections.context(previous).privateState); revoked = true; }
              catch { revoked = false; }
            }
            connections.remove(previous);
            auditLog.write(subject.id, 'connection.removed', 'connection', connection.id, { service: connection.service, revoked });
            return send(200, { ok: true, service_revoked: revoked });
          } finally { disconnects.delete(connection.id); }
        }
        if (!part && method === 'DELETE') {
          permit('remove', held.kind, held.id, held.owner_id);
          await inputBody();
          if (secret) secrets.remove(secret); else { await objects.remove(objects.get(held.id)); still(); }
          return send(200, { ok: true });
        }
        // The content of a thing: an object's bytes, or a secret's. A connection for a service has nothing to read;
        // what it yields is derived when it is injected.
        if (part === '/content' && method === 'GET') {
          if (connection) fail(405, 'method_not_allowed', 'この接続に読める中身はありません。使うには /v1/injections を使います。');
          permit(secret ? 'content' : 'read', held.kind, held.id, held.owner_id);
          const disposition = `attachment; filename="resource.bin"; filename*=UTF-8''${encodeURIComponent(held.name.split('/').pop()).replace(/['()*]/g, c => '%' + c.charCodeAt(0).toString(16))}`;
          if (secret) {
            res.setHeader('etag', secretTag(secret));
            return send(200, { content: secrets.content(secret).toString('base64url'), envelope: keys.envelopeOf(secret.id, subject.id)?.toString('base64url') ?? null, recipients: keys.recipientKeys(secret.id) });
          }
          const found = await objects.read(objects.get(held.id));
          still();
          res.writeHead(200, { 'content-type': found.contentType, 'content-length': found.content.length, 'content-disposition': disposition });
          return res.end(found.content);
        }
        if (part === '/content' && method === 'PUT') {
          if (connection) fail(405, 'method_not_allowed', 'この接続の中身は書き換えられません。');
          permit('write', held.kind, held.id, held.owner_id);
          if (secret) {
            limit('secrets', 120);
            const input = await inputBody(SECRET_MAX * 2), { content, plain } = sealedInput(input);
            if (plain) agentFor(held.owner_id);
            const saved = store.transaction(() => {
              const match = req.headers['if-match'], current = secrets.get(held.id);
              if (!current) fail(404, 'not_found', '見つかりません。');
              if (match !== undefined && match !== secretTag(current)) fail(412, 'secret_changed', 'ほかの操作で変更されています。開き直して確認してください。');
              const saved = plain ? secrets.writeAs(current, content) : secrets.write(current, content, input.envelopes);
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
        // Envelopes: the secret's key, sealed for one more recipient by whoever may share it - or by Foundation's
        // principal from its own envelope - and taken back the same way.
        if (part === '/envelopes') {
          if (!secret) fail(405, 'method_not_allowed', 'この操作は利用できません。');
          permit('share', 'secret', held.id, held.owner_id);
          const recipient = principals.at(route.params.principalId).id, input = await inputBody();
          if (method === 'PUT') keys.keepEnvelope(held.id, recipient, input.wrapped);
          else if (method === 'POST') keys.resealFor(held.id, recipient);
          else if (method === 'DELETE') { if (!keys.dropEnvelope(held.id, recipient)) fail(404, 'not_found', '封筒がありません。'); }
          else fail(405, 'method_not_allowed', 'この操作は利用できません。');
          auditLog.write(subject.id, method === 'DELETE' ? 'envelope.dropped' : 'envelope.kept', 'resource', held.id, { recipient });
          return send(200, { ok: true });
        }
        if (part === '/link' && method === 'POST') {
          if (held.kind !== 'object') fail(405, 'method_not_allowed', 'この操作は利用できません。');
          permit('link', 'object', held.id, held.owner_id);
          const input = await inputBody();
          limit('objects', 60);
          const link = await objects.link(objects.get(held.id), input.minutes);
          still();
          return send(200, link);
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (at === 'audit' && method === 'GET') { permit('audit-log', 'principal', subject.id); return send(200, { entries: auditLog.list(subject.id) }); }
      // The owner's screen, in one answer.
      if (at === 'overview' && method === 'GET') {
        permit('overview', 'principal', ownerId);
        return send(200, { user: { id: subject.id, email: emails.of(subject.id)[0] ?? null }, principal: self, payment: payments.view(ownerId), webauthn_credentials: webauthn.list(ownerId).map(row => webauthn.view(row)), secrets: secrets.list(ownerId).map(row => secrets.view(row)), connections: connections.list(ownerId).map(row => connections.view(row, { owner: true })),
          apps: [...apps.list(ownerId).map(row => apps.view(row, { owner: true })), ...apps.lent(ownerId).map(row => apps.view(row)), ...apps.offeredAll()],
          services: [...services.list(ownerId).map(row => services.view(row, { owner: true })), ...services.lent(ownerId).map(row => services.view(row))],
          catalog: services.catalogView(), principals: principals.owned(ownerId), actors: principals.actorsOf(ownerId),
          requests: requests.listTo(ownerId, 'pending').map(row => viewRequest(row, origin)), functions: FUNCTIONS, settings: settings.get(ownerId) ?? null,
          // Machines lent to the owner and still running, and the computing they spend.
          environments: environments.list(ownerId).filter(row => row.status !== 'stopped').map(row => environments.view(row)), compute: environments.usage(ownerId), foundation: { principal_id: keys.agentId } });
      }
      // Everything, in one file, for the owner alone. Lending someone a place to keep things means they can take
      // them away again; without this the promise is words.
      if (at === 'export' && method === 'GET') {
        permit('export', 'principal', ownerId);
        // A secret goes out as it is kept, sealed, with its envelopes; a connection with what is known of it, and a token with what was pasted.
        // What renews the others is Foundation's to keep and would be of no use elsewhere. A described service goes
        // out as its definition.
        const kept = secrets.list(ownerId).map(row => ({ ...secrets.view(row), content: secrets.content(row).toString('base64url'), encoding: 'base64url', envelopes: keys.envelopesOf(row.id) }));
        const value = { exported_at: new Date().toISOString(), owner: emails.of(subject.id)[0] ?? null, origin, secrets: kept,
          connections: connections.list(ownerId).map(row => ({ ...connections.view(row, { owner: true }), fields: connections.handed(row) })),
          services: services.list(ownerId).map(row => ({ id: row.id, name: row.name, definition: JSON.parse(row.definition) })), principals: principals.owned(ownerId) };
        res.writeHead(200, { 'content-type': 'application/json; charset=utf-8',
          'content-disposition': `attachment; filename="foundation-${new Date().toISOString().slice(0, 10)}.json"` });
        return res.end(JSON.stringify(value, null, 2));
      }
      // Connecting: a connection for a service, by one of its schemes. OAuth goes to the service's consent screen
      // and comes back at /oauth/callback; a role is made in the service's console and named here; a token is
      // handed over here. The connection it makes is a resource like any other: listed and removed at
      // /v1/resources.
      if (at === 'confirmation' && ['GET', 'POST', 'DELETE'].includes(method)) {
        permit('connect', 'connection');
        if (!session) fail(401, 'signin_required', 'サインインしてください。');
        const state = method === 'GET' ? url.searchParams.get('state') : (await inputBody()).state;
        const flow = flows.peek(session.id, state);
        if (!flow || flow.kind !== 'confirmation') fail(400, 'invalid_state', '接続をやり直してください。');
        progressRequestId = flow.requestId || null;
        if (method === 'DELETE') { flows.drop(session.id, state); return send(200, { ok: true }); }
        const previous = connections.reconnection(ownerId, flow.service, flow.scheme, flow.previous.id);
        if (previous.generation !== flow.previous.generation) fail(409, 'connection_changed', '接続の状態が変わりました。');
        if (flow.requestId) requests.forTo(flow.requestId, ownerId, true);
        if (method === 'GET') return send(200, { connection: connections.view(previous, { owner: true }), changes: flow.changes });
        still();
        const saved = requestActions.connect(flow.requestId, ownerId, flow.service, flow.scheme, flow.result, { requestedBy: flow.requestedBy, previous, scopes: flow.scopes ?? null, app: flow.app ?? null });
        flows.drop(session.id, state);
        return send(200, { connection: connections.view(saved, { owner: true }) });
      }
      if (at === 'connections' && method === 'POST') {
        permit('connect', 'connection');
        const input = await inputBody();
        limit('connect', 10);
        const request = input.request_id === undefined ? null : requests.forTo(input.request_id, ownerId, true);
        progressRequestId = request?.id || null;
        const asked = request ? requests.detail(request) : null;
        if (request && request.type !== 'connection') fail(409, 'approval_only', 'この依頼は接続の依頼ではありません。');
        // The service, the scheme, the scopes and the app are the request's when there is one: what the owner saw is
        // what happens.
        const { ref, definition } = services.get(asked ? asked.service : input.service, ownerId);
        const schemeId = asked ? asked.auth_scheme : input.auth_scheme ?? Object.keys(definition.auth_schemes)[0];
        if (request && input.service !== undefined && input.service !== ref) fail(400, 'scope_mismatch', '依頼されたサービスで接続してください。');
        const scheme = services.scheme(ref, schemeId);
        if (request) requests.record(request.id, 'connect_started', { service: ref });
        // Who asked for it, as they were called then. One started from the page was asked by no one.
        const requestedBy = request ? principals.get(request.from_id)?.name ?? '' : subject.id === ownerId ? '' : self.name;
        const target = asked ? asked.connection_id : input.connection_id;
        if (request && input.connection_id !== undefined && input.connection_id !== target) fail(409, 'connection_changed', '依頼された接続を選んでください。');
        const previous = target === undefined ? undefined : connections.reconnection(ownerId, ref, schemeId, target);
        // A token is pasted here by whoever may connect; there is no other site to go to and come back from. Pasting
        // one for an existing connection replaces its value.
        if (schemeId === 'token') {
          if (input.scopes !== undefined || input.app !== undefined) fail(400, 'invalid_fields', 'トークンの接続にはスコープもアプリもありません。');
          if (input.name !== undefined && (typeof input.name !== 'string' || !input.name.trim() || input.name.length > 80 || /[\x00-\x1f\x7f]/.test(input.name))) fail(400, 'invalid_name', '名前は80文字までで指定してください。');
          const result = await scheme.authorization.complete({ fields: input.fields });
          still();
          const saved = requestActions.connect(request?.id, ownerId, ref, 'token', result, { requestedBy, previous, name: input.name?.trim() });
          return send(previous ? 200 : 201, { connection: connections.view(saved, { owner: true }) });
        }
        if (!session) fail(401, 'signin_required', 'サインインしてください。');
        const previousState = previous ? connections.state(previous) : null;
        const scopes = requestedScopes(scheme, asked ? asked.scopes ?? [] : scopeList(input.scopes), previousState);
        // Reconnecting keeps the app the connection was made through unless another is named.
        const named = asked ? asked.app : appReference(input.app);
        if (named !== undefined && !takesApps(scheme)) fail(400, 'app_unsupported', 'この接続方法はアプリを通しません。');
        const appId = takesApps(scheme) ? named ?? previous?.app_id ?? FOUNDATION_APP : null;
        if (appId && appId !== FOUNDATION_APP) permit('use', 'app', appId, apps.at(appId).owner_id);
        const active = schemeId === 'oauth' ? apps.scheme(ref, appId) : scheme;
        still();
        const flow = { service: ref, requestedBy, requestId: request?.id, previous: previous ? { id: previous.id, generation: previous.generation } : null, scopes, app: appId };
        // A role is made by the owner in the service's own console, then named here; what Foundation must remember
        // meanwhile (the external ID it chose) travels in the flow, and the flow lasts until the answer is right.
        if (schemeId === 'role') {
          const started = await active.authorization.begin({ origin }, connections.context(previous));
          still();
          const state = flows.begin(session.id, { ...flow, kind: 'role', memo: started.memo ?? null });
          return send(200, { url: started.url, state });
        }
        const verifier = randomBytes(32).toString('base64url');
        const redirectUri = origin + '/oauth/callback';
        const state = flows.begin(session.id, { ...flow, verifier, redirectUri });
        return send(200, { url: await active.authorization.begin({ state, verifier, redirectUri, scopes }, connections.context(previous)) });
      }
      if (at === 'completeConnection' && method === 'POST') {
        permit('connect', 'connection');
        const input = await inputBody();
        if (!session) fail(401, 'signin_required', 'サインインしてください。');
        limit('connect', 10);
        const flow = flows.peek(session.id, input.state);
        if (!flow || flow.kind !== 'role') fail(400, 'invalid_state', '接続をやり直してください。');
        const scheme = services.scheme(flow.service, 'role');
        const previous = flow.previous ? connections.forService(ownerId, flow.previous.id) : undefined;
        if (previous && previous.generation !== flow.previous.generation) fail(409, 'connection_changed', '接続の状態が変わりました。');
        if (flow.requestId) { requests.forTo(flow.requestId, ownerId, true); progressRequestId = flow.requestId; }
        const fields = input.fields && typeof input.fields === 'object' && !Array.isArray(input.fields) ? input.fields : {};
        const saved = await verifyConnection(req, session,
          () => scheme.authorization.complete({ fields, memo: flow.memo }, connections.context(previous)),
          result => requestActions.connect(flow.requestId, ownerId, flow.service, 'role', result, { requestedBy: flow.requestedBy, previous }));
        flows.drop(session.id, input.state);
        return send(200, { connection: connections.view(saved, { owner: true }) });
      }
      // What this owner is using, and what they may use. Lending has a cost, so both sides can see it.
      if (at === 'usage' && method === 'GET') {
        permit('usage', 'principal', ownerId);
        const kept = secrets.usage(ownerId);
        const space = objects.enabled ? await objects.usage(ownerId) : null;
        still();
        return send(200, { secrets: { ...kept, count_max: SECRET_COUNT_MAX, bytes_max: SECRET_TOTAL_MAX },
          objects: space ? { count: space.count, bytes: space.bytes, count_max: space.count_max, bytes_max: space.bytes_max } : null });
      }
      // Injecting derives what each connection yields now: a secret its bytes, one for a service what its scheme
      // obtains. This is the one place a connection reaches a service.
      if (at === 'injections' && method === 'POST') {
        permit('inject', 'principal', ownerId);
        const input = await inputBody();
        limit('issue', 30);
        const names = Array.isArray(input.names) ? input.names : [];
        const { injection, expires_at } = await inputs.inject(ownerId, names);
        still();
        // Handed into a lent machine: what it prints is cleaned of these.
        if (subject.via.environment) environments.reveal(subject.via.environment, [...Object.values(injection.environment), ...injection.files.map(file => Buffer.from(file.content, 'base64').toString('utf8'))]);
        auditLog.write(subject.id, 'injection', 'principal', ownerId, { inputs: names.map(({ as, filename, ...reference }) => reference) });
        return send(200, { injection, expires_at, expires_in: expires_at === null ? null : Math.max(0, Math.floor((expires_at - Date.now()) / 1000)) });
      }
      if (at === 'functions' && method === 'GET') { permit('functions', 'principal', ownerId); return send(200, { functions: FUNCTIONS }); }
      if (at === 'httpRequest' && method === 'POST') {
        permit('invoke', 'principal', ownerId);
        const input = await inputBody(FETCH_BODY_MAX * 2);
        limit('fetch', 30);
        const result = await functions.request({ ownerId, still }, input, [url.hostname, ...(external ? [external.hostname] : [])]);
        auditLog.write(subject.id, 'function', 'principal', ownerId, { function: 'http.request', target: String(input.url).slice(0, 200), status: result.response?.status ?? null });
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
          // The tool names whom the caller acts for when it is exactly one and the call did not say.
          call: async ({ method: verb, path: target, body: payload, body_encoding }) => {
            const named = target !== '/openapi.json' && actsFor.length === 1 && !/[?&]as=/.test(target) ? target + (target.includes('?') ? '&' : '?') + 'as=' + encodeURIComponent(actsFor[0]) : target;
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
      const message = error instanceof HttpError ? error.message : '処理を完了できませんでした。';
      if (!res.headersSent) send(error instanceof HttpError ? error.status : 500, { error: { code: error instanceof HttpError ? error.code : 'internal_error', message: webT ? localizeErrorMessage(message, webT) : message,
        ...(error instanceof HttpError && error.extra ? error.extra : {}) } });
      else res.end();
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  return {
    server, store, resources, services, secrets, keys, connections, inputs, apps, objects, environments, payments, principals, sessions, emails, challenges, webauthn, flows, requests, requestActions, settings, auditLog,
    async close() {
      clearInterval(timer);
      if (server.listening) await new Promise((resolve) => { server.close(resolve); server.closeIdleConnections(); });
      store.close();
    },
  };
}
