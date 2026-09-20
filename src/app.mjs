import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Store } from './store.mjs';
import { fail, HttpError, nameValue } from './errors.mjs';
import { ProviderCatalog, gmailConnection } from './providers/catalog.mjs';
import { EmailLogins, LOGIN_TTL } from './email-login.mjs';
import { AccessRequests } from './access-requests.mjs';

const PUBLIC = new URL('../web/', import.meta.url);
const STATIC = new Map([['/', ['index.html', 'text/html; charset=utf-8']], ['/app.js', ['app.js', 'text/javascript; charset=utf-8']], ['/styles.css', ['styles.css', 'text/css; charset=utf-8']]]);
const MAX_BODY = 12_000;
const SESSION_AGE = 14 * 86400;
const LOGIN_CALLBACK = '/auth/callback';
const CONNECT_PAGE = /^\/connect\/[A-Za-z0-9_-]{43}$/;

function returnPath(value = '/') {
  if (value !== '/' && (typeof value !== 'string' || !CONNECT_PAGE.test(value))) fail(400, 'invalid_return', '接続リンクを開き直してください。');
  return value;
}

async function body(req) {
  if (req.headers['content-type']?.split(';')[0] !== 'application/json') fail(415, 'json_required', 'JSON形式で送信してください。');
  if (Number(req.headers['content-length']) > MAX_BODY) fail(413, 'body_too_large', '送信内容が大きすぎます。');
  const chunks = [];
  let length = 0;
  for await (const chunk of req) {
    length += chunk.length;
    if (length > MAX_BODY) fail(413, 'body_too_large', '送信内容が大きすぎます。');
    chunks.push(chunk);
  }
  let result;
  try { result = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { fail(400, 'invalid_json', '送信内容を読み取れませんでした。'); }
  if (!result || typeof result !== 'object' || Array.isArray(result)) fail(400, 'invalid_json', '送信内容を確認してください。');
  return result;
}
function purposeValue(value = '') {
  if (typeof value !== 'string' || value.length > 240 || /[\x00-\x1f]/.test(value)) fail(400, 'invalid_purpose', '用途は240文字以内で入力してください。');
  return value.trim();
}

export function createApp({ database = ':memory:', encryptionKey, auth, gmail, integrations, publicOrigin, loginClock }) {
  if (!auth || !gmail) throw new Error('Authentication and Gmail providers are required');
  let external;
  if (publicOrigin) {
    external = new URL(publicOrigin);
    if (external.protocol !== 'https:' || external.username || external.password || external.pathname !== '/' || external.search || external.hash) throw new Error('FOUNDATION_PUBLIC_ORIGIN must be an HTTPS origin without a path');
  }
  const store = new Store(database, encryptionKey);
  const providers = new ProviderCatalog(integrations || [gmailConnection(gmail)]);
  const requests = new AccessRequests(store, providers);
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
  function actor(req) {
    const agent = store.authenticate(req.headers.authorization?.match(/^Bearer (\S+)$/)?.[1]);
    if (!agent) fail(401, 'invalid_token', '実行環境のアクセスキーが無効です。');
    return agent;
  }
  function requireOrigin(req, origin) {
    if (req.headers.origin !== origin) fail(403, 'origin_denied', 'この操作はFoundationの画面から行ってください。');
  }
  function accountFor(ownerId, id) {
    const account = store.account(ownerId, id);
    if (!account) fail(404, 'not_found', '接続が見つかりません。');
    return account;
  }
  function currentAccount(account) {
    const current = accountFor(account.owner_id, account.id);
    if (current.status !== 'connected' || current.generation !== account.generation) fail(409, 'connection_changed', '接続状態が変わりました。');
  }
  function publicAccount(account, ownerId) {
    const provider = providers.get(account.provider);
    const info = provider.client.accountInfo?.(store.secrets(store.account(ownerId, account.id))) || {};
    return { ...account, ...info, permission: provider.permissions.find(permission => provider.matches(permission.id, account)) };
  }
  function resource(account, ownerId) {
    const provider = providers.get(account.provider);
    const info = publicAccount(account, ownerId);
    if (info.credential_type === 'expo_session') return { ...info, api: provider.api, authentication: { method: 'POST', credential_endpoint: '/v1/accounts/' + account.id + '/credentials', type: 'expo_session', header: 'expo-session', revocation: 'Stopping a runtime only stops future delivery. Disconnect this connection with provider revocation to invalidate its Expo session. No artificial expiry is applied.' } };
    return { ...info, api: provider.api, authentication: { method: 'POST', credential_endpoint: '/v1/accounts/' + account.id + '/credentials', type: provider.credentialType === 'api_key' ? 'api_key_bearer' : 'oauth2_bearer', revocation: provider.canRevoke === false ? `Stops future credential delivery only. Already delivered API keys remain usable until their provider expiry or deletion on ${provider.name}. No artificial short expiry is applied.` : 'Stops future credential issuance; already issued tokens may remain valid until expiry or provider revocation.' } };
  }
  const server = createServer(async (req, res) => {
    const send = (status, value) => { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(value)); };
    const redirect = (path) => { res.writeHead(303, { location: path }); res.end(); };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
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
        const [filename, type] = STATIC.get(CONNECT_PAGE.test(path) ? '/' : path);
        res.writeHead(200, { 'content-type': type });
        return res.end(await readFile(fileURLToPath(new URL(filename, PUBLIC))));
      }
      if (path === '/health' && method === 'GET') return send(200, { status: 'ok' });
      if (path === LOGIN_CALLBACK && method === 'GET') {
        let pending, destination = logins.get(loginToken)?.returnTo || '/';
        try {
          rateLimit('login:' + req.socket.remoteAddress, 30, 600_000);
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
      const providerCallback = path.match(/^\/oauth\/([a-z][a-z0-9-]{0,39})\/callback$/);
      if (providerCallback && method === 'GET') {
        let destination = '/';
        const connectionLocation = code => destination + '?connection=' + code + (destination === '/' && providerCallback[1] !== 'gmail' ? '&provider=' + encodeURIComponent(providerCallback[1]) : '');
        try {
          const { user, session } = await principal(req);
          if (url.searchParams.getAll('state').length !== 1 || url.searchParams.getAll('code').length > 1) fail(400, 'invalid_state', '接続をやり直してください。');
          const flow = store.takeFlow(session.id, url.searchParams.get('state'));
          if (!flow) fail(400, 'invalid_state', '接続をやり直してください。');
          if ((flow.provider || 'gmail') !== providerCallback[1]) fail(400, 'invalid_state', '接続をやり直してください。');
          const provider = providers.get(flow.provider || 'gmail');
          if (flow.accessRequestId) {
            destination = '/connect/' + flow.accessRequestId;
            requests.forUser(flow.accessRequestId, user.id, true);
          }
          if (url.searchParams.has('error')) return redirect(connectionLocation('denied'));
          const code = url.searchParams.get('code');
          if (!code || code.length > 8192) fail(400, 'invalid_state', '接続をやり直してください。');
          let previous;
          if (flow.previous) {
            previous = accountFor(user.id, flow.previous.id);
            if (previous.generation !== flow.previous.generation || previous.status === 'disconnecting') fail(409, 'connection_changed', '接続状態が変わりました。');
          }
          const result = await provider.client.exchange({ ...flow, code }, previous ? { email: previous.email, credentials: store.secrets(previous) } : undefined);
          if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
          if (flow.accessRequestId) requests.forUser(flow.accessRequestId, user.id, true);
          store.connect(user.id, { provider: provider.id, name: flow.name, purpose: flow.purpose, email: result.email, scopes: result.credentials.scopes }, result.credentials, previous);
          return redirect(connectionLocation('connected'));
        } catch (error) {
          const codes = { invalid_state: 'expired', login_required: 'expired', account_changed: 'wrong_account', already_connected: 'already_connected', scope_mismatch: 'scope', refresh_missing: 'retry', connection_changed: 'changed' };
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
        rateLimit('link-send:' + req.socket.remoteAddress, 12, 600_000);
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
      if (path === '/api/session' && method === 'POST') {
        requireOrigin(req, origin);
        await body(req);
        fail(400, 'email_link_required', 'メールのリンクからログインしてください。');
      }
      if (path === '/api/session' && method === 'DELETE') {
        requireOrigin(req, origin);
        const session = store.session(cookieToken(req));
        logins.cancel(loginToken);
        store.removeSession(cookieToken(req));
        setCookie('', 0);
        setNamedCookie('fdn_login', '', 0);
        let providerLogout = true;
        if (session) { try { await auth.logout(session.value.access_token); } catch { providerLogout = false; } }
        return send(200, { ok: true, providerLogout });
      }
      // Pairing bootstraps a runtime without a previously issued Foundation key.
      // Possessing the approval URL alone never gives access to this endpoint.
      if (path === '/v1/providers' && method === 'GET') return send(200, { providers: [...providers.providers.keys()].map(id => providers.describe(id)) });
      if (path === '/v1/access-requests' || path === '/v1/access-requests/current') {
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        const token = req.headers.authorization?.match(/^Bearer (\S+)$/)?.[1];
        const hash = requests.key(token);
        rateLimit('request-poll:' + hash, 30);
        if (path === '/v1/access-requests' && method === 'POST') {
          const input = await body(req);
          const name = nameValue(input.name, '依頼元'), purpose = purposeValue(input.purpose);
          providers.permission(input.provider, input.mode);
          rateLimit('request-create:' + req.socket.remoteAddress, 12, 600_000);
          return send(201, { request: requests.summary(requests.create(token, { name, purpose, provider: input.provider, mode: input.mode }), origin) });
        }
        if (path.endsWith('/current') && method === 'GET') return send(200, { request: requests.summary(requests.current(token), origin) });
        if (path.endsWith('/current') && method === 'DELETE') {
          await body(req);
          return send(200, { request: requests.summary(requests.cancel(token), origin) });
        }
        fail(405, 'method_not_allowed', 'この操作は利用できません。');
      }
      if (path.startsWith('/api/')) {
        if (!['GET', 'HEAD'].includes(method)) requireOrigin(req, origin);
        const { user, session } = await principal(req);
        if (path === '/api/state' && method === 'GET') return send(200, { user, accounts: store.accounts(user.id).map(account => publicAccount(account, user.id)), agents: store.agents(user.id), providers: [...providers.providers.keys()].map(id => providers.describe(id)), gmail: { available: gmail.enabled } });
        const requestRoute = path.match(/^\/api\/access-requests\/([A-Za-z0-9_-]{43})(\/(?:approve|deny))?$/);
        if (requestRoute) {
          const row = requests.forUser(requestRoute[1], user.id);
          if (!requestRoute[2] && method === 'GET') return send(200, { request: { ...requests.summary(row, origin), eligible_account_ids: store.accounts(user.id).filter(account => requests.matches(row, account)).map(account => account.id) } });
          if (method === 'POST' && requestRoute[2]) {
            const input = await body(req);
            if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
            const result = requestRoute[2] === '/deny' ? requests.deny(row.id, user.id) : requests.approve(row.id, user.id, input.accountId, input.confirmationCode);
            return send(200, { request: requests.summary(result, origin) });
          }
        }
        if (path === '/api/connections/expo/login' && method === 'POST') {
          const provider = providers.get('expo');
          provider.client.check(); providers.permission('expo', 'session');
          rateLimit('expo-login:' + user.id, 10, 600_000);
          const input = await body(req);
          let result, committed = false;
          try {
            const accessRequest = input.accessRequestId === undefined ? null : requests.forUser(input.accessRequestId, user.id, true);
            if (accessRequest && (accessRequest.provider !== 'expo' || accessRequest.mode !== 'session')) fail(400, 'scope_mismatch', '依頼されたサービスと権限で接続してください。');
            if (accessRequest && input.confirmationCode !== accessRequest.confirmation_code) fail(400, 'confirmation_required', '会話の確認コードを確認してください。');
            const name = nameValue(input.name ?? 'Expo', '表示名'), purpose = purposeValue(input.purpose ?? accessRequest?.purpose ?? '');
            if (accessRequest) requests.claim(accessRequest.id, user.id);
            result = await provider.client.login(input);
            if (req.aborted || res.destroyed || localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
            if (accessRequest) requests.forUser(accessRequest.id, user.id, true);
            if (result.challenge) return send(202, { challenge: result.challenge });
            const saved = store.transaction(() => {
              const id = store.connect(user.id, { provider: 'expo', name, purpose, email: result.email, scopes: result.credentials.scopes }, result.credentials);
              const approved = accessRequest ? requests.approve(accessRequest.id, user.id, id, input.confirmationCode) : null;
              return { connected: true, account_id: id, ...(approved ? { request: requests.summary(approved, origin) } : {}) };
            });
            committed = true;
            return send(200, saved);
          } finally {
            input.password = ''; input.otp = '';
            // A cancelled/expired request or failed atomic grant must not leave
            // a newly created upstream session behind. Never log provider errors.
            if (result?.credentials && !committed) await provider.client.revoke(result.credentials).catch(() => {});
          }
        }
        const connectRoute = path.match(/^\/api\/connections\/([a-z][a-z0-9-]{0,39})\/connect$/);
        if ((path === '/api/gmail/connect' || connectRoute) && method === 'POST') {
          const provider = providers.get(connectRoute?.[1] || 'gmail');
          provider.client.check();
          rateLimit('oauth:' + user.id, 10);
          const input = await body(req);
          const accessRequest = input.accessRequestId === undefined ? null : requests.forUser(input.accessRequestId, user.id, true);
          if (accessRequest && (input.mode !== accessRequest.mode || provider.id !== accessRequest.provider)) fail(400, 'scope_mismatch', '依頼されたサービスと権限で接続してください。');
          const name = nameValue(input.name, '表示名'), purpose = purposeValue(input.purpose);
          const permission = providers.permission(provider.id, input.mode);
          const previous = input.accountId ? accountFor(user.id, input.accountId) : undefined;
          if (previous && previous.provider !== provider.id) fail(400, 'invalid_provider', '接続先のサービスが一致しません。');
          if (previous && provider.canReconnect === false) fail(400, 'new_connection_required', '新しい接続を追加し、利用許可を設定してください。');
          if (previous?.status === 'disconnecting') fail(409, 'connection_changed', '接続の解除が進行中です。');
          if (accessRequest && previous && !requests.matches(accessRequest, previous)) fail(400, 'scope_mismatch', 'この依頼では既存の読み取り範囲を変更できません。');
          if (provider.connectionMethod === 'token' || permission.connection_method === 'token') {
            const result = await provider.client.importToken({ token: input.token, mode: input.mode });
            // Network validation must not resurrect a logged-out session or an
            // expired/cancelled request. Importing alone never grants a runtime.
            if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
            if (accessRequest) requests.claim(accessRequest.id, user.id);
            const accountId = store.connect(user.id, { provider: provider.id, name, purpose, email: result.email, scopes: result.credentials.scopes }, result.credentials);
            return send(200, { connected: true, account_id: accountId });
          }
          if (provider.connectionMethod === 'password') fail(400, 'login_required', 'Expoのログイン画面から接続してください。');
          const verifier = randomBytes(32).toString('base64url');
          const redirectUri = origin + '/oauth/' + provider.id + '/callback';
          if (localSession(req).id !== session.id) fail(401, 'login_required', 'ログインしてください。');
          if (accessRequest) requests.claim(accessRequest.id, user.id);
          const flow = { provider: provider.id, name, purpose, mode: input.mode, verifier, redirectUri, accessRequestId: accessRequest?.id, previous: previous ? { id: previous.id, generation: previous.generation } : null };
          const state = store.addFlow(session.id, flow);
          return send(200, { url: provider.client.authorize({ state, verifier, redirectUri, mode: input.mode, email: previous?.email }) });
        }
        const accountRoute = path.match(/^\/api\/accounts\/([a-f0-9-]{36})(\/check)?$/);
        if (accountRoute) {
          const account = accountFor(user.id, accountRoute[1]);
          if (!accountRoute[2] && method === 'PATCH') {
            const input = await body(req);
            store.updateAccount(user.id, account.id, nameValue(input.name, '表示名'), purposeValue(input.purpose));
            return send(200, { ok: true });
          }
          if (!accountRoute[2] && method === 'DELETE') {
            const input = await body(req);
            if (typeof input.revoke !== 'boolean') fail(400, 'invalid_revoke', '接続先の許可を取り消すか選んでください。');
            const provider = providers.get(account.provider), canRevoke = provider.client.canRevoke?.(store.secrets(account)) ?? provider.canRevoke !== false;
            if (input.revoke && !canRevoke) fail(409, 'manual_revocation_required', 'キーの無効化は接続先のキー管理画面で行ってください。');
            if (disconnects.has(account.id)) fail(409, 'disconnect_in_progress', '接続を解除しています。');
            disconnects.add(account.id);
            try {
              const previous = store.disconnect(user.id, account.id);
              if (input.revoke) await providers.get(account.provider).client.revoke(store.secrets(previous));
              store.removeAccount(user.id, account.id);
              return send(200, { ok: true, provider_revoked: input.revoke, ...(account.provider === 'gmail' ? { google_revoked: input.revoke } : {}) });
            } finally { disconnects.delete(account.id); }
          }
          if (accountRoute[2] && method === 'POST') {
            await body(req);
            rateLimit('check:' + account.id, 4);
            await providers.get(account.provider).client.token(store, account, true);
            localSession(req);
            currentAccount(account);
            return send(200, { ok: true });
          }
        }
        if (path === '/api/agents' && method === 'POST') {
          const input = await body(req);
          return send(201, { agent: store.addAgent(user.id, nameValue(input.name), input.accountIds) });
        }
        const agentRoute = path.match(/^\/api\/agents\/([a-f0-9-]{36})(\/grants)?$/);
        if (agentRoute) {
          if (agentRoute[2] && method === 'PUT') {
            const input = await body(req);
            store.setGrants(user.id, agentRoute[1], input.accountIds);
            return send(200, { ok: true });
          }
          if (!agentRoute[2] && method === 'DELETE') {
            store.removeAgent(user.id, agentRoute[1]);
            return send(200, { ok: true });
          }
        }
      }
      if (path.startsWith('/v1/')) {
        const agent = actor(req);
        if (req.headers.origin && req.headers.origin !== origin) fail(403, 'origin_denied', '外部サイトからは利用できません。');
        if (path === '/v1/accounts' && method === 'GET') return send(200, { accounts: store.allowedAccounts(agent).map(account => resource(account, agent.owner_id)) });
        const route = path.match(/^\/v1\/accounts\/([a-f0-9-]{36})\/credentials$/);
        if (route && method === 'POST') {
          await body(req);
          store.requireGrant(agent, route[1]);
          const account = accountFor(agent.owner_id, route[1]);
          rateLimit('issue:' + agent.id, 30);
          const provider = providers.get(account.provider);
          const credentials = await provider.client.token(store, account);
          const expoSession = account.provider === 'expo' && credentials.credential_type === 'expo_session';
          if (!(Number.isFinite(credentials.expires_at) && credentials.expires_at > Date.now()) && !((credentials.credential_type === 'api_key' || expoSession) && credentials.expires_at === null)) fail(502, 'provider_response', '認証情報の有効期限を確認できませんでした。');
          const still = actor(req);
          if (still.generation !== agent.generation) fail(403, 'access_denied', '利用許可が変わりました。');
          store.requireGrant(agent, account.id);
          currentAccount(account);
          store.recordIssuance(agent, credentials.expires_at);
          const info = provider.client.accountInfo?.(credentials) || {};
          return send(200, { access_token: credentials.access_token, token_type: expoSession ? 'Expo-Session' : 'Bearer', credential_type: credentials.credential_type || 'oauth2_access_token', expires_at: credentials.expires_at, expires_in: credentials.expires_at === null ? null : Math.max(0, Math.floor((credentials.expires_at - Date.now()) / 1000)), scope: credentials.scopes.join(' '), account: { id: account.id, provider: account.provider, email: account.email, label: info.label || account.email }, ...(expoSession ? { credential_header: 'expo-session', session_profile: { user_id: credentials.details.actor_id, username: credentials.details.label } } : {}), ...(info.key_info ? { key_info: info.key_info } : {}), api_base_url: provider.api.base_url });
        }
      }
      fail(404, 'not_found', '指定された操作が見つかりません。');
    } catch (error) {
      if (!res.headersSent) send(error instanceof HttpError ? error.status : 500, { error: { code: error instanceof HttpError ? error.code : 'internal_error', message: error instanceof HttpError ? error.message : '処理を完了できませんでした。' } });
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
