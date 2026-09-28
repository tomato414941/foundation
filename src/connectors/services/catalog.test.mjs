import test from 'node:test';
import assert from 'node:assert/strict';
import { SERVICES } from './catalog.mjs';
import { serviceClient, serviceConnector, create } from './index.mjs';
import { fixture } from '../../../test/helpers.mjs';

// Each service is data; these tests hold every entry to what it says. A fake answers at the addresses the entry names,
// in the shape the entry reads, so a connection runs end to end through an app the holder registered.
const SAMPLE = { domain: 'example.cybozu.com', shop: 'example', subdomain: 'example', tenant: 'contoso.onmicrosoft.com' };
const put = (target, path, value) => { const keys = path.split('.'); let at = target; for (const key of keys.slice(0, -1)) at = at[key] ??= {}; at[keys.at(-1)] = value; return target; };
const fill = (template, values) => template.replace(/\{([a-z_]+)\}/g, (_, name) => values[name]);
const reply = (status, body) => ({ ok: status >= 200 && status < 300, status, text: JSON.stringify(body) });

function fakeFor(definition, values) {
  const oauth = definition.oauth, calls = [], ids = [].concat(oauth.identity?.id ?? []);
  const kept = { instance_url: 'https://example.my.salesforce.com', id: 'https://login.salesforce.com/id/00D000000000001/005000000000001' };
  const who = body => { ids.forEach((path, index) => put(body, path, 'id-' + index)); const label = [].concat(oauth.identity?.label ?? [])[0]; if (label) put(body, label, 'someone@example.test'); return body; };
  const ok = oauth.okField ? { [oauth.okField]: true } : {};
  const fetcher = async (url, options = {}) => {
    calls.push({ url, options });
    if (url === fill(oauth.token, values)) {
      const body = { ...ok, access_token: 'access-' + calls.length, refresh_token: 'refresh-' + calls.length, expires_in: 3600, token_type: 'bearer', scope: 'granted' };
      for (const name of oauth.keep ?? []) body[name] = kept[name];
      return reply(200, oauth.identity?.from === 'token' ? who(body) : body);
    }
    if (oauth.identity?.url && url.startsWith(fill(oauth.identity.url, { ...values, ...kept, access_token: '' }).replace(/\/$/, '') || '\0')) return reply(200, who({ ...ok }));
    if (oauth.revoke && url.startsWith(fill(oauth.revoke.url, { ...values, refresh_token: '' }))) return reply(200, { ...ok });
    throw new Error(definition.key + ': unexpected request to ' + url);
  };
  return { calls, fetcher };
}

async function connectThroughApp(t, definition) {
  const values = { ...definition.oauth.defaults, ...Object.fromEntries((definition.appFields ?? []).map(field => [field.name, SAMPLE[field.name]])) };
  const fake = fakeFor(definition, values), connector = serviceConnector(definition, serviceClient(definition, {}, { fetcher: fake.fetcher }));
  const f = await fixture(t, { connectors: [connector] });
  const registered = await f.request('/v1/holdings?kind=app&name=' + definition.key, { method: 'PUT', data: { connector: connector.id, client_id: 'own-client', client_secret: 'own-secret',
    ...Object.fromEntries((definition.appFields ?? []).map(field => [field.name, SAMPLE[field.name]])) } });
  assert.equal(registered.status, 200, definition.key + ' ' + registered.text);
  const started = await f.request('/v1/connections', { method: 'POST', data: { connector: connector.id, app: registered.json.holding.id, ...(definition.scopes ? { scopes: ['one', 'two'] } : {}) } });
  assert.equal(started.status, 200, definition.key + ' ' + started.text);
  const url = new URL(started.json.url), done = await f.callback(url, 'code-1');
  assert.match(done.headers.get('location'), /connection=connected/, definition.key + ' ' + done.headers.get('location'));
  const connection = (await f.request('/v1/overview')).json.grants.find(item => item.connector === connector.id);
  return { f, fake, url, connector, connection, values };
}

for (const definition of SERVICES) {
  test(`${definition.name}: 利用者のOAuthアプリを通して、定義どおりの同意画面・トークン交換・本人確認で接続し、トークンを渡す`, async t => {
    const { f, fake, url, connector, connection, values } = await connectThroughApp(t, definition);
    const oauth = definition.oauth, token = fake.calls.find(call => call.url === fill(oauth.token, values));
    assert.equal(url.origin + url.pathname, fill(oauth.authorize, values));
    assert.equal(url.searchParams.get('client_id'), 'own-client');
    for (const [key, value] of Object.entries(oauth.authorizeParams ?? {})) assert.equal(url.searchParams.get(key), value);
    if (definition.scopes) assert.deepEqual(url.searchParams.get('scope').split(oauth.scopeSeparator ?? ' ').sort(), [...new Set([...definition.scopes.base, 'one', 'two'])].sort());
    const sent = oauth.tokenFormat === 'json' ? JSON.parse(token.options.body) : Object.fromEntries(new URLSearchParams(token.options.body));
    assert.equal(sent.code, 'code-1');
    if (oauth.clientAuth === 'body') assert.equal(sent.client_secret, 'own-secret');
    else assert.equal(token.options.headers.authorization, 'Basic ' + Buffer.from('own-client:own-secret').toString('base64'));
    if (oauth.identity) {
      const id = oauth.identity.from === 'app' ? values[oauth.identity.id] : [].concat(oauth.identity.id).map((_, index) => 'id-' + index).join(':');
      assert.equal(connection.facts.account, id);
      if (oauth.identity.label) assert.equal(connection.label, 'someone@example.test');
    }
    const delivery = await f.deliver(connection);
    assert.equal(delivery.status, 200, delivery.text);
    const environment = delivery.json.delivery.environment;
    assert.match(environment[connector.variables[0]], /^access-/);
    for (const name of Object.keys(definition.variables ?? {})) assert.ok(environment[name], definition.key + ' delivers ' + name);
    assert.deepEqual(Object.keys(environment).filter(name => !connector.variables.includes(name)), []);
    const removed = await f.request('/v1/holdings/' + connection.id, { method: 'DELETE', data: { revoke: true } });
    assert.equal(removed.status, 200, removed.text);
    assert.equal(removed.json.service_revoked === true, Boolean(oauth.revoke), definition.key + ' revokes when it can');
  });
}

test('Foundationのアプリは設定があるサービスだけで使え、ストアやドメインごとのサービスでは使わない', () => {
  const env = Object.fromEntries(SERVICES.flatMap(definition => [['FOUNDATION_' + definition.key.toUpperCase() + '_CLIENT_ID', 'id'], ['FOUNDATION_' + definition.key.toUpperCase() + '_CLIENT_SECRET', 'secret']]));
  const offered = Object.fromEntries(create(env).map(connector => [connector.id, connector.available]));
  assert.equal(offered['notion.oauth'], true);
  assert.equal(offered['kintone.oauth'], false);
  assert.equal(offered['shopify.oauth'], false);
  assert.ok(create({}).every(connector => connector.available === false));
});
