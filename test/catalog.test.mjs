import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFINITIONS, builtins } from '../src/catalog.mjs';
import { oauthScheme, oauthClient } from '../src/schemes/oauth.mjs';
import { checkDefinition } from '../src/service-definition.mjs';
import { fixture } from './helpers.mjs';
import { pointerTokens, valueAt } from '../src/json-pointer.mjs';
import { uriTemplate } from '../src/uri-template.mjs';

// Each service is data; these tests hold every definition to what it says. A fake answers at the addresses the
// definition names, in the shape the definition reads, so a connection is made end to end.
const SAMPLE = { domain: 'example.cybozu.com', shop: 'example', subdomain: 'example', tenant: 'contoso.onmicrosoft.com', token: 'token-value' };
const put = (target, pointer, value) => { const keys = pointerTokens(pointer); let at = target; for (const key of keys.slice(0, -1)) at = at[key] ??= {}; at[keys.at(-1)] = value; return target; };
const fill = (template, values) => uriTemplate(template).expand(values);
const reply = (status, body) => ({ ok: status >= 200 && status < 300, status, text: JSON.stringify(body) });
const who = (identity, body) => {
  [].concat(identity?.id ?? []).forEach((path, index) => put(body, path, 'id-' + index));
  const label = [].concat(identity?.label ?? [])[0];
  if (label) put(body, label, 'someone@example.test');
  return body;
};

function oauthFake(spec, values) {
  const calls = [], ok = spec.ok_field ? put({}, spec.ok_field, true) : {};
  const kept = { instance_url: 'https://example.my.salesforce.com', id: 'https://login.salesforce.com/id/00D000000000001/005000000000001' };
  const fetcher = async (url, options = {}) => {
    calls.push({ url, options });
    if (url === fill(spec.token, values)) {
      const body = { ...ok, access_token: 'access-' + calls.length, refresh_token: 'refresh-' + calls.length, expires_in: 3600, token_type: 'bearer', scope: 'granted' };
      for (const name of spec.keep ?? []) body[name] = kept[name];
      return reply(200, spec.identity?.from === 'token' ? who(spec.identity, body) : body);
    }
    if (spec.identity?.url && url.startsWith(fill(spec.identity.url, { ...values, ...kept }).replace(/\/$/, '') || '\0')) return reply(200, who(spec.identity, { ...ok }));
    if (spec.revoke && url.startsWith(fill(spec.revoke.url, values))) return reply(200, { ...ok });
    throw new Error('unexpected request to ' + url);
  };
  return { calls, fetcher };
}

for (const definition of DEFINITIONS.filter(item => item.auth_schemes.oauth && !item.auth_schemes.oauth.adapter)) {
  const spec = definition.auth_schemes.oauth;
  test(`${definition.name}: 利用者のOAuthアプリを通して、定義どおりの同意画面・トークン交換・本人確認で接続し、トークンを渡し、取り消す`, async t => {
    const values = { ...spec.defaults, ...Object.fromEntries((spec.app_fields ?? []).map(field => [field.name, SAMPLE[field.name]])) };
    const fake = oauthFake(spec, values);
    const f = await fixture(t, { services: [{ definition, schemes: { oauth: oauthScheme(definition, oauthClient(definition, {}, { fetcher: fake.fetcher })) } }] });
    const app = await f.request('/v1/principals/me/resources?kind=app&name=' + definition.id, { method: 'PUT', data: { service: definition.id, client_id: 'own-client', client_secret: 'own-secret',
      ...Object.fromEntries((spec.app_fields ?? []).map(field => [field.name, SAMPLE[field.name]])) } });
    assert.equal(app.status, 200, app.text);
    const started = await f.request('/v1/connections', { method: 'POST', data: { service: definition.id, app: app.json.resource.id, ...(spec.scopes ? { scopes: ['one', 'two'] } : {}) } });
    assert.equal(started.status, 200, started.text);
    const url = new URL(started.json.url), done = await f.callback(url, 'code-1');
    assert.match(done.headers.get('location'), /result=connected/, done.headers.get('location'));
    assert.equal(url.origin + url.pathname, fill(spec.authorize, values));
    assert.equal(url.searchParams.get('client_id'), 'own-client');
    for (const [key, value] of Object.entries(spec.authorize_params ?? {})) assert.equal(url.searchParams.get(key), value);
    if (spec.scopes) assert.deepEqual(url.searchParams.get('scope').split(spec.scope_separator ?? ' ').sort(), [...new Set([...spec.scopes.base, 'one', 'two'])].sort());
    const token = fake.calls.find(call => call.url === fill(spec.token, values));
    const sent = spec.token_format === 'json' ? JSON.parse(token.options.body) : Object.fromEntries(new URLSearchParams(token.options.body));
    assert.equal(sent.code, 'code-1');
    if (spec.client_auth === 'body') assert.equal(sent.client_secret, 'own-secret');
    else assert.equal(token.options.headers.authorization, 'Basic ' + Buffer.from('own-client:own-secret').toString('base64'));
    const connection = (await f.request('/v1/principals/me/resources?kind=connection')).json.resources.find(item => item.service?.id === definition.id);
    if (spec.identity) {
      assert.equal(connection.facts.account, spec.identity.from === 'app' ? valueAt(values, spec.identity.id) : [].concat(spec.identity.id).map((_, index) => 'id-' + index).join(':'));
      if (spec.identity.label) assert.equal(connection.label, 'someone@example.test');
    }
    const injected = await f.inject(connection);
    assert.equal(injected.status, 200, injected.text);
    const environment = injected.json.injection.environment;
    for (const [name, template] of Object.entries(spec.injection)) if (template === '/access_token') assert.match(environment[name], /^access-/);
    assert.deepEqual(Object.keys(environment).filter(name => !Object.keys(spec.injection).includes(name)), []);
    const removed = await f.request('/v1/resources/' + connection.id, { method: 'DELETE', data: { revoke: true } });
    assert.equal(removed.status, 200, removed.text);
    assert.equal(removed.json.service_revoked === true, Boolean(spec.revoke));
  });
}

test('Foundationのアプリは設定があるサービスだけで使え、ストアやドメインごとのサービスでは使わない', () => {
  const env = { ...Object.fromEntries(DEFINITIONS.flatMap(definition => ['CLIENT_ID', 'CLIENT_SECRET'].map(part => ['FOUNDATION_' + definition.id.toUpperCase().replace(/-/g, '_') + '_' + part, 'value']))), FOUNDATION_EBAY_RUNAME: 'value' };
  const offered = Object.fromEntries(builtins(env).map(entry => [entry.definition.id, entry.schemes.oauth?.available]));
  assert.equal(offered.notion, true);
  assert.equal(offered.kintone, false);
  assert.equal(offered.shopify, false);
  assert.ok(builtins({}).filter(entry => !entry.definition.auth_schemes.oauth?.adapter).every(entry => entry.schemes.oauth?.available !== true));
});

test('利用者のサービスの定義は、運営の定義と同じ規則で確かめ、コードの名前は運営の定義にだけ許す', () => {
  const oauth = { authorize: 'https://notes.example/authorize', token: 'https://notes.example/token', injection: { NOTES_TOKEN: '/access_token' } };
  assert.equal(checkDefinition({ name: 'Notes', auth_schemes: { oauth } }).name, 'Notes');
  for (const [broken, where] of [
    [{ name: 'Notes', auth_schemes: { oauth: { ...oauth, authorize: 'http://notes.example/authorize' } } }, 'definition.auth_schemes.oauth.authorize'],
    [{ name: 'Notes', auth_schemes: { oauth: { ...oauth, injection: { NOTES_TOKEN: '/password' } } } }, 'definition.auth_schemes.oauth.injection.NOTES_TOKEN'],
    [{ name: 'Notes', auth_schemes: { oauth: { adapter: 'github' } } }, 'definition.auth_schemes.oauth'],
    [{ id: 'notes', name: 'Notes', auth_schemes: { oauth } }, 'definition.id'],
    [{ name: 'Notes', unknown: true, auth_schemes: { oauth } }, 'definition'],
  ]) assert.throws(() => checkDefinition(broken), error => error.where === where, where);
});
