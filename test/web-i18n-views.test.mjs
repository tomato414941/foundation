import test from 'node:test';
import assert from 'node:assert/strict';
import { createI18n } from '../web/i18n.js';
import { brand, languagePicker, loading, pageTitle, pages, pendingView, workspaceView } from '../web/workspace-view.js';
import { detailOf, knownRequestKind, requestResultView } from '../web/request-view.js';
import { localizeService } from '../web/service-i18n.js';
import * as shared from '../web/locales/shared.js';
import * as services from '../web/locales/services.js';
import { DEFINITIONS } from '../src/catalog.mjs';
import { appFieldsOf } from '../src/apps.mjs';

const ja = createI18n('ja').t, en = createI18n('en').t;
const request = (type, status, more = {}) => ({ authorization_details: [{ type }], status, ...more });
const japanese = /[\u3040-\u30ff\u3400-\u9fff]/u;

function serviceView(definition) {
  return { ...structuredClone(definition), catalog: true, auth_schemes: Object.fromEntries(Object.entries(definition.auth_schemes).map(([name, spec]) => [name, {
    ...structuredClone(spec), ...(name === 'oauth' ? { app_fields: appFieldsOf(definition) } : {}),
  }])) };
}

function nonPresentation(value) {
  if (Array.isArray(value)) return value.map(nonPresentation);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !['label', 'placeholder', 'note', 'instructions'].includes(key)).map(([key, item]) => [key, nonPresentation(item)]));
  return value;
}

test('shared and catalog dictionaries have complete locale parity', () => {
  for (const dictionary of [shared, services]) {
    assert.deepEqual(Object.keys(dictionary.ja).sort(), Object.keys(dictionary.en).sort());
    for (const locale of ['ja', 'en']) for (const [key, value] of Object.entries(dictionary[locale])) {
      assert.equal(typeof value, 'string', key);
      assert.ok(value.length, key);
      assert.equal(createI18n(locale).t(key), value, key);
    }
  }
});

test('workspace navigation, titles, pending states and language control use the chosen locale', () => {
  assert.equal(pages['/services'], 'nav.services');
  assert.equal(pageTitle('/services'), 'サービス · Foundation');
  assert.equal(pageTitle('/services', en), 'Services · Foundation');
  assert.equal(pageTitle('/'), 'Foundation');
  assert.equal(pageTitle('__proto__', en), 'Foundation');
  for (const [t, locale, servicesLabel, loadingLabel, accountLabel] of [[ja, 'ja', 'サービス', '読み込み中', 'アカウント'], [en, 'en', 'Services', 'Loading', 'Account']]) {
    const html = workspaceView('/services', { pending: true, t });
    assert.ok(html.includes(`<h1>${servicesLabel}</h1>`));
    assert.ok(html.includes(`aria-label="${loadingLabel}"`));
    assert.ok(html.includes(`href="/account">${accountLabel}</a>`));
    assert.match(html, /href="\/services" aria-current="page"/);
    assert.match(html, /data-action="signout" disabled/);
    assert.match(html, /<main tabindex="-1" aria-busy="true">/);
    assert.ok(html.includes(`value="${locale}" lang="${locale}" selected`));
    assert.match(pendingView('/services', { t }), /aria-busy="true"/);
    assert.ok(pendingView('/services', { t }).includes(`<h1>${servicesLabel}</h1>`));
  }
  assert.match(brand(en), /Foundation home/);
  assert.match(loading(en), /aria-label="Loading"/);
  assert.match(languagePicker(en), /aria-label="Language"/);
  assert.match(workspaceView('/services', { t: en }), /data-action="signout">Sign out/);
  assert.doesNotMatch(workspaceView('/services', { t: en }), /aria-busy/);
});

test('shared HTML escapes translated text at every HTML sink', () => {
  const hostile = () => '<img src=x onerror="alert(1)">&';
  for (const html of [brand(hostile), loading(hostile), languagePicker(hostile, 'en'), workspaceView('/services', { pending: true, t: hostile }), pendingView('/services', { t: hostile })]) {
    assert.doesNotMatch(html, /<img/);
    assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;&amp;/);
  }
});

test('request results retain completion, authorization kind, and route semantics in both locales', () => {
  for (const [type, granted, denied, href] of [
    ['relation', 'Permission granted', 'Permission declined', '/principals'],
    ['connection', 'Connected', 'Connection declined', '/services'],
    ['secret', 'Saved', 'Not saved', '/secrets'],
    ['app', 'OAuth app registered', 'Not registered', '/services'],
  ]) {
    const done = requestResultView(request(type, 'granted'), '', en);
    assert.equal(done.title, granted); assert.equal(done.href, href); assert.equal(done.completed, true);
    assert.equal(done.description, 'You can close this window.');
    const refused = requestResultView(request(type, 'denied'), '', en);
    assert.equal(refused.title, denied); assert.equal(refused.href, href); assert.equal(refused.completed, false);
    for (const status of ['granted', 'denied', 'cancelled', 'pending']) {
      const source = request(type, status), japanese = requestResultView(source, '', ja), english = requestResultView(source, '', en);
      assert.equal(english.href, japanese.href); assert.equal(english.completed, japanese.completed);
    }
  }
  const agent = request('relation', 'granted', { authorization_details: [{ type: 'relation', relation: 'agent' }] });
  assert.equal(requestResultView(agent, '', en).title, 'Access granted');
  agent.status = 'denied'; assert.equal(requestResultView(agent, '', en).title, 'Access declined');
  assert.equal(requestResultView(request('connection', 'granted')).title, '接続しました');
  assert.equal(requestResultView(request('connection', 'cancelled', { reason: 'access_revoked' }), '', en).description, 'Access for the requester has been revoked.');
  assert.equal(requestResultView(request('connection', 'cancelled', { reason: 'requester_revoked' }), '', en).description, 'The requester has been removed.');
  for (const type of ['__proto__', 'constructor', 'toString', 'unknown']) {
    assert.equal(knownRequestKind(type), false);
    assert.deepEqual(requestResultView(request(type, 'granted'), '', en), { href: '/', label: 'Home', title: 'Request unavailable', description: 'Open the request link again.', completed: false });
  }
  assert.deepEqual(detailOf(null), {});
  assert.equal(requestResultView(null, 'A custom failure', en).description, 'A custom failure');
});

test('all built-in Web schema strings localize without changing API data or cached source', () => {
  for (const definition of DEFINITIONS) {
    const original = serviceView(definition), before = structuredClone(original);
    const translated = localizeService(original, 'en');
    assert.deepEqual(original, before, `${definition.id} source unchanged`);
    assert.deepEqual(localizeService(original, 'ja'), original, `${definition.id} Japanese source preserved`);
    assert.deepEqual(nonPresentation(translated), nonPresentation(original), `${definition.id} codes and values unchanged`);
    assert.equal(translated.name, definition.name);
    for (const [name, scheme] of Object.entries(translated.auth_schemes)) {
      if (scheme.instructions) assert.doesNotMatch(scheme.instructions, japanese, `${definition.id} instructions`);
      for (const group of ['fields', 'app_fields']) for (const field of scheme[group] || []) {
        for (const property of ['label', 'placeholder', 'note']) if (field[property]) {
          assert.doesNotMatch(field[property], japanese, `${definition.id}.${name}.${group}.${field.name}.${property}`);
        }
      }
    }
    // Alternating language is repeatable and never overwrites the original cache.
    assert.deepEqual(localizeService(localizeService(original, 'en'), 'ja'), localizeService(original, 'ja'));
  }
  const aws = localizeService(serviceView(DEFINITIONS.find(item => item.id === 'aws')), 'en');
  assert.equal(aws.auth_schemes.role.fields[0].label, 'ARN of the created IAM role');
  assert.equal(aws.auth_schemes.role.instructions, 'Choose permissions under Policies, then create the role.');
  const microsoft = localizeService(serviceView(DEFINITIONS.find(item => item.id === 'microsoft')), 'en');
  assert.equal(microsoft.auth_schemes.oauth.app_fields.find(field => field.name === 'client_id').label, 'Client ID');
  assert.match(microsoft.auth_schemes.oauth.app_fields.find(field => field.name === 'tenant').note, /Leave blank/);
});

test('custom or unrecognized services and fields remain user content, even when names match catalog entries', () => {
  const builtin = serviceView(DEFINITIONS.find(item => item.id === 'shopify'));
  for (const service of [{ ...builtin, catalog: false }, { ...builtin, catalog: undefined }, { ...builtin, id: 'my-service' }]) {
    const localized = localizeService(service, 'en');
    assert.equal(localized.name, service.name);
    assert.deepEqual(localized.auth_schemes.token, service.auth_schemes.token);
    assert.equal(localized.auth_schemes.oauth.app_fields.find(field => field.name === 'shop').label, 'ストア名');
  }
  const extra = { name: 'user_value', label: 'ストア名', note: '利用者のメモ', placeholder: '独自の値' };
  builtin.auth_schemes.token.fields.push(extra);
  assert.deepEqual(localizeService(builtin, 'en').auth_schemes.token.fields.at(-1), extra);
  assert.equal(localizeService(null, 'en'), null);
});


test('only Foundation-generated OAuth fields localize within a custom service', () => {
  const custom = { id: 'custom', name: 'クライアントID', catalog: false, auth_schemes: { oauth: { app_fields: [
    { name: 'client_id', label: 'クライアントID', required: true },
    { name: 'client_secret', label: 'クライアントシークレット', required: true, sealed: true },
    { name: 'client_id', label: 'クライアントID', required: true },
    { name: 'client_secret', label: 'クライアントシークレット', required: true },
    { name: 'domain', label: 'kintoneのドメイン', placeholder: '独自の値', note: '自分の説明' },
  ] } } };
  const original = structuredClone(custom), localized = localizeService(custom, 'en');
  assert.equal(localized.auth_schemes.oauth.app_fields[0].label, 'Client ID');
  assert.equal(localized.auth_schemes.oauth.app_fields[1].label, 'Client secret');
  assert.deepEqual(localized.auth_schemes.oauth.app_fields.slice(2), custom.auth_schemes.oauth.app_fields.slice(2));
  assert.equal(localized.name, custom.name);
  assert.deepEqual(custom, original);
  assert.equal(localizeService(custom, 'ja'), custom, 'unchanged custom presentation keeps its identity');
  const overridden = structuredClone(custom);
  overridden.auth_schemes.oauth.app_fields[0].label = '利用者のクライアントID';
  assert.equal(localizeService(overridden, 'en'), overridden, 'overridden base-field labels are user content');
  const noted = structuredClone(custom);
  noted.auth_schemes.oauth.app_fields[0].note = '利用者の説明';
  assert.equal(localizeService(noted, 'en'), noted, 'additional field metadata is user content');
  const unmarked = { ...custom, catalog: undefined };
  assert.equal(localizeService(unmarked, 'en'), unmarked);
});
