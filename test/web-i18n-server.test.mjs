import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fixture, USER_A } from './helpers.mjs';
import { createI18n } from '../web/i18n.js';
import { localizeErrorMessage } from '../src/web-i18n.mjs';

const en = createI18n('en').t, ja = createI18n('ja').t;

test('SSR resolves request locale for public, pending and authenticated shells', async t => {
  const f = await fixture(t, { signin: false });
  const english = await f.request('/', { headers: { 'accept-language': 'fr;q=1, en-US;q=0.9, ja;q=0.3' } });
  assert.match(english.text, /<html lang="en">/);
  assert.match(english.text, /API reference/);
  assert.match(english.text, /Enable JavaScript to sign in\./);
  assert.equal(english.headers.get('content-language'), 'en');
  assert.equal(english.headers.get('vary'), 'Accept-Language, Cookie');
  assert.doesNotMatch(english.text, /data-action="change-language"/);
  assert.doesNotMatch(english.text, /foundation-(locale|title|app|noscript|importmap)/);
  const japanese = await f.request('/', { headers: { cookie: 'foundation_locale=ja', 'accept-language': 'en-US' } });
  assert.match(japanese.text, /<html lang="ja">/);
  assert.match(japanese.text, /API仕様/);
  const pending = await f.request('/services', { headers: { cookie: 'foundation_locale=en' } });
  assert.match(pending.text, /<title>Services · Foundation<\/title>/);
  assert.match(pending.text, /aria-label="Loading"/);
  const confirmation = await f.request('/signin/confirm', { headers: { cookie: 'foundation_locale=en' } });
  assert.match(confirmation.text, /<html lang="en">/);
  assert.match(confirmation.text, /Enable JavaScript to sign in\./);
  await f.signin();
  const authenticated = await f.request('/account', { headers: { cookie: f.cookie() + '; foundation_locale=en' } });
  assert.match(authenticated.text, /<title>Account · Foundation<\/title>/);
  assert.match(authenticated.text, /Sign out/);
  assert.match(authenticated.text, /Access management/);
  assert.match(authenticated.text, /aria-current="page">Account/);
  for (const response of [japanese, pending, confirmation, authenticated]) {
    assert.doesNotMatch(response.text, /data-action="change-language"/, 'SSR shells never show the account-only control');
  }
});

test('concurrent JA and EN requests never share a mutable locale', async t => {
  const f = await fixture(t, { signin: false });
  const responses = await Promise.all(Array.from({ length: 24 }, (_, index) => {
    const locale = index % 2 ? 'en' : 'ja';
    return f.request('/secrets', { headers: { cookie: 'foundation_locale=' + locale } }).then(response => ({ locale, response }));
  }));
  for (const { locale, response } of responses) {
    assert.match(response.text, new RegExp('<html lang="' + locale + '">'));
    assert.match(response.text, locale === 'en' ? /<title>Secrets · Foundation<\/title>/ : /<title>シークレット · Foundation<\/title>/);
  }
});

test('JSON errors opt in only through an exact supported Web locale header', async t => {
  const f = await fixture(t, { signin: false });
  const path = '/v1/principals/me';
  const options = { headers: { cookie: 'foundation_locale=en', 'accept-language': 'en-US' } };
  const baseline = await f.request(path, options);
  assert.equal(baseline.json.error.message, 'サインインしてください。');
  for (const header of ['en-US', 'fr', 'en,ja', 'EN', '']) {
    const response = await f.request(path, { headers: { ...options.headers, 'x-foundation-locale': header } });
    assert.deepEqual(response.json, baseline.json);
  }
  const translated = await f.request(path, { headers: { 'x-foundation-locale': 'en' } });
  assert.equal(translated.status, baseline.status);
  assert.equal(translated.json.error.code, baseline.json.error.code);
  assert.equal(translated.json.error.message, 'Sign in to continue.');
  const japanese = await f.request(path, { headers: { ...options.headers, 'x-foundation-locale': 'ja' } });
  assert.deepEqual(japanese.json, baseline.json);
  const schema = await f.request('/v1/signin', { method: 'POST', data: { email: 123 }, headers: { 'x-foundation-locale': 'en' } });
  assert.equal(schema.status, 400);
  assert.equal(schema.json.error.code, 'invalid_email');
  assert.equal(schema.json.error.message, 'Check the information you entered.');
  const semantic = await f.request('/v1/signin', { method: 'POST', data: { email: 'invalid' }, headers: { 'x-foundation-locale': 'en' } });
  assert.equal(semantic.json.error.message, 'Check your email address.');
});

test('errors retain dynamic context and custom data while localizing known field labels', () => {
  for (const [original, translated] of [
    ['この相手には持ち主がいません。', 'This principal has no owner.'],
    ['環境は渡せません。', 'Environments cannot be transferred.'],
    ['すでにその相手のものです。', 'This already belongs to that principal.'],
    ['その相手はすでに同じ名前のものを持っています。', 'That principal already owns an item with the same name.'],
  ]) {
    assert.equal(localizeErrorMessage(original, en), translated);
    assert.equal(localizeErrorMessage(original, ja), original);
  }
  assert.equal(localizeErrorMessage('このアプリで作った接続が3件あります。削除すると、つなぎ直すまで使えなくなります。', en), '3 connections were created with this app. Deleting it will make them unavailable until you reconnect.');
  assert.equal(localizeErrorMessage('このアプリで作った接続が1件あります。削除すると、つなぎ直すまで使えなくなります。', en), '1 connection was created with this app. Deleting it will make the connection unavailable until you reconnect.');
  assert.equal(localizeErrorMessage('ヘッダ x-custom の値が不正です。', en), 'The value of the x-custom header is invalid.');
  assert.equal(localizeErrorMessage('「利用者の名前」はすでに使われています。別の保存名を入力してください。', en), '“利用者の名前” is already in use. Enter another storage name.');
  assert.equal(localizeErrorMessage('クライアントシークレットを入力してください。', en), 'Enter Client secret.');
  assert.equal(localizeErrorMessage('利用者独自項目を入力してください。', en), 'Enter 利用者独自項目.');
  assert.equal(localizeErrorMessage('APIトークンを確認してください。', en), 'Check API token.');
  assert.equal(localizeErrorMessage('サービスの定義を確認してください（auth_schemes.token: must list fields）。', en), 'Check the service definition. auth_schemes.token must list fields.');
  assert.equal(localizeErrorMessage('Googleの利用上限に達しました。時間をおいて再度お試しください。', en), 'The Google rate limit has been reached. Try again later.');
  assert.equal(localizeErrorMessage('接続先からの認証応答を確認できませんでした。', en), 'The service returned an invalid authentication response.');
  assert.equal(localizeErrorMessage('Unknown upstream message <example>', en), 'Unknown upstream message <example>');
  assert.equal(localizeErrorMessage('登録できる接続は100件までです。', ja), '登録できる接続は100件までです。');
});

test('new transfer routes preserve API contracts and opt into Web error translations', async t => {
  const f = await fixture(t);
  const kept = await f.keep('secret', '利用者の名前', 'transfer-fixture');
  for (const locale of [null, 'ja', 'en']) {
    const result = await f.request('/v1/resources/' + kept.json.resource.id + '/transfer', {
      method: 'POST', data: { to: USER_A },
      headers: locale ? { 'x-foundation-locale': locale } : {},
    });
    assert.equal(result.status, 400);
    assert.equal(result.json.error.code, 'invalid_transfer');
    assert.equal(result.json.error.message, locale === 'en' ? 'This already belongs to that principal.' : 'すでにその相手のものです。');
  }
  const other = await f.request('/v1/principals', { method: 'POST', data: { name: '受け取る相手', key: true } });
  const moved = await f.request('/v1/resources/' + kept.json.resource.id + '/transfer', {
    method: 'POST', data: { to: other.json.principal.id }, headers: { 'x-foundation-locale': 'en' },
  });
  assert.equal(moved.status, 200, moved.text);
  assert.equal(moved.json.resource.owner_id, other.json.principal.id);
  assert.equal(moved.json.resource.name, '利用者の名前');
});

test('localized assets are same-origin and the import map has only a fixed CSP hash', async t => {
  const f = await fixture(t, { signin: false });
  const page = await f.request('/');
  const map = page.text.match(/<script type="importmap">([\s\S]*?)<\/script>/)?.[1];
  assert.deepEqual(JSON.parse(map), { imports: { i18next: '/vendor/i18next.js' } });
  const hash = createHash('sha256').update(map).digest('base64');
  const csp = page.headers.get('content-security-policy');
  assert.ok(csp.includes("'sha256-" + hash + "'"));
  assert.ok(csp.includes("frame-ancestors 'none'"));
  assert.ok(csp.includes("form-action 'self'"));
  assert.ok(!csp.includes('unsafe-inline'));
  for (const path of ['/i18n.js', '/service-i18n.js', '/locales/shared.js', '/locales/client.js', '/locales/server.js', '/locales/services.js', '/vendor/i18next.js']) {
    const response = await f.request(path);
    assert.equal(response.status, 200, path);
    assert.match(response.headers.get('content-type'), /text\/javascript/);
    assert.ok(response.headers.get('etag'), path);
    const unchanged = await f.request(path, { headers: { 'if-none-match': response.headers.get('etag') } });
    assert.equal(unchanged.status, 304, path);
  }
  assert.equal((await f.request('/locales/unknown.js')).status, 404);
  const invalid = await f.request('/', { headers: { cookie: 'foundation_locale=%3Cscript%3E', 'accept-language': 'en-US' } });
  assert.match(invalid.text, /<html lang="en">/);
  assert.ok(!invalid.text.includes('&lt;script&gt;'));
});
