import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { workspaceView } from '../web/workspace-view.js';
import { createI18n, resolveLocale } from '../web/i18n.js';

const mode = process.argv[2], passkey = mode.startsWith('passkey-'), id = 'a'.repeat(43);
const initialLocale = mode === 'account-settings-en' ? 'en' : 'ja', accountMode = mode.startsWith('account-');
const path = accountMode ? '/account' : mode === 'boot' ? '/services' : ['deny', 'transfer'].includes(mode) ? '/requests/' + id : mode === 'editing' ? '/secrets'
  : mode === 'confirm' ? '/signin/confirm#email=owner%40example.test&token=' + id : '/';
const dom = new JSDOM(`<!doctype html><html lang="${initialLocale}"><body><div id="app">${workspaceView(path, { pending: true, t: createI18n(initialLocale).t })}</div>
  <dialog id="dialog"></dialog><div id="notice"></div><footer id="public-info"><a data-i18n="server.docs.api">API仕様</a></footer></body></html>`,
{ url: 'https://foundation.test' + path, pretendToBeVisual: true });
const w = dom.window;
w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
w.HTMLDialogElement.prototype.close = function () { this.open = false; this.dispatchEvent(new w.Event('close')); };
w.scrollTo = () => {};
for (const name of ['document', 'window', 'location', 'history', 'sessionStorage', 'navigator', 'HTMLElement', 'HTMLFormElement', 'MutationObserver', 'Event', 'InputEvent', 'FormData']) {
  Object.defineProperty(globalThis, name, { value: w[name], configurable: true });
}
globalThis.scrollX = 0; globalThis.scrollY = 0; globalThis.matchMedia = () => ({ matches: false });

const tick = () => new Promise(resolve => setTimeout(resolve, 10));
async function until(predicate) {
  for (let attempt = 0; attempt < 200 && !predicate(); attempt++) await tick();
  assert.ok(predicate(), 'the operation did not settle');
}
const pickerSelector = '[data-action="change-language"]';
function assertPlacement(account = accountMode) {
  assert.equal(document.querySelector('.topbar ' + pickerSelector), null, 'the permanent header has no language control');
  assert.equal(document.querySelectorAll(pickerSelector).length, account ? 1 : 0);
  if (account) assert.ok(document.querySelector('main [aria-labelledby="language-title"] ' + pickerSelector));
}
function change(locale) {
  let picker = document.querySelector(pickerSelector);
  // Keep defensive coverage of the unchanged locale guards even on screens that
  // no longer expose a picker. These injected events are not user-facing controls.
  const guardProbe = !accountMode;
  if (guardProbe) {
    assertPlacement(false);
    picker = document.createElement('select');
    picker.dataset.action = 'change-language';
    picker.innerHTML = '<option value="ja">日本語</option><option value="en">English</option>';
    document.body.append(picker);
  } else assertPlacement();
  picker.value = locale;
  picker.dispatchEvent(new w.Event('change', { bubbles: true }));
  if (guardProbe) picker.remove();
}
const heading = () => document.querySelector('main h1')?.textContent;
const overview = { user: { id: 'owner', email: 'owner@example.test' }, principal: { id: 'owner', name: 'Keeper Sirius' },
  secrets: [], connections: [], services: [], catalog: [], apps: [], agents: [], principals: [], webauthn_credentials: [], functions: [], environments: [] };
const request = { id, to: 'owner', requester_name: 'Test', authorization_details: [{ type: 'relation', relation: 'agent' }], status: 'pending', expires_at: Date.now() + 60_000 };
if (mode === 'transfer') {
  request.authorization_details[0].relation = 'transfer_grant';
  request.object = { id: 'resource', name: '利用者の名前' };
}
let signedIn = accountMode || ['boot', 'deny', 'transfer', 'editing'].includes(mode), release, bootWaited = false;
const calls = [], copied = [];
if (mode === 'account-transfer') {
  Object.defineProperty(navigator, 'clipboard', { value: { writeText: async value => { copied.push(value); } } });
}

if (passkey) {
  w.PublicKeyCredential = function () {};
  const raw = new Uint8Array(32).buffer;
  const credential = { id: 'testCredential', rawId: raw, type: 'public-key',
    getClientExtensionResults: () => ({ prf: { results: { first: raw } } }),
    response: { clientDataJSON: raw, authenticatorData: raw, signature: raw, attestationObject: raw } };
  const pending = new Promise(resolve => { release = () => resolve(credential); });
  Object.defineProperty(navigator, 'credentials', { value: { get: () => pending, create: () => pending } });
}
globalThis.fetch = async (url, options = {}) => {
  calls.push({ url, options });
  let data, status = 200;
  if (url === '/v1/overview') {
    if (mode === 'boot' && !bootWaited) { bootWaited = true; await new Promise(resolve => { release = resolve; }); }
    if (signedIn) data = overview;
    else { status = 401; data = { error: { code: 'signin_required', message: 'Sign in' } }; }
  } else if (url === '/v1/signin' && options.method === 'GET') data = { available: true, pending: null };
  else if (url === '/v1/signin' || url === '/v1/signin/verify') { status = 400; data = { error: { code: 'invalid_input', message: 'Sample error' } }; }
  else if (url.endsWith('/options')) data = { options: { challenge: 'AAAAAAAA', user: { id: 'b3duZXI', name: 'Keeper Sirius', displayName: 'Keeper Sirius' }, allowCredentials: [] } };
  else if (url === '/v1/principals' || url === '/v1/signin/webauthn') { signedIn = true; data = { return_to: '/', backed_up: mode !== 'passkey-local' }; }
  else if (url === '/v1/key') data = { key: {} };
  else if (url === '/v1/requests/' + id) data = { request };
  else if (url.endsWith('/deny')) { await new Promise(resolve => { release = resolve; }); request.status = 'denied'; data = {}; }
  else if (url.startsWith('/v1/resources?')) data = { resources: [] };
  else if (url === '/v1/usage') data = { objects: { count: 0, bytes: 0, bytes_max: 1024, count_max: 100 } };
  else throw new Error('Unexpected API operation: ' + url);
  return { ok: status < 400, status, json: async () => data };
};

const start = import('../web/app.js');
if (mode === 'boot') {
  await until(() => release);
  change('en'); await tick();
  assert.equal(document.documentElement.lang, 'ja');
  release(); await start;
  await until(() => document.documentElement.lang === 'en');
  assert.equal(heading(), 'Services');
  assert.equal(document.querySelector('#signin-form'), null);
} else {
  await start;
  assertPlacement();
  if (mode.startsWith('account-settings-')) {
    const other = initialLocale === 'ja' ? 'en' : 'ja';
    const labels = { ja: { title: 'アカウント', language: '言語' }, en: { title: 'Account', language: 'Language' } };
    const assertAccount = locale => {
      assertPlacement();
      assert.equal(document.documentElement.lang, locale);
      assert.equal(heading(), labels[locale].title);
      assert.equal(document.querySelector('#language-title').textContent, labels[locale].language);
      assert.equal(document.querySelector(pickerSelector).getAttribute('aria-label'), labels[locale].language);
      assert.equal(document.querySelector(pickerSelector).value, locale);
      assert.deepEqual([...document.querySelector(pickerSelector).options].map(option => option.textContent), ['日本語', 'English']);
    };
    assertAccount(initialLocale);
    for (const locale of [other, initialLocale, other]) {
      change(locale); await until(() => document.documentElement.lang === locale);
      assertAccount(locale);
      assert.equal(resolveLocale({ cookie: document.cookie, acceptLanguage: initialLocale }), locale, 'saved choice wins on the next request');
      const before = document.querySelector(pickerSelector);
      change(locale); await tick();
      assert.equal(document.querySelector(pickerSelector), before, 'selecting the current locale does not rerender');
    }
    for (const path of ['/', '/services', '/secrets', '/objects', '/principals', '/functions']) {
      document.querySelector('.topbar a[href="' + path + '"]').click();
      await until(() => location.pathname === path);
      assertPlacement(false);
      assert.equal(document.documentElement.lang, other);
      document.querySelector('.topbar a[href="/account"]').click();
      await until(() => location.pathname === '/account');
      assertAccount(other);
    }
    history.back(); await until(() => location.pathname === '/functions');
    assertPlacement(false);
    history.forward(); await until(() => location.pathname === '/account');
    assertAccount(other);
    assert.ok(calls.every(({ options }) => !options.method || options.method === 'GET'), 'locale preferences do not mutate account data');
    assert.equal(overview.user.id, 'owner');
    assert.equal(overview.principal.name, 'Keeper Sirius');
  } else if (mode === 'account-transfer') {
    const labels = {
      ja: { account: 'アカウント', copy: 'IDをコピー', title: '引き渡す', action: '引き渡す', recipient: '引き渡す相手の ID', close: '閉じる' },
      en: { account: 'Account', copy: 'Copy ID', title: 'Hand over', action: 'Hand over', recipient: "Recipient's ID", close: 'Close' },
    };
    const assertAccount = locale => {
      assertPlacement();
      const words = labels[locale], section = document.querySelector('[aria-labelledby="id-title"]');
      assert.equal(heading(), words.account);
      assert.equal(document.querySelector('#id-title').textContent, 'ID');
      assert.equal(section.querySelector('code').textContent, 'owner');
      assert.equal(section.querySelector('[data-action="copy-id"]').textContent.trim(), words.copy);
      assert.equal(document.querySelector('#handover-title').textContent, words.title);
      assert.equal(document.querySelector('[data-action="hand-over"]').textContent, words.action);
    };
    const assertDialog = locale => {
      const words = labels[locale], dialog = document.querySelector('#dialog');
      assert.ok(dialog.open);
      assert.equal(dialog.querySelector('#dialog-title').textContent, words.title);
      assert.equal(dialog.querySelector('label[for="handover-to"]').textContent, words.recipient);
      assert.equal(dialog.querySelector('[type="submit"]').textContent, words.action);
      assert.equal(dialog.querySelector('[data-action="close-dialog"]').getAttribute('aria-label'), words.close);
      assert.equal(dialog.querySelector('#handover-to').name, 'to');
    };
    const assertNoTransfer = () => {
      assert.equal(calls.filter(({ url }) => url.endsWith('/transfer')).length, 0, 'changing language never transfers ownership');
      assert.equal(calls.filter(({ url }) => url.endsWith('/public-key')).length, 0, 'changing language never starts the transfer flow');
      assert.ok(calls.every(({ options }) => options.method === 'GET' || !options.method), 'copy, language changes, and cancellation do not write to the API');
    };
    assertAccount('ja');
    document.querySelector('[data-action="copy-id"]').click();
    await until(() => copied.length === 1);
    assert.deepEqual(copied, ['owner']);
    change('en'); await until(() => document.documentElement.lang === 'en' && heading() === labels.en.account);
    assertAccount('en');
    document.querySelector('[data-action="copy-id"]').click();
    await until(() => copied.length === 2);
    assert.deepEqual(copied, ['owner', 'owner'], 'the copied ID never changes with the display language');
    assertNoTransfer();

    for (const [locale, next] of [['en', 'ja'], ['ja', 'en']]) {
      document.querySelector('[data-action="hand-over"]').click();
      await until(() => document.querySelector('#handover-to'));
      assertDialog(locale);
      const input = document.querySelector('#handover-to'), form = input.form;
      const targetId = 'recipient-unique-' + locale;
      input.value = targetId;
      input.dispatchEvent(new w.Event('input', { bubbles: true }));
      change(next); await tick();
      assert.equal(document.documentElement.lang, locale, 'language changes wait for the transfer dialog to close');
      assert.equal(document.querySelector('#handover-to'), input, 'the exact dirty target input is preserved');
      assert.equal(input.form, form, 'the original form and submission closure survive');
      assert.equal(input.value, targetId);
      assert.ok(!document.querySelector('.language-status').hidden);
      assertDialog(locale);
      assertNoTransfer();
      // Cancelling the queued language change also leaves the entered ID alone.
      change(locale); await tick();
      assert.ok(document.querySelector('.language-status').hidden);
      assert.equal(document.querySelector('#handover-to'), input);
      assert.equal(input.value, targetId);
      change(next); await tick();
      document.querySelector('#dialog [data-action="close-dialog"]').click();
      await until(() => document.documentElement.lang === next && heading() === labels[next].account);
      assert.ok(!document.querySelector('#dialog').open);
      assert.equal(document.querySelector('#handover-to'), null);
      assertAccount(next);
      assertNoTransfer();
      assert.ok(!document.cookie.includes(targetId));
    }
    assert.equal(overview.user.id, 'owner');
    assert.equal(overview.principal.name, 'Keeper Sirius');
  } else if (mode === 'transfer') {
    assert.ok(document.querySelector('.access-scope').textContent.includes('所有権を別の相手に渡す'));
    change('en'); await until(() => document.documentElement.lang === 'en');
    assert.equal(document.querySelector('.access-scope').textContent, 'Transfer ownership to another principal');
    assert.ok(document.querySelector('.approval-facts').textContent.includes('利用者の名前'));
    assert.equal(request.authorization_details[0].relation, 'transfer_grant');
  } else if (mode === 'deny') {
    const button = document.querySelector('[data-action="deny-request"]');
    button.click(); assert.ok(button.disabled);
    change('en'); await tick();
    assert.equal(document.documentElement.lang, 'ja');
    assert.ok(button.isConnected && button.disabled, 'the pending operation keeps its exact disabled control');
    release(); await until(() => document.documentElement.lang === 'en');
    assert.equal(heading(), 'Access declined');
  } else if (mode === 'editing') {
    change('en'); await until(() => document.documentElement.lang === 'en');
    assert.equal(heading(), 'Secrets');
    const form = document.createElement('form');
    form.innerHTML = '<input type="password"><button type="button">Cancel</button>';
    document.querySelector('main').append(form);
    const input = form.querySelector('input'); input.value = 'do-not-lose';
    let clicks = 0; form.querySelector('button').onclick = () => clicks++;
    input.dispatchEvent(new w.Event('input', { bubbles: true }));
    change('ja'); await tick();
    assert.equal(document.documentElement.lang, 'en');
    assert.ok(input.isConnected); assert.equal(input.value, 'do-not-lose');
    form.querySelector('button').click(); assert.equal(clicks, 1);
    change('en'); assert.ok(document.querySelector('.language-status').hidden);
    change('ja'); form.remove();
    await until(() => document.documentElement.lang === 'ja');
    assert.equal(heading(), 'シークレット');
    assert.ok(!document.cookie.includes('do-not-lose'));
  } else if (mode === 'signin') {
    const input = document.querySelector('#signin-email'); input.value = 'typed@example.test';
    input.dispatchEvent(new w.Event('input', { bubbles: true }));
    change('en'); await until(() => document.documentElement.lang === 'en' && document.querySelector('#signin-email'));
    assert.equal(document.querySelector('#signin-email').value, 'typed@example.test');
    assert.equal(document.querySelector('#public-info a').textContent, 'API reference');
    document.querySelector('#signin-form').dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
    await until(() => document.querySelector('.form-error')?.textContent === 'Sample error');
    change('ja'); await until(() => document.documentElement.lang === 'ja' && document.querySelector('#signin-email'));
    assert.equal(document.querySelector('#signin-email').value, 'typed@example.test');
  } else if (mode === 'confirm') {
    document.querySelector('#confirm-signin').dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
    await until(() => document.querySelector('.form-error')?.textContent === 'Sample error');
    change('en'); await until(() => document.documentElement.lang === 'en');
    assert.equal(document.querySelector('.form-error').textContent, 'Sample error');
    assert.equal(location.hash, ''); assert.ok(!document.cookie.includes(id));
  } else if (passkey) {
    const button = document.querySelector(mode === 'passkey-signin' ? '#passkey-signin' : '#passkey-start');
    button.click(); await until(() => button.disabled);
    change('en'); assert.equal(document.documentElement.lang, 'ja');
    release();
    if (mode === 'passkey-local') { await until(() => document.querySelector('#start-continue')); document.querySelector('#start-continue').click(); }
    await until(() => document.documentElement.lang === 'en' && heading() === 'Foundation');
    change('ja'); await until(() => document.documentElement.lang === 'ja');
    if (mode !== 'passkey-signin') {
      const created = calls.filter(call => call.url === '/v1/principals');
      assert.equal(created.length, 1, 'locale changes never regenerate a stored identity');
      assert.equal(JSON.parse(created[0].options.body).name, 'Keeper Sirius');
    }
    assert.equal(overview.principal.name, 'Keeper Sirius');
  } else throw new Error('Unknown fixture mode: ' + mode);
}
assert.ok(calls.every(({ options }) => ['ja', 'en'].includes(options.headers?.['X-Foundation-Locale'])));
assertPlacement();
assert.ok(!/client\./.test(document.body.textContent), 'no unresolved client resource keys');
dom.window.close();
