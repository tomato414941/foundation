import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { workspaceView } from '../web/workspace-view.js';

const mode = process.argv[2], passkey = mode.startsWith('passkey-'), id = 'a'.repeat(43);
const path = mode === 'account-transfer' ? '/account' : mode === 'boot' ? '/services' : ['deny', 'transfer'].includes(mode) ? '/requests/' + id : mode === 'editing' ? '/secrets'
  : mode === 'confirm' ? '/signin/confirm#email=owner%40example.test&token=' + id : '/';
const dom = new JSDOM(`<!doctype html><html lang="ja"><body><div id="app">${workspaceView(path, { pending: true })}</div>
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
function change(locale) {
  const picker = document.querySelector('[data-action="change-language"]');
  picker.value = locale;
  picker.dispatchEvent(new w.Event('change', { bubbles: true }));
}
const heading = () => document.querySelector('main h1')?.textContent;
const overview = { user: { id: 'owner', email: 'owner@example.test' }, principal: { id: 'owner', name: 'Keeper Sirius' },
  secrets: [], connections: [], services: [], catalog: [], apps: [], actors: [], principals: [], webauthn_credentials: [], functions: [], environments: [] };
const request = { id, to: 'owner', requester_name: 'Test', authorization_details: [{ type: 'relation', relation: 'agent' }], status: 'pending', expires_at: Date.now() + 60_000 };
if (mode === 'transfer') {
  request.authorization_details[0].relation = 'transfer_grant';
  request.object = { id: 'resource', name: '利用者の名前' };
}
let signedIn = ['boot', 'deny', 'transfer', 'editing', 'account-transfer'].includes(mode), release, bootWaited = false;
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
  if (mode === 'account-transfer') {
    const labels = {
      ja: { account: 'アカウント', copy: 'IDをコピー', title: '持ち物をすべて渡す', action: '渡す', recipient: '渡す相手の ID', close: '閉じる' },
      en: { account: 'Account', copy: 'Copy ID', title: 'Transfer all belongings', action: 'Transfer', recipient: 'Recipient ID', close: 'Close' },
    };
    const assertAccount = locale => {
      const words = labels[locale], section = document.querySelector('[aria-labelledby="id-title"]');
      assert.equal(heading(), words.account);
      assert.equal(document.querySelector('#id-title').textContent, 'ID');
      assert.equal(section.querySelector('code').textContent, 'owner');
      assert.equal(section.querySelector('[data-action="copy-id"]').textContent.trim(), words.copy);
      assert.equal(document.querySelector('#transfer-title').textContent, words.title);
      assert.equal(document.querySelector('[data-action="transfer-all"]').textContent, words.action);
    };
    const assertDialog = locale => {
      const words = labels[locale], dialog = document.querySelector('#dialog');
      assert.ok(dialog.open);
      assert.equal(dialog.querySelector('#dialog-title').textContent, words.title);
      assert.equal(dialog.querySelector('label[for="transfer-to"]').textContent, words.recipient);
      assert.equal(dialog.querySelector('[type="submit"]').textContent, words.action);
      assert.equal(dialog.querySelector('[data-action="close-dialog"]').getAttribute('aria-label'), words.close);
      assert.equal(dialog.querySelector('#transfer-to').name, 'to');
    };
    const assertNoTransfer = () => {
      assert.equal(calls.filter(({ url }) => url.endsWith('/transfer')).length, 0, 'changing language never transfers ownership');
      assert.equal(calls.filter(({ url }) => url.endsWith('/public-key')).length, 0, 'changing language never starts the transfer flow');
      assert.ok(calls.every(({ options }) => options.method === 'GET'), 'copy, language changes, and cancellation do not write to the API');
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
      document.querySelector('[data-action="transfer-all"]').click();
      assertDialog(locale);
      const input = document.querySelector('#transfer-to'), form = input.form;
      const targetId = 'recipient-unique-' + locale;
      input.value = targetId;
      input.dispatchEvent(new w.Event('input', { bubbles: true }));
      change(next); await tick();
      assert.equal(document.documentElement.lang, locale, 'language changes wait for the transfer dialog to close');
      assert.equal(document.querySelector('#transfer-to'), input, 'the exact dirty target input is preserved');
      assert.equal(input.form, form, 'the original form and submission closure survive');
      assert.equal(input.value, targetId);
      assert.ok(!document.querySelector('.language-status').hidden);
      assertDialog(locale);
      assertNoTransfer();
      // Cancelling the queued language change also leaves the entered ID alone.
      change(locale); await tick();
      assert.ok(document.querySelector('.language-status').hidden);
      assert.equal(document.querySelector('#transfer-to'), input);
      assert.equal(input.value, targetId);
      change(next); await tick();
      document.querySelector('#dialog [data-action="close-dialog"]').click();
      await until(() => document.documentElement.lang === next && heading() === labels[next].account);
      assert.ok(!document.querySelector('#dialog').open);
      assert.equal(document.querySelector('#transfer-to'), null);
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
assert.ok(!/client\./.test(document.body.textContent), 'no unresolved client resource keys');
dom.window.close();
