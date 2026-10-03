import { requestResultView, knownRequestKind, detailOf } from './request-view.js';
import { pages, brand, pageTitle, workspaceView, pendingView, languagePicker } from './workspace-view.js';
import * as sealing from './sealing.js';
import { createI18n, formatDate, formatNumber, compareText, isLocale } from './i18n.js';
import { localizeService } from './service-i18n.js';
const i18n = createI18n(document.documentElement.lang);
const t = (key, options) => i18n.t(key, options);
Object.defineProperty(t, 'locale', { get: () => i18n.language });
// The owner's own key: unwrapped by a passkey (its PRF output) and held only in this page, which seals what it
// keeps and opens what was sealed for it. Nothing of it is written anywhere.
let own = null, keyUnavailable = false;
const PRF_INPUT = new TextEncoder().encode('foundation-key');
const b64 = sealing.toBase64url, unb64 = sealing.fromBase64url;

const app = document.querySelector('#app'), dialog = document.querySelector('#dialog'), notice = document.querySelector('#notice');
const publicInfo = document.querySelector('#public-info');
// Language changes are local to this page. Editing dialogs and operations keep their
// original nodes and closures until complete; no secret value is copied or serialized.
let pendingLocale = null, changingLocale = false, signinBusy = false, activeOperations = 0, initializing = true;
const editedForms = new WeakSet();
const localeStatus = document.createElement('p');
localeStatus.className = 'language-status';
localeStatus.setAttribute('role', 'status');
localeStatus.setAttribute('aria-live', 'polite');
localeStatus.hidden = true;
notice.after(localeStatus);
function syncLanguagePickers() {
  document.querySelectorAll('[data-action="change-language"]').forEach(select => { select.value = pendingLocale || i18n.language; });
}
function languageChangeBlocked() {
  const hasEdits = [...document.forms].some(form => editedForms.has(form));
  return initializing || editingPage() || hasEdits || signinBusy || activeOperations > 0 || Boolean(app.querySelector('#confirm-signin button:disabled'));
}
function localizePublicInfo() {
  publicInfo?.querySelectorAll('[data-i18n]').forEach(element => { element.textContent = t(element.dataset.i18n); });
}
async function applyPendingLanguage() {
  if (!pendingLocale || changingLocale || languageChangeBlocked()) return;
  const locale = pendingLocale;
  pendingLocale = null; changingLocale = true;
  const email = app.querySelector('#signin-email')?.value || '';
  const showingSignin = Boolean(app.querySelector('#signin-form'));
  const message = app.querySelector('#signin-form .form-error')?.textContent || '';
  const confirmationError = app.querySelector('#confirm-signin .form-error')?.textContent || '';
  try {
    await i18n.changeLanguage(locale);
    document.documentElement.lang = locale;
    document.cookie = 'foundation_locale=' + locale + '; Path=/; SameSite=Lax; Max-Age=31536000' + (location.protocol === 'https:' ? '; Secure' : '');
    localizePublicInfo();
    if (isSigninConfirmation) {
      showSigninConfirmation();
      const error = app.querySelector('#confirm-signin .form-error');
      if (error) error.textContent = confirmationError;
    } else if (state) {
      app.innerHTML = workspaceView(pagePath, { t });
      render();
    } else if (showingSignin) await showSignin({ email, message });
    else {
      app.innerHTML = pendingView(pagePath, { t });
      await refresh();
    }
    localeStatus.hidden = true;
  } catch (error) { toast(error.message); }
  finally {
    changingLocale = false; syncLanguagePickers();
    if (pendingLocale) queueMicrotask(() => { void applyPendingLanguage(); });
  }
}
document.addEventListener('input', event => {
  const form = event.target.form;
  if (form && form.id !== 'signin-form') editedForms.add(form);
});
document.addEventListener('invalid', event => {
  const field = event.target;
  if (typeof field.setCustomValidity !== 'function') return;
  field.setCustomValidity('');
  const validity = field.validity;
  const key = validity.valueMissing ? 'client.validation.required' : validity.typeMismatch ? (field.type === 'email' ? 'client.validation.email' : 'client.validation.url')
    : validity.tooLong ? 'client.validation.tooLong' : validity.rangeUnderflow ? 'client.validation.minimum' : validity.rangeOverflow ? 'client.validation.maximum' : 'client.validation.invalid';
  field.setCustomValidity(t(key, { count: field.maxLength, minimum: field.min, maximum: field.max }));
}, true);
document.addEventListener('input', event => {
  if (typeof event.target.setCustomValidity === 'function') event.target.setCustomValidity('');
});
document.addEventListener('submit', event => {
  if (event.target instanceof HTMLFormElement) editedForms.add(event.target);
}, true);
document.addEventListener('change', event => {
  const picker = event.target.closest('[data-action="change-language"]');
  if (!picker) {
    if (event.target.form && event.target.form.id !== 'signin-form') editedForms.add(event.target.form);
    return;
  }
  if (!isLocale(picker.value)) { syncLanguagePickers(); return; }
  if (picker.value === i18n.language) {
    pendingLocale = null; localeStatus.hidden = true; syncLanguagePickers(); return;
  }
  pendingLocale = picker.value;
  if (languageChangeBlocked()) {
    localeStatus.textContent = t('client.language.deferred'); localeStatus.hidden = false;
    syncLanguagePickers();
  } else void applyPendingLanguage();
});
// A settled edit/operation removes its old form. Observe that lifecycle without
// touching any input, including password/file fields and the current selection.
new MutationObserver(() => {
  if (pendingLocale && !changingLocale) queueMicrotask(() => { void applyPendingLanguage(); });
}).observe(app, { childList: true, subtree: true, attributes: true, attributeFilter: ['disabled', 'aria-busy', 'class'] });

let state = null, toastTimer, signinTimer, revision = 0, refreshController, refreshDeferred = false;
const isSigninConfirmation = location.pathname === '/signin/confirm';
// A fragment is not sent in HTTP requests. Keep the emailed key only in this page's memory.
const signinLink = isSigninConfirmation ? new URLSearchParams(location.hash.slice(1)) : null;
const signinReturn = isSigninConfirmation ? new URL(location.href).searchParams.get('return_to') || '/' : '/';
if (isSigninConfirmation) history.replaceState(null, '', '/signin/confirm');
// Each request has its own URL, including a counterpart asking for access.
const requestId = location.pathname.match(/^\/requests\/([A-Za-z0-9_-]{43})$/)?.[1];
const requestApi = requestId && '/v1/requests/' + requestId;
// Opened through another product's single-use link: there is no Foundation signin, only that one request.
const linkToken = requestId ? new URLSearchParams(location.hash.slice(1)).get('link') : null;
let linked = false, back = null;
// Back to the product: its return page with how the request ended, or its refresh page when the link was no good.
const backTo = row => { if (!row) return back.refresh_url; const url = new URL(back.return_url); url.searchParams.set('foundation_status', row.status); return url.href; };
try { linked = Boolean(requestId) && sessionStorage.getItem('linked:' + requestId) === '1'; } catch {}
let page = Object.hasOwn(pages, location.pathname) ? location.pathname.slice(1) || 'home' : 'home';
let pagePath = requestId ? location.pathname : page === 'home' ? '/' : '/' + page;
let accessRequest = null, requestError = '';
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
// The lent space, laid out the way an object browser is: a prefix acts as a folder, the list is a table
// you can sort and select in, and everything acts on the level you are looking at. The keys only look
// like paths, so the levels are worked out from the keys themselves rather than fetched one at a time.
const prefixOf = url => url.pathname === '/objects' ? url.searchParams.get('prefix') || '' : '';
const objectsHref = prefix => '/objects' + (prefix ? '?' + new URLSearchParams({ prefix }) : '');
// Coming back from Stripe's page with a payment method set: the account page finishes it once.
let paymentReturn = new URL(location.href).searchParams.get('payment');
const returnTo = () => (page === 'objects' ? objectsHref(objectPrefix) : pagePath) + location.hash;
let objectPrefix = prefixOf(new URL(location.href)), objectFilter = '', objectLimit = 100, objectSort = 'updated', objectDescending = true, objectSearchPrefix = false;
let objectChosen = new Set();
function levelOf(objects) {
  const folders = new Map(), files = [];
  for (const item of objects) {
    if (!item.key.startsWith(objectPrefix)) continue;
    const rest = item.key.slice(objectPrefix.length);
    const cut = rest.indexOf('/');
    if (cut < 0) { files.push({ ...item, name: rest }); continue; }
    const name = rest.slice(0, cut + 1), found = folders.get(name) || { name, count: 0, bytes: 0, updated_at: 0 };
    found.count++; found.bytes += item.size; found.updated_at = Math.max(found.updated_at, item.updated_at);
    folders.set(name, found);
  }
  return { folders: [...folders.values()].sort((a, b) => compareText(a.name, b.name, i18n.language)), files };
}
// Only worth showing once you have stepped into something; at the top there is nowhere to go back to.
function crumbs() {
  const parts = objectPrefix.split('/').filter(Boolean);
  if (!parts.length) return '';
  const links = [`<a class="text-button" href="/objects">${esc(t('client.common.all'))}</a>`];
  let walked = '';
  for (const [at, part] of parts.entries()) {
    walked += part + '/';
    links.push(at === parts.length - 1 ? `<span aria-current="location">${esc(part)}</span>`
      : `<a class="text-button" href="${esc(objectsHref(walked))}">${esc(part)}</a>`);
  }
  return `<nav class="crumbs" aria-label="${esc(t('client.objects.path'))}">${links.join('<span aria-hidden="true">›</span>')}</nav>`;
}
const kindOf = name => { const cut = name.lastIndexOf('.'); return cut > 0 ? name.slice(cut + 1).toLowerCase() : '—'; };
function sortFiles(files) {
  const by = { name: (a, b) => compareText(a.name, b.name, i18n.language), size: (a, b) => a.size - b.size, updated: (a, b) => a.updated_at - b.updated_at };
  return [...files].sort((a, b) => (objectDescending ? -1 : 1) * by[objectSort](a, b));
}
function spaceSection() {
  const space = state.space;
  if (space === undefined) return `<section class="resource-section object-browser" aria-busy="true"><div class="content-loading" role="status" aria-label="${esc(t('client.common.loading'))}"><span></span><span></span><span></span></div></section>`;
  if (!space || !space.available) return `<section class="resource-section object-browser"><div class="access-empty"><p>${esc(t('client.objects.unavailable'))}</p><button class="text-button" data-action="retry-page">${esc(t('client.common.reload'))}</button></div></section>`;
  const needle = objectFilter.trim().toLowerCase();
  const matching = !needle ? space.objects
    : objectSearchPrefix ? space.objects.filter(item => item.key.slice(objectPrefix.length).toLowerCase().startsWith(needle))
    : space.objects.filter(item => item.key.toLowerCase().includes(needle));
  const { folders, files } = needle && !objectSearchPrefix
    ? { folders: [], files: matching.map(item => ({ ...item, name: item.key })) } : levelOf(matching);
  const sorted = sortFiles(files), shown = sorted.slice(0, objectLimit);
  const here = [...folders.map(item => objectPrefix + item.name), ...shown.map(item => item.key)];
  const allChosen = here.length > 0 && here.every(key => objectChosen.has(key));
  const column = (key, label) => `<button class="column-head" data-action="sort-objects" data-sort="${key}">${label}${objectSort === key ? (objectDescending ? ' ↓' : ' ↑') : ''}</button>`;
  const rows = folders.map(item => `<tr><td><input type="checkbox" data-action="choose-object" data-key="${esc(objectPrefix + item.name)}" ${objectChosen.has(objectPrefix + item.name) ? 'checked' : ''} aria-label="${esc(t('client.objects.selectName', { name: item.name }))}"></td>
      <td class="object-name"><span class="object-mark" aria-hidden="true">${icon('folder')}</span><a class="link-button" href="${esc(objectsHref(objectPrefix + item.name))}">${esc(item.name.slice(0, -1))}</a></td>
      <td>${esc(t('client.objects.folder'))}</td><td>${esc(kiloBytes(item.bytes))}</td><td>${esc(t('client.common.itemCount', { count: item.count }))}</td></tr>`).join('')
    + shown.map(item => `<tr><td><input type="checkbox" data-action="choose-object" data-key="${esc(item.key)}" ${objectChosen.has(item.key) ? 'checked' : ''} aria-label="${esc(t('client.objects.selectName', { name: item.name }))}"></td>
      <td class="object-name"><span class="object-mark" aria-hidden="true">${icon('note')}</span><a href="/v1/resources/${esc(item.id)}/content" download>${esc(item.name)}</a></td>
      <td>${esc(kindOf(item.name))}</td><td>${esc(kiloBytes(item.size))}</td><td>${esc(keptWhen(item.updated_at))}</td></tr>`).join('');
  const body = space.objects.length === 0 ? `<div class="access-empty"><p>${esc(t('client.objects.empty'))}</p></div>`
    : here.length === 0 ? `<div class="access-empty"><p>${needle ? esc(t('client.objects.noMatches', { filter: objectFilter })) : t('client.objects.emptyFolder')}</p></div>`
    : `<div class="object-table-wrap"><table class="object-table"><thead><tr>
        <th><input type="checkbox" data-action="choose-all" ${allChosen ? 'checked' : ''} aria-label="${esc(t('client.objects.selectAllVisible'))}"></th>
        <th>${column('name', t('client.common.name'))}</th><th>${esc(t('client.objects.type'))}</th><th>${column('size', t('client.objects.size'))}</th><th>${column('updated', t('client.objects.updated'))}</th></tr></thead>
        <tbody>${rows}</tbody></table></div>${paging(sorted.length, shown.length)}`;
  const chosen = chosenKeys();
  const tools = `<div class="object-tools"><input class="filter-field" id="object-filter" type="search" placeholder="${objectSearchPrefix ? t('client.objects.searchHereByPrefix') : t('client.objects.filterByName')}" value="${esc(objectFilter)}" autocomplete="off" aria-label="${esc(t('client.objects.filter'))}">
    <button class="text-button" data-action="toggle-search">${objectSearchPrefix ? t('client.objects.matchAnywhere') : t('client.objects.searchByPrefix')}</button>
    <button class="button secondary" data-action="copy-url" ${chosen.length === 1 && !chosen[0].endsWith('/') ? '' : 'disabled'}>${esc(t('client.objects.copyUrl'))}</button>
    <button class="button secondary danger" data-action="drop-chosen" ${chosen.length ? '' : 'disabled'}>${esc(chosen.length ? t('client.objects.deleteSelected', { count: chosen.length }) : t('client.common.delete'))}</button></div>`;
  return `<section class="resource-section object-browser" aria-label="${esc(t('client.objects.storedItems'))}"><div class="object-location"><div class="object-count">${esc(t('client.objects.count', { count: space.usage?.count ?? space.objects.length }))}</div>${crumbs()}</div>${tools}<div class="object-results">${body}</div></section>`;
}
// A folder chosen means everything under it.
function chosenKeys() {
  const all = state.space?.objects || [];
  const chosen = new Set();
  for (const key of objectChosen) {
    if (key.endsWith('/')) for (const item of all) { if (item.key.startsWith(key)) chosen.add(item.key); }
    else if (all.some(item => item.key === key)) chosen.add(key);
  }
  return [...chosen];
}
function paging(total, showing) {
  if (total <= objectLimit && objectLimit === 100) return '';
  return `<div class="object-paging"><span>${esc(t('client.objects.showingCount', { showing, count: total }))}</span>
    ${total > showing ? `<button class="button secondary" data-action="more-objects">${esc(t('client.objects.showNextHundred'))}</button>` : ''}
    ${objectLimit > 100 ? `<button class="text-button" data-action="less-objects">${esc(t('client.objects.showFirstHundred'))}</button>` : ''}</div>`;
}

// A service by its logo, when the page has one for it, or else by its initial.
const serviceLogo = service => service?.logo ? `<svg viewBox="0 0 24 24" aria-hidden="true"><use href="/service-logos.svg#${esc(service.logo)}"/></svg>`
  : service?.name ? `<span class="service-letter" aria-hidden="true">${esc([...service.name][0].toUpperCase())}</span>` : icon('key');
const icon = (name) => {
  const paths = {
    plus: '<path d="M12 5v14M5 12h14"/>', close: '<path d="m6 6 12 12M6 18 18 6"/>',
    device: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
    arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>', check: '<path d="m5 12 4 4L19 6"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    database: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
    cloud: '<path d="M7 18a5 5 0 1 1 1-9.9A6 6 0 0 1 20 10a4 4 0 0 1-1 8Z"/>',
    code: '<path d="m8 8-4 4 4 4m8-8 4 4-4 4m-2-10-4 12"/>',
    card: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 10h18"/>',
    key: '<circle cx="8" cy="14" r="4"/><path d="m11 11 8-8m-3 3 2 2m-5 1 2 2"/>',
    note: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>',
    globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    network: '<circle cx="6" cy="12" r="3"/><circle cx="18" cy="5" r="2"/><circle cx="18" cy="19" r="2"/><path d="m9 11 7-5m-7 7 7 5"/>',
    edit: '<path d="m15 5 4 4M4 20l5-1L20 8a2.8 2.8 0 0 0-4-4L5 15Z"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    'eye-off': '<path d="m3 3 18 18M10.6 5.1A12 12 0 0 1 12 5c6.5 0 10 7 10 7a19 19 0 0 1-3 3.9M6.1 6.1A22 22 0 0 0 2 12s3.5 7 10 7a12 12 0 0 0 5.9-1.9M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h3"/>',
    download: '<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>',
  };
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || ''}</svg>`;
};
const revocationNote = () => t('client.access.revocationNote');
function toast(text) {
  clearTimeout(toastTimer); notice.textContent = text; notice.hidden = false;
  toastTimer = setTimeout(() => { notice.hidden = true; }, 5500);
}
async function api(path, { method = 'GET', data, signal, headers = {} } = {}) {
  let response;
  try { response = await fetch(path, { method, signal, credentials: 'same-origin', cache: 'no-store', headers: { 'X-Foundation-Locale': i18n.language, ...(data !== undefined ? { 'content-type': 'application/json' } : {}), ...headers }, ...(data !== undefined ? { body: JSON.stringify(data) } : {}) }); }
  catch (error) { if (signal?.aborted) throw error; throw new Error(t('client.errors.networkCheck')); }
  const result = await response.json();
  signal?.throwIfAborted();
  if (!response.ok) {
    const error = new Error(result.error?.message || t('client.errors.requestFailed')); error.status = response.status; error.code = result.error?.code; error.details = result.error;
    if (response.status === 401 && !linked && path !== '/v1/session' && !path.startsWith('/v1/signin')) await showSignin();
    throw error;
  }
  return result;
}
function showSigninConfirmation() {
  document.title = t('client.signin.title') + ' · Foundation';
  const email = signinLink.get('email') || '', token = signinLink.get('token') || '';
  const valid = signinLink.getAll('email').length === 1 && signinLink.getAll('token').length === 1
    && email.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(email) && /^[A-Za-z0-9_-]{43}$/.test(token);
  app.innerHTML = `<div class="workspace signin-shell"><header class="topbar">${brand(t)}</header><main class="signin-main">
    <h1>${valid ? t('client.signin.title') : t('client.signin.checkLink')}</h1>
    ${valid ? `<p class="signin-address">${esc(email)}</p><form id="confirm-signin"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.signin.title'))} ${icon('arrow')}</button></form>
    <p class="signin-footer"><a href="/">${esc(t('client.signin.useAnotherEmail'))}</a></p>` : `<p class="signin-help">${esc(t('client.signin.reopenEmailLink'))}</p><p class="signin-footer"><a href="/">${esc(t('client.signin.sendEmail'))}</a></p>`}</main></div>`;
  if (!valid) return;
  const form = document.querySelector('#confirm-signin'), button = form.querySelector('button');
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (button.disabled) return;
    button.disabled = true;
    form.querySelector('.form-error').textContent = '';
    try {
      const result = await api('/v1/signin/verify', { method: 'POST', data: { email, token, return_to: signinReturn } });
      location.replace(result.return_to);
    } catch (error) {
      form.querySelector('.form-error').textContent = error.message;
      button.disabled = false; editedForms.delete(form); void applyPendingLanguage();
    }
  });
}
// Passkeys, through the browser's WebAuthn. The server speaks the JSON forms of the options and answers; these turn
// them into what navigator.credentials takes and back.
const passkeysWork = () => Boolean(window.PublicKeyCredential && navigator.credentials);
const bytes = text => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0));
const text64 = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const described = list => (list || []).map(item => ({ ...item, id: bytes(item.id) }));
// What a passkey yields for the key (PRF), when it does; the results never go to the server.
const yieldedBy = made => { const first = made.getClientExtensionResults().prf?.results?.first; return first ? new Uint8Array(first) : null; };
async function makePasskey(options) {
  const made = await navigator.credentials.create({ publicKey: { ...options, challenge: bytes(options.challenge), user: { ...options.user, id: bytes(options.user.id) }, excludeCredentials: described(options.excludeCredentials), extensions: { prf: { eval: { first: PRF_INPUT } } } } });
  return { yielded: yieldedBy(made), credential: { id: made.id, rawId: text64(made.rawId), type: made.type, authenticatorAttachment: made.authenticatorAttachment ?? undefined, clientExtensionResults: {},
    response: { clientDataJSON: text64(made.response.clientDataJSON), attestationObject: text64(made.response.attestationObject), transports: made.response.getTransports?.() || [] } } };
}
// The key behind this passkey: unwrapped with what it yields; made and wrapped, when the principal has none yet.
async function unlockWith(credentialId, yielded) {
  own = null; keyUnavailable = false;
  if (!yielded) { keyUnavailable = true; return; }
  const { key } = await api('/v1/key');
  if (!key.public_key) {
    const made = await sealing.generateKey();
    await api('/v1/key', { method: 'PUT', data: { public_key: b64(made.publicKey), wraps: { [credentialId]: b64(await sealing.wrap(made.privateKey, yielded)) } } });
    own = made; return;
  }
  const wrapped = key.wraps?.[credentialId];
  if (!wrapped) { keyUnavailable = true; return; }
  own = { privateKey: await sealing.unwrap(unb64(wrapped), yielded), publicKey: unb64(key.public_key) };
}
// Opening the key again, after the page was loaded anew: any passkey of the owner's, asked here for what it yields.
async function unlockKey() {
  const given = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: location.hostname, allowCredentials: [], userVerification: 'preferred', extensions: { prf: { eval: { first: PRF_INPUT } } } } });
  await unlockWith(given.id, yieldedBy(given));
}
// Where to go once signed in: within the workspace without leaving the page, so the key just opened stays.
async function arrive(path) {
  const url = new URL(path, location.origin);
  if (!own || !Object.hasOwn(pages, url.pathname) || requestId) { signinBusy = false; location.replace(path); return; }
  history.replaceState(null, '', url.href);
  pagePath = url.pathname; page = pagePath.slice(1) || 'home'; objectPrefix = prefixOf(url);
  try { await refresh(); }
  finally { signinBusy = false; void applyPendingLanguage(); }
}
const deviceName = () => navigator.userAgentData?.platform || t('client.passkey.thisDevice');
async function createPasskey(name) {
  const { options } = await api('/v1/webauthn-credentials/options', { method: 'POST', data: {} });
  const { credential, yielded } = await makePasskey(options);
  // With the key open here, it is wrapped for the new passkey too, so that one opens it as well.
  const wrap = own && yielded ? { wrap: b64(await sealing.wrap(own.privateKey, yielded)) } : {};
  return api('/v1/webauthn-credentials', { method: 'POST', data: { name, credential, ...wrap } });
}
// Starting with a passkey alone: the passkey made here makes the principal, signed in at once.
// Starting with a passkey alone: one press makes the passkey, and with it the principal, signed in at once. Nothing
// is asked: the name Foundation drew for the passkey's label becomes the principal's, to be changed on the account page.
async function startWithPasskey() {
  let made;
  const { options } = await api('/v1/principals/options', { method: 'POST', data: {} });
  const { credential, yielded } = await makePasskey(options);
  // The principal's key, made with its first passkey and wrapped for it.
  const key = yielded ? await sealing.generateKey() : null;
  made = await api('/v1/principals', { method: 'POST', data: { name: options.user.name, webauthn_credential: { name: deviceName(), credential, ...(key ? { wrap: b64(await sealing.wrap(key.privateKey, yielded)) } : {}) }, ...(key ? { public_key: b64(key.publicKey) } : {}), return_to: returnTo() } });
  own = key; keyUnavailable = !key;
  if (made.backed_up) { await arrive(made.return_to); return; }
  openDialog(`<h2 id="dialog-title">${esc(t('client.passkey.created'))}</h2><p>${esc(t('client.passkey.deviceOnly'))}</p><button class="button primary full" type="button" id="start-continue">${esc(t('client.common.continue'))}</button>`);
  dialog.querySelector('#start-continue').addEventListener('click', () => { closeDialog(); void arrive(made.return_to); });
}
async function answerPasskey() {
  const { options } = await api('/v1/signin/webauthn/options', { method: 'POST', data: {} });
  const given = await navigator.credentials.get({ publicKey: { ...options, challenge: bytes(options.challenge), allowCredentials: described(options.allowCredentials), extensions: { prf: { eval: { first: PRF_INPUT } } } } });
  return { yielded: yieldedBy(given), credential: { id: given.id, rawId: text64(given.rawId), type: given.type, clientExtensionResults: {},
    response: { clientDataJSON: text64(given.response.clientDataJSON), authenticatorData: text64(given.response.authenticatorData), signature: text64(given.response.signature),
      ...(given.response.userHandle ? { userHandle: text64(given.response.userHandle) } : {}) } } };
}
// What the browser says when the person closes its passkey dialog, or has no passkey here.
const passkeyDeclined = error => error?.name === 'NotAllowedError' || error?.name === 'AbortError';

async function showSignin({ email = '', message = '' } = {}) {
  clearInterval(signinTimer); signinBusy = false;
  refreshController?.abort();
  const current = ++revision; state = null; refreshDeferred = false; closeDialog();
  document.title = 'Foundation';
  app.innerHTML = pendingView('/', { t });
  let config = { available: false, pending: null };
  try { config = await api('/v1/signin'); }
  catch (error) { if (current === revision) showRefreshError(error, 'retry-signin'); return; }
  if (current !== revision) return;
  const pending = config.available ? config.pending : null, withPasskey = !pending && passkeysWork();
  app.innerHTML = `<div class="workspace signin-shell"><header class="topbar">${brand(t)}</header><main class="signin-main">${requestId ? `<p class="signin-context">${esc(t('client.request.review'))}</p>` : ''}<h1>${pending ? t('client.signin.checkEmail') : t('client.signin.title')}</h1>
    ${pending ? `<p class="signin-intro" id="email-sent">${esc(t('client.signin.linkSent'))}</p><p class="signin-address">${esc(pending.email)}</p><p class="signin-help">${esc(t('client.signin.emailInstructions'))}</p>` : ''}
    ${withPasskey ? `<div class="signin-passkey"><button class="button primary full" type="button" id="passkey-signin">${esc(t('client.signin.withPasskey'))}</button><p class="form-error" role="alert" id="passkey-error"></p><button class="text-button full" type="button" id="passkey-start">${esc(t('client.signin.startWithPasskey'))}</button></div>` : ''}
    <form id="signin-form">${pending ? '' : `<label for="signin-email">${esc(t('client.signin.emailAddress'))}</label><input id="signin-email" name="email" type="email" autocomplete="email" required maxlength="254" value="${esc(email)}" ${config.available ? '' : 'disabled'}>`}
    <p class="form-error" role="alert">${config.available ? esc(message) : t('client.signin.unavailable')}</p><button class="button ${pending || withPasskey ? 'secondary' : 'primary'} full" type="submit" ${pending ? 'id="resend-link" disabled' : config.available ? '' : 'disabled'}>${pending ? t('client.signin.resendEmail') : t('client.signin.sendEmail')} ${pending ? '' : icon('arrow')}</button></form>
    ${pending ? `<p class="signin-help signin-delivery">${esc(t('client.signin.checkSpam'))}</p><div class="signin-actions"><button class="text-button" type="button" id="change-email">${esc(t('client.signin.changeEmail'))}</button></div>` : ''}</main></div>`;
  if (!requestId && !pending && publicInfo) app.querySelector('.signin-main').append(publicInfo);
  const form = document.querySelector('#signin-form');
  let busy = false;
  function setBusy(value) {
    busy = value; signinBusy = value;
    for (const button of app.querySelectorAll('.signin-main button')) button.disabled = value;
    if (!value) { editedForms.delete(form); void applyPendingLanguage(); }
    if (!value && pending) updateResend();
  }
  function updateResend() {
    const resend = document.querySelector('#resend-link');
    if (current !== revision || !resend) { clearInterval(signinTimer); return; }
    const seconds = Math.max(0, Math.ceil((pending.resend_at - Date.now()) / 1000));
    resend.disabled = busy || seconds > 0;
    resend.textContent = seconds > 0 ? t('client.signin.resendCountdown', { count: seconds }) : t('client.signin.resendEmail');
  }
  document.querySelector('#passkey-start')?.addEventListener('click', async () => {
    if (busy) return;
    setBusy(true); document.querySelector('#passkey-error').textContent = '';
    try { await startWithPasskey(); }
    catch (error) {
      if (!app.querySelector('#passkey-start')) return;
      document.querySelector('#passkey-error').textContent = passkeyDeclined(error) ? t('client.passkey.createFailed') : error.message; setBusy(false);
    }
  });
  const passkeyButton = document.querySelector('#passkey-signin');
  passkeyButton?.addEventListener('click', async () => {
    if (busy) return;
    setBusy(true); document.querySelector('#passkey-error').textContent = '';
    try {
      const { credential, yielded } = await answerPasskey();
      const signed = await api('/v1/signin/webauthn', { method: 'POST', data: { credential, return_to: returnTo() } });
      await unlockWith(credential.id, yielded);
      await arrive(signed.return_to);
    } catch (error) {
      if (!passkeyButton.isConnected) return;
      document.querySelector('#passkey-error').textContent = passkeyDeclined(error) ? t('client.passkey.signinFailed') : error.message; setBusy(false);
    }
  });
  if (pending) {
    updateResend(); signinTimer = setInterval(updateResend, 1000);
    document.querySelector('#change-email').addEventListener('click', async () => {
      if (busy) return;
      setBusy(true);
      try { await api('/v1/signin', { method: 'DELETE' }); await showSignin({ email: pending.email }); }
      catch (error) { if (form.isConnected) { form.querySelector('.form-error').textContent = error.message; setBusy(false); } }
    });
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy || !config.available || (pending && Date.now() < pending.resend_at)) return;
    setBusy(true); form.querySelector('.form-error').textContent = '';
    try {
      await api('/v1/signin', { method: 'POST', data: { email: pending?.email || form.elements.email.value.trim(), return_to: returnTo() } });
      await showSignin();
    } catch (error) {
      if (!form.isConnected) return;
      form.querySelector('.form-error').textContent = error.message; setBusy(false);
    }
  });
}
window.addEventListener('focus', () => { if (document.querySelector('#email-sent')) void refresh().catch(() => {}); });
// The owner's objects: every page of the listing, and how much of the space they use.
async function loadSpace(signal) {
  const [listing, usage] = await Promise.all([api('/v1/resources?kind=object', { signal }), api('/v1/usage', { signal })]);
  const objects = listing.resources.map(item => ({ ...item, key: item.name, updated_at: Date.parse(item.updated_at) }));
  return { available: true, objects, usage: usage.objects };
}
// These elements live for the whole edit/operation, including blur, network waits and failed saves.
const editingPage = () => dialog.open || Boolean(app.querySelector('.secret-name-editor, .secret-value-panel.editing, .secret-value-panel[aria-busy="true"], [data-uploading]'));
function resumeRefresh() {
  queueMicrotask(() => { void applyPendingLanguage(); });
  const current = revision;
  queueMicrotask(() => {
    if (!refreshDeferred || !state || current !== revision || editingPage()) return;
    refreshDeferred = false;
    void refresh({ background: true }).catch(() => {});
  });
}
function showRefreshError(error, action = 'retry-page') {
  if (!state && !app.querySelector('main[aria-busy]')) app.innerHTML = pendingView(pagePath, { t });
  const main = app.querySelector('main');
  main.removeAttribute('aria-busy');
  main.querySelector('.content-loading')?.remove();
  main.querySelector('.object-browser[aria-busy]')?.removeAttribute('aria-busy');
  let alert = app.querySelector('.page-error');
  if (!alert) { alert = document.createElement('div'); alert.className = 'page-error'; main.before(alert); }
  alert.innerHTML = `<p role="alert">${esc(error.message)}</p><button class="text-button" data-action="${action}">${esc(t('client.common.reload'))}</button>`;
}
async function refresh({ background = false } = {}) {
  if (linked) {
    try { back = back || (await api('/v1/requests/' + requestId + '/return')).back; } catch {}
    try { accessRequest = (await api(requestApi)).request; requestError = ''; }
    catch (error) { accessRequest = null; requestError = error.status === 401 ? t('client.request.linkExpired') : error.message; }
    state = { user: { email: '' }, secrets: [], connections: [], agents: [], principals: [], catalog: [], services: [], apps: [], space: null };
    render();
    return;
  }
  refreshController?.abort();
  const controller = refreshController = new AbortController(), { signal } = controller;
  const current = ++revision, loading = ['home', 'objects'].includes(page) ? loadSpace(signal).then(value => ({ value }), error => ({ error })) : null;
  try {
    const result = await api('/v1/overview', { signal });
    if (requestId && current === revision) {
      try {
        const found = (await api(requestApi, { signal })).request;
        accessRequest = found; requestError = '';
      }
      catch (error) { accessRequest = null; requestError = error.message; }
    }
    if (current !== revision || signal.aborted) return;
    const sameOwner = state?.user.id === result.user.id;
    app.querySelector('.page-error')?.remove();
    // Refresh from the server after the last edit ends, never from a stale pre-save snapshot.
    if (sameOwner && editingPage()) { refreshDeferred = true; return; }
    refreshDeferred = false;
    const changed = !state || Object.entries(result).some(([key, value]) => JSON.stringify(state[key]) !== JSON.stringify(value));
    const space = sameOwner ? state.space : undefined;
    if (!sameOwner) { closeDialog(); objectChosen.clear(); }
    state = { ...result, space };
    if (!background || changed) render();
    if (loading) {
      const { value: loaded, error } = await loading;
      if (current !== revision || signal.aborted) return;
      if (editingPage()) { refreshDeferred = true; return; }
      if (error) {
        if (state.space === undefined) { state.space = null; render(); }
        if (page !== 'objects' || state.space) showRefreshError(error);
        return;
      }
      const changed = JSON.stringify(state.space) !== JSON.stringify(loaded);
      state.space = loaded;
      if (page === 'objects' && changed) render();
      if (page === 'home') {
        const count = app.querySelector('.home-card[href="/objects"] p');
        if (count) count.textContent = spaceSummary(loaded);
      }
    }
  } catch (error) {
    if (signal.aborted || current !== revision) return;
    showRefreshError(error);
    throw error;
  }
}
const spaceSummary = space => space === undefined ? '…' : space?.available ? t('client.objects.summary', { count: space.usage.count, used: kiloBytes(space.usage.bytes), limit: kiloBytes(space.usage.bytes_max) }) : t('client.common.unavailable');

// Ordinary links still open directly or in a new tab. Within the signed-in workspace, keep the frame.
function scrollToPage(position = [0, 0]) {
  let anchor;
  try { anchor = document.getElementById(decodeURIComponent(location.hash.slice(1))); } catch {}
  if (anchor) anchor.scrollIntoView();
  else window.scrollTo({ left: position[0], top: position[1], behavior: 'auto' });
}
function navigate(url, { restore = false, position } = {}) {
  if (!restore) {
    history.replaceState({ ...history.state, scroll: [scrollX, scrollY] }, '', location.href);
    history.pushState({ scroll: [0, 0] }, '', url);
  }
  const nextPrefix = prefixOf(url), changed = pagePath !== url.pathname || objectPrefix !== nextPrefix;
  if (changed) { objectPrefix = nextPrefix; objectFilter = ''; objectLimit = 100; objectChosen.clear(); }
  pagePath = url.pathname; page = pagePath.slice(1) || 'home';
  if (changed) {
    refreshDeferred = false; closeDialog(); clearTimeout(toastTimer); notice.hidden = true;
    app.querySelector('.page-error')?.remove();
    render();
    app.querySelector('main')?.focus({ preventScroll: true });
    void refresh({ background: true }).catch(() => {});
  }
  scrollToPage(position);
}
document.addEventListener('click', event => {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || !state || requestId || isSigninConfirmation) return;
  const link = event.target.closest('a[href]');
  if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
  const url = new URL(link.href);
  if (url.origin !== location.origin || !Object.hasOwn(pages, url.pathname)
    || [...url.searchParams.keys()].some(key => url.pathname !== '/objects' || key !== 'prefix')) return;
  event.preventDefault();
  if (url.href !== location.href) navigate(url);
});
if (!requestId && !isSigninConfirmation) {
  history.scrollRestoration = 'manual';
  window.addEventListener('popstate', event => {
    if (!state) { location.reload(); return; }
    navigate(new URL(location.href), { restore: true, position: event.state?.scroll });
  });
}
// What the owner let Foundation use: secrets they handed over, and connections for services.
const secrets = () => state.secrets || [];
const connected = () => (state.connections || []).map(presentConnection);
// Every service the owner can connect: those Foundation knows, and those they (or someone for them) described.
const allServices = () => [...(state.catalog || []), ...(state.services || []).map(row => row.service)].map(service => localizeService(service, i18n.language));
const presentService = service => service?.removed ? { ...service, name: t('client.service.removed') } : localizeService(service, i18n.language);
const presentApp = app => app?.foundation ? { ...app, name: t('client.apps.foundationName') } : app;
function presentConnection(connection) {
  let label = connection.label;
  // This fingerprint label is adapter-owned. Never translate owner-chosen names.
  if (connection.service?.catalog && connection.service.id === 'openrouter' && connection.auth_scheme === 'oauth') {
    const fingerprint = connection.facts?.management_url?.match(/^https:\/\/openrouter\.ai\/keys\/([a-f0-9]{12})[a-f0-9]*$/)?.[1];
    if (fingerprint && connection.label === connection.facts?.label) label = t('server.label.keyFingerprint', { fingerprint });
  }
  return { ...connection, label, service: presentService(connection.service), app: presentApp(connection.app) };
}
// Confirmation change captions belong to the built-in adapter, unlike account
// names and permission values. Match only in that known presentation context.
function presentedChanges(review) {
  if (!review.connection?.service?.catalog || review.connection.service.id !== 'cloudflare') return review.changes;
  const labels = ['server.label.oauthApp', 'server.label.permissions', 'server.label.observedAccounts'];
  return review.changes.map(change => {
    const key = labels.find(key => change.label === t(key, { lng: 'ja' }) || change.label === t(key, { lng: 'en' }));
    const values = items => key === 'server.label.observedAccounts' && items.length === 1 && items[0] === t('server.label.unverified', { lng: 'ja' }) ? [t('server.label.unverified')] : items;
    return key ? { ...change, label: t(key), before: values(change.before), after: values(change.after) } : change;
  });
}
const serviceById = id => allServices().find(item => item.id === id);
const ownService = id => (state.services || []).find(row => row.id === id && row.owner_id === state.user.id);
const unconnectedServices = () => (state.services || []).filter(row => !connected().some(connection => connection.service.id === row.id));
function rememberService(row) {
  state.services = [...(state.services || []).filter(item => item.id !== row.id), row];
  refreshDeferred = true;
  return row.service;
}
const keptWhen = value => formatDate(value, i18n.language);
const kiloBytes = size => size < 1024 ? t('client.common.bytes', { count: size }) : size < 1024 * 1024 ? formatNumber(Math.round(size / 1024), i18n.language) + ' KB'
  : size < 1024 * 1024 * 1024 ? formatNumber(Math.round(size / (1024 * 1024)), i18n.language) + ' MB' : formatNumber(size / (1024 * 1024 * 1024), i18n.language, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) + ' GB';
const statusName = status => ({ usable: t('client.connection.usable'), reconnect_required: t('client.connection.reconnectRequired'), disconnecting: t('client.connection.disconnecting') }[status] || t('client.connection.reviewRequired'));
// One connection for a service: which service, which account, and what is wrong when something is.
function connectionRow(connection) {
  const warning = connection.status !== 'usable';
  const account = connection.label;
  const app = connection.app === null ? `<p class="muted warning-text">${esc(t('client.oauth.appDeleted'))}</p>`
    : connection.app && !connection.app.foundation ? `<p class="muted">${esc(t('client.connections.oauthAppName', { name: connection.app.name }))}</p>` : '';
  const way = connection.auth_scheme === 'role' ? `<p class="muted">${esc(t('client.connection.iamRole'))}</p>` : connection.auth_scheme === 'token' ? `<p class="muted">${esc(t('client.connection.token'))}</p>` + tokenFacts(connection) : '';
  return `<article class="agent-row connection-row"><div class="connection-identity">${serviceLogo(connection.service)}<div class="agent-name"><h3>${esc(connection.service.name)}</h3>${account && account !== connection.service.name ? `<p class="connection-account">${esc(account)}</p>` : ''}</div></div>
    <div class="connection-details">${warning ? `<p class="connection-status warning-text">${esc(statusName(connection.status))}</p>` : ''}${way}${app}${accountDetails(connection)}${scopeDetails(connection.facts)}</div>
    <div class="agent-actions">${connection.can_reconnect ? `<button class="text-button" data-action="reconnect" data-id="${esc(connection.id)}">${connection.auth_scheme === 'token' ? t('client.connection.replaceValue') : t('client.connection.reconnect')}</button>` : ''}<button class="text-button danger" data-action="disconnect" data-id="${esc(connection.id)}">${esc(t('client.connection.disconnect'))}</button></div></article>`;
}
// What a token connection says of itself: the fields that are not the token, by the names the service gives them.
function tokenFacts(connection) {
  const fields = serviceById(connection.service.id)?.auth_schemes?.token?.fields || [];
  return fields.filter(field => connection.facts[field.name]).map(field => `<p class="muted">${esc(t('client.connections.fieldFact', { label: field.label, value: connection.facts[field.name] }))}</p>`).join('');
}
// The accounts a service said a connection reaches, when it says; null is not yet known.
function accountDetails(connection) {
  if (!Object.hasOwn(connection.facts || {}, 'observed_accounts')) return '';
  const accounts = connection.facts.observed_accounts;
  const names = accounts ? new Intl.ListFormat(i18n.language, { style: 'long', type: 'conjunction' }).format(accounts.items.map(item => item.name)) || t('client.common.none') : t('client.common.unverified');
  return `<p class="muted">${esc(accounts && !accounts.complete ? t('client.connections.accountsPartial', { names }) : t('client.connections.accounts', { names }))}</p>`;
}
// What the owner gave: the scopes the service granted, and any asked for but not granted.
function scopeDetails(facts) {
  const granted = facts?.scopes || [], missing = facts?.missing_scopes || [];
  if (!granted.length && !missing.length) return '';
  const list = scopes => `<ul class="scope-list">${scopes.map(scope => `<li><code>${esc(scope)}</code></li>`).join('')}</ul>`;
  return `<details class="scope-details"><summary>${esc(t('client.connections.grantedScopes', { count: granted.length }))}</summary>${list(granted)}</details>`
    + (missing.length ? `<details class="scope-details"><summary class="warning-text">${esc(t('client.connections.missingScopes', { count: missing.length }))}</summary>${list(missing)}</details>` : '');
}
function secretRow(entry) {
  return `<article class="secret-row" aria-label="${esc(entry.name)}"><div class="secret-field"><span class="secret-field-label">${esc(t('client.common.name'))}</span><div class="agent-name secret-title"><h3>${esc(entry.name)}</h3><button class="icon-button" data-action="copy-name" data-name="${esc(entry.name)}" aria-label="${esc(t('client.secret.copyName'))}" title="${esc(t('client.secret.copyName'))}">${icon('copy')}</button><button class="icon-button" data-action="edit-secret" data-name="${esc(entry.name)}" aria-label="${esc(t('client.common.editName'))}" title="${esc(t('client.common.editName'))}">${icon('edit')}</button></div></div>
    <div class="secret-field"><span class="secret-field-label">${esc(t('client.secret.value'))}</span><section class="secret-value-panel" aria-label="${esc(t('client.secret.value'))}"></section></div>
    <footer class="secret-footer"><p class="secret-meta">${secretMeta(entry)}</p><div class="secret-actions"><button class="text-button danger" data-action="drop-secret" data-name="${esc(entry.name)}">${esc(t('client.common.delete'))}</button></div></footer></article>`;
}
// The value's own size: what is kept is it with the seal's 28 bytes.
const secretMeta = entry => `<span>${esc(kiloBytes(entry.size - 28))}</span><span>${esc(t('client.secrets.updatedAt', { date: keptWhen(entry.updated_at) }))}</span>`;
function render() {
  if (!state) return;
  if (requestId) { renderRequest(); return; }
  const shell = inner => {
    if (!app.querySelector('.page-nav')) app.innerHTML = workspaceView(pagePath, { t });
    app.querySelector('.topbar').querySelectorAll('a').forEach(link => {
      if (link.getAttribute('href') === pagePath) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    document.title = pageTitle(pagePath, t);
    app.querySelector('[data-action="signout"]').disabled = false;
    app.querySelector('main').removeAttribute('aria-busy');
    app.querySelector('main').innerHTML = inner;
  };
  if (page === 'objects') {
    if (!app.querySelector('#space-upload')) {
      shell(`<header class="page-heading page-heading-actions"><div><h1>${esc(t('client.objects.title'))}</h1><p id="object-usage"></p></div>
        <button class="button secondary" type="button" data-action="upload-object">${icon('plus')} ${esc(t('client.common.add'))}</button><input id="space-upload" type="file" hidden></header>${spaceSection()}`);
      bindObjects();
    }
    updateObjects();
    return;
  }
  if (page === 'functions') {
    // Available operations, independent of their invocations.
    const known = { 'http.request': [t('client.functions.httpRequest'), t('client.functions.httpRequestDescription')] };
    shell(`<header class="page-heading"><h1>${esc(t('client.functions.title'))}</h1></header>
      <section class="resource-section" aria-labelledby="functions-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('network')}</span><div><h2 id="functions-title">${esc(t('client.functions.operations'))}</h2></div></div></div>
      <div class="agent-list">${(state.functions || []).map(item => `<article class="agent-row"><div class="agent-name"><h3>${esc(known[item.id]?.[0] || item.id)}</h3><p><code>${esc(item.id)}</code></p></div><div class="agent-permissions"><span class="muted">${esc(known[item.id]?.[1] || item.description)}</span></div><div class="agent-actions"></div></article>`).join('')}</div></section>
      `);
    return;
  }
  if (page === 'account' && paymentReturn) {
    const session = paymentReturn;
    paymentReturn = null;
    history.replaceState(null, '', '/account');
    void api('/v1/payment/complete', { method: 'POST', data: { session_id: session } }).then(async () => { await refresh(); toast(t('client.payment.added')); }, error => toast(error.message));
  }
  if (page === 'account') {
    // The account itself: who this is, and the few things done to it rather than in it.
    const passkeyRow = item => `<article class="agent-row" aria-label="${esc(item.name)}"><div class="agent-name"><h3>${esc(item.name)}</h3><p>${item.last_used_at ? esc(t('client.account.passkeyLastUsed', { date: keptWhen(item.last_used_at) })) : t('client.passkey.neverUsed')}</p></div>
      <div class="agent-actions"><button class="text-button danger" data-action="remove-passkey" data-id="${esc(item.id)}">${esc(t('client.common.delete'))}</button></div></article>`;
    shell(`<header class="page-heading"><h1>${esc(t('client.account.title'))}</h1><p>${esc(state.user.email || '')}</p></header>
      <section class="resource-section" aria-labelledby="id-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('key')}</span><div><h2 id="id-title">${esc(t('client.account.id'))}</h2><p><code>${esc(state.user.id)}</code></p></div></div><button class="button secondary" data-action="copy-id">${icon('copy')} ${esc(t('client.account.copyId'))}</button></div></section>
      <section class="resource-section" aria-labelledby="name-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('edit')}</span><div><h2 id="name-title">${esc(t('client.common.name'))}</h2><p>${esc(state.principal.name || '')}</p></div></div><button class="button secondary" data-action="rename-me">${esc(t('client.common.changeName'))}</button></div></section>
      <section class="resource-section" aria-labelledby="language-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('globe')}</span><h2 id="language-title">${esc(t('language.label'))}</h2></div>${languagePicker(t, i18n.language)}</div></section>
      <section class="resource-section" aria-labelledby="passkeys-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('key')}</span><div><h2 id="passkeys-title">${esc(t('client.passkey.title'))}</h2><p>${esc(t('client.passkey.description'))}</p></div></div>${passkeysWork() ? `<button class="button secondary" data-action="add-passkey">${icon('plus')} ${esc(t('client.passkey.add'))}</button>` : ''}</div>
        ${(state.webauthn_credentials || []).length ? `<div class="agent-list">${state.webauthn_credentials.map(passkeyRow).join('')}</div>` : ''}</section>
      ${state.payment?.available ? `<section class="resource-section" aria-labelledby="payment-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('card')}</span><div><h2 id="payment-title">${esc(t('client.payment.title'))}</h2><p>${state.payment.paying ? t('client.payment.registeredNote') : t('client.payment.addMethodNote')}</p></div></div><button class="button secondary" data-action="set-payment">${state.payment.paying ? t('client.payment.changeMethod') : t('client.payment.addMethod')}</button></div></section>` : ''}
      <section class="resource-section" aria-labelledby="export-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('download')}</span><div><h2 id="export-title">${esc(t('client.account.downloadData'))}</h2><p>${esc(t('client.account.exportDescription'))}</p></div></div><a class="button secondary" href="/v1/export" download>${icon('download')} ${esc(t('client.common.download'))}</a></div></section>
      <section class="resource-section" aria-labelledby="handover-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('arrow')}</span><div><h2 id="handover-title">${esc(t('client.handover.title'))}</h2><p>${esc(t('client.handover.description'))}</p></div></div><button class="button secondary" data-action="hand-over">${esc(t('client.handover.action'))}</button></div></section>
      <section class="resource-section" aria-labelledby="merge-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('key')}</span><div><h2 id="merge-title">${esc(t('client.merge.title'))}</h2></div></div>${passkeysWork() ? `<button class="button secondary" data-action="merge">${esc(t('client.merge.action'))}</button>` : ''}</div></section>
      <section class="resource-section" aria-labelledby="developers-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('network')}</span><div><h2 id="developers-title">${esc(t('client.account.developers'))}</h2></div></div><a class="button secondary" href="/principals#apps">${esc(t('client.integration.registration'))}</a></div></section>`);
    return;
  }
  if (page === 'home') {
    // A look over everything, and the way to each page. Nothing is managed here.
    const space = state.space, kept = secrets(), connections = connected(), keys = state.agents || [];
    const card = (href, title, line) => `<a class="home-card" href="${href}"><h2>${title}</h2><p>${esc(line)}</p></a>`;
    const lastUsed = keys.flatMap(key => key.keys.map(item => item.last_used_at)).filter(Boolean).sort().at(-1);
    shell(`<header class="page-heading"><h1>Foundation</h1></header>
      <div class="home-cards">
        ${card('/services', t('client.service.title'), t('client.common.itemCount', { count: connections.length + unconnectedServices().length }))}
        ${card('/secrets', t('client.secret.title'), t('client.common.itemCount', { count: kept.length }))}
        ${card('/objects', t('client.objects.title'), spaceSummary(space))}
        ${card('/principals', t('client.access.title'), keys.length ? lastUsed ? t('client.home.accessLastUsed', { count: keys.length, date: formatDate(lastUsed, i18n.language) }) : t('client.home.accessCount', { count: keys.length }) : t('client.common.noItems'))}
        ${card('/functions', t('client.functions.title'), t('client.home.functionCount', { count: state.functions?.length || 0 }))}
      </div>`);
    return;
  }
  if (page === 'principals') {
    const agents = state.agents || [], others = (state.principals || []).filter(item => !agents.some(agent => agent.id === item.id));
    const used = item => { const at = item.keys.map(c => c.last_used_at).filter(Boolean).sort().at(-1); return at ? esc(t('client.principals.lastUsed', { date: formatDate(at, i18n.language) })) : t('client.access.neverUsed'); };
    const row = (item, allowed) => `<article class="agent-row access-row"><div class="agent-name"><h3>${esc(item.name)}</h3><p>${used(item)}</p></div><div class="agent-permissions"><span class="muted">${allowed ? esc(t('client.principals.approvedAt', { date: formatDate(item.approved_at, i18n.language, { year: 'numeric', month: 'numeric', day: 'numeric' }) })) : t('client.access.noFullAccess')}</span></div><div class="agent-actions"><button class="text-button" data-action="principal-details" data-id="${esc(item.id)}">${esc(t('client.common.details'))}</button>${allowed ? `<button class="text-button danger" data-action="revoke-access" data-id="${esc(item.id)}">${esc(t('client.access.revoke'))}</button>` : ''}</div></article>`;
    shell(`<header class="page-heading"><h1>${esc(t('client.access.title'))}</h1></header>
      <section class="resource-section" aria-labelledby="access-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('device')}</span><h2 id="access-title">${esc(t('client.access.registeredPrincipals'))}</h2></div><button class="button secondary" data-action="add-key">${icon('plus')} ${esc(t('client.common.add'))}</button></div>
      ${agents.length || others.length ? `<div class="agent-list">${agents.map(item => row(item, true)).join('')}${others.map(item => row(item, false)).join('')}</div>` : `<div class="access-empty"><p>${esc(t('client.access.empty'))}</p></div>`}</section>
      ${environmentsSection()}
      <div class="integration-entry" id="apps"><button class="text-button" data-action="add-integration">${esc(t('client.integration.register'))}</button></div>`);
    return;
  }
  if (page === 'services') {
    // The services the owner's AI may use, by service. Adding one is a way in, not the page itself; the OAuth apps
    // connections go through are there when needed, folded away.
    const connections = connected(), waiting = unconnectedServices();
    const rows = [...connections.map(connection => ({ name: connection.service.name, label: connection.label, html: connectionRow(connection) })),
      ...waiting.map(row => ({ name: row.service.name, label: '', html: `<article class="agent-row connection-row" aria-label="${esc(row.service.name)}"><div class="connection-identity">${serviceLogo(row.service)}<div class="agent-name"><h3>${esc(row.service.name)}</h3></div></div>
        <div class="connection-details"><p class="muted">${esc(t('client.connection.notConnected'))}</p></div><div class="agent-actions"><button class="text-button" data-action="choose-service" data-id="${esc(row.id)}">${esc(t('client.connection.add'))}</button>${ownService(row.id) ? `<button class="text-button danger" data-action="remove-service" data-id="${esc(row.id)}">${esc(t('client.common.delete'))}</button>` : ''}</div></article>` }))]
      .sort((a, b) => compareText(a.name, b.name, i18n.language) || compareText(a.label, b.label, i18n.language));
    shell(`<header class="page-heading page-heading-actions"><h1>${esc(t('client.service.title'))}</h1><button class="button secondary" data-action="add-service">${icon('plus')} ${esc(t('client.service.add'))}</button></header>
      <section class="resource-section" aria-label="${esc(t('client.service.title'))}">
        ${rows.length ? `<div class="agent-list">${rows.map(row => row.html).join('')}</div>` : `<div class="access-empty"><p>${esc(t('client.connection.empty'))}</p></div>`}</section>
      ${appsSection()}`);
    app.querySelector('#oauth-apps').addEventListener('toggle', event => { appsOpen = event.currentTarget.open; });
    return;
  }
  if (page === 'secrets') {
    const focused = document.activeElement, focusedRow = focused.closest('.secret-row')?.getAttribute('aria-label');
    const focusedAction = focused.getAttribute('aria-label') || focused.dataset.action;
    const kept = secrets(), handed = (state.agents || []).some(item => item.id === state.foundation?.principal_id);
    // What the page can do here: nothing with a value until the owner's key is open.
    const keyLine = own ? '' : !(state.webauthn_credentials || []).length
      ? `<div class="access-empty key-state"><p>${esc(t('client.secret.passkeyRequired'))}</p>${passkeysWork() ? `<button class="button secondary" data-action="add-passkey">${icon('plus')} ${esc(t('client.passkey.add'))}</button>` : ''}</div>`
      : keyUnavailable ? `<div class="access-empty key-state"><p>${esc(t('client.secret.keyUnavailable'))}</p></div>`
        : `<div class="access-empty key-state"><button class="button secondary" data-action="unlock-key">${icon('lock')} ${esc(t('client.secret.unlockWithPasskey'))}</button></div>`;
    const foundationLine = handed ? '' : `<div class="access-empty key-state"><p>${esc(t('client.secret.shareFoundationNote'))}</p><button class="button secondary" data-action="allow-foundation"${own ? '' : ' disabled'}>${esc(t('client.secret.shareFoundation'))}</button></div>`;
    shell(`<header class="page-heading page-heading-actions"><h1>${esc(t('client.secret.title'))}</h1>
      <button class="button secondary" data-action="add-secret"${own ? '' : ' disabled'}>${icon('plus')} ${esc(t('client.common.add'))}</button></header>
      ${keyLine}${foundationLine}
      <section class="resource-section" aria-label="${esc(t('client.secret.title'))}">
        ${kept.length ? `<div class="agent-list">${kept.map(secretRow).join('')}</div>` : `<div class="access-empty"><p>${esc(t('client.secret.empty'))}</p></div>`}</section>`);
    if (own) void receiveFromFoundation();
    app.querySelectorAll('.secret-row').forEach(row => bindSecretValue(kept.find(item => item.name === row.getAttribute('aria-label')), row));
    if (focusedRow && focusedAction && !focused.isConnected) {
      const row = [...app.querySelectorAll('.secret-row')].find(item => item.getAttribute('aria-label') === focusedRow);
      [...(row?.querySelectorAll('button') || [])].find(button => (button.getAttribute('aria-label') || button.dataset.action) === focusedAction)?.focus({ preventScroll: true });
    }
  }
}
function updateObjectSelection() {
  const boxes = [...app.querySelectorAll('[data-action="choose-object"]')];
  for (const box of boxes) box.checked = objectChosen.has(box.dataset.key);
  const all = app.querySelector('[data-action="choose-all"]');
  if (all) {
    const count = boxes.filter(box => box.checked).length;
    all.checked = boxes.length > 0 && count === boxes.length;
    all.indeterminate = count > 0 && count < boxes.length;
  }
  const chosen = chosenKeys(), copy = app.querySelector('[data-action="copy-url"]'), drop = app.querySelector('[data-action="drop-chosen"]');
  if (copy) copy.disabled = chosen.length !== 1 || chosen[0].endsWith('/');
  if (drop) { drop.disabled = chosen.length === 0; drop.textContent = chosen.length ? t('client.objects.deleteSelected', { count: chosen.length }) : t('client.common.delete'); }
}
function updateObjects() {
  const usage = state.space?.usage, description = app.querySelector('#object-usage');
  description.textContent = usage ? t('client.objects.usage', { used: kiloBytes(usage.bytes), limit: kiloBytes(usage.bytes_max), count: usage.count, maximum: usage.count_max }) : '';
  description.hidden = !usage;
  const upload = app.querySelector('#space-upload');
  upload.disabled = state.space === undefined || upload.hasAttribute('data-uploading');
  app.querySelector('[data-action="upload-object"]').disabled = upload.disabled;
  const section = app.querySelector('.object-browser'), template = document.createElement('template');
  template.innerHTML = spaceSection();
  const next = template.content.firstElementChild, focus = document.activeElement;
  const identity = focus?.dataset.key !== undefined ? ['data-key', focus.dataset.key]
    : focus?.dataset.sort ? ['data-sort', focus.dataset.sort]
    : focus?.dataset.action ? ['data-action', focus.dataset.action]
    : focus?.getAttribute('href') ? ['href', focus.getAttribute('href')] : null;
  if (section.querySelector('.object-results') && next.querySelector('.object-results')) {
    section.querySelector('.object-location').innerHTML = next.querySelector('.object-location').innerHTML;
    section.querySelector('.object-results').innerHTML = next.querySelector('.object-results').innerHTML;
  } else section.replaceWith(next);
  const filter = app.querySelector('#object-filter');
  if (filter) {
    if (filter.value !== objectFilter) filter.value = objectFilter;
    filter.placeholder = objectSearchPrefix ? t('client.objects.searchHereByPrefix') : t('client.objects.filterByName');
    filter.oninput = () => { objectFilter = filter.value; objectLimit = 100; updateObjects(); };
    app.querySelector('[data-action="toggle-search"]').textContent = objectSearchPrefix ? t('client.objects.matchAnywhere') : t('client.objects.searchByPrefix');
  }
  updateObjectSelection();
  if (identity && !focus.isConnected) {
    const [attribute, value] = identity;
    [...app.querySelectorAll('.object-browser [' + attribute + ']')].find(node => node.getAttribute(attribute) === value)?.focus({ preventScroll: true });
  }
}
function bindObjects() {
  const upload = document.querySelector('#space-upload');
  if (upload) upload.addEventListener('change', async () => {
    const file = upload.files?.[0];
    if (!file) return;
    const key = objectPrefix + file.name;
    upload.setAttribute('data-uploading', '');
    upload.disabled = true;
    app.querySelector('[data-action="upload-object"]').disabled = true;
    try {
      if ((state.space?.objects || []).some(item => item.key === key)) {
        const go = await new Promise(resolve => {
          openDialog(`<h2 id="dialog-title">${esc(t('client.objects.replaceTitle', { name: file.name }))}</h2><form><p>${esc(t('client.objects.replaceWarning'))}</p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">${esc(t('client.common.cancel'))}</button><button type="submit" class="button primary">${esc(t('client.common.replace'))}</button></div></form>`);
          const cancelled = () => resolve(false);
          dialog.addEventListener('close', cancelled, { once: true });
          dialog.querySelector('form').onsubmit = event => { event.preventDefault(); dialog.removeEventListener('close', cancelled); resolve(true); closeDialog(); };
        });
        if (!go) return;
      }
      const response = await fetch('/v1/resources?' + new URLSearchParams({ kind: 'object', name: key }), { method: 'PUT', credentials: 'same-origin',
        headers: { 'X-Foundation-Locale': i18n.language, 'content-type': file.type || 'application/octet-stream' }, body: file });
      const result = await response.json();
      if (response.status === 401) await showSignin();
      if (!response.ok) throw new Error(result.error?.message || t('client.errors.addFailed'));
      toast(t('client.common.addedName', { name: file.name }));
      refreshDeferred = true;
    } catch (error) { toast(error.message); }
    finally {
      upload.removeAttribute('data-uploading'); upload.value = ''; upload.disabled = false;
      if (upload.isConnected) app.querySelector('[data-action="upload-object"]').disabled = false;
      resumeRefresh();
    }
  });
}
const siteLink = value => { try { const url = new URL(value); return `<a href="${esc(url.href)}" target="_blank" rel="noopener noreferrer"><strong>${esc(url.host)}</strong>${esc(url.pathname === '/' ? '' : url.pathname)} ↗</a>`; } catch { return esc(value); } };
// Guidance the requesting AI wrote for its owner. Framed as the AI's words; line breaks kept, nothing else interpreted.
// The steps the requesting AI wrote for the owner to follow, shown as the numbered list they are.
const stepsBlock = steps => steps?.length ? `<section class="ai-guidance"><h3>${esc(t('client.request.steps'))}</h3><ol class="guidance-steps">${steps.map(step => `<li>${esc(step)}</li>`).join('')}</ol></section>` : '';
const requestHeading = (row, title, symbol = 'lock') => `${state?.user?.email ? `<p class="request-account">${esc(state.user.email)}</p>` : ''}<header class="approval-heading"><span class="approval-symbol">${icon(symbol)}</span><div><p class="approval-eyebrow">${esc(t('client.requests.requester', { name: row.requester_name }))}</p><h1>${esc(title)}</h1></div></header>`;
const requestPurpose = row => row.binding_message ? `<div class="approval-purpose"><dt>${esc(t('client.request.purpose'))}</dt><dd>${esc(row.binding_message)}</dd></div>` : '';
const codeComplete = form => /^[0-9A-Z]{8}$/.test((form.elements.confirmationCode?.value || '').toUpperCase().replace(/[^0-9A-Z]/g, ''));
function codeField(enabled = true) {
  return `<label for="confirmation-code">${esc(t('client.request.confirmationCode'))}</label><input id="confirmation-code" name="confirmationCode" required maxlength="9" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX" aria-describedby="confirmation-help" ${enabled ? '' : 'disabled'}><p class="permission-note" id="confirmation-help">${esc(t('client.request.codeInstructions'))}</p>`;
}
// The link of a request shows the one screen its kind calls for:
//   approve   a key not yet approved: the owner accepts it with the code. Nothing is registered here.
//   connect   an approved key: Foundation performs the connection itself. No code.
//   store     an approved key: the owner puts something into storage, following the AI's instructions.
function renderRequest() {
  document.title = t('client.request.review') + ' · Foundation';
  const row = accessRequest;
  const shell = (content) => `<div class="workspace"><header class="topbar">${brand(t)}${linked ? '' : `<div class="user-menu"><a href="/account"${page === 'account' ? ' aria-current="page"' : ''}>${esc(t('client.account.title'))}</a><button class="text-button" data-action="signout">${esc(t('client.signin.signout'))}</button></div>`}</header><main class="approval-main">${content}</main></div>`;
  const type = detailOf(row).type, asked = detailOf(row);
  if (!row || row.status !== 'pending' || !knownRequestKind(type)) {
    const view = requestResultView(row, requestError, t);
    const subject = view.completed ? type === 'secret' ? new Intl.ListFormat(i18n.language).format(row.result.names) : type === 'connection' ? connected().find(item => item.id === row.result.connection_id)?.label : row.requester_name : '';
    const link = !linked ? '<a class="button secondary" href="' + view.href + '">' + esc(view.label) + ' ' + icon('arrow') + '</a>'
      : back ? '<a class="button secondary" href="' + esc(backTo(row)) + '">' + esc(t('client.requests.returnTo', { name: back.name })) + '</a>' : '';
    app.innerHTML = shell('<section class="approval-card approval-result"><span class="approval-symbol">' + icon(view.completed ? 'check' : 'lock') + '</span><h1>' + esc(view.title) + '</h1>' + (subject ? '<p>' + esc(subject) + '</p>' : '') + (view.description ? '<p>' + esc(view.description) + '</p>' : '') + link + '</section>');
    return;
  }
  const expiry = `<p class="request-expiry">${esc(type === 'relation' ? t('client.requests.approvalExpiry', { time: formatDate(row.expires_at, i18n.language, { hour: '2-digit', minute: '2-digit' }) }) : t('client.requests.requestExpiry', { time: formatDate(row.expires_at, i18n.language, { hour: '2-digit', minute: '2-digit' }) }))}</p>`;
  if (type === 'relation') { renderApproval(row, shell, expiry); return; }
  if (type === 'secret') { renderStore(row, shell, expiry); return; }
  if (type === 'app') { renderAppRequest(row, shell, expiry); return; }
  const service = localizeService(row.service, i18n.language);
  if (!service) {
    app.innerHTML = shell(`<section class="approval-card"><h1>${esc(t('client.connection.title'))}</h1><p>${esc(t('client.connection.serviceUnavailable'))}</p><button class="text-button full" data-action="deny-request">${esc(t('client.connection.decline'))}</button>${expiry}</section>`);
    return;
  }
  const way = row.auth_scheme, scheme = service.auth_schemes[way], name = service.name;
  const reconnecting = Boolean(asked.connection_id), title = reconnecting ? t('client.connections.reconnectName', { name }) : t('client.connections.connectName', { name });
  const facts = `<dl class="approval-facts">${requestPurpose(row)}${row.connection ? `<div><dt>${esc(t('client.connection.connectionToUpdate'))}</dt><dd>${esc(row.connection.label)}${accountDetails(row.connection)}</dd></div>` : ''}
    <div><dt>${esc(t('client.connection.method'))}</dt><dd>${WAYS()[way]}${way === 'oauth' ? requestedScopesView(row, scheme) : ''}</dd></div>${row.app && !row.app.foundation ? `<div><dt>${esc(t('client.oauth.app'))}</dt><dd>${esc(row.app.name)}</dd></div>` : ''}</dl>`;
  let body;
  if (reconnecting && !row.connection) body = `<p class="form-error" role="status">${esc(t('client.connection.updateTargetMissing'))}</p>`;
  else if (row.app === null) body = `<p class="form-error" role="status">${esc(t('client.oauth.appMissing'))}</p>`;
  else if (!scheme.available && (way !== 'oauth' || row.app?.foundation || !scheme.takes_apps)) body = `<p class="form-error" role="status">${esc(t('client.connections.unavailableName', { name }))}</p>`;
  else if (way === 'token') body = `${serviceLink(scheme.console, t('client.connections.createToken', { name }))}${instructions(scheme)}<form id="token-request-form">${pastedFields(scheme, 'request-token')}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">${reconnecting ? t('client.common.replaceValue') : t('client.connection.connect')}</button></form>`;
  else body = `<button class="button primary full request-connect" type="button" data-action="request-connect">${esc(way === 'role' ? t('client.connection.createIamRole') : t('client.connections.goToService', { name }))} ${icon('arrow')}</button>`;
  app.innerHTML = shell(`<section class="approval-card">${requestHeading(row, title)}${facts}
    ${stepsBlock(row.steps)}
    <div class="register-body">${body}</div>
    <button class="text-button full" type="button" data-action="deny-request">${esc(t('client.connection.decline'))}</button>${expiry}</section>`);
  if (way === 'token' && app.querySelector('#token-request-form')) bindForm(async (form) => {
    await api('/v1/connections', { method: 'POST', data: { request_id: row.id, fields: pastedValues(scheme, form) } });
    await refresh();
  }, app.querySelector('.register-body'));
}
// The scopes a request asks the service for, as the service names them; the owner sees each before agreeing.
function requestedScopesView(row, scheme) {
  const detail = detailOf(row), asked = detail.scopes || [];
  if (!scheme.scopes) return '';
  if (!asked.length) return `<small class="muted block">${detail.connection_id ? t('client.connection.reconnectSamePermissions') : t('client.connection.identityPermissionsOnly')}</small>`;
  return `<small class="muted block">${esc(detail.connection_id ? t('client.requests.additionalScopes') : t('client.requests.requestedScopes'))}</small><ul class="scope-list">${asked.map(scope => `<li><code>${esc(scope)}</code></li>`).join('')}</ul>`;
}
// The owner registers an OAuth app for a key: its values go into the app, and the key learns only which app it is.
function renderAppRequest(row, shell, expiry) {
  const service = localizeService(row.service, i18n.language);
  if (!service?.auth_schemes.oauth?.takes_apps) {
    app.innerHTML = shell(`<section class="approval-card"><h1>${esc(t('client.oauth.registration'))}</h1><p>${esc(t('client.oauth.registrationUnavailable'))}</p><button class="text-button full" data-action="deny-request">${esc(t('client.common.declineRegistration'))}</button>${expiry}</section>`);
    return;
  }
  const title = t('client.apps.registerService', { name: service.name });
  app.innerHTML = shell(`<section class="approval-card">${requestHeading(row, title)}
    <dl class="approval-facts">${requestPurpose(row)}</dl>${stepsBlock(row.steps)}
    <form id="app-request-form"><label for="request-app-name">${esc(t('client.common.name'))}</label><input id="request-app-name" name="name" required maxlength="200" autocomplete="off" value="${esc(detailOf(row).name || t('client.apps.defaultName', { name: service.name }))}">
      ${appFields(service, 'request-app')}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.register'))} ${icon('arrow')}</button></form>
    <button class="text-button full" type="button" data-action="deny-request">${esc(t('client.common.declineRegistration'))}</button>${expiry}</section>`);
  bindForm(async (form) => {
    const values = Object.fromEntries(service.auth_schemes.oauth.app_fields.map(({ name }) => [name, String(form.get(name) || '')]));
    await api('/v1/requests/' + row.id + '/grant', { method: 'POST', data: { name: String(form.get('name') || ''), ...values } });
    await refresh();
  }, app);
}
// The owner puts something into storage for a key. Everything specific to the service is the AI's words;
// Foundation shows only where it will go and how it will be handed over.
function renderStore(row, shell, expiry) {
  const asked = detailOf(row).fields, replacing = asked.some(one => one.replace);
  const title = asked.length === 1 ? replacing ? t('client.requests.replaceField', { name: asked[0].label }) : t('client.requests.storeField', { name: asked[0].label }) : replacing ? t('client.requests.replaceFields', { count: asked.length }) : t('client.requests.storeFields', { count: asked.length });
  const site = asked.find(one => one.site)?.site;
  const field = (one, at) => one.multiline
    ? `<textarea id="stored-${at}" name="value-${at}" rows="6" required maxlength="100000" autocomplete="off" spellcheck="false"></textarea>`
    : `<input id="stored-${at}" name="value-${at}" type="${one.readable ? 'text' : 'password'}" required maxlength="16384" autocomplete="off" spellcheck="false">`;
  app.innerHTML = shell(`<section class="approval-card">${requestHeading(row, title)}
    <dl class="approval-facts">${requestPurpose(row)}</dl>
    ${stepsBlock(row.steps)}
    ${site ? `<a class="button secondary full setup-link" href="${esc(site)}" target="_blank" rel="noopener noreferrer"><span>${esc(t('client.requests.openSite', { host: new URL(site).host }))}</span></a>` : ''}
    <form id="store-request-form">${asked.map((one, at) => `<div class="declared-field"><label for="stored-name-${at}">${esc(t('client.secret.storageName'))}</label><input id="stored-name-${at}" name="name-${at}" value="${esc(one.name)}" aria-describedby="stored-label-${at}" required maxlength="200" autocomplete="off" autocapitalize="off" spellcheck="false">${one.replace ? `<p class="permission-note replace-note" id="replace-note-${at}" data-name="${esc(one.name)}">${esc(t('client.requests.replaceExisting', { name: one.name }))}</p>` : ''}<label id="stored-label-${at}" for="stored-${at}">${esc(one.label)}</label>${field(one, at)}</div>`).join('')}
    <p class="permission-note">${esc(t('client.secret.validationNote'))}</p>
    <p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit">${esc(t('client.common.register'))} ${icon('arrow')}</button></form>
    <button class="text-button full" type="button" data-action="deny-request">${esc(t('client.common.declineRegistration'))}</button>${expiry}</section>`);
  // A replacement the owner renames becomes a new value; the note says which it is now.
  app.querySelectorAll('.replace-note').forEach(note => {
    const nameInput = note.parentElement.querySelector('input[name^="name-"]');
    const update = () => { note.textContent = nameInput.value === note.dataset.name ? t('client.requests.replaceExisting', { name: note.dataset.name }) : t('client.requests.storeRenamed', { previous: note.dataset.name, name: nameInput.value }); };
    nameInput.addEventListener('input', update);
  });
  bindForm(async (data) => {
    const entries = [];
    for (const [at] of asked.entries()) entries.push({ name: String(data.get('name-' + at) ?? ''), ...await sealFor(new TextEncoder().encode(String(data.get('value-' + at) ?? '')), row.recipients || []) });
    try { await api(`/v1/requests/${row.id}/grant`, { method: 'POST', data: { entries } }); }
    catch (error) { if ([401, 404].includes(error.status)) await refresh(); throw error; }
    await refresh(); toast(t('client.common.registered'));
  }, app);
}
const accessSummary = () => t('client.access.summary');
const accessScope = () => `<ul class="access-scope"><li>${esc(t('client.access.dataScope'))}</li><li>${esc(t('client.access.serviceScope'))}</li></ul>`;
const accessExclusions = () => t('client.access.exclusions');
const accessDetails = () => `<details class="access-permissions"><summary>${esc(t('client.access.permissionDetails'))}</summary>${accessScope()}<p>${accessExclusions()}</p></details>`;
// What one action lets its owner do, in the words of whoever grants it.
const ACTION_WORDS = () => ({
  transfer_grant: t('client.permissions.transfer'),
  'secret.list': t('client.permissions.secretList'), 'secret.read': t('client.permissions.secretRead'), 'secret.content': t('client.permissions.secretContent'), 'secret.write': t('client.permissions.secretWrite'), 'secret.remove': t('client.permissions.secretRemove'),
  'connection.list': t('client.permissions.connectionList'), 'connection.read': t('client.permissions.connectionRead'), 'connection.connect': t('client.permissions.connectionConnect'), 'connection.disconnect': t('client.permissions.connectionDisconnect'),
  'object.list': t('client.permissions.objectList'), 'object.read': t('client.permissions.objectRead'), 'object.write': t('client.permissions.objectWrite'), 'object.remove': t('client.permissions.objectRemove'), 'object.link': t('client.permissions.objectLink'),
  'app.use': t('client.permissions.appUse'), 'app.write': t('client.permissions.appWrite'), 'app.remove': t('client.permissions.appRemove'),
  'service.write': t('client.permissions.serviceWrite'), 'service.remove': t('client.permissions.serviceRemove'),
  'environment.open': t('client.permissions.environmentOpen'), 'environment.exec': t('client.permissions.environmentExec'), 'environment.remove': t('client.permissions.environmentRemove'),
  'principal.export': t('client.permissions.principalExport'), 'principal.audit-log': t('client.permissions.principalAuditLog'), 'principal.relate': t('client.permissions.principalRelate'), 'principal.issue-key': t('client.permissions.principalIssueKey'),
  'principal.inject': t('client.permissions.principalInject'), 'principal.invoke': t('client.permissions.principalInvoke'),
});
const actionWords = relation => ACTION_WORDS()[relation] ?? { viewer: t('client.permissions.viewer'), editor: t('client.permissions.editor') }[relation] ?? relation.replace(/^[a-z_]+\./, '').replace(/-/g, ' ');
// A relation asked for: to act for the one answering, asked by a key nobody knows yet and confirmed with its code; or
// one permission onto something, asked by a key already known.
function renderApproval(row, shell, expiry) {
  const asked = detailOf(row), first = row.to === null, acting = asked.relation === 'agent';
  const target = row.object ? `<div><dt>${esc(t('client.access.target'))}</dt><dd>${esc(row.object.name || row.object.id)}</dd></div>` : '';
  const scope = acting ? `${accessScope()}<small class="muted block">${accessExclusions()}</small>` : `<ul class="access-scope"><li>${esc(actionWords(asked.relation))}</li></ul>`;
  app.innerHTML = shell(`<section class="approval-card">${requestHeading(row, acting ? t('client.access.allowAccess') : t('client.access.grantPermissions'), 'device')}
    <dl class="approval-facts">${requestPurpose(row)}<div><dt>${esc(t('client.access.permissions'))}</dt><dd>${scope}</dd></div>${target}
    <div><dt>${esc(t('client.access.durationLabel'))}</dt><dd>${esc(acting ? t('client.access.durationAll') : t('client.access.duration'))}</dd></div></dl>
    <form id="access-request-form">${first ? codeField() : ''}
    <p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit"${first ? ' disabled' : ''}>${esc(t('client.access.allow'))} ${icon('arrow')}</button></form>
    <button class="text-button full" type="button" data-action="deny-request">${esc(t('client.access.decline'))}</button>${expiry}</section>`);
  const form = document.querySelector('#access-request-form'), submit = form.querySelector('[type="submit"]');
  const update = () => { submit.disabled = first && !codeComplete(form); };
  form.addEventListener('change', update); form.addEventListener('input', update);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submit.disabled || !form.reportValidity()) return;
    submit.disabled = true;
    const errorElement = form.querySelector('[role="alert"]'); errorElement.textContent = '';
    try {
      await api(`${requestApi}/grant`, { method: 'POST', data: first ? { user_code: form.elements.confirmationCode.value } : {} });
      await handEnvelope(row);
      await refresh();
    } catch (error) { if (form.isConnected) { errorElement.textContent = error.message; submit.disabled = false; } }
  });
}
function openDialog(content) {
  dialog.innerHTML = `<button class="dialog-close icon-button" data-action="close-dialog" aria-label="${esc(t('client.common.close'))}">${icon('close')}</button>${content}`;
  if (!dialog.open) dialog.showModal();
}
function closeDialog() {
  if (dialog.open) dialog.close();
  dialog.innerHTML = '';
  resumeRefresh();
}
dialog.addEventListener('cancel', (event) => { event.preventDefault(); closeDialog(); });
function bindForm(handler, container = dialog) {
  container.querySelector('form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget, button = form.querySelector('[type="submit"]');
    button.disabled = true; form.querySelector('.form-error').textContent = '';
    try { await handler(new FormData(form)); }
    catch (error) { if (form.isConnected) { form.querySelector('.form-error').textContent = error.message; button.disabled = false; } }
  });
}
// What the owner decides when connecting: which of the service's scopes to give, and which OAuth app to connect
// through - Foundation's, one of their own, or one someone lent them.
const appsFor = serviceId => (state.apps || []).filter(app => app.service?.id === serviceId).map(presentApp);
const oauthUsable = service => Boolean(service?.auth_schemes.oauth && (service.auth_schemes.oauth.foundation_app || (!service.auth_schemes.oauth.takes_apps && service.auth_schemes.oauth.available) || appsFor(service.id).length));
function connectChoices(service, connectionId, appId) {
  const scheme = service.auth_schemes.oauth, reconnecting = connectionId ? connected().find(item => item.id === connectionId) : null;
  const scopes = scheme.scopes ? `<label for="connect-scopes">${esc(reconnecting ? t('client.connections.additionalScopesLabel') : t('client.connections.scopesLabel'))}</label>
    <textarea id="connect-scopes" name="scopes" rows="3" autocomplete="off" spellcheck="false" placeholder="${esc(t('client.connections.scopePlaceholder', { name: service.name }))}"></textarea>
    <p class="permission-note">${reconnecting ? esc(t('client.connections.keepScopes')) + ' ' : ''}${esc(scheme.scopes.base.length ? t('client.connections.baseScopes', { scopes: new Intl.ListFormat(i18n.language).format(scheme.scopes.base) }) : t('client.connections.noBaseScopes'))} ${scheme.scopes.documentation_url ? `<a href="${esc(scheme.scopes.documentation_url)}" target="_blank" rel="noopener noreferrer">${esc(t('client.connection.permissionReference'))}</a>` : ''}</p>` : '';
  const apps = appsFor(service.id);
  if (!scheme.takes_apps || !apps.length) return scopes;
  const chosen = appId || reconnecting?.app?.id || (apps.find(app => app.foundation) || apps[0]).id;
  return scopes + `<label for="connect-app">${esc(t('client.oauth.app'))}</label><select id="connect-app" name="app">${apps.map(app => `<option value="${esc(app.id)}"${app.id === chosen ? ' selected' : ''}>${esc(app.name)}</option>`).join('')}</select>
    <p class="permission-note">${esc(t('client.apps.consentNotice', { name: service.name }))}</p>`;
}
// OAuth apps: what OAuth connections go through. Foundation's are there for anyone; the owner may add their own,
// and then decides at the service what can be granted and what name the consent screen shows.
// Whether the owner opened the apps; kept while the page is drawn again.
let appsOpen = false;
function appsSection() {
  // By service, so a service's own app and Foundation's for it sit side by side; Foundation's comes first.
  const apps = (state.apps || []).map(presentApp).sort((a, b) => compareText(a.service?.name || '', b.service?.name || '', i18n.language) || Number(b.foundation) - Number(a.foundation) || compareText(a.name, b.name, i18n.language));
  const row = app => {
    const mine = !app.foundation && app.owner_id === state.principal?.id;
    const detail = app.foundation ? t('client.oauth.availableToEveryone') : mine ? esc(t('client.apps.connectionCount', { id: app.client_id, count: app.connections ?? 0 })) : t('client.oauth.sharedApp');
    return `<article class="agent-row"><div class="connection-identity">${serviceLogo(app.service)}<div class="agent-name"><h3>${esc(app.service?.name || '')}</h3><p>${esc(app.name)}</p></div></div>
      <div class="agent-permissions"><span class="muted">${detail}</span></div>
      <div class="agent-actions">${mine ? `<button class="text-button" data-action="change-app" data-id="${esc(app.id)}">${esc(t('client.oauth.changeSecret'))}</button><button class="text-button danger" data-action="remove-app" data-id="${esc(app.id)}">${esc(t('client.common.delete'))}</button>` : ''}</div></article>`;
  };
  return `<details class="resource-section folded-section" id="oauth-apps" aria-labelledby="oauth-apps-title"${appsOpen ? ' open' : ''}><summary><h2 id="oauth-apps-title">${esc(t('client.oauth.app'))}</h2></summary>
    <div class="section-heading"><p>${esc(t('client.oauth.explanation'))}</p><button class="button secondary" data-action="add-app">${icon('plus')} ${esc(t('client.oauth.add'))}</button></div>
    ${apps.length ? `<div class="agent-list">${apps.map(row).join('')}</div>` : `<div class="access-empty"><p>${esc(t('client.oauth.empty'))}</p></div>`}</details>`;
}
// The fields an app of this service needs, and where its registration at the service must send people back.
const appFields = (service, prefix = 'app') => `${service.auth_schemes.oauth.app_fields.map(field => `<label for="${prefix}-${field.name}">${esc(field.required ? field.label : t('client.common.optionalLabel', { label: field.label }))}</label><input id="${prefix}-${field.name}" name="${field.name}"${field.required ? ' required' : ''} autocomplete="off" spellcheck="false"${field.sealed ? ' type="password"' : ''}${field.placeholder ? ` placeholder="${esc(field.placeholder)}"` : ''}>${field.note ? `<p class="permission-note">${esc(field.note)}</p>` : ''}`).join('')}
  <p class="permission-note">${esc(t('client.apps.redirectInstruction', { name: service.name, url: location.origin + '/oauth/callback' }))} ${service.console ? `<a href="${esc(service.console)}" target="_blank" rel="noopener noreferrer">${esc(t('client.oauth.openAppConsole'))}</a>` : ''}</p>`;
const takingApps = () => allServices().filter(service => service.auth_schemes.oauth?.takes_apps);
function addApp(serviceId, then) {
  const accepting = takingApps();
  const initial = accepting.find(service => service.id === serviceId) || accepting[0];
  if (!initial) return;
  const body = service => `<label for="app-name">${esc(t('client.common.name'))}</label><input id="app-name" name="name" required maxlength="200" autocomplete="off" value="${esc(t('client.apps.defaultName', { name: service.name }))}">${appFields(service)}`;
  openDialog(`<h2 id="dialog-title">${esc(t('client.oauth.add'))}</h2><p>${esc(t('client.oauth.addDescription'))}</p>
    <form><label for="app-service">${esc(t('client.service.title'))}</label><select id="app-service" name="service">${accepting.map(service => `<option value="${esc(service.id)}"${service.id === initial.id ? ' selected' : ''}>${esc(service.name)}</option>`).join('')}</select>
    <div class="app-body">${body(initial)}</div><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.add'))}</button></form>`);
  const choice = dialog.querySelector('#app-service');
  choice.addEventListener('change', () => { dialog.querySelector('.app-body').innerHTML = body(accepting.find(service => service.id === choice.value)); });
  bindForm(async (form) => {
    const service = accepting.find(item => item.id === form.get('service')), name = String(form.get('name') || '');
    const values = Object.fromEntries(service.auth_schemes.oauth.app_fields.map(({ name }) => [name, String(form.get(name) || '')]));
    await api('/v1/resources?kind=app&name=' + encodeURIComponent(name), { method: 'PUT', data: { service: service.id, ...values } });
    closeDialog(); await refresh(); toast(t('client.common.addedName', { name: name }));
    then?.(service.id);
  });
}
function changeApp(app) {
  const service = serviceById(app.service.id);
  openDialog(`<h2 id="dialog-title">${esc(t('client.apps.changeSecretTitle', { name: app.name }))}</h2><p>${esc(t('client.oauth.connectionsUnchanged'))}</p><form>${appFields(service, 'change')}
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.change'))}</button></form>`);
  dialog.querySelector('#change-client_id').value = app.client_id;
  bindForm(async (form) => {
    await api('/v1/resources/' + app.id, { method: 'PATCH', data: Object.fromEntries(service.auth_schemes.oauth.app_fields.map(({ name }) => [name, String(form.get(name) || '')])) });
    closeDialog(); await refresh(); toast(t('client.common.changed'));
  });
}
// Removing an app stops the connections made through it, as removing it at the service would.
function removeApp(app) {
  const count = app.connections ?? 0;
  openDialog(`<h2 id="dialog-title">${esc(t('client.common.deleteNameTitle', { name: app.name }))}</h2><form>
    <p>${count ? esc(t('client.apps.removeConnectionsWarning', { count })) : t('client.oauth.noConnectionsThroughApp')}</p>
    <p class="permission-note">${esc(t('client.apps.remoteAppRemains', { name: app.service?.name || '' }))}</p><p class="form-error" role="alert"></p>
    <div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">${esc(t('client.common.cancel'))}</button><button type="submit" class="button destructive">${esc(t('client.common.delete'))}</button></div></form>`);
  bindForm(async () => {
    const result = await api('/v1/resources/' + app.id, { method: 'DELETE', data: { confirm: true } });
    closeDialog(); await refresh();
    toast(result.connections_stopped ? t('client.apps.deletedConnections', { count: result.connections_stopped }) : t('client.common.deleted'));
  });
}
// Adding a service: find it among those Foundation knows and those the owner described, or describe one it does not.
let serviceFilter = '';
function servicePicker({ title, services, query = '', choose, create, filtered = () => {} }) {
  const sorted = [...services].sort((a, b) => compareText(a.name, b.name, i18n.language));
  openDialog(`<h2 id="dialog-title">${esc(title)}</h2>
    <input id="service-filter" type="search" aria-label="${esc(t('client.service.search'))}" placeholder="${esc(t('client.service.search'))}" value="${esc(query)}" autocomplete="off">
    <div class="service-grid">${sorted.map(service => `<button class="service-choice" data-id="${esc(service.id)}" data-name="${esc(service.name.toLowerCase())}">${serviceLogo(service)}<span>${esc(service.name)}</span></button>`).join('')}</div>
    <p class="permission-note" id="service-none" hidden>${esc(t('client.service.notFound'))}</p>
    <button class="text-button" id="create-service">${esc(t('client.service.addUnlisted'))}</button>`);
  const filter = dialog.querySelector('#service-filter');
  const apply = () => {
    const word = filter.value.trim().toLowerCase();
    let shown = 0;
    dialog.querySelectorAll('.service-choice').forEach(choice => { choice.hidden = Boolean(word) && !choice.dataset.name.includes(word); if (!choice.hidden) shown++; });
    dialog.querySelector('#service-none').hidden = shown > 0;
  };
  filter.addEventListener('input', () => { filtered(filter.value); apply(); });
  dialog.querySelectorAll('.service-choice').forEach(button => button.addEventListener('click', () => choose(serviceById(button.dataset.id))));
  dialog.querySelector('#create-service').addEventListener('click', () => create(filter.value.trim()));
  // Typing at once helps with a mouse and a keyboard; on a touch screen it only raises the keyboard over the list.
  apply(); if (matchMedia('(pointer: fine)').matches) filter.focus();
}
function addService() {
  servicePicker({ title: t('client.service.add'), services: allServices().filter(service => Object.keys(service.auth_schemes).length || ownService(service.id)), query: serviceFilter,
    filtered: value => { serviceFilter = value; }, choose: service => chooseService(service.id), create: name => defineService({ name }) });
}
// How a connection was made, as the owner did it. The words say what the owner does, not the protocol.
const WAYS = () => ({ oauth: t('client.connection.signinAndAllow'), role: t('client.connection.createIamRole'), token: t('client.connection.useToken') });
// The ways a service can be connected, the one that asks least of the owner first: Foundation's own app, a token
// they paste, then an OAuth app of their own. The first is offered outright; the rest sit under it, lighter.
function waysOf(service) {
  const oauth = service.auth_schemes.oauth, ways = [];
  if (service.auth_schemes.role) ways.push('role');
  if (oauth && (oauth.foundation_app || (!oauth.takes_apps && oauth.available))) ways.push('oauth');
  if (service.auth_schemes.token) ways.push('token');
  if (oauth?.takes_apps) ways.push('app');
  if (!oauth && ownService(service.id)) ways.push('configure');
  return ways;
}
const OTHER_WAYS = { oauth: service => t('client.connections.signInService', { name: service.name }), role: () => t('client.connection.createIamRole'), token: () => t('client.connection.useToken'), app: () => t('client.connection.useOwnOAuthApp'), configure: () => t('client.oauth.configure') };
function otherWays(service, shown) {
  const rest = waysOf(service).filter(way => way !== shown);
  return rest.length ? `<div class="other-ways">${rest.map(way => `<button class="button secondary full" type="button" data-action="choose-way" data-id="${esc(service.id)}" data-way="${way}">${esc(OTHER_WAYS[way](service))}</button>`).join('')}</div>` : '';
}
function chooseService(serviceId) {
  const service = serviceById(serviceId);
  if (!service) return;
  const [first] = waysOf(service);
  if (first) connectBy(service, first);
  else openDialog(`<h2 id="dialog-title">${esc(t('client.connections.connectName', { name: service.name }))}</h2><p>${esc(t('client.service.noConnectionMethods'))}</p>`);
}
function connectBy(service, way, connectionId) {
  if (way === 'configure') configureOAuth(service);
  else if (way === 'role' || way === 'token') connectByPaste(service, way, { connectionId });
  else if (way === 'app') {
    const own = appsFor(service.id).find(app => !app.foundation);
    if (own) connect(service.id, connectionId, own.id, 'app');
    else addApp(service.id, id => connect(id, connectionId));
  } else connect(service.id, connectionId);
}
// Starting a connection Foundation performs itself: the service decides who it is.
function connect(serviceId, connectionId, appId, shown = 'oauth') {
  const service = serviceById(serviceId);
  if (!service) return;
  if (!oauthUsable(service)) { addApp(service.id, id => connect(id, connectionId)); return; }
  openDialog(`<h2 id="dialog-title">${esc(t(connectionId ? 'client.connections.reconnectName' : 'client.connections.connectName', { name: service.name }))}</h2><p>${esc(t('client.connections.signInGrant', { name: service.name }))}</p><form>
    ${connectChoices(service, connectionId, appId)}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.connections.goToService', { name: service.name }))} ${icon('arrow')}</button></form>${connectionId ? '' : otherWays(service, shown)}`);
  bindForm(async (form) => {
    const scopes = String(form.get('scopes') || '').split(/\s+/).filter(Boolean), app = String(form.get('app') || '');
    const result = await api('/v1/connections', { method: 'POST', data: { service: service.id, auth_scheme: 'oauth', ...(connectionId ? { connection_id: connectionId } : {}),
      ...(scopes.length ? { scopes } : {}), ...(app && app !== 'foundation' ? { app } : {}) } });
    location.assign(result.url);
  });
}
// Made at the service and pasted here: a token, or a role made from a link Foundation prepares. The service says
// what is pasted and what to do there first; the link is its page for tokens, or one made for this connection.
// Pasting a token again replaces its value.
// Each field is pasted as a value, or refers to one of the owner's secrets, whose bytes are used - and whose line is
// looked at - every time; the choice sits under the field, and choosing a secret puts the input away.
const pastedFields = (scheme, prefix) => scheme.fields.map(field => `<label for="${prefix}-${esc(field.name)}">${esc(field.required === false ? t('client.common.optionalLabel', { label: field.label }) : field.label)}</label><input id="${prefix}-${esc(field.name)}" name="${esc(field.name)}"${field.required === false ? '' : ' required'}${field.secret ? ' type="password"' : ''} autocomplete="off" spellcheck="false"${field.placeholder ? ` placeholder="${esc(field.placeholder)}"` : ''}>${secrets().length ? `<select name="${esc(field.name)}:reference" aria-label="${esc(t('client.connections.referenceSecret', { label: field.label }))}" data-field="${esc(prefix)}-${esc(field.name)}" class="field-source"><option value="">${esc(t('client.connections.pasteValue'))}</option>${secrets().map(item => `<option value="${esc(item.id)}">${esc(t('client.connections.referenceSecret', { label: item.name }))}</option>`).join('')}</select>` : ''}${field.note ? `<p class="permission-note">${esc(field.note)}</p>` : ''}`).join('');
const pastedValues = (scheme, form) => Object.fromEntries(scheme.fields.map(field => { const reference = String(form.get(field.name + ':reference') || ''); return [field.name, reference ? { reference } : String(form.get(field.name) || '').trim()]; }).filter(([, value]) => value));
// Choosing a secret for a field puts its input away and lets the form be sent without it.
dialog.addEventListener('change', event => {
  const select = event.target.closest('select.field-source'); if (!select) return;
  const input = dialog.querySelector('#' + CSS.escape(select.dataset.field)); if (!input) return;
  input.hidden = Boolean(select.value); input.disabled = Boolean(select.value);
});
const serviceLink = (href, label) => href ? `<a class="button secondary full" href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(label)} ↗</a>` : '';
const instructions = scheme => scheme.instructions ? `<p class="permission-note">${esc(scheme.instructions)}</p>` : '';
async function connectByPaste(service, way, { connectionId, requestId } = {}) {
  const scheme = service.auth_schemes[way], replacing = connectionId ? connected().find(item => item.id === connectionId) : null, name = esc(service.name);
  // A role's link is made for this connection; what is pasted finishes that flow.
  const started = way === 'role' ? await api('/v1/connections', { method: 'POST', data: requestId ? { request_id: requestId } : { service: service.id, auth_scheme: 'role', ...(connectionId ? { connection_id: connectionId } : {}) } }) : null;
  const words = way === 'role'
    ? { title: esc(t('client.connections.createRole', { name: service.name })), link: t('client.connections.openService', { name: service.name }), paste: t('client.connection.pasteCreatedValue'), submit: esc(t('client.connection.connect')) + ' ' + icon('arrow') }
    : { title: replacing ? esc(t('client.connections.replaceValueTitle', { name: replacing.label })) : esc(t('client.connections.tokenTitle', { name: service.name })), lead: esc(t('client.connections.tokenLead', { name: service.name })), link: t('client.connections.createToken', { name: service.name }), submit: replacing ? t('client.common.replaceValue') : t('client.connection.connect') };
  const naming = way === 'token' && !replacing ? `<label for="pasted-name">${esc(t('client.common.name'))}</label><input id="pasted-name" name="name" maxlength="80" autocomplete="off" value="${esc(t('client.connections.tokenDefaultName', { name: service.name }))}">` : '';
  openDialog(`<h2 id="dialog-title">${words.title}</h2>${words.lead ? `<p>${words.lead}</p>` : ''}${serviceLink(started ? started.url : scheme.console, words.link)}${instructions(scheme)}
    <form>${words.paste ? `<p>${words.paste}</p>` : ''}${naming}${pastedFields(scheme, 'pasted')}
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${words.submit}</button></form>${replacing || requestId ? '' : otherWays(service, way)}`);
  bindForm(async (form) => {
    const fields = pastedValues(scheme, form), label = String(form.get('name') || '').trim();
    if (started) await api('/v1/connections/complete', { method: 'POST', data: { state: started.state, fields } });
    else await api('/v1/connections', { method: 'POST', data: { service: service.id, auth_scheme: 'token', fields, ...(replacing ? { connection_id: replacing.id } : label ? { name: label } : {}) } });
    closeDialog(); await refresh(); toast(replacing && !started ? t('client.connection.valueReplaced') : t('client.connections.connectedName', { name: service.name }));
  });
}
async function addServiceScheme(service, way, definition) {
  const result = await api('/v1/resources/' + service.id, { method: 'PATCH', data: { auth_schemes: { [way]: definition } } });
  return rememberService(result.resource);
}
// Registering the service and choosing how to connect it are separate steps.
function defineService({ name = '', created } = {}) {
  openDialog(`<h2 id="dialog-title">${esc(t('client.service.add'))}</h2><form>
    <label for="define-name">${esc(t('client.service.name'))}</label><input id="define-name" name="name" required maxlength="80" autocomplete="off" placeholder="${esc(t('client.service.namePlaceholder'))}" value="${esc(name)}">
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.add'))}</button></form>`);
  bindForm(async (form) => {
    const name = String(form.get('name') || '').trim();
    const result = await api('/v1/resources?kind=service&name=' + encodeURIComponent(name), {
      method: 'PUT', headers: { 'if-none-match': '*' }, data: { name },
    });
    const service = rememberService(result.resource);
    if (created) { created(service); return; }
    closeDialog(); await refresh(); toast(t('client.common.addedName', { name: name }));
  });
}
function configureOAuth(service) {
  openDialog(`<h2 id="dialog-title">${esc(t('client.services.oauthSettings', { name: service.name }))}</h2><form>
    <label for="define-authorize">${esc(t('client.oauth.authorizationUrl'))}</label><input id="define-authorize" name="authorize" required autocomplete="off" spellcheck="false" placeholder="https://example.com/oauth/authorize">
    <label for="define-token">${esc(t('client.oauth.tokenUrl'))}</label><input id="define-token" name="token" required autocomplete="off" spellcheck="false" placeholder="https://example.com/oauth/token">
    <label for="define-identity">${esc(t('client.oauth.identityUrl'))}</label><input id="define-identity" name="identity" autocomplete="off" spellcheck="false"><p class="permission-note">${esc(t('client.oauth.identityUrlNote'))}</p>
    <label for="define-revoke">${esc(t('client.oauth.revocationUrl'))}</label><input id="define-revoke" name="revoke" autocomplete="off" spellcheck="false"><p class="permission-note">${esc(t('client.oauth.revocationUrlNote'))}</p>
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.next'))} ${icon('arrow')}</button></form>`);
  bindForm(async (form) => {
    const value = name => String(form.get(name) || '').trim();
    const oauth = { authorize: value('authorize'), token: value('token'), scopes: { base: [] },
      ...(value('identity') ? { identity: { url: value('identity') } } : {}), ...(value('revoke') ? { revoke: { url: value('revoke'), style: 'rfc7009' } } : {}),
      injection: { OAUTH_ACCESS_TOKEN: '/access_token', OAUTH_EXPIRES_AT: '/expires_at' } };
    await addServiceScheme(service, 'oauth', oauth);
    addApp(service.id, id => connect(id));
  });
}
// Disconnect only this connection; secrets kept by hand remain.
function disconnect(connection) {
  const revoke = connection.can_revoke
    ? `<label class="check"><input type="checkbox" name="revoke" checked> ${esc(t('client.connections.revokeRemote', { name: connection.service.name }))}</label>`
    : `<p class="permission-note">${esc(t(connection.auth_scheme === 'role' ? 'client.connections.remoteRoleRemains' : connection.auth_scheme === 'token' ? 'client.connections.remoteTokenRemains' : 'client.connections.remotePermissionRemains', { name: connection.service.name }))}</p>`;
  openDialog(`<h2 id="dialog-title">${esc(t('client.connections.disconnectTitle', { name: connection.label }))}</h2><form>
    <p>${esc(t('client.connection.disconnectWarning'))}</p>
    <p class="permission-note">${esc(revocationNote())}</p>${revoke}<p class="form-error" role="alert"></p>
    <div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">${esc(t('client.common.cancel'))}</button><button type="submit" class="button destructive">${esc(t('client.connection.disconnect'))}</button></div></form>`);
  bindForm(async (form) => {
    const result = await api('/v1/resources/' + encodeURIComponent(connection.id), { method: 'DELETE', data: { revoke: form.get('revoke') === 'on' } });
    closeDialog(); await refresh();
    toast(result.service_revoked === false ? t('client.connection.disconnectedWithoutRevoking') : t('client.connection.disconnected'));
  });
}
// Adding a principal makes it and issues its key; it reaches nothing until a line is drawn to it, from its details.
function addKey() {
  openDialog(`<h2 id="dialog-title">${esc(t('client.access.addPrincipal'))}</h2><form><label for="agent-name">${esc(t('client.common.name'))}</label><input id="agent-name" name="name" placeholder="${esc(t('client.access.namePlaceholder'))}" required maxlength="80" autocomplete="off"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.access.addAndIssueKey'))}</button></form>`);
  bindForm(async (form) => {
    const result = await api('/v1/principals', { method: 'POST', data: { name: form.get('name'), key: true } });
    await refresh(); if (!state) return;
    openDialog(`<h2 id="dialog-title">${esc(t('client.principals.accessKeyTitle', { name: result.principal.name }))}</h2><p>${esc(t('client.access.keyStorageWarning'))}</p><label for="agent-token">${esc(t('client.access.key'))}</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.token)}</textarea><button class="button secondary full" data-action="copy-token">${esc(t('client.access.copyKey'))}</button><label for="api-url">${esc(t('client.access.endpoint'))}</label><input id="api-url" readonly value="${esc(location.origin)}/v1"><p class="permission-note">${esc(t('client.access.keySharingWarning'))}</p><button class="button primary full" data-action="close-dialog">${esc(t('client.common.close'))}</button>`);
  });
}
const principalById = id => (state.actors || []).find(item => item.id === id) || (state.principals || []).find(item => item.id === id);
// Machines lent to this account and still running: who each acts as, until when, and the month's computing.
function environmentsSection() {
  const running = state.environments || [], compute = state.compute;
  const minutes = seconds => t('client.environments.minutes', { count: Math.ceil(seconds / 60) });
  const status = { starting: t('client.environment.starting'), ready: t('client.environment.ready'), busy: t('client.environment.busy'), stopping: t('client.environment.stopping') };
  const identity = id => !id ? t('client.environment.noPermissions') : id === state.user.id ? t('client.environment.actingAsYou') : t('client.environments.actingAs', { name: principalById(id)?.name || t('client.principals.registeredPerson') });
  const row = item => `<article class="agent-row access-row"><div class="agent-name"><h3>${esc(item.name)}</h3><p>${esc(status[item.status] || item.status)} · ${esc(identity(item.identity))}</p></div>
    <div class="agent-permissions"><span class="muted">${esc(t('client.environments.until', { time: formatDate(item.expires_at, i18n.language, { hour: '2-digit', minute: '2-digit' }) }))}</span></div>
    <div class="agent-actions"><button class="text-button danger" data-action="close-environment" data-id="${esc(item.id)}">${esc(t('client.common.close'))}</button></div></article>`;
  return `<section class="resource-section" aria-labelledby="environments-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('device')}</span><h2 id="environments-title">${esc(t('client.environment.title'))}</h2></div>${compute ? `<span class="muted">${esc(t('client.environments.monthlyCompute', { used: minutes(compute.used_seconds), limit: minutes(compute.limit_seconds) }))}</span>` : ''}</div>
    ${running.length ? `<div class="agent-list">${running.map(row).join('')}</div>` : `<div class="access-empty"><p>${esc(t('client.environment.empty'))}</p></div>`}</section>`;
}
async function principalDetails(id) {
  const owned = (state.principals || []).some(item => item.id === id);
  const item = owned ? (await api(`/v1/principals/${id}`)).principal : principalById(id);
  if (!item) return;
  const allowed = owned ? item.acts_for.includes(state.user.id) : true;
  const keys = item.keys;
  openDialog(`<div class="principal-heading"><h2 id="dialog-title">${esc(item.name)}</h2>${owned ? `<button class="icon-button" data-action="rename-principal" data-id="${esc(id)}" aria-label="${esc(t('client.common.editName'))}" title="${esc(t('client.common.editName'))}">${icon('edit')}</button>` : ''}</div>
    <p>${allowed ? t('client.access.allowed') : t('client.access.noFullAccess')}</p>
    ${allowed ? `<p>${t('client.access.grantedSummary')}</p>${accessDetails()}` : owned ? `<p>${accessSummary()}</p><p class="permission-note">${esc(t('client.access.durationIncludingFuture'))}</p><button class="button secondary" data-action="make-agent" data-id="${esc(id)}">${esc(t('client.access.makeAgent'))}</button>` : ''}
    ${owned ? `<section class="principal-keys"><div class="section-heading"><h3>${esc(t('client.access.key'))}</h3><button class="text-button" data-action="issue-key" data-id="${esc(id)}">${esc(t('client.access.issueKey'))}</button></div>
      ${keys.length ? `<ul class="connection-list">${keys.map(key => `<li><div><code>${esc(key.id.slice(0, 8))}</code><p>${key.environment_id ? t('client.access.environmentKey') : esc(t('client.principals.keyIssuedAt', { date: formatDate(key.created_at, i18n.language) }))}</p></div><button class="text-button danger" data-action="revoke-key" data-id="${esc(id)}" data-key="${esc(key.id)}">${esc(t('client.access.revokeKey'))}</button></li>`).join('')}</ul>` : `<p class="muted">${esc(t('client.access.noKeys'))}</p>`}</section>
      <div class="principal-delete"><button class="text-button danger" data-action="remove-principal" data-id="${esc(id)}">${esc(t('client.access.deleteRegistration'))}</button></div>` : ''}`);
}
function renamePrincipal(item) {
  openDialog(`<h2 id="dialog-title">${esc(t('client.common.changeName'))}</h2><form><label for="agent-name">${esc(t('client.common.name'))}</label><input id="agent-name" name="name" required maxlength="80" autocomplete="off" value="${esc(item.name)}"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.save'))}</button></form>`);
  bindForm(async (form) => { await api(`/v1/principals/${item.id}`, { method: 'PATCH', data: { name: form.get('name') } }); await refresh(); await principalDetails(item.id); });
}
function renameMe() {
  openDialog(`<h2 id="dialog-title">${esc(t('client.common.changeName'))}</h2><form><label for="my-name">${esc(t('client.common.name'))}</label><input id="my-name" name="name" required maxlength="80" autocomplete="name" value="${esc(state.principal.name || '')}"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.save'))}</button></form>`);
  bindForm(async (form) => {
    const { principal } = await api('/v1/principals/me', { method: 'PATCH', data: { name: form.get('name') } });
    // The device's passkey list is told the new name too, where the browser can (the WebAuthn signal API).
    try { await PublicKeyCredential.signalCurrentUserDetails?.({ rpId: location.hostname, userId: text64(new TextEncoder().encode(principal.id)), name: principal.name, displayName: principal.name }); } catch {}
    closeDialog(); await refresh();
  });
}
// Things of the account's, chosen, given to another principal: each resource and each owned principal, one by one,
// as the API gives them. A secret goes with an envelope made here when the key is open; otherwise Foundation makes one.
async function handOver() {
  let objects = [];
  try { objects = (await api('/v1/resources?kind=object')).resources; } catch {}
  const groups = [[t('client.handover.secrets'), secrets()], [t('client.handover.connections'), connected().map(item => ({ ...item, name: item.label || item.service.name }))], [t('client.handover.objects'), objects],
    [t('client.handover.apps'), (state.apps || []).filter(item => !item.foundation && item.owner_id === state.user.id)], [t('client.handover.services'), (state.services || []).filter(item => item.owner_id === state.user.id)],
    [t('client.handover.principals'), (state.principals || []).map(item => ({ ...item, kind: 'principal' }))]].filter(([, items]) => items.length);
  const choice = (item, at) => `<label class="handover-item"><input type="checkbox" name="item" value="${esc(item.kind + ':' + item.id)}" id="hand-${esc(at)}"> ${esc(item.name)}</label>`;
  openDialog(`<h2 id="dialog-title">${esc(t('client.handover.title'))}</h2><form>${groups.map(([title, items], group) => `<fieldset class="handover-group"><legend>${esc(title)}</legend>${items.map((item, at) => choice(item, group + '-' + at)).join('')}</fieldset>`).join('') || `<p>${esc(t('client.handover.nothing'))}</p>`}
    <label for="handover-to">${esc(t('client.handover.recipientId'))}</label><input id="handover-to" name="to" required maxlength="64" autocomplete="off" spellcheck="false"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.handover.action'))}</button></form>`);
  bindForm(async (form) => {
    const to = String(form.get('to') || '').trim(), chosen = form.getAll('item').map(String);
    if (!chosen.length) throw new Error(t('client.handover.chooseSomething'));
    const { key } = await api('/v1/principals/' + encodeURIComponent(to) + '/public-key');
    const failures = [];
    for (const [title, items] of groups) for (const item of items) {
      if (!chosen.includes(item.kind + ':' + item.id)) continue;
      try {
        if (item.kind === 'principal') { await api('/v1/principals/' + item.id + '/transfer', { method: 'POST', data: { to } }); continue; }
        let envelope;
        if (item.kind === 'secret' && own && key.public_key) {
          try { const kept = await api('/v1/resources/' + item.id + '/content'); if (kept.envelope) envelope = b64(await sealing.seal(await openKey(kept), unb64(key.public_key))); } catch {}
        }
        await api('/v1/resources/' + item.id + '/transfer', { method: 'POST', data: { to, ...(envelope ? { envelope } : {}) } });
      } catch (error) { failures.push(t('client.handover.itemFailure', { group: title, name: item.name, message: error.message })); }
    }
    if (failures.length) throw new Error(failures.join('\n'));
    closeDialog(); await refresh();
  });
}
// Two accounts made one. First which way: the other into this, or this into the other. Then the other, by its id, and
// its passkey, which proves it and yields its key. The one that ends has its secrets sealed anew for the remaining
// one's key in this page, and ends with its lines and sessions.
function mergeAccount() {
  openDialog(`<h2 id="dialog-title">${esc(t('client.merge.title'))}</h2><form><fieldset class="handover-group">
    <label class="handover-item"><input type="radio" name="into" value="this" checked> ${esc(t('client.merge.intoThis'))}</label>
    <label class="handover-item"><input type="radio" name="into" value="other"> ${esc(t('client.merge.intoOther'))}</label></fieldset>
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.next'))}</button></form>`);
  bindForm(async (form) => {
    const into = String(form.get('into'));
    openDialog(`<h2 id="dialog-title">${esc(t('client.merge.title'))}</h2><form><label for="merge-other">${esc(t('client.merge.otherId'))}</label><input id="merge-other" name="other" required maxlength="64" autocomplete="off" spellcheck="false">
      <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.merge.confirmWithPasskey'))}</button></form>`);
    bindForm(async (form) => {
      const otherId = String(form.get('other') || '').trim();
      const { options } = await api('/v1/merge/options', { method: 'POST', data: { principal_id: otherId } });
      let given;
      try { given = await navigator.credentials.get({ publicKey: { ...options, challenge: bytes(options.challenge), allowCredentials: described(options.allowCredentials), extensions: { prf: { eval: { first: PRF_INPUT } } } } }); }
      catch (error) { if (passkeyDeclined(error)) return; throw error; }
      const yielded = yieldedBy(given);
      const credential = { id: given.id, rawId: text64(given.rawId), type: given.type, clientExtensionResults: {},
        response: { clientDataJSON: text64(given.response.clientDataJSON), authenticatorData: text64(given.response.authenticatorData), signature: text64(given.response.signature), ...(given.response.userHandle ? { userHandle: text64(given.response.userHandle) } : {}) } };
      const begun = await api('/v1/merge', { method: 'POST', data: { credential, principal_id: otherId } });
      const name = begun.other.name || begun.other.id;
      openDialog(`<h2 id="dialog-title">${esc(t('client.merge.title'))}</h2><form><p>${esc(t(into === 'this' ? 'client.merge.confirmThis' : 'client.merge.confirmOther', { name }))}</p><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.merge.action'))}</button></form>`);
      bindForm(async () => {
        const envelopes = {};
        if (into === 'this') {
          // This account's key: open here, or published, or made now with what the passkey yielded.
          let mine = own, made = null;
          if (!mine) { const { key } = await api('/v1/key'); if (key.public_key) mine = { publicKey: unb64(key.public_key) }; else if (yielded) { made = await sealing.generateKey(); mine = made; } }
          if (begun.wrap && yielded && mine && begun.key.public_key) {
            const theirs = { privateKey: await sealing.unwrap(unb64(begun.wrap), yielded), publicKey: unb64(begun.key.public_key) };
            for (const item of begun.secrets) { if (item.envelope) envelopes[item.id] = b64(await sealing.seal(await sealing.open(unb64(item.envelope), theirs.privateKey, theirs.publicKey), mine.publicKey)); }
          }
          const wrap = yielded && (made || own) ? b64(await sealing.wrap((made || own).privateKey, yielded)) : undefined;
          await api('/v1/merge/complete', { method: 'POST', data: { ticket: begun.ticket, into, envelopes, ...(wrap ? { wrap } : {}), ...(made ? { public_key: b64(made.publicKey) } : {}) } });
          if (made) { own = made; keyUnavailable = false; }
          closeDialog(); await refresh();
          return;
        }
        // This account ends: its secrets go sealed for the other's key, with this key when it is open here.
        if (own && begun.key.public_key) {
          for (const item of secrets()) {
            try { const kept = await api('/v1/resources/' + item.id + '/content'); if (kept.envelope) envelopes[item.id] = b64(await sealing.seal(await openKey(kept), unb64(begun.key.public_key))); } catch {}
          }
        }
        await api('/v1/merge/complete', { method: 'POST', data: { ticket: begun.ticket, into, envelopes } });
        own = null;
        location.replace('/');
      });
    });
  });
}
async function issueKey(item) {
  const result = await api(`/v1/principals/${item.id}/keys`, { method: 'POST', data: {} });
  await refresh();
  openDialog(`<h2 id="dialog-title">${esc(t('client.principals.accessKeyTitle', { name: item.name }))}</h2><p>${esc(t('client.access.keyShownOnce'))}</p><label for="agent-token">${esc(t('client.access.key'))}</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.token)}</textarea><button class="button secondary full" data-action="copy-token">${esc(t('client.access.copyKey'))}</button><button class="button primary full" data-action="principal-details" data-id="${esc(item.id)}">${esc(t('client.common.done'))}</button>`);
}
function revokeKey(item, key) {
  openDialog(`<h2 id="dialog-title">${esc(t('client.access.confirmRevokeKey'))}</h2><p>${esc(item.name)} · ${esc(key.slice(0, 8))}</p><form><p>${esc(t('client.access.revokeKeyWarning'))}</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="principal-details" data-id="${esc(item.id)}">${esc(t('client.common.cancel'))}</button><button type="submit" class="button destructive">${esc(t('client.access.confirmRevoke'))}</button></div></form>`);
  bindForm(async () => { await api(`/v1/principals/${item.id}/keys/${key}`, { method: 'DELETE', data: {} }); await refresh(); await principalDetails(item.id); toast(t('client.access.keyRevoked')); });
}
function addIntegration() {
  openDialog(`<h2 id="dialog-title">${esc(t('client.integration.register'))}</h2><form>
    <label for="integration-name">${esc(t('client.common.name'))}</label><input id="integration-name" name="name" placeholder="${esc(t('client.integration.namePlaceholder'))}" required maxlength="80" autocomplete="off">
    <label for="integration-return">${esc(t('client.integration.returnUrl'))}</label><input id="integration-return" name="return_url" type="url" required placeholder="https://example.com/foundation" autocomplete="off">
    <p class="permission-note">${esc(t('client.integration.returnUrlNote'))}</p>
    <label for="integration-refresh">${esc(t('client.integration.refreshUrl'))}</label><input id="integration-refresh" name="refresh_url" type="url" autocomplete="off">
    <label for="integration-webhook">${esc(t('client.integration.webhookUrl'))}</label><input id="integration-webhook" name="webhook_url" type="url" autocomplete="off">
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.integration.issueKey'))}</button></form>`);
  bindForm(async (form) => {
    // An app is a principal of this person's making, with settings for handing its users back, and a key of its own.
    const made = (await api('/v1/principals', { method: 'POST', data: { name: form.get('name') } })).principal;
    const settings = (await api(`/v1/principals/${made.id}/settings`, { method: 'PUT', data: { return_url: form.get('return_url'), refresh_url: form.get('refresh_url') || undefined, webhook_url: form.get('webhook_url') || undefined } })).settings;
    const issued = await api(`/v1/principals/${made.id}/keys`, { method: 'POST', data: {} });
    const result = { ...made, token: issued.token, webhook_secret: settings.webhook_secret };
    await refresh(); if (!state) return;
    openDialog(`<h2 id="dialog-title">${esc(t('client.integrations.keyTitle', { name: result.name }))}</h2><p>${esc(t('client.access.keyShownOnce'))}</p><label for="agent-token">${esc(t('client.integration.key'))}</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.token)}</textarea><button class="button secondary full" data-action="copy-token">${esc(t('client.access.copyKey'))}</button>
      ${result.webhook_secret ? `<label for="webhook-secret">${esc(t('client.integration.webhookSecret'))}</label><textarea id="webhook-secret" rows="2" readonly spellcheck="false">${esc(result.webhook_secret)}</textarea><p class="permission-note">${esc(t('client.integration.webhookSecretNote'))}</p>` : ''}
      <button class="button primary full" data-action="close-dialog">${esc(t('client.common.close'))}</button>`);
  });
}
function removePrincipal(item) {
  openDialog(`<h2 id="dialog-title">${esc(t('client.access.confirmDeleteRegistration'))}</h2><p>${esc(item.name)}</p><form><p>${esc(t('client.access.deleteRegistrationWarning'))}</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="principal-details" data-id="${esc(item.id)}">${esc(t('client.common.cancel'))}</button><button type="submit" class="button destructive">${esc(t('client.common.confirmDelete'))}</button></div></form>`);
  bindForm(async () => { await api(`/v1/principals/${item.id}`, { method: 'DELETE', data: {} }); closeDialog(); await refresh(); toast(t('client.access.registrationDeleted')); });
}
function revokeAccess(item) {
  openDialog(`<h2 id="dialog-title">${esc(t('client.access.confirmRevokeAccess'))}</h2><p>${esc(item.name)}</p><form><p>${esc(t('client.access.revokeAccessWarning'))}</p><p class="permission-note">${esc(t('client.access.revokeExternalCredentials'))}</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">${esc(t('client.common.cancel'))}</button><button type="submit" class="button destructive">${esc(t('client.access.revokePermission'))}</button></div></form>`);
  bindForm(async () => { await api(`/v1/principals/${item.id}/access`, { method: 'DELETE', data: {} }); closeDialog(); await refresh(); toast(t('client.access.revoked')); });
}
// Sealing for everyone a secret of the owner's is for: those the server names (the owner, and Foundation when it
// acts for them), and whoever already had the secret's key.
async function sealFor(bytes, recipients) {
  const contentKey = sealing.newContentKey(), envelopes = {};
  for (const item of recipients) envelopes[item.principal_id] = b64(await sealing.seal(contentKey, unb64(item.public_key)));
  return { content: b64(await sealing.sealContent(contentKey, bytes)), envelopes };
}
// The secret's key, from the envelope made for the owner.
const openKey = kept => sealing.open(unb64(kept.envelope), own.privateKey, own.publicKey);
let receiving = false;
// Secrets sealed for Foundation and not yet for the owner's key - as those kept before the owner had one -
// are handed to the owner by Foundation, from its own envelope, as soon as the key is open.
async function receiveFromFoundation() {
  const me = state.user.id, foundation = state.foundation?.principal_id;
  const waiting = secrets().filter(item => !item.recipients.includes(me) && item.recipients.includes(foundation));
  if (!waiting.length || receiving) return;
  receiving = true;
  try {
    for (const item of waiting) await api('/v1/resources/' + item.id + '/envelopes/' + me, { method: 'POST', data: {} });
    await refresh();
  } catch (error) { toast(error.message); } finally { receiving = false; }
}
// Foundation made the owner's agent: a line, and an envelope for everything kept so far.
async function allowFoundation(button) {
  const foundation = state.foundation.principal_id;
  button.disabled = true;
  try {
    await api('/v1/relations', { method: 'POST', data: { subject: foundation, relation: 'agent', object_type: 'principal', object_id: state.user.id } });
    const { key } = await api('/v1/principals/' + foundation + '/public-key');
    for (const item of secrets()) {
      if (item.recipients.includes(foundation)) continue;
      const kept = await api('/v1/resources/' + item.id + '/content');
      if (!kept.envelope) continue;
      await api('/v1/resources/' + item.id + '/envelopes/' + foundation, { method: 'PUT', data: { wrapped: b64(await sealing.seal(await openKey(kept), unb64(key.public_key))) } });
    }
    await refresh();
  } catch (error) { toast(error.message); if (button.isConnected) button.disabled = false; }
}
// A line drawn onto a secret reaches its bytes only with an envelope: Foundation makes one from its own, or the
// owner's key does here.
async function handEnvelope(row) {
  if (row.object?.kind !== 'secret' || !['viewer', 'editor', 'content_grant', 'write_grant', 'share_grant'].includes(detailOf(row).relation)) return;
  const path = '/v1/resources/' + row.object.id + '/envelopes/' + row.from;
  try { await api(path, { method: 'POST', data: {} }); return; } catch (error) { if (!own || error.code !== 'not_sealed_for_foundation') { toast(error.message); return; } }
  try {
    const kept = await api('/v1/resources/' + row.object.id + '/content'), { key } = await api('/v1/principals/' + row.from + '/public-key');
    if (!kept.envelope || !key.public_key) return;
    await api(path, { method: 'PUT', data: { wrapped: b64(await sealing.seal(await openKey(kept), unb64(key.public_key))) } });
  } catch (error) { toast(error.message); }
}
// One confirmation, for removing something a key kept. Nothing here can be undone, and nothing reaches the service.
// The name and the way it reaches a command, changed without the value ever being handed back.
// Something the owner has in hand, put there without an agent asking for it first.
function addSecret() {
  openDialog(`<h2 id="dialog-title">${esc(t('client.secret.add'))}</h2>
    <form><label for="new-name">${esc(t('client.common.name'))}</label><input id="new-name" name="name" required maxlength="200" placeholder="${esc(t('client.secret.namePlaceholder'))}" autocomplete="off" spellcheck="false">
    <label for="new-value">${esc(t('client.secret.value'))}</label><textarea id="new-value" name="value" rows="4" required maxlength="100000" autocomplete="off" spellcheck="false"></textarea>
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.add'))}</button></form>`);
  bindForm(async (form) => {
    const name = form.get('name');
    const { recipients } = await api('/v1/recipients');
    await api('/v1/resources?' + new URLSearchParams({ kind: 'secret', name }), { method: 'PUT', data: await sealFor(new TextEncoder().encode(String(form.get('value'))), recipients) });
    closeDialog(); await refresh(); toast(t('client.common.addedName', { name: name }));
  });
}
function editSecret(entry, trigger) {
  if (!entry) return;
  const row = trigger.closest('.secret-row'), heading = row.querySelector('h3');
  const actions = [...row.querySelectorAll('button')];
  const form = document.createElement('form');
  form.className = 'secret-name-editor'; form.setAttribute('aria-label', t('client.common.rename'));
  form.innerHTML = `<div class="secret-name-field"><input name="name" aria-label="${esc(t('client.common.name'))}" required maxlength="200" value="${esc(entry.name)}" autocomplete="off" autocapitalize="off" spellcheck="false">
    <button class="icon-button save-name" type="submit" aria-label="${esc(t('client.common.save'))}" title="${esc(t('client.common.save'))}">${icon('check')}</button>
    <button class="icon-button" type="button" aria-label="${esc(t('client.common.cancel'))}" title="${esc(t('client.common.cancel'))}">${icon('close')}</button></div><p class="form-error" role="alert"></p>`;
  heading.hidden = true; heading.after(form); row.classList.add('renaming');
  actions.forEach(button => { button.disabled = true; });
  trigger.hidden = true;
  const input = form.querySelector('input'), save = form.querySelector('[type="submit"]'), cancel = form.querySelector('[type="button"]'), error = form.querySelector('[role="alert"]');
  let saving = false;
  const close = () => {
    if (saving) return;
    form.remove(); heading.hidden = false; row.classList.remove('renaming');
    actions.forEach(button => { button.disabled = false; });
    trigger.hidden = false; trigger.focus();
    resumeRefresh();
  };
  cancel.addEventListener('click', close);
  form.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !event.isComposing) { event.preventDefault(); event.stopPropagation(); close(); }
  });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (saving) return;
    const name = input.value;
    if (name === entry.name) { close(); return; }
    saving = true; save.disabled = true; cancel.disabled = true; input.readOnly = true;
    form.setAttribute('aria-busy', 'true'); error.textContent = '';
    try {
      const { resource: saved } = await api('/v1/resources/' + entry.id, { method: 'PATCH', data: { name } });
      state.secrets = state.secrets.map(item => item.id === entry.id ? saved : item);
      const template = document.createElement('template'); template.innerHTML = secretRow(saved);
      const next = template.content.firstElementChild;
      row.replaceWith(next); bindSecretValue(saved, next);
      next.querySelector('[data-action="edit-secret"]').focus();
      toast(t('client.common.renamed'));
      resumeRefresh();
    } catch (failure) { if (form.isConnected) { error.textContent = failure.message; input.focus(); } }
    finally {
      saving = false; save.disabled = false; cancel.disabled = false; input.readOnly = false;
      form.removeAttribute('aria-busy');
    }
  });
  input.focus(); input.select();
}
function bindSecretValue(entry, row) {
  const path = '/v1/resources/' + entry.id + '/content', panel = row.querySelector('.secret-value-panel');
  let value = null, text = null, etag = null, recipients = [], revealed = false, binary = false, busy = false;
  const lock = locked => row.querySelectorAll('[data-action]').forEach(button => { button.disabled = locked; });
  const clear = () => { value = null; text = null; etag = null; revealed = false; };
  const control = (action, label, glyph) => `<button type="button" class="icon-button" data-value-action="${action}" aria-label="${label}" title="${label}"${own ? '' : ' disabled'}>${icon(glyph)}</button>`;
  const decode = bytes => {
    try {
      const decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
      return /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(decoded) ? null : decoded;
    } catch { return null; }
  };
  const load = async () => {
    busy = true; lock(true); panel.setAttribute('aria-busy', 'true');
    panel.querySelectorAll('button').forEach(button => { button.disabled = true; });
    try {
      const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store', headers: { 'X-Foundation-Locale': i18n.language } });
      if (response.status === 401) await showSignin();
      if (!response.ok) throw new Error(t('client.secret.loadFailed'));
      const kept = await response.json();
      if (!kept.envelope || !own) throw new Error(t('client.secret.loadFailed'));
      const bytes = await sealing.openContent(await openKey(kept), unb64(kept.content));
      if (!panel.isConnected) return false;
      value = bytes; text = decode(value); binary = text === null; etag = response.headers.get('etag'); recipients = kept.recipients;
      return true;
    } catch (error) {
      if (panel.isConnected) panel.querySelector('[role="alert"]').textContent = error instanceof TypeError ? t('client.errors.connectionFailed') : error.message;
      return false;
    } finally {
      busy = false; lock(false); panel.removeAttribute('aria-busy');
      panel.querySelectorAll('button').forEach(button => { button.disabled = false; });
    }
  };
  const show = (focus) => {
    lock(false);
    panel.innerHTML = `<div class="secret-value-line">${binary ? `<span class="secret-file">${icon('note')}${esc(t('client.common.file'))}</span>`
      : `<pre class="kept-document${revealed ? '' : ' secret-mask'}" aria-label="${revealed ? t('client.secret.value') : t('client.secret.hiddenValue')}">${revealed ? esc(text) : '••••••••'}</pre>`}<div class="secret-value-actions">${binary
      ? control('download', t('client.common.download'), 'download')
      : control('reveal', revealed ? t('client.secret.hideValue') : t('client.secret.showValue'), revealed ? 'eye-off' : 'eye') + control('copy', t('client.common.copy'), 'copy')}${control('edit', t('client.secret.editValue'), 'edit')}</div></div><p class="form-error" role="alert"></p>`;
    panel.querySelectorAll('[data-value-action]').forEach(button => button.addEventListener('click', async () => {
      if (busy) return;
      const action = button.dataset.valueAction;
      if (action === 'reveal' && revealed) { clear(); show('reveal'); return; }
      try {
        if (!await load()) return;
        if (action === 'edit') { edit(); return; }
        if (action === 'download') {
          const url = URL.createObjectURL(new Blob([value])), link = document.createElement('a');
          link.href = url; link.download = entry.name.split('/').pop(); link.click();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
          clear(); show('download'); return;
        }
        if (action === 'reveal') { revealed = !binary; show(binary ? 'edit' : 'reveal'); return; }
        if (binary) { clear(); show('edit'); return; }
        const copied = text;
        if (!revealed) clear();
        try { await navigator.clipboard.writeText(copied); toast(t('client.common.copied')); }
        catch { if (panel.isConnected) panel.querySelector('[role="alert"]').textContent = t('client.errors.copyFailed'); }
      } finally { resumeRefresh(); }
    }));
    if (focus) panel.querySelector(`[data-value-action="${focus}"]`)?.focus();
  };
  const edit = () => {
    lock(true); panel.classList.add('editing');
    panel.innerHTML = `<form aria-label="${esc(t('client.secret.valueEditor'))}">${binary
      ? `<input type="file" name="file" aria-label="${esc(t('client.common.file'))}" required>`
      : `<textarea name="value" aria-label="${esc(t('client.secret.value'))}" rows="6" required autocomplete="off" autocapitalize="off" spellcheck="false"></textarea>`}
      <p class="form-error" role="alert"></p><div class="dialog-actions"><button class="button secondary" type="button">${esc(t('client.common.cancel'))}</button><button class="button primary" type="submit">${esc(t('client.common.save'))}</button></div></form>`;
    const form = panel.querySelector('form'), input = form.querySelector('textarea, input'), cancel = form.querySelector('[type="button"]'), save = form.querySelector('[type="submit"]'), error = form.querySelector('[role="alert"]');
    if (!binary) input.value = text;
    const initial = input.value;
    let saving = false;
    const cancelEdit = () => { if (!saving) { clear(); panel.classList.remove('editing'); show('edit'); resumeRefresh(); } };
    cancel.addEventListener('click', cancelEdit);
    form.addEventListener('keydown', event => {
      if (event.key === 'Escape' && !event.isComposing) { event.preventDefault(); event.stopPropagation(); cancelEdit(); }
    });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (saving) return;
      if (!binary && input.value === initial) { cancelEdit(); return; }
      const file = binary ? input.files[0] : null;
      if (binary && !file) return;
      const content = binary ? file : new TextEncoder().encode(input.value);
      if ((binary ? file.size : content.length) > 1024 * 1024) { error.textContent = t('client.secret.sizeLimit'); return; }
      saving = true; error.textContent = ''; save.disabled = true; cancel.disabled = true; input.disabled = true;
      panel.setAttribute('aria-busy', 'true');
      try {
        if (!etag) throw new Error(t('client.secret.restartEdit'));
        const bytes = binary ? new Uint8Array(await file.arrayBuffer()) : content;
        // Sealed anew, for everyone who had it and everyone it is for now.
        const named = (await api('/v1/recipients')).recipients;
        const sealed = await sealFor(bytes, [...recipients, ...named.filter(item => !recipients.some(one => one.principal_id === item.principal_id))]);
        const response = await fetch(path, { method: 'PUT', credentials: 'same-origin', cache: 'no-store',
          headers: { 'X-Foundation-Locale': i18n.language, 'content-type': 'application/json', 'if-match': etag }, body: JSON.stringify(sealed) });
        const result = await response.json();
        if (response.status === 401) await showSignin();
        if (!response.ok) throw new Error(result.error?.message || t('client.errors.saveFailed'));
        binary = decode(bytes) === null; entry = result.resource; clear();
        state.secrets = state.secrets.map(item => item.id === entry.id ? entry : item);
        if (!panel.isConnected) return;
        row.querySelector('.secret-meta').innerHTML = secretMeta(entry); panel.classList.remove('editing');
        show('edit'); toast(t('client.common.saved')); resumeRefresh();
      } catch (failure) { if (form.isConnected) error.textContent = failure instanceof TypeError ? t('client.errors.connectionFailed') : failure.message; }
      finally {
        saving = false; save.disabled = false; cancel.disabled = false; input.disabled = false;
        panel.removeAttribute('aria-busy');
      }
    });
    input.focus();
  };
  show();
}
// A passkey for this browser's device or password manager. One kept only on this device is said so: losing the device
// loses it.
function addPasskey() {
  openDialog(`<h2 id="dialog-title">${esc(t('client.passkey.add'))}</h2><form><label for="passkey-name">${esc(t('client.common.name'))}</label><input id="passkey-name" name="name" required maxlength="80" autocomplete="off" value="${esc(deviceName())}">
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(t('client.common.add'))}</button></form>`);
  bindForm(async (form) => {
    let made;
    try { made = await createPasskey(String(form.get('name') || '').trim()); }
    catch (error) { throw passkeyDeclined(error) ? new Error(t('client.passkey.createFailed')) : error; }
    closeDialog(); await refresh();
    toast(made.backed_up ? t('client.passkey.added') : t('client.passkey.addedDeviceOnly'));
  });
}
function confirmRemoval(title, body, run, done = t('client.common.deleted'), label = t('client.common.confirmDelete')) {
  openDialog(`<h2 id="dialog-title">${esc(title)}</h2><form><p>${esc(body)}</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">${esc(t('client.common.cancel'))}</button><button type="submit" class="button destructive">${esc(label)}</button></div></form>`);
  bindForm(async () => { await run(); closeDialog(); await refresh(); toast(done); });
}
document.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-action]'); if (!target || target.disabled) return;
  const { action, id } = target.dataset;
  activeOperations++;
  try {
    if (action === 'close-dialog') closeDialog();
    if (action === 'add-passkey') addPasskey();
    if (action === 'unlock-key') {
      target.disabled = true;
      try { await unlockKey(); } catch (error) { if (!passkeyDeclined(error)) toast(error.message); }
      if (target.isConnected) target.disabled = false;
      render();
    }
    if (action === 'allow-foundation') await allowFoundation(target);
    if (action === 'set-payment') { target.disabled = true; location.assign((await api('/v1/payment/setup', { method: 'POST', data: {} })).url); }
    if (action === 'remove-passkey') {
      const item = (state.webauthn_credentials || []).find(entry => entry.id === id);
      if (item) confirmRemoval(t('client.common.deleteNameTitle', { name: item.name }), t('client.passkey.deleteWarning'), () => api('/v1/webauthn-credentials/' + encodeURIComponent(item.id), { method: 'DELETE', data: {} }));
    }
    if (action === 'retry-page') { target.disabled = true; try { await refresh(); } finally { if (target.isConnected) target.disabled = false; } }
    if (action === 'retry-signin') { target.disabled = true; await showSignin(); }
    if (action === 'signout') { target.disabled = true; await api('/v1/session', { method: 'DELETE', data: {} }); await showSignin(); }
    if (action === 'request-connect') {
      target.disabled = true;
      if (accessRequest.auth_scheme === 'role') { await connectByPaste(localizeService(accessRequest.service, i18n.language), 'role', { requestId }); target.disabled = false; return; }
      location.assign((await api('/v1/connections', { method: 'POST', data: { request_id: requestId } })).url);
    }
    if (action === 'deny-request') {
      target.disabled = true;
      await api(`${requestApi}/deny`, { method: 'POST', data: {} });
      await refresh();
    }
    if (action === 'add-service') addService();
    if (action === 'choose-service') chooseService(id);
    if (action === 'choose-way') connectBy(serviceById(id), target.dataset.way);
    if (action === 'remove-service') {
      const entry = ownService(id);
      if (entry) confirmRemoval(t('client.common.deleteNameTitle', { name: entry.service.name }), t('client.service.deleteWarning'), () => api('/v1/resources/' + entry.id, { method: 'DELETE', data: {} }));
    }
    if (action === 'reconnect') {
      const connection = connected().find(item => item.id === id);
      connectBy(serviceById(connection.service.id), connection.auth_scheme, connection.id);
    }
    if (action === 'add-app') addApp();
    if (action === 'change-app') changeApp((state.apps || []).find(item => item.id === target.dataset.id));
    if (action === 'remove-app') removeApp((state.apps || []).find(item => item.id === target.dataset.id));
    if (action === 'disconnect') disconnect(connected().find(item => item.id === target.dataset.id));
    if (action === 'drop-secret') {
      const name = target.dataset.name, entry = secrets().find(item => item.name === name);
      confirmRemoval(t('client.common.deleteNameTitle', { name: name }), t('client.secret.deleteWarning'), () => api('/v1/resources/' + entry.id, { method: 'DELETE', data: {} }));
    }
    if (action === 'upload-object') app.querySelector('#space-upload').click();
    if (action === 'more-objects') { objectLimit += 100; render(); }
    if (action === 'less-objects') { objectLimit = 100; render(); }
    if (action === 'toggle-search') { objectSearchPrefix = !objectSearchPrefix; render(); }
    if (action === 'sort-objects') {
      const key = target.dataset.sort;
      if (objectSort === key) objectDescending = !objectDescending; else { objectSort = key; objectDescending = key !== 'name'; }
      render();
    }
    if (action === 'choose-object') {
      if (target.checked) objectChosen.add(target.dataset.key); else objectChosen.delete(target.dataset.key);
      updateObjectSelection();
    }
    if (action === 'choose-all') {
      const boxes = [...document.querySelectorAll('tbody [data-action="choose-object"]')];
      for (const box of boxes) { if (target.checked) objectChosen.add(box.dataset.key); else objectChosen.delete(box.dataset.key); }
      updateObjectSelection();
    }
    if (action === 'copy-url') {
      const key = chosenKeys()[0];
      target.disabled = true;
      try {
        const result = await api('/v1/resources/' + state.space.objects.find(item => item.key === key).id + '/link', { method: 'POST', data: { minutes: 60 } });
        try { await navigator.clipboard.writeText(result.url); toast(t('client.objects.linkCopied')); }
        catch {
          openDialog(`<h2 id="dialog-title">${esc(t('client.objects.downloadUrl'))}</h2><p>${esc(t('client.objects.publicLinkNotice', { name: key }))}</p>
            <label for="object-link">URL</label><input id="object-link" readonly value="${esc(result.url)}"><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">${esc(t('client.common.close'))}</button></div>`);
          document.querySelector('#object-link')?.select();
        }
      } catch (error) { toast(error.message); }
      finally { target.disabled = false; }
    }
    if (action === 'drop-chosen') {
      const keys = chosenKeys();
      confirmRemoval(keys.length === 1 ? t('client.common.deleteNameTitle', { name: keys[0] }) : t('client.objects.deleteCountTitle', { count: keys.length }), t('client.objects.deleteWarning'),
        async () => { for (const key of keys) await api('/v1/resources/' + state.space.objects.find(item => item.key === key).id, { method: 'DELETE', data: {} }); objectChosen = new Set(); });
    }
    if (action === 'add-secret') addSecret();
    if (action === 'copy-name') {
      try { await navigator.clipboard.writeText(target.dataset.name); toast(t('client.common.copied')); }
      catch { toast(t('client.errors.copyFailed')); }
    }
    if (action === 'edit-secret') editSecret(secrets().find(item => item.name === target.dataset.name), target);
    if (action === 'add-key') addKey();
    if (action === 'make-agent') { target.disabled = true; await api('/v1/relations', { method: 'POST', data: { subject: id, relation: 'agent', object_type: 'principal', object_id: state.user.id } }); await refresh(); await principalDetails(id); }
    if (action === 'revoke-access') revokeAccess(principalById(id));
    if (action === 'close-environment') {
      const item = (state.environments || []).find(row => row.id === id);
      if (item) confirmRemoval(t('client.environments.closeTitle', { name: item.name }), t('client.environment.closeWarning'), () => api('/v1/environments/' + item.id, { method: 'DELETE', data: {} }), t('client.environment.closed'), t('client.environment.close'));
    }
    if (action === 'principal-details') await principalDetails(id);
    if (action === 'issue-key') { target.disabled = true; await issueKey(principalById(id)); }
    if (action === 'revoke-key') revokeKey(principalById(id), target.dataset.key);
    if (action === 'add-integration') addIntegration();
    if (action === 'remove-principal') removePrincipal(principalById(id));
    if (action === 'rename-principal') renamePrincipal(principalById(id));
    if (action === 'rename-me') renameMe();
    if (action === 'copy-id') { try { await navigator.clipboard.writeText(state.user.id); toast(t('client.common.copied')); } catch { toast(t('client.errors.copyFailed')); } }
    if (action === 'hand-over') handOver();
    if (action === 'merge') mergeAccount();
    if (action === 'copy-token') {
      const token = document.querySelector('#agent-token');
      try { await navigator.clipboard.writeText(token.value); toast(t('client.access.keyCopied')); }
      catch { token.select(); toast(t('client.access.keySelected')); }
    }
  } catch (error) { if (target.isConnected) target.disabled = false; toast(error.message); }
  finally { activeOperations--; void applyPendingLanguage(); }
});
const resultCode = new URL(location.href).searchParams.get('result');
const confirmationState = resultCode === 'review' ? new URL(location.href).searchParams.get('state') : null;
window.addEventListener('pageshow', event => { if (event.persisted && !isSigninConfirmation) void refresh().catch(() => {}); });
if (linkToken) {
  try {
    await api('/v1/links/exchange', { method: 'POST', data: { request_id: requestId, link: linkToken } });
    linked = true;
    try { sessionStorage.setItem('linked:' + requestId, '1'); } catch {}
  } catch (error) { if (!linked) { linked = true; requestError = error.message; } }
}
if (isSigninConfirmation) showSigninConfirmation();
else {
  if ((location.search || linkToken) && resultCode !== 'review') {
    const url = new URL(location.href);
    for (const key of ['signin', 'result', 'state']) url.searchParams.delete(key);
    if (linkToken) url.hash = '';
    history.replaceState(history.state, '', url);
  }
  try { await refresh(); } catch {}
  if (state && !requestId) scrollToPage(history.state?.scroll);
}
// What came back from an OAuth round trip, in words that hold for any service.
const resultMessages = { connected: t('client.connection.connected'), denied: t('client.connection.cancelled'), expired: t('client.connection.sessionExpired'),
  wrong_account: t('client.connection.wrongAccount'), scope: t('client.connection.scopeMismatch'),
  retry: t('client.connection.ongoingAccessFailed'), changed: t('client.connection.stateChanged'), failed: t('client.connection.failedRetry') };
if (resultCode === 'review') {
  try {
    const review = await api('/v1/connections/confirmation?state=' + encodeURIComponent(confirmationState));
    const values = items => items.length ? items.join('\n') : t('client.common.none');
    openDialog(`<h2 id="dialog-title">${esc(t('client.connection.reviewChanges'))}</h2><p>${esc(review.connection.service.name)} · ${esc(review.connection.label)}</p>
      <dl class="approval-facts">${presentedChanges(review).map(change => `<div><dt>${esc(change.label)}</dt><dd><p>${esc(t('client.connections.beforeValues', { values: values(change.before) })).replace(/\n/g, '<br>')}</p><p>${esc(t('client.connections.afterValues', { values: values(change.after) })).replace(/\n/g, '<br>')}</p></dd></div>`).join('')}</dl>
      <p class="permission-note">${esc(t('client.connection.updatePermissionWarning'))}</p>
      <form><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="cancel-connection-review">${esc(t('client.common.cancel'))}</button><button type="submit" class="button primary">${esc(t('client.connection.confirmUpdate'))}</button></div></form>`);
    document.querySelector('[data-action="cancel-connection-review"]').addEventListener('click', async () => {
      try { await api('/v1/connections/confirmation', { method: 'DELETE', data: { state: confirmationState } }); history.replaceState(null, '', pagePath); closeDialog(); }
      catch (error) { toast(error.message); }
    });
    bindForm(async () => { await api('/v1/connections/confirmation', { method: 'POST', data: { state: confirmationState } }); history.replaceState(null, '', pagePath); closeDialog(); await refresh(); toast(t('client.connection.updated')); });
  } catch (error) { toast(error.message); }
} else if (resultCode) toast(resultMessages[resultCode] || t('client.connection.checkAndRetry'));
initializing = false;
void applyPendingLanguage();
