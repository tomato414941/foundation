import { requestResultView, knownRequestKind, detailOf } from './request-view.js';
import { pages, brand, pageTitle, workspaceView, pendingView } from './workspace-view.js';

const app = document.querySelector('#app'), dialog = document.querySelector('#dialog'), notice = document.querySelector('#notice');
const publicInfo = document.querySelector('#public-info');
let state = null, toastTimer, loginTimer, revision = 0, refreshController, refreshDeferred = false;
const isLoginConfirmation = location.pathname === '/login/confirm';
// A fragment is not sent in HTTP requests. Keep the emailed key only in this page's memory.
const loginLink = isLoginConfirmation ? new URLSearchParams(location.hash.slice(1)) : null;
const loginReturn = isLoginConfirmation ? new URL(location.href).searchParams.get('return_to') || '/' : '/';
if (isLoginConfirmation) history.replaceState(null, '', '/login/confirm');
// Each request has its own URL, including a counterpart asking for access.
const requestId = location.pathname.match(/^\/requests\/([A-Za-z0-9_-]{43})$/)?.[1];
const requestApi = requestId && '/v1/requests/' + requestId;
// Opened through another product's single-use link: there is no Foundation login, only that one request.
const linkToken = requestId ? new URLSearchParams(location.hash.slice(1)).get('link') : null;
let linked = false, back = null;
// Back to the product: its return page with how the request ended, or its refresh page when the link was no good.
const backTo = row => { if (!row) return back.refresh_url; const url = new URL(back.return_url); url.searchParams.set('foundation_status', row.status); return url.href; };
try { linked = Boolean(requestId) && sessionStorage.getItem('linked:' + requestId) === '1'; } catch {}
let page = Object.hasOwn(pages, location.pathname) ? location.pathname.slice(1) || 'home' : 'home';
let pagePath = requestId ? location.pathname : page === 'home' ? '/' : '/' + page;
let accessRequest = null, requestError = '';
const loginMessages = {
  expired: '有効期限が切れています。もう一度ログインメールを送信してください。',
  invalid: 'リンクが無効か、有効期限が切れています。最新のメールのリンクを開いてください。',
  busy: 'ログインを確認しています。少し待ってからページを開き直してください。',
  limited: '操作が続いています。しばらく待ってからお試しください。',
  unavailable: 'ログインサービスに接続できません。少し待ってからリンクを開き直してください。',
};
let loginNotice = loginMessages[new URL(location.href).searchParams.get('login')] || '';
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
// The lent space, laid out the way an object browser is: a prefix acts as a folder, the list is a table
// you can sort and select in, and everything acts on the level you are looking at. The keys only look
// like paths, so the levels are worked out from the keys themselves rather than fetched one at a time.
const prefixOf = url => url.pathname === '/objects' ? url.searchParams.get('prefix') || '' : '';
const objectsHref = prefix => '/objects' + (prefix ? '?' + new URLSearchParams({ prefix }) : '');
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
  return { folders: [...folders.values()].sort((a, b) => a.name.localeCompare(b.name)), files };
}
// Only worth showing once you have stepped into something; at the top there is nowhere to go back to.
function crumbs() {
  const parts = objectPrefix.split('/').filter(Boolean);
  if (!parts.length) return '';
  const links = ['<a class="text-button" href="/objects">すべて</a>'];
  let walked = '';
  for (const [at, part] of parts.entries()) {
    walked += part + '/';
    links.push(at === parts.length - 1 ? `<span aria-current="location">${esc(part)}</span>`
      : `<a class="text-button" href="${esc(objectsHref(walked))}">${esc(part)}</a>`);
  }
  return `<nav class="crumbs" aria-label="パス">${links.join('<span aria-hidden="true">›</span>')}</nav>`;
}
const kindOf = name => { const cut = name.lastIndexOf('.'); return cut > 0 ? name.slice(cut + 1).toLowerCase() : '—'; };
function sortFiles(files) {
  const by = { name: (a, b) => a.name.localeCompare(b.name), size: (a, b) => a.size - b.size, updated: (a, b) => a.updated_at - b.updated_at };
  return [...files].sort((a, b) => (objectDescending ? -1 : 1) * by[objectSort](a, b));
}
function spaceSection() {
  const space = state.space;
  if (space === undefined) return '<section class="resource-section object-browser" aria-busy="true"><div class="content-loading" role="status" aria-label="読み込み中"><span></span><span></span><span></span></div></section>';
  if (!space || !space.available) return '<section class="resource-section object-browser"><div class="access-empty"><p>置き場は現在使えません。</p><button class="text-button" data-action="retry-page">再読み込み</button></div></section>';
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
  const rows = folders.map(item => `<tr><td><input type="checkbox" data-action="choose-object" data-key="${esc(objectPrefix + item.name)}" ${objectChosen.has(objectPrefix + item.name) ? 'checked' : ''} aria-label="${esc(item.name)} を選ぶ"></td>
      <td class="object-name"><span class="object-mark" aria-hidden="true">${icon('folder')}</span><a class="link-button" href="${esc(objectsHref(objectPrefix + item.name))}">${esc(item.name.slice(0, -1))}</a></td>
      <td>フォルダ</td><td>${esc(kiloBytes(item.bytes))}</td><td>${item.count} 件</td></tr>`).join('')
    + shown.map(item => `<tr><td><input type="checkbox" data-action="choose-object" data-key="${esc(item.key)}" ${objectChosen.has(item.key) ? 'checked' : ''} aria-label="${esc(item.name)} を選ぶ"></td>
      <td class="object-name"><span class="object-mark" aria-hidden="true">${icon('note')}</span><a href="/v1/resources/${esc(item.id)}/content" download>${esc(item.name)}</a></td>
      <td>${esc(kindOf(item.name))}</td><td>${esc(kiloBytes(item.size))}</td><td>${esc(keptWhen(item.updated_at))}</td></tr>`).join('');
  const body = space.objects.length === 0 ? '<div class="access-empty"><p>まだ何も置かれていません。AIに頼むか、ここから追加できます。</p></div>'
    : here.length === 0 ? `<div class="access-empty"><p>${needle ? `「${esc(objectFilter)}」に当てはまるものはありません。` : 'ここには何もありません。'}</p></div>`
    : `<div class="object-table-wrap"><table class="object-table"><thead><tr>
        <th><input type="checkbox" data-action="choose-all" ${allChosen ? 'checked' : ''} aria-label="この画面のものをすべて選ぶ"></th>
        <th>${column('name', '名前')}</th><th>種類</th><th>${column('size', 'サイズ')}</th><th>${column('updated', '更新')}</th></tr></thead>
        <tbody>${rows}</tbody></table></div>${paging(sorted.length, shown.length)}`;
  const chosen = chosenKeys();
  const tools = `<div class="object-tools"><input class="filter-field" id="object-filter" type="search" placeholder="${objectSearchPrefix ? 'この場所を接頭辞で探す' : '名前で絞り込む'}" value="${esc(objectFilter)}" autocomplete="off" aria-label="絞り込む">
    <button class="text-button" data-action="toggle-search">${objectSearchPrefix ? '部分一致にする' : '接頭辞で探す'}</button>
    <button class="button secondary" data-action="copy-url" ${chosen.length === 1 && !chosen[0].endsWith('/') ? '' : 'disabled'}>URLをコピー</button>
    <button class="button secondary danger" data-action="drop-chosen" ${chosen.length ? '' : 'disabled'}>削除${chosen.length ? `（${chosen.length}）` : ''}</button></div>`;
  return `<section class="resource-section object-browser" aria-label="置いてあるもの"><div class="object-location"><div class="object-count">オブジェクト（${space.usage?.count ?? space.objects.length}）</div>${crumbs()}</div>${tools}<div class="object-results">${body}</div></section>`;
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
  return `<div class="object-paging"><span>${showing} / ${total} 件</span>
    ${total > showing ? `<button class="button secondary" data-action="more-objects">さらに100件</button>` : ''}
    ${objectLimit > 100 ? `<button class="text-button" data-action="less-objects">最初の100件に戻す</button>` : ''}</div>`;
}

// A service by its logo, when the page has one for it, or else by its initial.
const serviceLogo = service => service?.logo ? `<svg viewBox="0 0 24 24" aria-hidden="true"><use href="/service-logos.svg#${esc(service.logo)}"/></svg>`
  : service?.name ? `<span class="service-letter" aria-hidden="true">${esc([...service.name][0].toUpperCase())}</span>` : icon('key');
const icon = (name) => {
  const paths = {
    plus: '<path d="M12 5v14M5 12h14"/>', close: '<path d="m6 6 12 12M6 18 18 6"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="3"/><path d="m3 7 9 6 9-6"/>',
    device: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
    arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>', check: '<path d="m5 12 4 4L19 6"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    database: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
    cloud: '<path d="M7 18a5 5 0 1 1 1-9.9A6 6 0 0 1 20 10a4 4 0 0 1-1 8Z"/>',
    code: '<path d="m8 8-4 4 4 4m8-8 4 4-4 4m-2-10-4 12"/>',
    key: '<circle cx="8" cy="14" r="4"/><path d="m11 11 8-8m-3 3 2 2m-5 1 2 2"/>',
    note: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/>',
    network: '<circle cx="6" cy="12" r="3"/><circle cx="18" cy="5" r="2"/><circle cx="18" cy="19" r="2"/><path d="m9 11 7-5m-7 7 7 5"/>',
    edit: '<path d="m15 5 4 4M4 20l5-1L20 8a2.8 2.8 0 0 0-4-4L5 15Z"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    'eye-off': '<path d="m3 3 18 18M10.6 5.1A12 12 0 0 1 12 5c6.5 0 10 7 10 7a19 19 0 0 1-3 3.9M6.1 6.1A22 22 0 0 0 2 12s3.5 7 10 7a12 12 0 0 0 5.9-1.9M9.9 9.9a3 3 0 0 0 4.2 4.2"/>',
    copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h3"/>',
    download: '<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>',
  };
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || ''}</svg>`;
};
const revocationNote = '停止後も、受け渡し済みの認証情報は有効期限まで使える場合があります。期限のないキーは、接続先で削除するまで無効になりません。';
function toast(text) {
  clearTimeout(toastTimer); notice.textContent = text; notice.hidden = false;
  toastTimer = setTimeout(() => { notice.hidden = true; }, 5500);
}
async function api(path, { method = 'GET', data, signal, headers = {} } = {}) {
  let response;
  try { response = await fetch(path, { method, signal, credentials: 'same-origin', cache: 'no-store', headers: { ...(data !== undefined ? { 'content-type': 'application/json' } : {}), ...headers }, ...(data !== undefined ? { body: JSON.stringify(data) } : {}) }); }
  catch (error) { if (signal?.aborted) throw error; throw new Error('接続できませんでした。通信状況を確認してください。'); }
  const result = await response.json();
  signal?.throwIfAborted();
  if (!response.ok) {
    const error = new Error(result.error?.message || '処理を完了できませんでした。'); error.status = response.status; error.code = result.error?.code; error.details = result.error;
    if (response.status === 401 && !linked && path !== '/v1/session' && !path.startsWith('/v1/login')) await showLogin();
    throw error;
  }
  return result;
}
function showLoginConfirmation() {
  const email = loginLink.get('email') || '', tokenHash = loginLink.get('token_hash') || '';
  const valid = loginLink.getAll('email').length === 1 && loginLink.getAll('token_hash').length === 1
    && email.length <= 254 && /^[^\s@]+@[^\s@]+$/.test(email) && /^[A-Za-z0-9_-]{20,2048}$/.test(tokenHash);
  app.innerHTML = `<div class="workspace login-shell"><header class="topbar">${brand}</header><main class="login-main"><div class="login-symbol" aria-hidden="true">${icon('mail')}</div>
    <h1>${valid ? 'ログイン' : 'リンクを確認'}</h1>
    ${valid ? `<p class="login-address">${esc(email)}</p><form id="confirm-login"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">ログイン ${icon('arrow')}</button></form>
    <p class="login-footer"><a href="/">別のメールアドレスを使う</a></p>` : '<p class="login-help">メールに届いたリンクを開き直してください。</p><p class="login-footer"><a href="/">ログインメールを送信</a></p>'}</main></div>`;
  if (!valid) return;
  const form = document.querySelector('#confirm-login'), button = form.querySelector('button');
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (button.disabled) return;
    button.disabled = true;
    form.querySelector('.form-error').textContent = '';
    try {
      const result = await api('/v1/login/verify', { method: 'POST', data: { email, token_hash: tokenHash, return_to: loginReturn } });
      location.replace(result.return_to);
    } catch (error) {
      form.querySelector('.form-error').textContent = error.message;
      button.disabled = false;
    }
  });
}
async function showLogin({ email = '', message = loginNotice } = {}) {
  clearInterval(loginTimer);
  refreshController?.abort();
  const current = ++revision; state = null; refreshDeferred = false; closeDialog();
  document.title = 'Foundation';
  app.innerHTML = pendingView('/');
  let config = { available: false, pending: null };
  try { config = await api('/v1/login'); }
  catch (error) { if (current === revision) showRefreshError(error, 'retry-login'); return; }
  if (current !== revision) return;
  const pending = config.available ? config.pending : null;
  app.innerHTML = `<div class="workspace login-shell"><header class="topbar">${brand}</header><main class="login-main"><div class="login-symbol" aria-hidden="true">${icon('mail')}</div>${requestId ? '<p class="login-context">依頼の確認</p>' : ''}<h1>${pending ? 'メールを確認' : 'ログイン'}</h1>
    ${pending ? `<p class="login-intro" id="email-sent">ログイン用のリンクをお送りしました。</p><p class="login-address">${esc(pending.email)}</p><p class="login-help">メールのリンクからログインしてください。有効期限は15分です。</p>` : '<p class="login-intro">メールに届くリンクからログインできます。</p>'}
    <form id="login-form">${pending ? '' : `<label for="login-email">メールアドレス</label><input id="login-email" name="email" type="email" autocomplete="email" required maxlength="254" value="${esc(email)}" ${config.available ? '' : 'disabled'}>`}
    <p class="form-error" role="alert">${config.available ? esc(message) : '現在ログインを利用できません。'}</p><button class="button ${pending ? 'secondary' : 'primary'} full" type="submit" ${pending ? 'id="resend-link" disabled' : config.available ? '' : 'disabled'}>${pending ? 'メールを再送信' : 'ログインメールを送信'} ${pending ? '' : icon('arrow')}</button></form>
    ${pending ? '<p class="login-help login-delivery">届かない場合は、迷惑メールフォルダもご確認ください。</p><div class="login-actions"><button class="text-button" type="button" id="change-email">メールアドレスを変更</button></div>' : config.available ? '<p class="login-help login-footer">初めての方も、このまま始められます。</p>' : ''}</main></div>`;
  if (!requestId && !pending && publicInfo) app.querySelector('.login-main').append(publicInfo);
  const form = document.querySelector('#login-form');
  let busy = false;
  function setBusy(value) {
    busy = value;
    for (const button of app.querySelectorAll('.login-main button')) button.disabled = value;
    if (!value && pending) updateResend();
  }
  function updateResend() {
    const resend = document.querySelector('#resend-link');
    if (current !== revision || !resend) { clearInterval(loginTimer); return; }
    const seconds = Math.max(0, Math.ceil((pending.resend_at - Date.now()) / 1000));
    resend.disabled = busy || seconds > 0;
    resend.textContent = seconds > 0 ? `再送信まで ${seconds}秒` : 'メールを再送信';
  }
  if (pending) {
    updateResend(); loginTimer = setInterval(updateResend, 1000);
    document.querySelector('#change-email').addEventListener('click', async () => {
      if (busy) return;
      setBusy(true);
      try { await api('/v1/login', { method: 'DELETE' }); loginNotice = ''; await showLogin({ email: pending.email }); }
      catch (error) { if (form.isConnected) { form.querySelector('.form-error').textContent = error.message; setBusy(false); } }
    });
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy || !config.available || (pending && Date.now() < pending.resend_at)) return;
    setBusy(true); loginNotice = ''; form.querySelector('.form-error').textContent = '';
    try {
      await api('/v1/login', { method: 'POST', data: { email: pending?.email || form.elements.email.value.trim(), return_to: returnTo() } });
      await showLogin();
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
  const current = revision;
  queueMicrotask(() => {
    if (!refreshDeferred || !state || current !== revision || editingPage()) return;
    refreshDeferred = false;
    void refresh({ background: true }).catch(() => {});
  });
}
function showRefreshError(error, action = 'retry-page') {
  if (!state && !app.querySelector('main[aria-busy]')) app.innerHTML = pendingView(pagePath);
  const main = app.querySelector('main');
  main.removeAttribute('aria-busy');
  main.querySelector('.content-loading')?.remove();
  main.querySelector('.object-browser[aria-busy]')?.removeAttribute('aria-busy');
  let alert = app.querySelector('.page-error');
  if (!alert) { alert = document.createElement('div'); alert.className = 'page-error'; main.before(alert); }
  alert.innerHTML = `<p role="alert">${esc(error.message)}</p><button class="text-button" data-action="${action}">再読み込み</button>`;
}
async function refresh({ background = false } = {}) {
  if (linked) {
    try { back = back || (await api('/v1/requests/' + requestId + '/return')).back; } catch {}
    try { accessRequest = (await api(requestApi)).request; requestError = ''; }
    catch (error) { accessRequest = null; requestError = error.status === 401 ? 'このリンクはもう使えません。元の画面から開き直してください。' : error.message; }
    state = { user: { email: '' }, secrets: [], credentials: [], actors: [], principals: [], catalog: [], services: [], apps: [], space: null };
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
const spaceSummary = space => space === undefined ? '…' : space?.available ? `${space.usage.count} 件・${kiloBytes(space.usage.bytes)} / ${kiloBytes(space.usage.bytes_max)}` : '使えません';

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
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || !state || requestId || isLoginConfirmation) return;
  const link = event.target.closest('a[href]');
  if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
  const url = new URL(link.href);
  if (url.origin !== location.origin || !Object.hasOwn(pages, url.pathname)
    || [...url.searchParams.keys()].some(key => url.pathname !== '/objects' || key !== 'prefix')) return;
  event.preventDefault();
  if (url.href !== location.href) navigate(url);
});
if (!requestId && !isLoginConfirmation) {
  history.scrollRestoration = 'manual';
  window.addEventListener('popstate', event => {
    if (!state) { location.reload(); return; }
    navigate(new URL(location.href), { restore: true, position: event.state?.scroll });
  });
}
// What the holder let Foundation use: secrets they handed over, and credentials for services.
const secrets = () => state.secrets || [];
const connected = () => state.credentials || [];
// Every service the holder can connect: those Foundation knows, and those they (or someone for them) described.
const allServices = () => [...(state.catalog || []), ...(state.services || []).map(row => row.service)];
const serviceById = id => allServices().find(item => item.id === id);
const ownService = id => (state.services || []).find(row => row.id === id && row.holder_id === state.user.id);
const unconnectedServices = () => (state.services || []).filter(row => !connected().some(connection => connection.service.id === row.id));
function rememberService(row) {
  state.services = [...(state.services || []).filter(item => item.id !== row.id), row];
  refreshDeferred = true;
  return row.service;
}
const keptWhen = value => new Date(value).toLocaleString('ja-JP');
const kiloBytes = size => size < 1024 ? size + ' バイト' : size < 1024 * 1024 ? Math.round(size / 1024) + ' KB'
  : size < 1024 * 1024 * 1024 ? Math.round(size / (1024 * 1024)) + ' MB' : (size / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
const statusName = status => ({ usable: '利用できます', reconnect_required: '接続し直しが必要です', disconnecting: '解除しています' }[status] || '確認が必要です');
// One credential for a service: which service, which account, and what is wrong when something is.
function connectionRow(connection) {
  const warning = connection.status !== 'usable';
  const account = connection.label;
  const app = connection.app === null ? '<p class="muted warning-text">使っていたOAuthアプリが削除されました</p>'
    : connection.app && !connection.app.foundation ? `<p class="muted">OAuthアプリ：${esc(connection.app.name)}</p>` : '';
  const way = connection.auth_scheme === 'role' ? '<p class="muted">IAMロール</p>' : '';
  return `<article class="agent-row connection-row"><div class="connection-identity">${serviceLogo(connection.service)}<div class="agent-name"><h3>${esc(connection.service.name)}</h3>${account && account !== connection.service.name ? `<p class="connection-account">${esc(account)}</p>` : ''}</div></div>
    <div class="connection-details">${warning ? `<p class="connection-status warning-text">${esc(statusName(connection.status))}</p>` : ''}${way}${app}${cloudflareDetails(connection)}${scopeDetails(connection.facts)}</div>
    <div class="agent-actions">${connection.can_reconnect ? `<button class="text-button" data-action="reconnect" data-id="${esc(connection.id)}">接続し直す</button>` : ''}<button class="text-button danger" data-action="disconnect" data-id="${esc(connection.id)}">接続を解除</button></div></article>`;
}
function cloudflareDetails(connection) {
  if (connection.service?.id !== 'cloudflare' || connection.auth_scheme !== 'oauth') return '';
  const accounts = connection.facts.observed_accounts;
  const names = accounts ? accounts.items.map(item => item.name).join('、') || 'なし' : '未確認';
  return `<p class="muted">確認できたアカウント：${esc(names)}${accounts && !accounts.complete ? '（一部）' : ''}</p>`;
}
// What the holder gave: the scopes the service granted, and any asked for but not granted.
function scopeDetails(facts) {
  const granted = facts?.scopes || [], missing = facts?.missing_scopes || [];
  if (!granted.length && !missing.length) return '';
  const list = scopes => `<ul class="scope-list">${scopes.map(scope => `<li><code>${esc(scope)}</code></li>`).join('')}</ul>`;
  return `<details class="scope-details"><summary>許可している権限（${granted.length}件）</summary>${list(granted)}</details>`
    + (missing.length ? `<details class="scope-details"><summary class="warning-text">許可されなかった権限（${missing.length}件）</summary>${list(missing)}</details>` : '');
}
function secretRow(entry) {
  return `<article class="secret-row" aria-label="${esc(entry.name)}"><div class="secret-field"><span class="secret-field-label">名前</span><div class="agent-name secret-title"><h3>${esc(entry.name)}</h3><button class="icon-button" data-action="copy-name" data-name="${esc(entry.name)}" aria-label="名前をコピー" title="名前をコピー">${icon('copy')}</button><button class="icon-button" data-action="edit-secret" data-name="${esc(entry.name)}" aria-label="名前を編集" title="名前を編集">${icon('edit')}</button></div></div>
    <div class="secret-field"><span class="secret-field-label">値</span><section class="secret-value-panel" aria-label="値"></section></div>
    <footer class="secret-footer"><p class="secret-meta">${secretMeta(entry)}</p><div class="secret-actions"><button class="text-button danger" data-action="drop-secret" data-name="${esc(entry.name)}">削除</button></div></footer></article>`;
}
const secretMeta = entry => `<span>${esc(kiloBytes(entry.size))}</span><span>更新 ${esc(keptWhen(entry.updated_at))}</span>`;
function render() {
  if (!state) return;
  if (requestId) { renderRequest(); return; }
  const shell = inner => {
    if (!app.querySelector('.page-nav')) app.innerHTML = workspaceView(pagePath);
    app.querySelector('.topbar').querySelectorAll('a').forEach(link => {
      if (link.getAttribute('href') === pagePath) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    document.title = pageTitle(pagePath);
    app.querySelector('[data-action="logout"]').disabled = false;
    app.querySelector('main').removeAttribute('aria-busy');
    app.querySelector('main').innerHTML = inner;
  };
  if (page === 'objects') {
    if (!app.querySelector('#space-upload')) {
      shell(`<header class="page-heading page-heading-actions"><div><h1>オブジェクト</h1><p id="object-usage"></p></div>
        <button class="button secondary" type="button" data-action="upload-object">${icon('plus')} 追加</button><input id="space-upload" type="file" hidden></header>${spaceSection()}`);
      bindObjects();
    }
    updateObjects();
    return;
  }
  if (page === 'functions') {
    // Available operations, independent of their invocations.
    const known = { 'http.request': ['HTTPS リクエスト', '預けたものを使ってHTTPSリクエストを送ります。'] };
    shell(`<header class="page-heading"><h1>ファンクション</h1></header>
      <section class="resource-section" aria-labelledby="functions-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('network')}</span><div><h2 id="functions-title">処理</h2></div></div></div>
      <div class="agent-list">${(state.functions || []).map(item => `<article class="agent-row"><div class="agent-name"><h3>${esc(known[item.id]?.[0] || item.id)}</h3><p><code>${esc(item.id)}</code></p></div><div class="agent-permissions"><span class="muted">${esc(known[item.id]?.[1] || item.description)}</span></div><div class="agent-actions"></div></article>`).join('')}</div></section>
      `);
    return;
  }
  if (page === 'account') {
    // The account itself: who this is, and the few things done to it rather than in it.
    shell(`<header class="page-heading"><h1>アカウント</h1><p>${esc(state.user.email)}</p></header>
      <section class="resource-section" aria-labelledby="export-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('download')}</span><div><h2 id="export-title">データのダウンロード</h2><p>シークレットの値、サービスとの接続、自分で定義したサービス、登録した相手の一覧が JSON ファイルで入ります。オブジェクトは入りません。</p></div></div><a class="button secondary" href="/v1/export" download>${icon('download')} ダウンロード</a></div></section>
      <section class="resource-section" aria-labelledby="developers-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('network')}</span><div><h2 id="developers-title">開発者</h2></div></div><a class="button secondary" href="/principals#apps">アプリの登録</a></div></section>`);
    return;
  }
  if (page === 'home') {
    // A look over everything, and the way to each page. Nothing is managed here.
    const space = state.space, kept = secrets(), connections = connected(), keys = state.actors || [];
    const card = (href, title, line) => `<a class="home-card" href="${href}"><h2>${title}</h2><p>${esc(line)}</p></a>`;
    const lastUsed = keys.flatMap(key => key.keys.map(item => item.last_used_at)).filter(Boolean).sort().at(-1);
    shell(`<header class="page-heading"><h1>Foundation</h1></header>
      <div class="home-cards">
        ${card('/services', 'サービス', `${connections.length + unconnectedServices().length} 件`)}
        ${card('/secrets', 'シークレット', `${kept.length} 件`)}
        ${card('/objects', 'オブジェクト', spaceSummary(space))}
        ${card('/principals', 'アクセス管理', keys.length ? `許可済み ${keys.length} 件${lastUsed ? '・最終利用 ' + new Date(lastUsed).toLocaleString('ja-JP') : ''}` : 'ありません')}
        ${card('/functions', 'ファンクション', `${state.functions?.length || 0} 種類`)}
      </div>`);
    return;
  }
  if (page === 'principals') {
    const actors = state.actors || [], others = (state.principals || []).filter(item => !actors.some(actor => actor.id === item.id));
    const used = item => { const at = item.keys.map(c => c.last_used_at).filter(Boolean).sort().at(-1); return at ? '最終利用 ' + esc(new Date(at).toLocaleString('ja-JP')) : 'まだ利用されていません'; };
    const row = (item, allowed) => `<article class="agent-row access-row"><div class="agent-name"><h3>${esc(item.name)}</h3><p>${used(item)}</p></div><div class="agent-permissions"><span class="muted">${allowed ? '許可 ' + esc(new Date(item.approved_at).toLocaleDateString('ja-JP')) : '全体へのアクセス許可なし'}</span></div><div class="agent-actions"><button class="text-button" data-action="principal-details" data-id="${esc(item.id)}">詳細</button>${allowed ? `<button class="text-button danger" data-action="revoke-access" data-id="${esc(item.id)}">取り消す</button>` : ''}</div></article>`;
    shell(`<header class="page-heading"><h1>アクセス管理</h1></header>
      <section class="resource-section" aria-labelledby="access-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('device')}</span><h2 id="access-title">登録した相手</h2></div><button class="button secondary" data-action="add-key">${icon('plus')} 追加</button></div>
      ${actors.length || others.length ? `<div class="agent-list">${actors.map(item => row(item, true)).join('')}${others.map(item => row(item, false)).join('')}</div>` : '<div class="access-empty"><p>登録した相手はいません。</p></div>'}</section>
      ${environmentsSection()}
      <div class="integration-entry" id="apps"><button class="text-button" data-action="add-integration">アプリを登録</button></div>`);
    return;
  }
  if (page === 'services') {
    // The services the holder's AI may use, by service. Adding one is a way in, not the page itself; the OAuth apps
    // connections go through are there when needed, folded away.
    const connections = connected(), waiting = unconnectedServices();
    const rows = [...connections.map(connection => ({ name: connection.service.name, label: connection.label, html: connectionRow(connection) })),
      ...waiting.map(row => ({ name: row.service.name, label: '', html: `<article class="agent-row connection-row" aria-label="${esc(row.service.name)}"><div class="connection-identity">${serviceLogo(row.service)}<div class="agent-name"><h3>${esc(row.service.name)}</h3></div></div>
        <div class="connection-details"><p class="muted">未接続</p></div><div class="agent-actions"><button class="text-button" data-action="choose-service" data-id="${esc(row.id)}">接続を追加</button>${ownService(row.id) ? `<button class="text-button danger" data-action="remove-service" data-id="${esc(row.id)}">削除</button>` : ''}</div></article>` }))]
      .sort((a, b) => a.name.localeCompare(b.name, 'ja') || a.label.localeCompare(b.label, 'ja'));
    shell(`<header class="page-heading page-heading-actions"><h1>サービス</h1><button class="button secondary" data-action="add-service">${icon('plus')} サービスを追加</button></header>
      <section class="resource-section" aria-label="サービス">
        ${rows.length ? `<div class="agent-list">${rows.map(row => row.html).join('')}</div>` : '<div class="access-empty"><p>接続はありません。</p></div>'}</section>
      ${appsSection()}`);
    app.querySelector('#oauth-apps').addEventListener('toggle', event => { appsOpen = event.currentTarget.open; });
    return;
  }
  if (page === 'secrets') {
    const focused = document.activeElement, focusedRow = focused.closest('.secret-row')?.getAttribute('aria-label');
    const focusedAction = focused.getAttribute('aria-label') || focused.dataset.action;
    const kept = secrets();
    shell(`<header class="page-heading page-heading-actions"><h1>シークレット</h1>
      <button class="button secondary" data-action="add-secret">${icon('plus')} 追加</button></header>
      <section class="resource-section" aria-label="シークレット">
        ${kept.length ? `<div class="agent-list">${kept.map(secretRow).join('')}</div>` : '<div class="access-empty"><p>シークレットはありません。</p></div>'}</section>`);
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
  if (drop) { drop.disabled = chosen.length === 0; drop.textContent = '削除' + (chosen.length ? `（${chosen.length}）` : ''); }
}
function updateObjects() {
  const usage = state.space?.usage, description = app.querySelector('#object-usage');
  description.textContent = usage ? `${kiloBytes(usage.bytes)} / ${kiloBytes(usage.bytes_max)}・${usage.count} / ${usage.count_max} 件` : '';
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
    filter.placeholder = objectSearchPrefix ? 'この場所を接頭辞で探す' : '名前で絞り込む';
    filter.oninput = () => { objectFilter = filter.value; objectLimit = 100; updateObjects(); };
    app.querySelector('[data-action="toggle-search"]').textContent = objectSearchPrefix ? '部分一致にする' : '接頭辞で探す';
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
          openDialog(`<h2 id="dialog-title">${esc(file.name)} を置き換えますか？</h2><form><p>同じ名前のものが置かれています。前のものは戻せません。</p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button primary">置き換える</button></div></form>`);
          const cancelled = () => resolve(false);
          dialog.addEventListener('close', cancelled, { once: true });
          dialog.querySelector('form').onsubmit = event => { event.preventDefault(); dialog.removeEventListener('close', cancelled); resolve(true); closeDialog(); };
        });
        if (!go) return;
      }
      const response = await fetch('/v1/resources?' + new URLSearchParams({ kind: 'object', name: key }), { method: 'PUT', credentials: 'same-origin',
        headers: { 'content-type': file.type || 'application/octet-stream' }, body: file });
      const result = await response.json();
      if (response.status === 401) await showLogin();
      if (!response.ok) throw new Error(result.error?.message || '追加できませんでした。');
      toast(file.name + ' を追加しました。');
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
const stepsBlock = steps => steps?.length ? `<section class="ai-guidance"><h3>手順</h3><ol class="guidance-steps">${steps.map(step => `<li>${esc(step)}</li>`).join('')}</ol></section>` : '';
const requestHeading = (row, title, symbol = 'lock') => `${state?.user?.email ? `<p class="request-account">${esc(state.user.email)}</p>` : ''}<header class="approval-heading"><span class="approval-symbol">${icon(symbol)}</span><div><p class="approval-eyebrow">${esc(row.requester_name)}の依頼</p><h1>${esc(title)}</h1></div></header>`;
const requestPurpose = row => row.binding_message ? `<div class="approval-purpose"><dt>目的</dt><dd>${esc(row.binding_message)}</dd></div>` : '';
const codeComplete = form => /^[0-9A-Z]{8}$/.test((form.elements.confirmationCode?.value || '').toUpperCase().replace(/[^0-9A-Z]/g, ''));
function codeField(enabled = true) {
  return `<label for="confirmation-code">確認コード</label><input id="confirmation-code" name="confirmationCode" required maxlength="9" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX" aria-describedby="confirmation-help" ${enabled ? '' : 'disabled'}><p class="permission-note" id="confirmation-help">依頼元から受け取ったコードを入力してください。</p>`;
}
// The link of a request shows the one screen its kind calls for:
//   approve   a key not yet approved: the owner accepts it with the code. Nothing is registered here.
//   connect   an approved key: Foundation performs the connection itself. No code.
//   store     an approved key: the owner puts something into storage, following the AI's instructions.
function renderRequest() {
  const row = accessRequest;
  const shell = (content) => `<div class="workspace"><header class="topbar">${brand}${linked ? '' : `<div class="user-menu"><a href="/account"${page === 'account' ? ' aria-current="page"' : ''}>アカウント</a><button class="text-button" data-action="logout">ログアウト</button></div>`}</header><main class="approval-main">${content}</main></div>`;
  const type = detailOf(row).type, asked = detailOf(row);
  if (!row || row.status !== 'pending' || !knownRequestKind(type)) {
    const view = requestResultView(row, requestError);
    const subject = view.completed ? type === 'secret' ? row.result.names.join('、') : type === 'credential' ? connected().find(item => item.id === row.result.credential_id)?.label : row.requester_name : '';
    const link = !linked ? '<a class="button secondary" href="' + view.href + '">' + view.label + ' ' + icon('arrow') + '</a>'
      : back ? '<a class="button secondary" href="' + esc(backTo(row)) + '">' + esc(back.name) + 'に戻る</a>' : '';
    app.innerHTML = shell('<section class="approval-card approval-result"><span class="approval-symbol">' + icon(view.completed ? 'check' : 'lock') + '</span><h1>' + view.title + '</h1>' + (subject ? '<p>' + esc(subject) + '</p>' : '') + (view.description ? '<p>' + esc(view.description) + '</p>' : '') + link + '</section>');
    return;
  }
  const expiry = `<p class="request-expiry">${type === 'relation' ? '承認期限：' : '依頼の期限：'}${esc(new Date(row.expires_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }))}</p>`;
  if (type === 'relation') { renderApproval(row, shell, expiry); return; }
  if (type === 'secret') { renderStore(row, shell, expiry); return; }
  if (type === 'app') { renderAppRequest(row, shell, expiry); return; }
  const service = row.service;
  if (!service) {
    app.innerHTML = shell(`<section class="approval-card"><h1>接続</h1><p>このサービスには現在接続できません。</p><button class="text-button full" data-action="deny-request">接続しない</button>${expiry}</section>`);
    return;
  }
  const way = row.auth_scheme, scheme = service.auth_schemes[way], name = service.name;
  const reconnecting = Boolean(asked.credential_id), title = reconnecting ? name + 'に接続し直す' : name + 'に接続';
  const facts = `<dl class="approval-facts">${requestPurpose(row)}${row.credential ? `<div><dt>更新する接続</dt><dd>${esc(row.credential.label)}${cloudflareDetails(row.credential)}</dd></div>` : ''}
    <div><dt>方法</dt><dd>${WAYS[way][0]}${way === 'oauth' ? requestedScopesView(row, scheme) : ''}</dd></div>${row.app && !row.app.foundation ? `<div><dt>OAuthアプリ</dt><dd>${esc(row.app.name)}</dd></div>` : ''}</dl>`;
  let body;
  if (reconnecting && !row.credential) body = '<p class="form-error" role="status">更新する接続が見つかりません。</p>';
  else if (row.app === null) body = '<p class="form-error" role="status">使うOAuthアプリが見つかりません。</p>';
  else if (!scheme.available && (way !== 'oauth' || row.app?.foundation || !scheme.takes_apps)) body = `<p class="form-error" role="status">現在${esc(name)}に接続できません。</p>`;
  else body = `<button class="button primary full request-connect" type="button" data-action="request-connect">${esc(way === 'role' ? 'IAMロールを作る' : name + 'の画面へ')} ${icon('arrow')}</button>`;
  app.innerHTML = shell(`<section class="approval-card">${requestHeading(row, title)}${facts}
    ${stepsBlock(row.steps)}
    <div class="register-body">${body}</div>
    <button class="text-button full" type="button" data-action="deny-request">接続しない</button>${expiry}</section>`);
}
// The scopes a request asks the service for, as the service names them; the holder sees each before agreeing.
function requestedScopesView(row, scheme) {
  const detail = detailOf(row), asked = detail.scopes || [];
  if (!scheme.scopes) return '';
  if (!asked.length) return `<small class="muted block">${detail.credential_id ? '今許可している権限のまま接続し直します。' : '本人確認のための権限だけを頼みます。'}</small>`;
  return `<small class="muted block">${detail.credential_id ? '今の権限に加えて、' : ''}次の権限を頼みます。</small><ul class="scope-list">${asked.map(scope => `<li><code>${esc(scope)}</code></li>`).join('')}</ul>`;
}
// The owner registers an OAuth app for a key: its values go into the app, and the key learns only which app it is.
function renderAppRequest(row, shell, expiry) {
  const service = row.service;
  if (!service?.auth_schemes.oauth?.takes_apps) {
    app.innerHTML = shell(`<section class="approval-card"><h1>OAuthアプリの登録</h1><p>このサービスでは、OAuthアプリを登録できません。</p><button class="text-button full" data-action="deny-request">登録しない</button>${expiry}</section>`);
    return;
  }
  const title = service.name + 'のOAuthアプリを登録';
  app.innerHTML = shell(`<section class="approval-card">${requestHeading(row, title)}
    <dl class="approval-facts">${requestPurpose(row)}</dl>${stepsBlock(row.steps)}
    <form id="app-request-form"><label for="request-app-name">名前</label><input id="request-app-name" name="name" required maxlength="200" autocomplete="off" value="${esc(detailOf(row).name || service.name + 'のアプリ')}">
      ${appFields(service, 'request-app')}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">登録する ${icon('arrow')}</button></form>
    <button class="text-button full" type="button" data-action="deny-request">登録しない</button>${expiry}</section>`);
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
  const title = asked.length === 1 ? `${asked[0].label}を${replacing ? '置き換える' : '登録する'}` : `${asked.length}件を${replacing ? '置き換える' : '登録する'}`;
  const site = asked.find(one => one.site)?.site;
  const field = (one, at) => one.multiline
    ? `<textarea id="stored-${at}" name="value-${at}" rows="6" required maxlength="100000" autocomplete="off" spellcheck="false"></textarea>`
    : `<input id="stored-${at}" name="value-${at}" type="${one.readable ? 'text' : 'password'}" required maxlength="16384" autocomplete="off" spellcheck="false">`;
  app.innerHTML = shell(`<section class="approval-card">${requestHeading(row, title)}
    <dl class="approval-facts">${requestPurpose(row)}</dl>
    ${stepsBlock(row.steps)}
    ${site ? `<a class="button secondary full setup-link" href="${esc(site)}" target="_blank" rel="noopener noreferrer"><span>${esc(new URL(site).host)} を開く ↗</span></a>` : ''}
    <form id="store-request-form">${asked.map((one, at) => `<div class="declared-field"><label for="stored-name-${at}">保存名</label><input id="stored-name-${at}" name="name-${at}" value="${esc(one.name)}" aria-describedby="stored-label-${at}" required maxlength="200" autocomplete="off" autocapitalize="off" spellcheck="false">${one.replace ? `<p class="permission-note replace-note" id="replace-note-${at}" data-name="${esc(one.name)}">既存の「${esc(one.name)}」を置き換えます。</p>` : ''}<label id="stored-label-${at}" for="stored-${at}">${esc(one.label)}</label>${field(one, at)}</div>`).join('')}
    <p class="permission-note">接続先での有効性や権限は確認しません。登録した値は、アクセスを許可した相手が利用できます。</p>
    <p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit">登録する ${icon('arrow')}</button></form>
    <button class="text-button full" type="button" data-action="deny-request">登録しない</button>${expiry}</section>`);
  // A replacement the owner renames becomes a new value; the note says which it is now.
  app.querySelectorAll('.replace-note').forEach(note => {
    const nameInput = note.parentElement.querySelector('input[name^="name-"]');
    const update = () => { note.textContent = nameInput.value === note.dataset.name ? `既存の「${note.dataset.name}」を置き換えます。` : `「${note.dataset.name}」はそのまま残り、「${nameInput.value}」として新しく保管します。`; };
    nameInput.addEventListener('input', update);
  });
  bindForm(async (data) => {
    const entries = asked.map((_, at) => ({ name: String(data.get('name-' + at) ?? ''), content: String(data.get('value-' + at) ?? '') }));
    try { await api(`/v1/requests/${row.id}/grant`, { method: 'POST', data: { entries } }); }
    catch (error) { if ([401, 404].includes(error.status)) await refresh(); throw error; }
    await refresh(); toast('登録しました。');
  }, app);
}
const accessSummary = '保存データの取得・変更・削除と、接続済みサービスの利用を許可します。';
const accessScope = '<ul class="access-scope"><li>認証情報とオブジェクトの取得・追加・更新・削除</li><li>接続済みサービスの利用とファンクションの実行</li></ul>';
const accessExclusions = '接続の追加・解除、他の相手への権限付与、アカウント管理は含みません。';
const accessDetails = () => `<details class="access-permissions"><summary>許可の詳細</summary>${accessScope}<p>${accessExclusions}</p></details>`;
// What one action lets its holder do, in the words of whoever grants it.
const ACTION_WORDS = {
  'secret.list': 'シークレットの一覧を見る', 'secret.read': 'シークレットの情報を見る', 'secret.content': 'シークレットの値を読む', 'secret.write': 'シークレットの値を書き換える', 'secret.remove': 'シークレットを削除する',
  'credential.list': 'サービスとの接続の一覧を見る', 'credential.read': 'サービスとの接続の情報を見る', 'credential.connect': 'サービスに接続する', 'credential.disconnect': 'サービスとの接続を解除する',
  'object.list': 'オブジェクトの一覧を見る', 'object.read': 'オブジェクトを読む', 'object.write': 'オブジェクトを書き換える', 'object.remove': 'オブジェクトを削除する', 'object.link': 'オブジェクトの共有リンクを作る',
  'app.use': 'このOAuthアプリで接続する', 'app.write': 'OAuthアプリの設定を変える', 'app.remove': 'OAuthアプリを削除する',
  'service.write': 'サービスの定義を変える', 'service.remove': 'サービスの定義を削除する',
  'environment.open': '計算機を立ち上げる', 'environment.exec': '計算機でコマンドを実行する', 'environment.remove': '計算機を片付ける',
  'principal.export': 'データを書き出す', 'principal.audit-log': '操作の記録を見る', 'principal.relate': '他の相手に権限を渡す', 'principal.issue-key': 'キーを発行する',
  'principal.inject': '保存した値をコマンドに渡す', 'principal.invoke': 'ファンクションを実行する',
};
const actionWords = relation => ACTION_WORDS[relation] ?? { viewer: '見る', editor: '見る・変える' }[relation] ?? relation.replace(/^[a-z_]+\./, '').replace(/-/g, ' ');
// A relation asked for: to act for the one answering, asked by a key nobody knows yet and confirmed with its code; or
// one permission onto something, asked by a key already known.
function renderApproval(row, shell, expiry) {
  const asked = detailOf(row), first = row.to === null, acting = asked.relation === 'actor';
  const target = row.object ? `<div><dt>対象</dt><dd>${esc(row.object.name || row.object.id)}</dd></div>` : '';
  const scope = acting ? `${accessScope}<small class="muted block">${accessExclusions}</small>` : `<ul class="access-scope"><li>${esc(actionWords(asked.relation))}</li></ul>`;
  app.innerHTML = shell(`<section class="approval-card">${requestHeading(row, acting ? 'アクセスを許可する' : '権限を渡す', 'device')}
    <dl class="approval-facts">${requestPurpose(row)}<div><dt>権限</dt><dd>${scope}</dd></div>${target}
    <div><dt>期間</dt><dd>${acting ? '今後追加するものも含め、' : ''}取り消すまで有効です。</dd></div></dl>
    <form id="access-request-form">${first ? codeField() : ''}
    <p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit"${first ? ' disabled' : ''}>許可する ${icon('arrow')}</button></form>
    <button class="text-button full" type="button" data-action="deny-request">許可しない</button>${expiry}</section>`);
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
      await refresh();
    } catch (error) { if (form.isConnected) { errorElement.textContent = error.message; submit.disabled = false; } }
  });
}
function openDialog(content) {
  dialog.innerHTML = `<button class="dialog-close icon-button" data-action="close-dialog" aria-label="閉じる">${icon('close')}</button>${content}`;
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
// What the holder decides when connecting: which of the service's scopes to give, and which OAuth app to connect
// through - Foundation's, one of their own, or one someone lent them.
const appsFor = serviceId => (state.apps || []).filter(app => app.service?.id === serviceId);
const oauthUsable = service => Boolean(service?.auth_schemes.oauth && (service.auth_schemes.oauth.foundation_app || (!service.auth_schemes.oauth.takes_apps && service.auth_schemes.oauth.available) || appsFor(service.id).length));
function connectChoices(service, credentialId, appId) {
  const scheme = service.auth_schemes.oauth, reconnecting = credentialId ? connected().find(item => item.id === credentialId) : null;
  const scopes = scheme.scopes ? `<label for="connect-scopes">${reconnecting ? '追加で許可する権限' : '許可する権限'}（1行に1つ）</label>
    <textarea id="connect-scopes" name="scopes" rows="3" autocomplete="off" spellcheck="false" placeholder="${esc(service.name)}の権限名"></textarea>
    <p class="permission-note">${reconnecting ? '今許可している権限はそのまま残ります。' : ''}本人確認のため${scheme.scopes.base.length ? esc(scheme.scopes.base.join('、')) + 'も頼みます。' : '追加で頼む権限はありません。'}${scheme.scopes.documentation_url ? `<a href="${esc(scheme.scopes.documentation_url)}" target="_blank" rel="noopener noreferrer">権限の一覧 ↗</a>` : ''}</p>` : '';
  const apps = appsFor(service.id);
  if (!scheme.takes_apps || !apps.length) return scopes;
  const chosen = appId || reconnecting?.app?.id || (apps.find(app => app.foundation) || apps[0]).id;
  return scopes + `<label for="connect-app">OAuthアプリ</label><select id="connect-app" name="app">${apps.map(app => `<option value="${esc(app.id)}"${app.id === chosen ? ' selected' : ''}>${esc(app.name)}</option>`).join('')}</select>
    <p class="permission-note">${esc(service.name)}の同意画面には、このアプリの名前が出ます。ほかの人から共有されたアプリは、その人を信頼できる場合だけ使ってください。</p>`;
}
// OAuth apps: what OAuth connections go through. Foundation's are there for anyone; the holder may add their own,
// and then decides at the service what can be granted and what name the consent screen shows.
// Whether the holder opened the apps; kept while the page is drawn again.
let appsOpen = false;
function appsSection() {
  // By service, so a service's own app and Foundation's for it sit side by side; Foundation's comes first.
  const apps = [...(state.apps || [])].sort((a, b) => (a.service?.name || '').localeCompare(b.service?.name || '', 'ja') || Number(b.foundation) - Number(a.foundation) || a.name.localeCompare(b.name, 'ja'));
  const row = app => {
    const mine = !app.foundation && app.holder_id === state.principal?.id;
    const detail = app.foundation ? '誰でも使えます。' : mine ? `クライアントID ${esc(app.client_id)}・接続 ${esc(String(app.credentials ?? 0))}件` : 'ほかの人から使うことを許可されたアプリ';
    return `<article class="agent-row"><div class="connection-identity">${serviceLogo(app.service)}<div class="agent-name"><h3>${esc(app.service?.name || '')}</h3><p>${esc(app.name)}</p></div></div>
      <div class="agent-permissions"><span class="muted">${detail}</span></div>
      <div class="agent-actions">${mine ? `<button class="text-button" data-action="change-app" data-id="${esc(app.id)}">シークレットを変更</button><button class="text-button danger" data-action="remove-app" data-id="${esc(app.id)}">削除</button>` : ''}</div></article>`;
  };
  return `<details class="resource-section folded-section" id="oauth-apps" aria-labelledby="oauth-apps-title"${appsOpen ? ' open' : ''}><summary><h2 id="oauth-apps-title">OAuthアプリ</h2></summary>
    <div class="section-heading"><p>ログインして許可する接続は、いずれかのOAuthアプリを通ります。</p><button class="button secondary" data-action="add-app">${icon('plus')} OAuthアプリを追加</button></div>
    ${apps.length ? `<div class="agent-list">${apps.map(row).join('')}</div>` : '<div class="access-empty"><p>OAuthアプリはありません。</p></div>'}</details>`;
}
// The fields an app of this service needs, and where its registration at the service must send people back.
const appFields = (service, prefix = 'app') => `${service.auth_schemes.oauth.app_fields.map(field => `<label for="${prefix}-${field.name}">${esc(field.label)}${field.required ? '' : '（任意）'}</label><input id="${prefix}-${field.name}" name="${field.name}"${field.required ? ' required' : ''} autocomplete="off" spellcheck="false"${field.sealed ? ' type="password"' : ''}${field.placeholder ? ` placeholder="${esc(field.placeholder)}"` : ''}>${field.note ? `<p class="permission-note">${esc(field.note)}</p>` : ''}`).join('')}
  <p class="permission-note">${esc(service.name)}でアプリを作るとき、リダイレクトURLに <code>${esc(location.origin + '/oauth/callback')}</code> を登録してください。${service.console ? `<a href="${esc(service.console)}" target="_blank" rel="noopener noreferrer">アプリを作る画面 ↗</a>` : ''}</p>`;
const takingApps = () => allServices().filter(service => service.auth_schemes.oauth?.takes_apps);
function addApp(serviceId, then) {
  const accepting = takingApps();
  const initial = accepting.find(service => service.id === serviceId) || accepting[0];
  if (!initial) return;
  const body = service => `<label for="app-name">名前</label><input id="app-name" name="name" required maxlength="200" autocomplete="off" value="${esc(service.name)}のアプリ">${appFields(service)}`;
  openDialog(`<h2 id="dialog-title">OAuthアプリを追加</h2><p>自分で作ったOAuthアプリを通して接続できます。許可できる権限や、同意画面に出る名前は、アプリの設定で決まります。</p>
    <form><label for="app-service">サービス</label><select id="app-service" name="service">${accepting.map(service => `<option value="${esc(service.id)}"${service.id === initial.id ? ' selected' : ''}>${esc(service.name)}</option>`).join('')}</select>
    <div class="app-body">${body(initial)}</div><p class="form-error" role="alert"></p><button class="button primary full" type="submit">追加</button></form>`);
  const choice = dialog.querySelector('#app-service');
  choice.addEventListener('change', () => { dialog.querySelector('.app-body').innerHTML = body(accepting.find(service => service.id === choice.value)); });
  bindForm(async (form) => {
    const service = accepting.find(item => item.id === form.get('service')), name = String(form.get('name') || '');
    const values = Object.fromEntries(service.auth_schemes.oauth.app_fields.map(({ name }) => [name, String(form.get(name) || '')]));
    await api('/v1/resources?kind=app&name=' + encodeURIComponent(name), { method: 'PUT', data: { service: service.id, ...values } });
    closeDialog(); await refresh(); toast(name + ' を追加しました。');
    then?.(service.id);
  });
}
function changeApp(app) {
  const service = serviceById(app.service.id);
  openDialog(`<h2 id="dialog-title">${esc(app.name)} のシークレットを変更</h2><p>このアプリの接続は、そのまま使えます。</p><form>${appFields(service, 'change')}
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">変更</button></form>`);
  dialog.querySelector('#change-client_id').value = app.client_id;
  bindForm(async (form) => {
    await api('/v1/resources/' + app.id, { method: 'PATCH', data: Object.fromEntries(service.auth_schemes.oauth.app_fields.map(({ name }) => [name, String(form.get(name) || '')])) });
    closeDialog(); await refresh(); toast('変更しました。');
  });
}
// Removing an app stops the connections made through it, as removing it at the service would.
function removeApp(app) {
  const count = app.credentials ?? 0;
  openDialog(`<h2 id="dialog-title">${esc(app.name)} を削除しますか？</h2><form>
    <p>${count ? `このアプリで作った接続が${esc(String(count))}件あります。削除すると、別のアプリでつなぎ直すまで使えなくなります。` : 'このアプリで作った接続はありません。'}</p>
    <p class="permission-note">${esc(app.service?.name || '')}側のアプリは残ります。不要ならそちらでも削除してください。</p><p class="form-error" role="alert"></p>
    <div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">削除</button></div></form>`);
  bindForm(async () => {
    const result = await api('/v1/resources/' + app.id, { method: 'DELETE', data: { confirm: true } });
    closeDialog(); await refresh();
    toast(result.credentials_stopped ? `削除しました。${result.credentials_stopped}件の接続がつなぎ直し待ちになりました。` : '削除しました。');
  });
}
// Adding a service: find it among those Foundation knows and those the holder described, or describe one it does not.
let serviceFilter = '';
function servicePicker({ title, services, query = '', choose, create, filtered = () => {} }) {
  const sorted = [...services].sort((a, b) => a.name.localeCompare(b.name, 'ja'));
  openDialog(`<h2 id="dialog-title">${esc(title)}</h2>
    <input id="service-filter" type="search" aria-label="サービスを探す" placeholder="サービスを探す" value="${esc(query)}" autocomplete="off">
    <div class="service-grid">${sorted.map(service => `<button class="service-choice" data-id="${esc(service.id)}" data-name="${esc(service.name.toLowerCase())}">${serviceLogo(service)}<span>${esc(service.name)}</span></button>`).join('')}</div>
    <p class="permission-note" id="service-none" hidden>見つかりません。</p>
    <button class="text-button" id="create-service">一覧にないサービスを追加</button>`);
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
  servicePicker({ title: 'サービスを追加', services: allServices().filter(service => Object.keys(service.auth_schemes).length || ownService(service.id)), query: serviceFilter,
    filtered: value => { serviceFilter = value; }, choose: service => chooseService(service.id), create: name => defineService({ name }) });
}
// How to connect a service, when it offers more than one way. The words say what the holder does, not the protocol.
const WAYS = { oauth: ['ログインして許可する', 'サービスの画面で許可します。'], role: ['IAMロールを作る', 'AWSの画面でFoundation用のロールを作ります。'] };
function chooseService(serviceId) {
  const service = serviceById(serviceId);
  if (!service) return;
  const ways = Object.keys(service.auth_schemes);
  if (ownService(service.id)) {
    if (!ways.includes('oauth')) ways.push('oauth');
  } else if (ways.length === 1) { connectBy(service, ways[0]); return; }
  openDialog(`<h2 id="dialog-title">${esc(service.name)}に接続</h2>
    ${ways.length ? `<div class="way-list">${ways.map(way => `<button class="way-choice" data-action="choose-way" data-id="${esc(service.id)}" data-way="${way}"><strong>${WAYS[way][0]}</strong><span>${way === 'oauth' && !service.auth_schemes.oauth ? 'OAuth 2.0の接続先とアプリを設定します。' : WAYS[way][1] + (way === 'oauth' && !oauthUsable(service) ? '先にOAuthアプリの登録が要ります。' : '')}</span></button>`).join('')}</div>` : '<p>接続方法が未設定です。</p>'}`);
}
function connectBy(service, way, credentialId) {
  if (way === 'oauth' && !service.auth_schemes.oauth && ownService(service.id)) configureOAuth(service);
  else connect(service.id, credentialId);
}
// Starting a connection Foundation performs itself: the service decides who it is.
function connect(serviceId, credentialId, appId) {
  const service = serviceById(serviceId);
  if (!service) return;
  if (service.auth_schemes.role) { startRole(service, credentialId); return; }
  if (!oauthUsable(service)) { addApp(service.id, id => connect(id, credentialId)); return; }
  openDialog(`<h2 id="dialog-title">${esc(service.name)}に${credentialId ? '接続し直す' : '接続'}</h2><p>${esc(service.name)}の画面でログインし、アクセスを許可します。</p><form>
    ${connectChoices(service, credentialId, appId)}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(service.name)}の画面へ ${icon('arrow')}</button></form>`);
  bindForm(async (form) => {
    const scopes = String(form.get('scopes') || '').split(/\s+/).filter(Boolean), app = String(form.get('app') || '');
    const result = await api('/v1/credentials', { method: 'POST', data: { service: service.id, auth_scheme: 'oauth', ...(credentialId ? { credential_id: credentialId } : {}),
      ...(scopes.length ? { scopes } : {}), ...(app && app !== 'foundation' ? { app } : {}) } });
    location.assign(result.url);
  });
}
async function addServiceScheme(service, way, definition) {
  const result = await api('/v1/resources/' + service.id, { method: 'PATCH', data: { auth_schemes: { [way]: definition } } });
  return rememberService(result.resource);
}
async function startRole(service, credentialId, requestId) {
  const started = await api('/v1/credentials', { method: 'POST', data: requestId ? { request_id: requestId } : { service: service.id, auth_scheme: 'role', ...(credentialId ? { credential_id: credentialId } : {}) } });
  completeByHand(service, started);
}
// A role flow: the service's console opens in another tab, the holder makes what Foundation asked for there, and
// pastes back the one thing Foundation needs to find it. A wrong paste is answered here; the flow is not lost.
function completeByHand(service, started) {
  openDialog(`<h2 id="dialog-title">${esc(service.name)}でIAMロールを作る</h2><p>Foundationは鍵を預かりません。作ったロールを引き受けて、使うたびに1時間だけの認証情報を得ます。</p>
    <ol class="guidance-steps"><li><a class="button secondary" href="${esc(started.url)}" target="_blank" rel="noopener noreferrer">${esc(service.name)}の画面を開く ↗</a><p class="permission-note">付ける権限をPoliciesで選び、内容を確認して「作成」を押します。1分ほどで終わります。</p></li>
    <li>できあがった値を貼り付けます。</li></ol>
    <form>${started.complete.fields.map(field => `<label for="complete-${esc(field.name)}">${esc(field.label)}</label><input id="complete-${esc(field.name)}" name="${esc(field.name)}" required autocomplete="off" spellcheck="false" placeholder="${esc(field.placeholder || '')}">`).join('')}
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">接続する ${icon('arrow')}</button></form>`);
  bindForm(async (form) => {
    const fields = Object.fromEntries(started.complete.fields.map(field => [field.name, String(form.get(field.name) || '')]));
    await api('/v1/credentials/complete', { method: 'POST', data: { state: started.state, fields } });
    closeDialog(); await refresh(); toast(service.name + 'に接続しました。');
  });
}
// Registering the service and choosing how to connect it are separate steps.
function defineService({ name = '', created } = {}) {
  openDialog(`<h2 id="dialog-title">サービスを追加</h2><form>
    <label for="define-name">サービス名</label><input id="define-name" name="name" required maxlength="80" autocomplete="off" placeholder="例: Notes" value="${esc(name)}">
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">追加</button></form>`);
  bindForm(async (form) => {
    const name = String(form.get('name') || '').trim();
    const result = await api('/v1/resources?kind=service&name=' + encodeURIComponent(name), {
      method: 'PUT', headers: { 'if-none-match': '*' }, data: { version: 1, name },
    });
    const service = rememberService(result.resource);
    if (created) { created(service); return; }
    closeDialog(); await refresh(); toast(name + ' を追加しました。');
  });
}
function configureOAuth(service) {
  openDialog(`<h2 id="dialog-title">${esc(service.name)}のOAuth設定</h2><form>
    <label for="define-authorize">認可エンドポイントのURL</label><input id="define-authorize" name="authorize" required autocomplete="off" spellcheck="false" placeholder="https://example.com/oauth/authorize">
    <label for="define-token">トークンエンドポイントのURL</label><input id="define-token" name="token" required autocomplete="off" spellcheck="false" placeholder="https://example.com/oauth/token">
    <label for="define-identity">利用者情報のURL（任意）</label><input id="define-identity" name="identity" autocomplete="off" spellcheck="false"><p class="permission-note">入れると、接続したアカウントを確かめ、一覧に名前を出します。</p>
    <label for="define-revoke">取り消しのURL（任意）</label><input id="define-revoke" name="revoke" autocomplete="off" spellcheck="false"><p class="permission-note">入れると、接続の解除のときにサービス側の許可も取り消せます。</p>
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">次へ ${icon('arrow')}</button></form>`);
  bindForm(async (form) => {
    const value = name => String(form.get(name) || '').trim();
    const oauth = { authorize: value('authorize'), token: value('token'), scopes: { base: [] },
      ...(value('identity') ? { identity: { url: value('identity') } } : {}), ...(value('revoke') ? { revoke: { url: value('revoke'), style: 'rfc7009' } } : {}),
      injection: { OAUTH_ACCESS_TOKEN: '{access_token}', OAUTH_EXPIRES_AT: '{expires_at}' } };
    await addServiceScheme(service, 'oauth', oauth);
    addApp(service.id, id => connect(id));
  });
}
// Disconnect only this credential; secrets kept by hand remain.
function disconnect(connection) {
  const revoke = connection.can_revoke
    ? `<label class="check"><input type="checkbox" name="revoke" checked> ${esc(connection.service.name)}側の許可も取り消す</label>`
    : `<p class="permission-note">${esc(connection.service.name)}側の${connection.auth_scheme === 'role' ? 'IAMロール' : '許可'}は残ります。不要なら${esc(connection.service.name)}で削除してください。</p>`;
  openDialog(`<h2 id="dialog-title">${esc(connection.label)} の接続を解除しますか？</h2><form>
    <p>この接続から認証情報を取得できなくなります。シークレットに預けた値は残ります。</p>
    <p class="permission-note">${esc(revocationNote)}</p>${revoke}<p class="form-error" role="alert"></p>
    <div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">接続を解除</button></div></form>`);
  bindForm(async (form) => {
    const result = await api('/v1/resources/' + encodeURIComponent(connection.id), { method: 'DELETE', data: { revoke: form.get('revoke') === 'on' } });
    closeDialog(); await refresh();
    toast(result.service_revoked === false ? '解除しました。サービス側の許可は取り消せませんでした。' : '解除しました。');
  });
}
function addKey() {
  openDialog(`<h2 id="dialog-title">アクセスを許可する相手を追加</h2><p>${accessSummary}</p><form><label for="agent-name">名前</label><input id="agent-name" name="name" placeholder="laptop など" required maxlength="80" autocomplete="off"><p class="permission-note">今後追加するものも含め、取り消すまで有効です。</p><p class="form-error" role="alert"></p><button class="button primary full" type="submit">追加してキーを発行</button></form>`);
  bindForm(async (form) => {
    const result = await api('/v1/principals', { method: 'POST', data: { name: form.get('name'), actor: true, key: true } });
    await refresh(); if (!state) return;
    openDialog(`<h2 id="dialog-title">${esc(result.principal.name)} のアクセスキー</h2><p>キーは一度だけ表示します。AIを動かす環境の秘密情報として保管してください。</p><label for="agent-token">アクセスキー</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.token)}</textarea><button class="button secondary full" data-action="copy-token">キーをコピー</button><label for="api-url">接続先</label><input id="api-url" readonly value="${esc(location.origin)}/v1"><p class="permission-note">キーを会話や共有ファイルに貼り付けないでください。</p><button class="button primary full" data-action="close-dialog">閉じる</button>`);
  });
}
const principalById = id => (state.actors || []).find(item => item.id === id) || (state.principals || []).find(item => item.id === id);
// Machines lent to this account and still running: who each acts as, until when, and the month's computing.
function environmentsSection() {
  const running = state.environments || [], compute = state.compute;
  const minutes = seconds => Math.ceil(seconds / 60).toLocaleString('ja-JP') + ' 分';
  const status = { starting: '準備中', ready: '待機中', busy: '実行中' };
  const identity = id => !id ? '権限なし' : id === state.user.id ? 'あなたとして動作' : (principalById(id)?.name || '登録した相手') + ' として動作';
  const row = item => `<article class="agent-row access-row"><div class="agent-name"><h3>${esc(item.name)}</h3><p>${esc(status[item.status] || item.status)} · ${esc(identity(item.identity))}</p></div>
    <div class="agent-permissions"><span class="muted">${esc(new Date(item.expires_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }))} まで</span></div>
    <div class="agent-actions"><button class="text-button danger" data-action="close-environment" data-id="${esc(item.id)}">閉じる</button></div></article>`;
  return `<section class="resource-section" aria-labelledby="environments-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('device')}</span><h2 id="environments-title">環境</h2></div>${compute ? `<span class="muted">今月の計算時間 ${esc(minutes(compute.used_seconds))} / ${esc(minutes(compute.limit_seconds))}</span>` : ''}</div>
    ${running.length ? `<div class="agent-list">${running.map(row).join('')}</div>` : '<div class="access-empty"><p>開いている環境はありません。</p></div>'}</section>`;
}
async function principalDetails(id) {
  const owned = (state.principals || []).some(item => item.id === id);
  const item = owned ? (await api(`/v1/principals/${id}`)).principal : principalById(id);
  if (!item) return;
  const allowed = owned ? item.acts_for.includes(state.user.id) : true;
  const keys = item.keys;
  openDialog(`<div class="principal-heading"><h2 id="dialog-title">${esc(item.name)}</h2>${owned ? `<button class="icon-button" data-action="rename-principal" data-id="${esc(id)}" aria-label="名前を編集" title="名前を編集">${icon('edit')}</button>` : ''}</div>
    <p>${allowed ? 'アクセス許可済み' : '全体へのアクセス許可なし'}</p>
    ${allowed ? `<p>${accessSummary.replace('許可します。', '許可しています。')}</p>${accessDetails()}` : ''}
    ${owned ? `<section class="principal-keys"><div class="section-heading"><h3>アクセスキー</h3><button class="text-button" data-action="issue-key" data-id="${esc(id)}">キーを発行</button></div>
      ${keys.length ? `<ul class="credential-list">${keys.map(key => `<li><div><code>${esc(key.id.slice(0, 8))}</code><p>${key.environment_id ? '環境用（閉じると消えます）' : '発行 ' + esc(new Date(key.created_at).toLocaleString('ja-JP'))}</p></div><button class="text-button danger" data-action="revoke-key" data-id="${esc(id)}" data-key="${esc(key.id)}">失効</button></li>`).join('')}</ul>` : '<p class="muted">キーはありません。</p>'}</section>
      <div class="principal-delete"><button class="text-button danger" data-action="remove-principal" data-id="${esc(id)}">登録を削除</button></div>` : ''}`);
}
function renamePrincipal(item) {
  openDialog(`<h2 id="dialog-title">名前を変更</h2><form><label for="agent-name">名前</label><input id="agent-name" name="name" required maxlength="80" autocomplete="off" value="${esc(item.name)}"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">保存</button></form>`);
  bindForm(async (form) => { await api(`/v1/principals/${item.id}`, { method: 'PATCH', data: { name: form.get('name') } }); await refresh(); await principalDetails(item.id); });
}
async function issueKey(item) {
  const result = await api(`/v1/principals/${item.id}/keys`, { method: 'POST', data: {} });
  await refresh();
  openDialog(`<h2 id="dialog-title">${esc(item.name)} のアクセスキー</h2><p>キーは一度だけ表示します。</p><label for="agent-token">アクセスキー</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.token)}</textarea><button class="button secondary full" data-action="copy-token">キーをコピー</button><button class="button primary full" data-action="principal-details" data-id="${esc(item.id)}">完了</button>`);
}
function revokeKey(item, key) {
  openDialog(`<h2 id="dialog-title">このキーを失効させますか？</h2><p>${esc(item.name)} · ${esc(key.slice(0, 8))}</p><form><p>このキーは使えなくなります。他のキーとアクセス許可は残ります。</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="principal-details" data-id="${esc(item.id)}">キャンセル</button><button type="submit" class="button destructive">失効させる</button></div></form>`);
  bindForm(async () => { await api(`/v1/principals/${item.id}/keys/${key}`, { method: 'DELETE', data: {} }); await refresh(); await principalDetails(item.id); toast('キーを失効させました。'); });
}
function addIntegration() {
  openDialog(`<h2 id="dialog-title">アプリを登録</h2><form>
    <label for="integration-name">名前</label><input id="integration-name" name="name" placeholder="アプリの名前" required maxlength="80" autocomplete="off">
    <label for="integration-return">戻り先のURL</label><input id="integration-return" name="return_url" type="url" required placeholder="https://example.com/foundation" autocomplete="off">
    <p class="permission-note">依頼はこのページで開かれ、終わるとここに戻ります。</p>
    <label for="integration-refresh">リンクが使えないときの戻り先（省略可）</label><input id="integration-refresh" name="refresh_url" type="url" autocomplete="off">
    <label for="integration-webhook">完了の通知先（省略可）</label><input id="integration-webhook" name="webhook_url" type="url" autocomplete="off">
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">アプリキーを発行</button></form>`);
  bindForm(async (form) => {
    // An app is a principal of this person's making, with settings for handing its users back, and a key of its own.
    const made = (await api('/v1/principals', { method: 'POST', data: { name: form.get('name') } })).principal;
    const settings = (await api(`/v1/principals/${made.id}/settings`, { method: 'PUT', data: { return_url: form.get('return_url'), refresh_url: form.get('refresh_url') || undefined, webhook_url: form.get('webhook_url') || undefined } })).settings;
    const issued = await api(`/v1/principals/${made.id}/keys`, { method: 'POST', data: {} });
    const result = { ...made, token: issued.token, webhook_secret: settings.webhook_secret };
    await refresh(); if (!state) return;
    openDialog(`<h2 id="dialog-title">${esc(result.name)} のアプリキー</h2><p>キーは一度だけ表示します。</p><label for="agent-token">アプリキー</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.token)}</textarea><button class="button secondary full" data-action="copy-token">キーをコピー</button>
      ${result.webhook_secret ? `<label for="webhook-secret">通知の署名キー</label><textarea id="webhook-secret" rows="2" readonly spellcheck="false">${esc(result.webhook_secret)}</textarea><p class="permission-note">通知が本物かどうかを、この値で確かめます。</p>` : ''}
      <button class="button primary full" data-action="close-dialog">閉じる</button>`);
  });
}
function removePrincipal(item) {
  openDialog(`<h2 id="dialog-title">登録を削除しますか？</h2><p>${esc(item.name)}</p><form><p>この相手の全キーと、この相手自身の保存データを削除します。他のアカウントへのアクセスも失われます。</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="principal-details" data-id="${esc(item.id)}">キャンセル</button><button type="submit" class="button destructive">削除する</button></div></form>`);
  bindForm(async () => { await api(`/v1/principals/${item.id}`, { method: 'DELETE', data: {} }); closeDialog(); await refresh(); toast('登録を削除しました。'); });
}
function revokeAccess(item) {
  openDialog(`<h2 id="dialog-title">アクセス許可を取り消しますか？</h2><p>${esc(item.name)}</p><form><p>あなたのデータへのアクセスを停止し、あなた宛ての未完了の依頼を取り消します。</p><p class="permission-note">取得済みの外部サービスの認証情報は、接続先で失効させてください。</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">許可を取り消す</button></div></form>`);
  bindForm(async () => { await api(`/v1/principals/${item.id}/access`, { method: 'DELETE', data: {} }); closeDialog(); await refresh(); toast('アクセス許可を取り消しました。'); });
}
// One confirmation, for removing something a key kept. Nothing here can be undone, and nothing reaches the service.
// The name and the way it reaches a command, changed without the value ever being handed back.
// Something the owner has in hand, put there without an agent asking for it first.
function addSecret() {
  openDialog(`<h2 id="dialog-title">シークレットを追加</h2>
    <form><label for="new-name">名前</label><input id="new-name" name="name" required maxlength="200" placeholder="任意の名前" autocomplete="off" spellcheck="false">
    <label for="new-value">値</label><textarea id="new-value" name="value" rows="4" required maxlength="100000" autocomplete="off" spellcheck="false"></textarea>
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">追加</button></form>`);
  bindForm(async (form) => {
    const name = form.get('name');
    const response = await fetch('/v1/resources?' + new URLSearchParams({ kind: 'secret', name }),
      { method: 'PUT', credentials: 'same-origin', headers: { 'content-type': 'text/plain' }, body: String(form.get('value')) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message || '追加できませんでした。');
    closeDialog(); await refresh(); toast(name + ' を追加しました。');
  });
}
function editSecret(entry, trigger) {
  if (!entry) return;
  const row = trigger.closest('.secret-row'), heading = row.querySelector('h3');
  const actions = [...row.querySelectorAll('button')];
  const form = document.createElement('form');
  form.className = 'secret-name-editor'; form.setAttribute('aria-label', '名前の変更');
  form.innerHTML = `<div class="secret-name-field"><input name="name" aria-label="名前" required maxlength="200" value="${esc(entry.name)}" autocomplete="off" autocapitalize="off" spellcheck="false">
    <button class="icon-button save-name" type="submit" aria-label="保存" title="保存">${icon('check')}</button>
    <button class="icon-button" type="button" aria-label="キャンセル" title="キャンセル">${icon('close')}</button></div><p class="form-error" role="alert"></p>`;
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
      toast('名前を変更しました。');
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
  let value = null, text = null, etag = null, revealed = false, binary = false, busy = false;
  const lock = locked => row.querySelectorAll('[data-action]').forEach(button => { button.disabled = locked; });
  const clear = () => { value = null; text = null; etag = null; revealed = false; };
  const control = (action, label, glyph) => `<button type="button" class="icon-button" data-value-action="${action}" aria-label="${label}" title="${label}">${icon(glyph)}</button>`;
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
      const response = await fetch(path, { credentials: 'same-origin', cache: 'no-store' });
      if (response.status === 401) await showLogin();
      if (!response.ok) throw new Error('値を取得できませんでした。');
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (!panel.isConnected) return false;
      value = bytes; text = decode(value); binary = text === null; etag = response.headers.get('etag');
      return true;
    } catch (error) {
      if (panel.isConnected) panel.querySelector('[role="alert"]').textContent = error instanceof TypeError ? '接続できませんでした。' : error.message;
      return false;
    } finally {
      busy = false; lock(false); panel.removeAttribute('aria-busy');
      panel.querySelectorAll('button').forEach(button => { button.disabled = false; });
    }
  };
  const show = (focus) => {
    lock(false);
    panel.innerHTML = `<div class="secret-value-line">${binary ? `<span class="secret-file">${icon('note')}ファイル</span>`
      : `<pre class="kept-document${revealed ? '' : ' secret-mask'}" aria-label="${revealed ? '値' : '値（非表示）'}">${revealed ? esc(text) : '••••••••'}</pre>`}<div class="secret-value-actions">${binary
      ? `<a class="icon-button" href="${path}" download aria-label="ダウンロード" title="ダウンロード">${icon('download')}</a>`
      : control('reveal', revealed ? '値を隠す' : '値を表示', revealed ? 'eye-off' : 'eye') + control('copy', 'コピー', 'copy')}${control('edit', '値を編集', 'edit')}</div></div><p class="form-error" role="alert"></p>`;
    panel.querySelectorAll('[data-value-action]').forEach(button => button.addEventListener('click', async () => {
      if (busy) return;
      const action = button.dataset.valueAction;
      if (action === 'reveal' && revealed) { clear(); show('reveal'); return; }
      try {
        if (!await load()) return;
        if (action === 'edit') { edit(); return; }
        if (action === 'reveal') { revealed = !binary; show(binary ? 'edit' : 'reveal'); return; }
        if (binary) { clear(); show('edit'); return; }
        const copied = text;
        if (!revealed) clear();
        try { await navigator.clipboard.writeText(copied); toast('コピーしました。'); }
        catch { if (panel.isConnected) panel.querySelector('[role="alert"]').textContent = 'コピーできませんでした。'; }
      } finally { resumeRefresh(); }
    }));
    if (focus) panel.querySelector(`[data-value-action="${focus}"]`)?.focus();
  };
  const edit = () => {
    lock(true); panel.classList.add('editing');
    panel.innerHTML = `<form aria-label="値の編集">${binary
      ? '<input type="file" name="file" aria-label="ファイル" required>'
      : '<textarea name="value" aria-label="値" rows="6" required autocomplete="off" autocapitalize="off" spellcheck="false"></textarea>'}
      <p class="form-error" role="alert"></p><div class="dialog-actions"><button class="button secondary" type="button">キャンセル</button><button class="button primary" type="submit">保存</button></div></form>`;
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
      if ((binary ? file.size : content.length) > 1024 * 1024) { error.textContent = '1件あたり1MBまでです。'; return; }
      saving = true; error.textContent = ''; save.disabled = true; cancel.disabled = true; input.disabled = true;
      panel.setAttribute('aria-busy', 'true');
      try {
        if (!etag) throw new Error('編集をやり直してから保存してください。');
        const bytes = binary ? new Uint8Array(await file.arrayBuffer()) : content;
        const response = await fetch(path, { method: 'PUT', credentials: 'same-origin', cache: 'no-store',
          headers: { 'content-type': 'application/octet-stream', 'if-match': etag }, body: bytes });
        const result = await response.json();
        if (response.status === 401) await showLogin();
        if (!response.ok) throw new Error(result.error?.message || '保存できませんでした。');
        binary = decode(bytes) === null; entry = result.resource; clear();
        state.secrets = state.secrets.map(item => item.id === entry.id ? entry : item);
        if (!panel.isConnected) return;
        row.querySelector('.secret-meta').innerHTML = secretMeta(entry); panel.classList.remove('editing');
        show('edit'); toast('保存しました。'); resumeRefresh();
      } catch (failure) { if (form.isConnected) error.textContent = failure instanceof TypeError ? '接続できませんでした。' : failure.message; }
      finally {
        saving = false; save.disabled = false; cancel.disabled = false; input.disabled = false;
        panel.removeAttribute('aria-busy');
      }
    });
    input.focus();
  };
  show();
}
function confirmRemoval(title, body, run, done = '削除しました。', label = '削除する') {
  openDialog(`<h2 id="dialog-title">${esc(title)}</h2><form><p>${esc(body)}</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">${esc(label)}</button></div></form>`);
  bindForm(async () => { await run(); closeDialog(); await refresh(); toast(done); });
}
document.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-action]'); if (!target || target.disabled) return;
  const { action, id } = target.dataset;
  try {
    if (action === 'close-dialog') closeDialog();
    if (action === 'retry-page') { target.disabled = true; try { await refresh(); } finally { if (target.isConnected) target.disabled = false; } }
    if (action === 'retry-login') { target.disabled = true; await showLogin(); }
    if (action === 'logout') { target.disabled = true; await api('/v1/session', { method: 'DELETE', data: {} }); await showLogin(); }
    if (action === 'request-connect') {
      target.disabled = true;
      if (accessRequest.auth_scheme === 'role') { await startRole(accessRequest.service, undefined, requestId); target.disabled = false; return; }
      location.assign((await api('/v1/credentials', { method: 'POST', data: { request_id: requestId } })).url);
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
      if (entry) confirmRemoval(entry.service.name + ' を削除しますか？', 'サービスの登録を削除します。', () => api('/v1/resources/' + entry.id, { method: 'DELETE', data: {} }));
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
      confirmRemoval(name + ' を削除しますか？', 'AIはこれを使えなくなります。元には戻せません。', () => api('/v1/resources/' + entry.id, { method: 'DELETE', data: {} }));
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
        try { await navigator.clipboard.writeText(result.url); toast('URLをコピーしました。1時間で切れます。'); }
        catch {
          openDialog(`<h2 id="dialog-title">取り出し用のURL</h2><p>${esc(key)} を、このURLを知っている人なら誰でも取り出せます。1時間で切れます。</p>
            <label for="object-link">URL</label><input id="object-link" readonly value="${esc(result.url)}"><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">閉じる</button></div>`);
          document.querySelector('#object-link')?.select();
        }
      } catch (error) { toast(error.message); }
      finally { target.disabled = false; }
    }
    if (action === 'drop-chosen') {
      const keys = chosenKeys();
      confirmRemoval(keys.length === 1 ? keys[0] + ' を削除しますか？' : keys.length + '件を削除しますか？', '置き場から消えます。元には戻せません。',
        async () => { for (const key of keys) await api('/v1/resources/' + state.space.objects.find(item => item.key === key).id, { method: 'DELETE', data: {} }); objectChosen = new Set(); });
    }
    if (action === 'add-secret') addSecret();
    if (action === 'copy-name') {
      try { await navigator.clipboard.writeText(target.dataset.name); toast('コピーしました。'); }
      catch { toast('コピーできませんでした。'); }
    }
    if (action === 'edit-secret') editSecret(secrets().find(item => item.name === target.dataset.name), target);
    if (action === 'add-key') addKey();
    if (action === 'revoke-access') revokeAccess(principalById(id));
    if (action === 'close-environment') {
      const item = (state.environments || []).find(row => row.id === id);
      if (item) confirmRemoval(item.name + ' を閉じますか？', '中のファイルは消え、この環境に渡した鍵は使えなくなります。', () => api('/v1/environments/' + item.id, { method: 'DELETE', data: {} }), '閉じました。', '環境を閉じる');
    }
    if (action === 'principal-details') await principalDetails(id);
    if (action === 'issue-key') { target.disabled = true; await issueKey(principalById(id)); }
    if (action === 'revoke-key') revokeKey(principalById(id), target.dataset.key);
    if (action === 'add-integration') addIntegration();
    if (action === 'remove-principal') removePrincipal(principalById(id));
    if (action === 'rename-principal') renamePrincipal(principalById(id));
    if (action === 'copy-token') {
      const token = document.querySelector('#agent-token');
      try { await navigator.clipboard.writeText(token.value); toast('キーをコピーしました。'); }
      catch { token.select(); toast('キーを選択しました。コピーしてください。'); }
    }
  } catch (error) { if (target.isConnected) target.disabled = false; toast(error.message); }
});
const resultCode = new URL(location.href).searchParams.get('result');
const confirmationState = resultCode === 'review' ? new URL(location.href).searchParams.get('state') : null;
window.addEventListener('pageshow', event => { if (event.persisted && !isLoginConfirmation) void refresh().catch(() => {}); });
if (linkToken) {
  try {
    await api('/v1/links/exchange', { method: 'POST', data: { request_id: requestId, link: linkToken } });
    linked = true;
    try { sessionStorage.setItem('linked:' + requestId, '1'); } catch {}
  } catch (error) { if (!linked) { linked = true; requestError = error.message; } }
}
if (isLoginConfirmation) showLoginConfirmation();
else {
  if ((location.search || linkToken) && resultCode !== 'review') {
    const url = new URL(location.href);
    for (const key of ['login', 'result', 'state']) url.searchParams.delete(key);
    if (linkToken) url.hash = '';
    history.replaceState(history.state, '', url);
  }
  try { await refresh(); } catch {}
  if (state && !requestId) scrollToPage(history.state?.scroll);
}
// What came back from an OAuth round trip, in words that hold for any service.
const resultMessages = { connected: '接続しました。', denied: '接続をキャンセルしました。', expired: '接続の手続きが切れました。もう一度お試しください。',
  wrong_account: '更新する接続と同じユーザーやIAMロールを選んでください。', scope: '要求した権限と許可された権限が一致しません。',
  retry: '継続利用の許可を取得できませんでした。もう一度接続してください。', changed: '接続の状態が変わりました。もう一度お試しください。', failed: '接続できませんでした。もう一度お試しください。' };
if (resultCode === 'review') {
  try {
    const review = await api('/v1/credentials/confirmation?state=' + encodeURIComponent(confirmationState));
    const values = items => items.length ? items.map(esc).join('<br>') : 'なし';
    openDialog(`<h2 id="dialog-title">接続の変更を確認</h2><p>${esc(review.credential.service.name)} · ${esc(review.credential.label)}</p>
      <dl class="approval-facts">${review.changes.map(change => `<div><dt>${esc(change.label)}</dt><dd><p>変更前：${values(change.before)}</p><p>変更後：${values(change.after)}</p></dd></div>`).join('')}</dl>
      <p class="permission-note">更新すると、この接続を使うAIにも変更後の権限が渡ります。キャンセルしても、接続先で許可した内容は残ります。</p>
      <form><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="cancel-connection-review">キャンセル</button><button type="submit" class="button primary">この内容で更新</button></div></form>`);
    document.querySelector('[data-action="cancel-connection-review"]').addEventListener('click', async () => {
      try { await api('/v1/credentials/confirmation', { method: 'DELETE', data: { state: confirmationState } }); history.replaceState(null, '', pagePath); closeDialog(); }
      catch (error) { toast(error.message); }
    });
    bindForm(async () => { await api('/v1/credentials/confirmation', { method: 'POST', data: { state: confirmationState } }); history.replaceState(null, '', pagePath); closeDialog(); await refresh(); toast('接続を更新しました。'); });
  } catch (error) { toast(error.message); }
} else if (resultCode) toast(resultMessages[resultCode] || '接続を確認し、もう一度お試しください。');
