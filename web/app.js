const app = document.querySelector('#app'), dialog = document.querySelector('#dialog'), notice = document.querySelector('#notice');
let state = null, toastTimer, loginTimer, revision = 0;
// A request page is either what an approved key asks for (/requests/…) or a new key asking to be approved (/keys/…).
const keyRequest = /^\/keys\//.test(location.pathname);
const requestId = location.pathname.match(/^\/(?:requests|keys)\/([A-Za-z0-9_-]{43})$/)?.[1];
const requestApi = requestId && (keyRequest ? '/api/key-requests/' : '/api/requests/') + requestId;
// Opened through another product's single-use link: there is no Foundation login, only that one request.
const linkToken = requestId && !keyRequest ? new URLSearchParams(location.hash.slice(1)).get('link') : null;
let linked = false, back = null;
// Back to the product: its return page with how the request ended, or its refresh page when the link was no good.
const backTo = row => { if (!row) return back.refresh_url; const url = new URL(back.return_url); url.searchParams.set('foundation_status', row.status); return url.href; };
try { linked = Boolean(requestId) && sessionStorage.getItem('linked:' + requestId) === '1'; } catch {}
const page = location.pathname === '/objects' ? 'objects' : location.pathname === '/secrets' ? 'secrets' : 'home';
const pagePath = requestId ? location.pathname : page === 'objects' ? '/objects' : page === 'secrets' ? '/secrets' : '/';
let accessRequest = null, requestError = '';
const loginMessages = {
  expired: 'メールを送信したブラウザでリンクを開いてください。期限が切れた場合は、もう一度メールを送信してください。',
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
let objectPrefix = '', objectFilter = '', objectLimit = 100, objectSort = 'updated', objectDescending = true, objectSearchPrefix = false;
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
  const links = ['<button class="text-button" data-action="go-prefix" data-prefix="">すべて</button>'];
  let walked = '';
  for (const [at, part] of parts.entries()) {
    walked += part + '/';
    links.push(at === parts.length - 1 ? `<span aria-current="location">${esc(part)}</span>`
      : `<button class="text-button" data-action="go-prefix" data-prefix="${esc(walked)}">${esc(part)}</button>`);
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
  if (!space || !space.available) return '<section class="resource-section object-browser"><div class="access-empty"><p>置き場は現在使えません。</p></div></section>';
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
      <td class="object-name"><span class="object-mark" aria-hidden="true">${icon('folder')}</span><button class="link-button" data-action="go-prefix" data-prefix="${esc(objectPrefix + item.name)}">${esc(item.name.slice(0, -1))}</button></td>
      <td>フォルダ</td><td>${esc(kiloBytes(item.bytes))}</td><td>${item.count} 件</td></tr>`).join('')
    + shown.map(item => `<tr><td><input type="checkbox" data-action="choose-object" data-key="${esc(item.key)}" ${objectChosen.has(item.key) ? 'checked' : ''} aria-label="${esc(item.name)} を選ぶ"></td>
      <td class="object-name"><span class="object-mark" aria-hidden="true">${icon('note')}</span><a href="/api/objects/${encodeURIComponent(item.key)}" download>${esc(item.name)}</a></td>
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
  return `<section class="resource-section object-browser" aria-label="置いてあるもの"><div class="object-count">オブジェクト（${space.usage?.count ?? space.objects.length}）</div>${crumbs()}${tools}${body}</section>`;
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

// The service an acquisition reaches.
const serviceName = adapter => adapter.service?.name || adapter.label;
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
  };
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || ''}</svg>`;
};
const brand = '<a class="brand" href="/" aria-label="Foundation ホーム"><span class="brand-mark" aria-hidden="true">F</span>Foundation</a>';
const nav = `<nav class="page-nav">${[['/', 'home', 'ホーム'], ['/secrets', 'secrets', 'シークレット'], ['/objects', 'objects', 'オブジェクト']]
  .map(([href, name, label]) => `<a href="${href}"${name === page ? ' aria-current="page"' : ''}>${label}</a>`).join('')}</nav>`;
const revocationNote = '停止後も、受け渡し済みの認証情報は有効期限まで使える場合があります。期限のないキーは、接続先で削除するまで無効になりません。';
function toast(text) {
  clearTimeout(toastTimer); notice.textContent = text; notice.hidden = false;
  toastTimer = setTimeout(() => { notice.hidden = true; }, 5500);
}
async function api(path, { method = 'GET', data, signal } = {}) {
  let response;
  try { response = await fetch(path, { method, signal, credentials: 'same-origin', cache: 'no-store', headers: data !== undefined ? { 'content-type': 'application/json' } : {}, ...(data !== undefined ? { body: JSON.stringify(data) } : {}) }); }
  catch { throw new Error('接続できませんでした。通信状況を確認してください。'); }
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error?.message || '処理を完了できませんでした。'); error.status = response.status; error.code = result.error?.code;
    if (response.status === 401 && !linked && path !== '/api/session' && path !== '/api/auth/link') await showLogin();
    throw error;
  }
  return result;
}
async function showLogin({ email = '', message = loginNotice } = {}) {
  clearInterval(loginTimer);
  const current = ++revision; state = null; closeDialog();
  let config = { available: false, pending: null };
  try { config = await api('/api/auth/config'); } catch {}
  if (current !== revision) return;
  const pending = config.available ? config.pending : null;
  app.innerHTML = `<div class="workspace login-shell"><header class="topbar">${brand}</header><main class="login-main"><div class="login-symbol" aria-hidden="true">${icon('mail')}</div>${requestId ? '<p class="login-context">依頼の確認</p>' : ''}<h1>${pending ? 'メールを確認' : 'ログイン'}</h1>
    ${pending ? `<p class="login-intro" id="email-sent">ログイン用のリンクをお送りしました。</p><p class="login-address">${esc(pending.email)}</p><p class="login-help">メールのリンクを、このブラウザで開いてください。有効期限は1時間です。</p>` : '<p class="login-intro">メールに届くリンクからログインできます。</p>'}
    <form id="login-form">${pending ? '' : `<label for="login-email">メールアドレス</label><input id="login-email" name="email" type="email" autocomplete="email" required maxlength="254" value="${esc(email)}" ${config.available ? '' : 'disabled'}>`}
    <p class="form-error" role="alert">${config.available ? esc(message) : '現在ログインを利用できません。'}</p><button class="button ${pending ? 'secondary' : 'primary'} full" type="submit" ${pending ? 'id="resend-link" disabled' : config.available ? '' : 'disabled'}>${pending ? 'メールを再送信' : 'ログインメールを送信'} ${pending ? '' : icon('arrow')}</button></form>
    ${pending ? '<p class="login-help login-delivery">届かない場合は、迷惑メールフォルダもご確認ください。</p><div class="login-actions"><button class="text-button" type="button" id="change-email">メールアドレスを変更</button></div>' : config.available ? '<p class="login-help login-footer">初めての方も、このまま始められます。</p>' : ''}</main></div>`;
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
      try { await api('/api/auth/link', { method: 'DELETE' }); loginNotice = ''; await showLogin({ email: pending.email }); }
      catch (error) { if (form.isConnected) { form.querySelector('.form-error').textContent = error.message; setBusy(false); } }
    });
  }
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy || !config.available || (pending && Date.now() < pending.resend_at)) return;
    setBusy(true); loginNotice = ''; form.querySelector('.form-error').textContent = '';
    try {
      await api('/api/auth/link', { method: 'POST', data: { email: pending?.email || form.elements.email.value.trim(), returnTo: pagePath } });
      await showLogin();
    } catch (error) {
      if (!form.isConnected) return;
      form.querySelector('.form-error').textContent = error.message; setBusy(false);
    }
  });
}
window.addEventListener('focus', () => { if (document.querySelector('#email-sent')) void refresh().catch(() => {}); });
async function refresh() {
  if (linked) {
    try { back = back || (await api('/api/request-links/' + requestId)).back; } catch {}
    try { accessRequest = (await api(requestApi)).request; requestError = ''; }
    catch (error) { accessRequest = null; requestError = error.status === 401 ? 'このリンクはもう使えません。元の画面から開き直してください。' : error.message; }
    state = { user: { email: '' }, secrets: [], keys: [], acquisitions: [], adapters: [], space: null };
    render();
    return;
  }
  const current = ++revision, result = await api('/api/state');
  let space = null;
  if (page !== 'secrets') { try { space = await api('/api/objects'); } catch { space = null; } }
  if (requestId && current === revision) {
    try {
      const found = (await api(requestApi)).request;
      accessRequest = keyRequest ? { ...found, kind: 'approve', requester_name: found.name } : found; requestError = '';
    }
    catch (error) { accessRequest = null; requestError = error.message; }
  }
  if (current !== revision) return;
  state = { ...result, space };
  render();
}
// Saved values and OAuth connections are independent lists.
const keptWhen = value => new Date(value).toLocaleString('ja-JP');
const kiloBytes = size => size < 1024 ? size + ' バイト' : size < 1024 * 1024 ? Math.round(size / 1024) + ' KB'
  : size < 1024 * 1024 * 1024 ? Math.round(size / (1024 * 1024)) + ' MB' : (size / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
const statusName = status => ({ connected: '利用できます', reconnect_required: '接続し直しが必要です', disconnecting: '解除しています' }[status] || '確認が必要です');
function connectionRow(connection) {
  const warning = connection.status !== 'connected';
  const until = connection.expiry_known === false ? '有効期限は不明です' : connection.expires_at ? '認証情報の有効期限 ' + esc(new Date(connection.expires_at).toLocaleString('ja-JP')) : '';
  return `<article class="agent-row"><div class="agent-name"><h3>${esc(connection.label)}</h3><p>${esc(connection.service?.name || '')} · <span class="${warning ? 'warning-text' : ''}">${esc(statusName(connection.status))}</span></p></div>
    <div class="agent-permissions"><span class="muted">${esc(connection.access?.name || '')}</span><span class="muted block">${until}</span></div>
    <div class="agent-actions">${connection.can_reconnect ? `<button class="text-button" data-action="reconnect" data-id="${esc(connection.id)}" data-adapter="${esc(connection.adapter)}" ${connection.available ? '' : 'disabled'}>接続し直す</button>` : ''}<button class="text-button danger" data-action="disconnect" data-id="${esc(connection.id)}">接続を解除</button></div></article>`;
}
function secretRow(entry) {
  return `<article class="agent-row"><div class="agent-name"><h3>${esc(entry.name)}</h3><p>${esc(kiloBytes(entry.size))}</p></div>
    <div class="agent-permissions"><span class="muted">${esc(keptWhen(entry.updated_at))}</span></div>
    <div class="agent-actions"><button class="text-button" data-action="show-secret" data-name="${esc(entry.name)}">中身を見る</button><button class="text-button" data-action="edit-secret" data-name="${esc(entry.name)}">名前を変える</button><button class="text-button danger" data-action="drop-secret" data-name="${esc(entry.name)}">削除</button></div></article>`;
}
function connectSection() {
  const available = state.adapters.filter(adapter => adapter.available);
  if (!available.length) return '';
  const services = new Map();
  for (const adapter of available) {
    const name = adapter.service?.name || adapter.label;
    if (!services.has(name)) services.set(name, { name, icon: adapter.service?.icon || 'key', adapters: [] });
    services.get(name).adapters.push(adapter);
  }
  const row = service => `<article class="agent-row"><div class="agent-name"><h3>${esc(service.name)}</h3><p>${esc(service.adapters.map(adapter => adapter.kind || adapter.access.name).join(' / '))}</p></div>
    <div class="agent-permissions"><span class="muted">${esc(service.adapters[0].intro)}</span></div>
    <div class="agent-actions">${service.adapters.map(adapter => `<button class="button secondary" data-action="add-adapter" data-adapter="${esc(adapter.id)}">${icon('plus')} ${esc(service.adapters.length > 1 ? adapter.kind || adapter.access.name : adapter.label)}</button>`).join('')}</div></article>`;
  return `<section class="resource-section" aria-labelledby="connect-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('lock')}</span><div><h2 id="connect-title">接続を追加</h2><p>接続先の画面で認証します</p></div></div></div>
    <div class="agent-list">${[...services.values()].map(row).join('')}</div></section>`;
}
function render() {
  if (!state) return;
  if (requestId) { renderRequest(); return; }
  const shell = inner => `<div class="workspace"><header class="topbar">${brand}${nav}<div class="user-menu"><span>${esc(state.user.email)}</span><button class="text-button" data-action="logout">ログアウト</button></div></header><main>${inner}</main></div>`;
  if (page === 'objects') {
    const usage = state.space?.usage;
    app.innerHTML = shell(`<header class="page-heading page-heading-actions"><div><h1>オブジェクト</h1>${usage ? `<p>${esc(kiloBytes(usage.bytes))} / ${esc(kiloBytes(usage.bytes_max))}・${usage.count} / ${usage.count_max} 件</p>` : ''}</div>
      <label class="button secondary" for="space-upload">${icon('plus')} 追加</label><input id="space-upload" type="file" hidden></header>${spaceSection()}`);
    bindObjects();
    return;
  }
  if (page === 'home') {
    const space = state.space, kept = state.secrets || [];
    const card = (href, title, line) => `<a class="home-card" href="${href}"><h2>${title}</h2><p>${esc(line)}</p></a>`;
    app.innerHTML = shell(`<header class="page-heading"><h1>Foundation</h1></header>
      <div class="home-cards">
        ${card('/secrets', 'シークレット', `保存値 ${kept.length} 件・接続 ${(state.acquisitions || []).length} 件`)}
        ${card('/objects', 'オブジェクト', space?.available ? `${space.usage.count} 件・${kiloBytes(space.usage.bytes)} / ${kiloBytes(space.usage.bytes_max)}` : '使えません')}
      </div>
      <section class="resource-section" aria-labelledby="access-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('device')}</span><div><h2 id="access-title">アクセスキー</h2></div></div><button class="button secondary" data-action="add-key">${icon('plus')} アクセスキーを追加</button></div>
      ${state.keys.length ? `<div class="agent-list">${state.keys.map(key => `<article class="agent-row"><div class="agent-name"><h3>${esc(key.name)}</h3><p>${key.last_used_at ? '最終利用 ' + esc(new Date(key.last_used_at).toLocaleString('ja-JP')) : 'まだ利用されていません'}</p></div><div class="agent-permissions"><span class="muted">承認 ${esc(new Date(key.created_at).toLocaleDateString('ja-JP'))}</span></div><div class="agent-actions"><button class="text-button" data-action="rename-key" data-id="${esc(key.id)}">名前を変更</button><button class="text-button danger" data-action="remove-key" data-id="${esc(key.id)}">失効</button></div></article>`).join('')}</div>` : '<div class="access-empty"><p>承認したアクセスキーはありません。AIが依頼を作ると、承認後にここに登録されます。</p></div>'}</section>
      <section class="resource-section" aria-labelledby="integration-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('network')}</span><div><h2 id="integration-title">連携</h2><p>あなたの製品の利用者が、登録なしで使えるようにします。</p></div></div><button class="button secondary" data-action="add-integration">${icon('plus')} 連携を追加</button></div>
      ${state.integrations?.length ? `<div class="agent-list">${state.integrations.map(item => `<article class="agent-row"><div class="agent-name"><h3>${esc(item.name)}</h3><p>${esc(new URL(item.return_url).host)} · 利用者 ${esc(String(item.accounts))} 人</p></div><div class="agent-permissions"><span class="muted">${item.last_used_at ? '最終利用 ' + esc(new Date(item.last_used_at).toLocaleString('ja-JP')) : 'まだ利用されていません'}</span>${item.webhook_url ? '<span class="muted block">完了を通知します</span>' : ''}</div><div class="agent-actions"><button class="text-button danger" data-action="remove-integration" data-id="${esc(item.id)}">削除</button></div></article>`).join('')}</div>` : '<div class="access-empty"><p>連携はありません。</p></div>'}</section>
      <p class="home-export"><a href="/api/export" download>まとめて取り出す</a></p>`);
    return;
  }
  const kept = state.secrets || [], connections = state.acquisitions || [];
  app.innerHTML = shell(`<header class="page-heading page-heading-actions"><div><h1>シークレット</h1></div>
    <button class="button secondary" data-action="add-secret">${icon('plus')} 追加</button></header>
    <section class="resource-section" aria-label="保存した値">${kept.length ? `<div class="agent-list">${kept.map(secretRow).join('')}</div>` : '<div class="access-empty"><p>保存した値はありません。</p></div>'}</section>
    ${connections.length ? `<section class="resource-section" aria-labelledby="connections-title"><div class="section-heading"><h2 id="connections-title">接続</h2></div><div class="agent-list">${connections.map(connectionRow).join('')}</div></section>` : ''}
    ${connectSection()}`);
}
function bindObjects() {
  const filter = document.querySelector('#object-filter');
  if (filter) {
    filter.addEventListener('input', () => {
      objectFilter = filter.value; objectLimit = 50;
      const at = filter.selectionStart;
      render();
      const again = document.querySelector('#object-filter');
      if (again) { again.focus(); again.setSelectionRange(at, at); }
    });
  }
  const upload = document.querySelector('#space-upload');
  if (upload) upload.addEventListener('change', async () => {
    const file = upload.files?.[0];
    if (!file) return;
    if ((state.space?.objects || []).some(item => item.key === objectPrefix + file.name)) {
      const go = await new Promise(resolve => confirmRemoval(file.name + ' を置き換えますか？', '同じ名前のものが置かれています。前のものは戻せません。', async () => resolve(true), () => resolve(false)));
      if (!go) { upload.value = ''; return; }
    }
    upload.disabled = true;
    try {
      const key = objectPrefix + file.name;
      const response = await fetch('/api/objects/' + encodeURIComponent(key), { method: 'PUT', credentials: 'same-origin',
        headers: { 'content-type': file.type || 'application/octet-stream' }, body: file });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error?.message || '追加できませんでした。');
      toast(file.name + ' を追加しました。');
      await refresh();
    } catch (error) { toast(error.message); upload.disabled = false; }
  });
}
const siteLink = value => { try { const url = new URL(value); return `<a href="${esc(url.href)}" target="_blank" rel="noopener noreferrer"><strong>${esc(url.host)}</strong>${esc(url.pathname === '/' ? '' : url.pathname)} ↗</a>`; } catch { return esc(value); } };
// Guidance the requesting AI wrote for its owner. Framed as the AI's words; line breaks kept, nothing else interpreted.
// The steps the requesting AI wrote for the owner to follow, shown as the numbered list they are.
const stepsBlock = steps => steps?.length ? `<section class="ai-guidance"><h3>依頼元のAIからの案内</h3><ol class="guidance-steps">${steps.map(step => `<li>${esc(step)}</li>`).join('')}</ol></section>` : '';
const codeComplete = form => /^[0-9a-fA-F]{8}$/.test((form.elements.confirmationCode?.value || '').replace(/[^0-9a-zA-Z]/g, ''));
function codeField(enabled = true) {
  return `<label for="confirmation-code">確認コード</label><input id="confirmation-code" name="confirmationCode" required maxlength="9" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="0000-0000" aria-describedby="confirmation-help" ${enabled ? '' : 'disabled'}><p class="permission-note" id="confirmation-help">AIとの会話に表示されたコードを入力してください。心当たりのない依頼は承認しないでください。</p>`;
}
// The link of a request shows the one screen its kind calls for:
//   approve   a key not yet approved: the owner accepts it with the code. Nothing is registered here.
//   connect   an approved key: Foundation performs the acquisition itself. No code.
//   store     an approved key: the owner puts something into storage, following the AI's instructions.
function renderRequest() {
  const row = accessRequest;
  const shell = (content) => `<div class="workspace"><header class="topbar">${brand}${linked ? '' : `<div class="user-menu"><span>${esc(state.user.email)}</span><button class="text-button" data-action="logout">ログアウト</button></div>`}</header><main class="approval-main">${content}</main></div>`;
  const finished = {
    done: ['登録しました', `${row?.result?.label || row?.result?.names?.join('、') || ''} を、${row?.requester_name || ''}から利用できます。この画面は閉じて構いません。`],
    approved: ['承認しました', `${row?.requester_name || ''}から、あなたが預けているものを利用できるようになりました。この画面は閉じて構いません。`],
    denied: row && row.kind !== 'approve' ? ['登録しませんでした', 'この依頼による変更はありません。'] : ['承認しませんでした', 'このアクセスキーは使えません。'],
    cancelled: ['依頼は取り消されました', '必要な場合は、AIに新しい依頼を作ってもらってください。'],
    revoked: ['アクセスキーは失効しています', 'この依頼元のキーは利用できません。'],
    reconnect_required: ['接続し直しが必要です', '管理画面から接続し直してください。'],
  };
  if (!row || row.status !== 'pending') {
    const [title, description] = row ? finished[row.status] || ['依頼を確認できません', '依頼のリンクを開き直してください。'] : ['依頼を確認できません', requestError];
    app.innerHTML = shell(`<section class="approval-card approval-result"><span class="approval-symbol">${icon(['approved', 'done'].includes(row?.status) ? 'check' : 'lock')}</span><h1>${title}</h1><p>${esc(description)}</p>${!linked ? '<a class="button secondary" href="/">預けているものを見る</a>'
      : back ? `<a class="button secondary" href="${esc(backTo(row))}">${esc(back.name)}に戻る</a>` : ''}</section>`);
    return;
  }
  const expiry = `<p class="request-expiry">この依頼は ${esc(new Date(row.expires_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }))} まで有効です。</p>`;
  if (row.kind === 'approve') { renderApproval(row, shell, expiry); return; }
  if (row.kind === 'store') { renderStore(row, shell, expiry); return; }
  const adapter = row.adapter, name = serviceName(adapter);
  const unavailable = `<p class="form-error" role="status">現在${esc(name)}に接続できません。</p>`;
  const body = !adapter.available ? unavailable
    : `<button class="button primary full request-connect" type="button" data-action="request-connect">${esc(adapter.label)} ${icon('arrow')}</button>
      ${adapter.failure_note && ['failed', 'scope', 'retry', 'changed'].includes(resultCode) ? `<p class="permission-note">${esc(adapter.failure_note.text)}<a href="${esc(adapter.failure_note.href)}" target="_blank" rel="noopener noreferrer">${esc(adapter.failure_note.link)} ↗</a></p>` : ''}`;
  app.innerHTML = shell(`<section class="approval-card"><header class="approval-heading"><span class="approval-symbol">${icon('lock')}</span><div><p class="approval-eyebrow">${esc(row.requester_name)}の依頼</p><h1>${esc(adapter.label)}</h1></div></header>
    <dl class="approval-facts">${row.purpose ? `<div><dt>用途</dt><dd>${esc(row.purpose)}</dd></div>` : ''}<div><dt>届く範囲</dt><dd>${esc(adapter.access.name)}</dd></div></dl>
    ${stepsBlock(row.steps)}
    <div class="register-body">${body}</div>
    <button class="text-button full" type="button" data-action="deny-request">接続しない</button>${expiry}</section>`);
}
// The owner puts something into storage for a key. Everything specific to the service is the AI's words;
// Foundation shows only where it will go and how it will be handed over.
function renderStore(row, shell, expiry) {
  const asked = Array.isArray(row.store) ? row.store : [row.store];
  const title = asked.length === 1 ? `${esc(asked[0].label)}を預ける` : `${asked.length}件を預ける`;
  const site = asked.find(one => one.site)?.site;
  const field = (one, at) => one.multiline
    ? `<textarea id="stored-${at}" name="value-${at}" rows="6" required maxlength="100000" autocomplete="off" spellcheck="false"></textarea>`
    : `<input id="stored-${at}" name="value-${at}" type="${one.secret ? 'password' : 'text'}" required maxlength="16384" autocomplete="off" spellcheck="false">`;
  app.innerHTML = shell(`<section class="approval-card"><header class="approval-heading"><span class="approval-symbol">${icon('lock')}</span><div><p class="approval-eyebrow">${esc(row.requester_name)}の依頼</p><h1>${title}</h1></div></header>
    <dl class="approval-facts">${row.purpose ? `<div><dt>用途</dt><dd>${esc(row.purpose)}</dd></div>` : ''}</dl>
    ${stepsBlock(row.steps)}
    ${site ? `<a class="button secondary full setup-link" href="${esc(site)}" target="_blank" rel="noopener noreferrer"><span>${esc(new URL(site).host)} を開く ↗</span></a>` : ''}
    <form id="store-request-form">${asked.map((one, at) => `<label for="stored-${at}">${esc(one.label)}</label>${field(one, at)}`).join('')}
    <p class="permission-note">接続先での有効性や権限は確認しません。登録した値は、承認済みのAIが利用できます。</p>
    <p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit">登録する ${icon('arrow')}</button></form>
    <button class="text-button full" type="button" data-action="deny-request">登録しない</button>${expiry}</section>`);
  bindForm(async (data) => {
    const contents = Object.fromEntries(asked.map((one, at) => [one.name, String(data.get('value-' + at) ?? '')]));
    try { await api(`/api/requests/${row.id}/store`, { method: 'POST', data: { contents } }); }
    catch (error) { if ([401, 404].includes(error.status)) await refresh(); throw error; }
    await refresh(); toast('登録しました。');
  }, app);
}
// Approving a key: only who is asking, what the key will reach, and the code.
function renderApproval(row, shell, expiry) {
  app.innerHTML = shell(`<section class="approval-card"><header class="approval-heading"><span class="approval-symbol">${icon('lock')}</span><div><p class="approval-eyebrow">新しいアクセスキー</p><h1>このアクセスキーを承認しますか？</h1></div></header>
    <dl class="approval-facts"><div><dt>依頼元</dt><dd>${esc(row.requester_name)}</dd></div><div><dt>使えるもの</dt><dd>保存した値・オブジェクト・接続したサービスのすべて</dd></div></dl>
    <form id="access-request-form">${codeField()}
    <p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit" disabled>承認する ${icon('arrow')}</button><button class="text-button full" type="button" data-action="deny-request">承認しない</button></form>${expiry}</section>`);
  const form = document.querySelector('#access-request-form'), submit = form.querySelector('[type="submit"]');
  const update = () => { submit.disabled = !codeComplete(form); };
  form.addEventListener('change', update); form.addEventListener('input', update);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submit.disabled || !form.reportValidity()) return;
    submit.disabled = true;
    const errorElement = form.querySelector('[role="alert"]'); errorElement.textContent = '';
    try {
      await api(`${requestApi}/approve`, { method: 'POST', data: { confirmationCode: form.elements.confirmationCode.value } });
      await refresh();
    } catch (error) { if (form.isConnected) { errorElement.textContent = error.message; submit.disabled = false; } }
  });
}
function openDialog(content) {
  dialog.innerHTML = `<button class="dialog-close icon-button" data-action="close-dialog" aria-label="閉じる">${icon('close')}</button>${content}`;
  if (!dialog.open) dialog.showModal();
}
function closeDialog() { if (dialog.open) dialog.close(); dialog.innerHTML = ''; }
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
// Starting an acquisition Foundation performs itself. There is nothing to fill in: the service decides who it is.
function connect(adapterId, connectionId) {
  const adapter = state.adapters.find(item => item.id === adapterId);
  if (!adapter?.available) return;
  const name = serviceName(adapter);
  openDialog(`<h2 id="dialog-title">${esc(name)}に${connectionId ? '接続し直す' : '接続'}</h2><p>${esc(adapter.intro)}</p><form>
    <p class="permission-note">${esc(adapter.access.name)}。${esc(adapter.access.restrictions)} ${connectionId ? '' : '接続すると、承認済みのアクセスキーから使えるようになります。'}${adapter.can_revoke ? '' : `停止は${esc(name)}で行います。`}</p><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(adapter.label)} ${icon('arrow')}</button></form>`);
  bindForm(async () => {
    const result = await api(`/api/adapters/${adapter.id}/connect`, { method: 'POST', data: connectionId ? { connection_id: connectionId } : {} });
    location.assign(result.url);
  });
}
// Disconnect only the OAuth connection; independently saved values remain.
function disconnect(connection) {
  const revoke = connection.can_revoke
    ? `<label class="check"><input type="checkbox" name="revoke" checked> ${esc(connection.service?.name || '')}側の許可も取り消す</label>`
    : `<p class="permission-note">${esc(connection.service?.name || '')}側のキーは残ります。不要なら${esc(connection.service?.name || '')}で削除してください。</p>`;
  openDialog(`<h2 id="dialog-title">${esc(connection.label)} の接続を解除しますか？</h2><form>
    <p>この接続から認証情報を取得できなくなります。別途保存した値は残ります。</p>
    <p class="permission-note">${esc(revocationNote)}</p>${revoke}<p class="form-error" role="alert"></p>
    <div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">接続を解除</button></div></form>`);
  bindForm(async (form) => {
    const result = await api('/api/acquisitions/' + encodeURIComponent(connection.id), { method: 'DELETE', data: { revoke: form.get('revoke') === 'on' } });
    closeDialog(); await refresh();
    toast(result.service_revoked === false ? '解除しました。接続先の許可は取り消せませんでした。' : '解除しました。');
  });
}
function addKey() {
  openDialog(`<h2 id="dialog-title">アクセスキーを追加</h2><p>AIの実行環境に置くキーを発行します。承認済みのキーと同じく、あなたが預けているものをすべて使えます。</p><form><label for="agent-name">アクセスキーの名前</label><input id="agent-name" name="name" placeholder="dev-us など" required maxlength="80" autocomplete="off"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">アクセスキーを発行</button></form>`);
  bindForm(async (form) => {
    const result = await api('/api/keys', { method: 'POST', data: { name: form.get('name') } });
    await refresh(); if (!state) return;
    openDialog(`<h2 id="dialog-title">${esc(result.key.name)} のアクセスキー</h2><p>キーは一度だけ表示します。AIを動かす環境の秘密情報として保管してください。</p><label for="agent-token">アクセスキー</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.key.token)}</textarea><button class="button secondary full" data-action="copy-token">キーをコピー</button><label for="api-url">接続先</label><input id="api-url" readonly value="${esc(location.origin)}/v1"><p class="permission-note">キーを会話や共有ファイルに貼り付けないでください。</p><button class="button primary full" data-action="close-dialog">閉じる</button>`);
  });
}
function removeCredential(credential) {
  const adapter = adapterOf(credential), name = credential.service;
  const manage = credential.management_url || adapter.service?.management_url;
  // The same three sentences for every credential: what leaves Foundation, what stays elsewhere, and where to remove that.
  const body = `<p>Foundationから削除します。承認済みのアクセスキーには渡らなくなります。</p>
    <p>すでにAIに渡した値と、${esc(name)}側のキーは残ります。</p>
    ${manage ? `<p><a href="${esc(manage)}" target="_blank" rel="noopener noreferrer">${esc(name)}でキーを確認・削除する ↗</a></p>` : ''}
    ${adapter.can_revoke ? `<label class="choice revoke-choice"><input type="checkbox" name="revoke" checked><span><strong>${esc(name)}側の許可も取り消す</strong><small>取り消せなかった場合は、その旨をお知らせします。</small></span></label>` : ''}`;
  openDialog(`<h2 id="dialog-title">${esc(name)}の認証情報を解除しますか？</h2><p>${esc(credentialLabel(credential))}</p><form>${body}<p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">登録を解除</button></div></form>`);
  bindForm(async (form) => {
    let result;
    try { result = await api(`/api/credentials/${credential.id}`, { method: 'DELETE', data: { revoke: form.has('revoke') } }); }
    catch (error) { await refresh(); throw error; }
    closeDialog(); await refresh();
    toast(result.service_revoked === false ? `登録を解除しました。${name}側の許可は取り消せませんでした。${name}の画面で取り消してください。` : '登録を解除しました。');
  });
}
function renameKey(key) {
  openDialog(`<h2 id="dialog-title">アクセスキーの名前を変更</h2><form><label for="agent-name">名前</label><input id="agent-name" name="name" required maxlength="80" autocomplete="off" value="${esc(key.name)}"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">保存</button></form>`);
  bindForm(async (form) => { await api(`/api/keys/${key.id}`, { method: 'PATCH', data: { name: form.get('name') } }); closeDialog(); await refresh(); toast('名前を変更しました。'); });
}
function addIntegration() {
  openDialog(`<h2 id="dialog-title">連携を追加</h2><p>あなたの製品が、利用者ごとのアカウントを作れるようになります。製品から利用者の預けたものは読めません。</p><form>
    <label for="integration-name">名前</label><input id="integration-name" name="name" placeholder="ai-simplicity など" required maxlength="80" autocomplete="off">
    <label for="integration-return">戻り先のURL</label><input id="integration-return" name="return_url" type="url" required placeholder="https://example.com/foundation" autocomplete="off">
    <p class="permission-note">依頼はこのページで開かれ、終わるとここに戻ります。</p>
    <label for="integration-refresh">リンクが使えないときの戻り先（省略可）</label><input id="integration-refresh" name="refresh_url" type="url" autocomplete="off">
    <label for="integration-webhook">完了の通知先（省略可）</label><input id="integration-webhook" name="webhook_url" type="url" autocomplete="off">
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">連携キーを発行</button></form>`);
  bindForm(async (form) => {
    const result = (await api('/api/integrations', { method: 'POST', data: { name: form.get('name'), return_url: form.get('return_url'), refresh_url: form.get('refresh_url') || undefined, webhook_url: form.get('webhook_url') || undefined } })).integration;
    await refresh(); if (!state) return;
    openDialog(`<h2 id="dialog-title">${esc(result.name)} の連携キー</h2><p>キーは一度だけ表示します。製品のサーバーの秘密情報として保管してください。</p><label for="agent-token">連携キー</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.token)}</textarea><button class="button secondary full" data-action="copy-token">キーをコピー</button>
      ${result.webhook_secret ? `<label for="webhook-secret">通知の署名キー</label><textarea id="webhook-secret" rows="2" readonly spellcheck="false">${esc(result.webhook_secret)}</textarea><p class="permission-note">通知が本物かどうかを、この値で確かめます。</p>` : ''}
      <button class="button primary full" data-action="close-dialog">閉じる</button>`);
  });
}
function removeIntegration(item) {
  openDialog(`<h2 id="dialog-title">連携を削除しますか？</h2><p>${esc(item.name)}</p><form><p>連携キーは使えなくなります。作られたアカウントと、発行済みのキーは利用者のもとに残ります。</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">削除する</button></div></form>`);
  bindForm(async () => { await api(`/api/integrations/${item.id}`, { method: 'DELETE', data: {} }); closeDialog(); await refresh(); toast('連携を削除しました。'); });
}
function removeKey(key) {
  const expiry = key.issued_nonexpiring ? '<p class="permission-note">このアクセスキーには、有効期限が未指定または不明の認証情報を渡しています。完全に無効にするには、認証情報の登録解除も必要です。</p>' : key.issued_until > Date.now() ? `<p class="permission-note">受け渡し済みの認証情報の最長有効期限：${esc(new Date(key.issued_until).toLocaleString('ja-JP'))}</p>` : '';
  openDialog(`<h2 id="dialog-title">アクセスキーを失効させますか？</h2><p>${esc(key.name)}</p><form><p>このアクセスキーでは認証情報を取得できなくなります。${revocationNote}</p>${expiry}<p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">失効させる</button></div></form>`);
  bindForm(async () => { await api(`/api/keys/${key.id}`, { method: 'DELETE' }); closeDialog(); await refresh(); toast('アクセスキーを失効させました。'); });
}
// One confirmation, for removing something a key kept. Nothing here can be undone, and nothing reaches the service.
// The name and the way it reaches a command, changed without the value ever being handed back.
// Something the owner has in hand, put there without an agent asking for it first.
function addSecret() {
  openDialog(`<h2 id="dialog-title">追加</h2>
    <form><label for="new-name">名前</label><input id="new-name" name="name" required maxlength="200" placeholder="任意の名前" autocomplete="off" spellcheck="false">
    <label for="new-value">値</label><textarea id="new-value" name="value" rows="4" required maxlength="100000" autocomplete="off" spellcheck="false"></textarea>
    <label class="checkbox"><input type="checkbox" name="readable"> 値の直接読み出しを許可する</label>
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">追加</button></form>`);
  bindForm(async (form) => {
    const name = form.get('name'), open = form.get('readable') === 'on';
    const response = await fetch('/api/secrets?name=' + encodeURIComponent(name) + (open ? '&secret=false' : ''),
      { method: 'PUT', credentials: 'same-origin', headers: { 'content-type': 'text/plain' }, body: String(form.get('value')) });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message || '追加できませんでした。');
    closeDialog(); await refresh(); toast(name + ' を追加しました。');
  });
}
function editSecret(entry) {
  if (!entry) return;
  openDialog(`<h2 id="dialog-title">名前を変える</h2><p>中身はそのままです。AIがこれを指すときの名前を変えられます。</p>
    <form><label for="secret-name">名前</label><input id="secret-name" name="name" required maxlength="200" value="${esc(entry.name)}" autocomplete="off" spellcheck="false">
    <p class="permission-note">この名前を指定している操作では、新しい名前への変更が必要です。</p>
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">変更する</button></form>`);
  bindForm(async (form) => {
    await api('/api/secrets?name=' + encodeURIComponent(entry.name), { method: 'PATCH', data: { name: form.get('name') } });
    closeDialog(); await refresh(); toast('変更しました。');
  });
}
function confirmRemoval(title, body, run) {
  openDialog(`<h2 id="dialog-title">${esc(title)}</h2><form><p>${esc(body)}</p><p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">削除する</button></div></form>`);
  bindForm(async () => { await run(); closeDialog(); await refresh(); toast('削除しました。'); });
}
document.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-action]'); if (!target || target.disabled) return;
  const { action, id } = target.dataset;
  try {
    if (action === 'close-dialog') closeDialog();
    if (action === 'logout') { target.disabled = true; await api('/api/session', { method: 'DELETE' }); await showLogin(); }
    if (action === 'request-connect') {
      target.disabled = true;
      const result = await api(`/api/adapters/${accessRequest.adapter.id}/connect`, { method: 'POST', data: { requestId } });
      location.assign(result.url);
    }
    if (action === 'deny-request') {
      target.disabled = true;
      await api(`${requestApi}/deny`, { method: 'POST', data: {} });
      await refresh();
    }
    if (action === 'add-adapter') connect(target.dataset.adapter);
    if (action === 'reconnect') connect(target.dataset.adapter, target.dataset.id);
    if (action === 'disconnect') disconnect(state.acquisitions.find(item => item.id === target.dataset.id));
    if (action === 'show-secret') {
      const name = target.dataset.name, entry = state.secrets.find(item => item.name === name);

      const response = await fetch('/api/secrets?name=' + encodeURIComponent(name), { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error('中身を取得できませんでした。');
      // What the bytes are is decided by looking at them: anything that is not plain text is offered as a file.
      const bytes = new Uint8Array(await response.arrayBuffer());
      const text = new TextDecoder('utf-8', { fatal: true });
      let shown = null;
      try { const value = text.decode(bytes); if (!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value)) shown = value; } catch {}
      const body = shown !== null
        ? `<pre class="kept-document">${esc(shown)}</pre>`
        : `<p>この形式は画面で表示できません。</p><a class="button secondary full" href="/api/secrets?name=${encodeURIComponent(name)}" download>ファイルとして保存</a>`;
      openDialog(`<h2 id="dialog-title">${esc(name)}</h2><p>${esc(keptWhen(entry.updated_at))}</p>${body}`);
    }
    if (action === 'drop-secret') {
      const name = target.dataset.name;
      confirmRemoval(name + ' を削除しますか？', 'AIはこれを使えなくなります。元には戻せません。', () => api('/api/secrets?name=' + encodeURIComponent(name), { method: 'DELETE', data: {} }));
    }
    if (action === 'go-prefix') { objectPrefix = target.dataset.prefix; objectFilter = ''; objectLimit = 100; objectChosen = new Set(); render(); }
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
      render();
    }
    if (action === 'choose-all') {
      const boxes = [...document.querySelectorAll('tbody [data-action="choose-object"]')];
      for (const box of boxes) { if (target.checked) objectChosen.add(box.dataset.key); else objectChosen.delete(box.dataset.key); }
      render();
    }
    if (action === 'copy-url') {
      const key = chosenKeys()[0];
      target.disabled = true;
      try {
        const result = await api('/api/objects/' + encodeURIComponent(key) + '/link', { method: 'POST', data: { minutes: 60 } });
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
        async () => { for (const key of keys) await api('/api/objects/' + encodeURIComponent(key), { method: 'DELETE', data: {} }); objectChosen = new Set(); });
    }
    if (action === 'add-secret') addSecret();
    if (action === 'edit-secret') editSecret((state.secrets || []).find(item => item.name === target.dataset.name));
    if (action === 'add-key') addKey();
    if (action === 'remove-key') removeKey(state.keys.find((key) => key.id === id));
    if (action === 'add-integration') addIntegration();
    if (action === 'remove-integration') removeIntegration(state.integrations.find((item) => item.id === id));
    if (action === 'rename-key') renameKey(state.keys.find((key) => key.id === id));
    if (action === 'copy-token') {
      const token = document.querySelector('#agent-token');
      try { await navigator.clipboard.writeText(token.value); toast('キーをコピーしました。'); }
      catch { token.select(); toast('キーを選択しました。コピーしてください。'); }
    }
  } catch (error) { if (target.isConnected) target.disabled = false; toast(error.message); }
});
const resultCode = new URL(location.href).searchParams.get('connection');
window.addEventListener('pageshow', event => { if (event.persisted) void refresh().catch(() => {}); });
if (linkToken) {
  try {
    await api('/api/request-links', { method: 'POST', data: { request_id: requestId, link: linkToken } });
    linked = true;
    try { sessionStorage.setItem('linked:' + requestId, '1'); } catch {}
  } catch (error) { if (!linked) { linked = true; requestError = error.message; } }
}
if (location.search || location.hash) history.replaceState(null, '', pagePath);
try { await refresh(); } catch (error) { if (error.status !== 401) { await showLogin(); toast(error.message); } }
// What came back from an OAuth round trip, in words that hold for any service.
const resultMessages = { connected: '認証情報を登録しました。', denied: '登録をキャンセルしました。', expired: '登録の手続きが切れました。もう一度お試しください。',
  wrong_account: '登録し直すには同じアカウントを選んでください。', already_connected: 'この認証情報は登録済みです。', scope: '求めた範囲とサービスの許可が一致しません。',
  retry: '継続利用の許可を取得できませんでした。もう一度登録してください。', changed: '認証情報の状態が変わりました。もう一度お試しください。', failed: '登録できませんでした。もう一度お試しください。' };
if (resultCode) toast(resultMessages[resultCode] || '登録を確認し、もう一度お試しください。');
