const app = document.querySelector('#app'), dialog = document.querySelector('#dialog'), notice = document.querySelector('#notice');
let state = null, selected = null, toastTimer, loginTimer, revision = 0;
const requestId = location.pathname.match(/^\/connect\/([A-Za-z0-9_-]{43})$/)?.[1];
const pagePath = requestId ? '/connect/' + requestId : '/';
let accessRequest = null, requestError = '';
let disposePrivateInput = () => {};
function clearPrivateInput() { const dispose = disposePrivateInput; disposePrivateInput = () => {}; dispose(); }
window.addEventListener('pagehide', clearPrivateInput);
const loginMessages = {
  expired: 'メールを送信したブラウザでリンクを開いてください。期限が切れた場合は、もう一度メールを送信してください。',
  invalid: 'リンクが無効か、有効期限が切れています。最新のメールのリンクを開いてください。',
  busy: 'ログインを確認しています。少し待ってからページを開き直してください。',
  limited: '操作が続いています。しばらく待ってからお試しください。',
  unavailable: 'ログインサービスに接続できません。少し待ってからリンクを開き直してください。',
};
let loginNotice = loginMessages[new URL(location.href).searchParams.get('login')] || '';
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const credentialLabel = credential => credential?.label || credential?.subject || '';
// The verified label, shown under the name only when the owner gave the credential another name.
const otherLabel = credential => credentialLabel(credential) === credential?.name ? '' : credentialLabel(credential);
const adapterOf = credential => state.adapters.find(adapter => adapter.id === credential.adapter);
// What a credential reaches. A stored credential carries the name; an adapter carries it, or for the generic adapter the request does.
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
    key: '<circle cx="8" cy="14" r="4"/><path d="m11 11 8-8m-3 3 2 2m-5 1 2 2"/>',
    network: '<circle cx="6" cy="12" r="3"/><circle cx="18" cy="5" r="2"/><circle cx="18" cy="19" r="2"/><path d="m9 11 7-5m-7 7 7 5"/>',
  };
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || ''}</svg>`;
};
const brand = '<a class="brand" href="/" aria-label="Foundation ホーム"><span class="brand-mark" aria-hidden="true">F</span>Foundation</a>';
const statusName = (credential) => ({ connected: '利用可能', reconnect_required: '登録し直しが必要', disconnecting: '解除待ち' }[credential.status] || '確認が必要');
const accessName = credential => credential.access?.name || 'サービスで許可した範囲';
const revocationNote = '停止後も、受け渡し済みの認証情報は有効期限まで使える場合があります。期限のないキーは、接続先で削除するまで無効になりません。';
function verificationDetails(report) {
  if (!report?.checks?.length) return '';
  const attention = report.checks.some(item => item.status === 'failed' || item.status === 'unknown' && item.check !== 'permissions');
  const statuses = { passed: '成功', failed: '失敗', unknown: '未確認' };
  return `<details class="verification-result" ${attention ? 'open' : ''}><summary>検証結果</summary><ul>${report.checks.map(item => `<li><span class="verification-label">${esc(item.label)}<small>${esc(statuses[item.status] || '未確認')}</small></span><p>${esc(item.message)}</p></li>`).join('')}</ul></details>`;
}
function keyFacts(credential) {
  if (!credential.key_info) return credential.credential_type === 'api_key' && credential.expiry_known === true ? `<dl class="key-facts"><div><dt>有効期限</dt><dd>${credential.expires_at === null ? '期限の指定なし' : esc(new Date(credential.expires_at).toLocaleString('ja-JP'))}</dd></div></dl>` : '';
  const info = credential.key_info, dollars = value => value === null ? '上限なし' : new Intl.NumberFormat('ja-JP', { style: 'currency', currency: 'USD', maximumFractionDigits: 4 }).format(value);
  const reset = { daily: '毎日', weekly: '毎週', monthly: '毎月' }[info.limit_reset] || 'リセットなし';
  return `<dl class="key-facts"><div><dt>キーの利用上限</dt><dd>${esc(dollars(info.limit))} · ${esc(reset)}</dd></div><div><dt>残りの上限額</dt><dd>${info.limit_remaining === null && info.limit !== null ? '情報がありません' : esc(dollars(info.limit_remaining))}</dd></div><div><dt>有効期限</dt><dd>${credential.expiry_known === false ? '情報がありません' : credential.expires_at === null ? '期限の指定なし' : esc(new Date(credential.expires_at).toLocaleString('ja-JP'))}</dd></div><div><dt>持ち込みキーの利用分</dt><dd>${info.include_byok_in_limit ? '上限に含む' : '上限に含まない'}</dd></div></dl><p class="muted key-caption">${esc(new Date(info.checked_at).toLocaleString('ja-JP'))} 時点。上限と期限はOpenRouterで管理します。</p><a class="key-management" href="${esc(credential.management_url)}" target="_blank" rel="noopener noreferrer">OpenRouterで上限・期限を確認 ↗</a>`;
}
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
    if (response.status === 401 && path !== '/api/session' && path !== '/api/auth/link') await showLogin();
    throw error;
  }
  return result;
}
async function showLogin({ email = '', message = loginNotice } = {}) {
  clearInterval(loginTimer);
  const current = ++revision; state = null; selected = null; closeDialog();
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
  const current = ++revision, result = await api('/api/state');
  if (requestId && current === revision) {
    try { accessRequest = (await api('/api/access-requests/' + requestId)).request; requestError = ''; }
    catch (error) { accessRequest = null; requestError = error.message; }
  }
  if (current !== revision) return;
  state = result;
  if (!state.credentials.some((credential) => credential.id === selected)) selected = state.credentials[0]?.id || null;
  render();
}
function details(credential) {
  if (!credential) return '';
  const adapter = adapterOf(credential), name = credential.service;
  return `<div class="credential-heading"><span class="status ${credential.status === 'connected' ? '' : 'warning'}">${credential.status === 'connected' ? icon('check') : ''}${statusName(credential)}</span>${credential.verified === false ? '<span class="status neutral">未検証</span>' : ''}<h3>${esc(credential.name)}</h3>${otherLabel(credential) ? `<p class="credential-email">${esc(otherLabel(credential))}</p>` : ''}</div>
    <dl class="credential-facts"><div><dt>用途</dt><dd>${esc(credential.purpose || '未設定')}</dd></div>${Array.isArray(credential.organizations) ? `<div><dt>組織</dt><dd>${credential.organizations.length ? credential.organizations.map(item => esc(item.name)).join('、') : 'なし'}</dd></div>` : ''}${claimRows(adapter, credential.details)}<div><dt>届く範囲</dt><dd>${esc(accessName(credential))}<span class="muted block">${esc(credential.access?.restrictions)}</span></dd></div><div><dt>渡す変数</dt><dd>${credential.variables?.length ? credential.variables.map(name => `<code>${esc(name)}</code>`).join(' ') : 'Expo のログイン状態として渡します'}</dd></div></dl>${keyFacts(credential)}
    <div class="credential-actions">${credential.verified === false ? '' : `<button class="button secondary" data-action="check" data-id="${esc(credential.id)}" ${credential.status !== 'connected' || !adapter.available ? 'disabled' : ''}>検証する</button>`}${adapter.can_reconnect ? `<button class="text-button" data-action="reconnect" data-id="${esc(credential.id)}" ${credential.status === 'disconnecting' || !adapter.available ? 'disabled' : ''}>登録し直す</button>` : ''}<button class="text-button" data-action="edit-credential" data-id="${esc(credential.id)}">編集</button></div>
    ${verificationDetails(credential.verification)}<details class="credential-reference"><summary>識別情報</summary><dl><dt>認証情報ID</dt><dd><code>${esc(credential.id)}</code></dd></dl>${adapter.service?.api.documentation_url ? `<a href="${esc(adapter.service.api.documentation_url)}" target="_blank" rel="noopener noreferrer">${esc(name)} APIの公式ドキュメント ↗</a>` : ''}</details>
    <div class="credential-footer">${credential.credential_type === 'expo_session' ? '' : `<a href="${esc(credential.management_url || adapter.service?.management_url)}" target="_blank" rel="noopener noreferrer">${esc(name)}の${adapter.declared ? 'キー管理ページ' : '管理ページ'} ↗</a>`}<button class="text-button danger" data-action="remove-credential" data-id="${esc(credential.id)}">${credential.status === 'disconnecting' ? '解除を再試行' : '登録を解除'}</button></div>`;
}
// One section per service. Credentials sit under the name of what they reach, whichever adapter holds them;
// the add button offers the adapters the owner can use from here.
function serviceGroups() {
  const groups = new Map(), group = (name, icon) => groups.get(name) || groups.set(name, { name, icon, adapters: [], credentials: [] }).get(name);
  for (const adapter of state.adapters) if (adapter.service && !adapter.declared) group(adapter.service.name, adapter.service.icon).adapters.push(adapter);
  for (const credential of state.credentials) group(credential.service, adapterOf(credential)?.service?.icon || 'key').credentials.push(credential);
  return [...groups.values()];
}
function serviceSection(group) {
  const id = group.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'service-' + [...group.name].map(char => char.codePointAt(0).toString(36)).join(''), credentials = group.credentials;
  const available = group.adapters.some(adapter => adapter.available), credential = credentials.find(item => item.id === selected) || credentials[0];
  return `<section class="resource-section" aria-labelledby="${id}-title"><div class="section-heading"><div class="section-label"><span class="service-icon">${icon(group.icon)}</span><div><h2 id="${id}-title">${esc(group.name)}</h2><p>${credentials.length ? `${credentials.length}件の認証情報` : '未登録'}</p></div></div>${group.adapters.length ? `<button class="button primary" data-action="add-credential" data-service="${esc(group.name)}" ${available ? '' : 'disabled'}>${icon('plus')} ${esc(group.name)}を登録</button>` : ''}</div>
    ${credentials.length ? `<div class="credential-workspace"><div class="credential-list" role="group" aria-label="${esc(group.name)}の認証情報">${credentials.map(item => `<button class="credential-item ${item.id === credential.id ? 'selected' : ''}" data-action="select-credential" data-id="${esc(item.id)}" aria-pressed="${item.id === credential.id}"><strong>${esc(item.name)}</strong>${otherLabel(item) ? `<span>${esc(otherLabel(item))}</span>` : ''}${item.status !== 'connected' ? `<small class="warning-text">${statusName(item)}</small>` : ''}</button>`).join('')}</div><div class="credential-pane">${details(credential)}</div></div>` : `<div class="empty-state"><span class="empty-icon">${icon(group.icon)}</span><div><h3>${esc(group.name)}の認証情報を登録しましょう</h3><p>${esc(group.adapters.length > 1 ? group.adapters.map(adapter => adapter.access.name).join('、') + 'から選んで登録できます。' : group.adapters[0]?.intro)}</p></div></div>`}
    ${group.adapters.length && !available ? '<p class="availability" role="status">現在、新しい認証情報を登録できません。</p>' : ''}</section>`;
}
function render() {
  if (!state) return;
  clearPrivateInput();
  if (requestId) { renderRequest(); return; }
  const byId = new Map(state.credentials.map((item) => [item.id, item]));
  app.innerHTML = `<div class="workspace"><header class="topbar">${brand}<div class="user-menu"><span>${esc(state.user.email)}</span><button class="text-button" data-action="logout">ログアウト</button></div></header><main><header class="page-heading"><h1>認証情報</h1><p>預けた認証情報と、AIのアクセスキーを管理</p></header>
    ${serviceGroups().filter(group => group.credentials.length || group.adapters.some(adapter => adapter.available)).map(serviceSection).join('')}
    <section class="resource-section" aria-labelledby="access-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('device')}</span><div><h2 id="access-title">AIのアクセスキー</h2><p>承認したキーは、預けた認証情報をすべて使えます</p></div></div><button class="button secondary" data-action="add-agent">${icon('plus')} アクセスキーを追加</button></div>
    ${state.agents.length ? `<div class="agent-list">${state.agents.map((agent) => `<article class="agent-row"><div class="agent-name"><h3>${esc(agent.name)}</h3><p>${agent.last_used_at ? '最終利用 ' + esc(new Date(agent.last_used_at).toLocaleString('ja-JP')) : 'まだ利用されていません'}</p></div><div class="agent-permissions"><span class="muted">承認 ${esc(new Date(agent.created_at).toLocaleDateString('ja-JP'))}</span></div><div class="agent-actions"><button class="text-button" data-action="rename-agent" data-id="${esc(agent.id)}">名前を変更</button><button class="text-button danger" data-action="remove-agent" data-id="${esc(agent.id)}">失効</button></div></article>`).join('')}</div>` : '<div class="access-empty"><p>承認したアクセスキーはありません。AIが依頼を作ると、承認後にここに登録されます。</p></div>'}</section></main></div>`;
}
const siteLink = value => { try { const url = new URL(value); return `<a href="${esc(url.href)}" target="_blank" rel="noopener noreferrer"><strong>${esc(url.host)}</strong>${esc(url.pathname === '/' ? '' : url.pathname)} ↗</a>`; } catch { return esc(value); } };
function claimRows(adapter, details) {
  if (!adapter.request_fields?.length || !details) return '';
  return adapter.request_fields.map(field => `<div><dt>${esc(field.label)}</dt><dd>${field.type === 'url' ? siteLink(details[field.id]) : field.type === 'code' ? `<code>${esc(details[field.id])}</code>` : esc(details[field.id])}</dd></div>`).join('');
}
// Guidance the requesting AI wrote for its owner. Framed as the AI's words; line breaks kept, nothing else interpreted.
const guidanceBlock = (text) => text ? `<section class="ai-guidance"><h3>依頼元のAIからの案内</h3>${text.split(/\n{2,}/).map(part => `<p>${esc(part).replace(/\n/g, '<br>')}</p>`).join('')}</section>` : '';
const codeComplete = form => /^[0-9a-fA-F]{8}$/.test((form.elements.confirmationCode?.value || '').replace(/[^0-9a-zA-Z]/g, ''));
function codeField(enabled = true) {
  return `<label for="confirmation-code">確認コード</label><input id="confirmation-code" name="confirmationCode" required maxlength="9" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="0000-0000" aria-describedby="confirmation-help" ${enabled ? '' : 'disabled'}><p class="permission-note" id="confirmation-help">AIとの会話に表示されたコードを入力してください。心当たりのない依頼は許可しないでください。</p>`;
}
// The approval URL shows one of two screens. Registering an credential is between the owner and the service, and
// completes the request of a key the owner already approved. Approving a key is the owner's one-time acknowledgement
// that the key is theirs; from then on it uses every credential they registered. The AI's guidance is about registering.
let requestScreen = null;
function renderRequest() {
  const row = accessRequest;
  const shell = (content) => `<div class="workspace"><header class="topbar">${brand}<div class="user-menu"><span>${esc(state.user.email)}</span><button class="text-button" data-action="logout">ログアウト</button></div></header><main class="approval-main">${content}</main></div>`;
  const finished = {
    approved: row?.credential ? ['登録しました', `${row.credential.label || row.credential.subject} を、${row.requester_name}から利用できます。この画面は閉じて構いません。`] : ['承認しました', `${row?.requester_name || ''}から、預けた認証情報を利用できるようになりました。この画面は閉じて構いません。`],
    denied: ['利用を許可しませんでした', 'この依頼による変更はありません。'],
    cancelled: ['依頼は取り消されました', '必要な場合は、AIに新しい依頼を作ってもらってください。'],
    revoked: ['アクセスキーは失効しています', 'この依頼元のキーは利用できません。'],
    reconnect_required: ['登録し直しが必要です', '管理画面から認証情報を登録し直してください。'],
  };
  if (!row || row.status !== 'pending') {
    const [title, description] = row ? finished[row.status] || ['依頼を確認できません', '依頼のリンクを開き直してください。'] : ['依頼を確認できません', requestError];
    app.innerHTML = shell(`<section class="approval-card approval-result"><span class="approval-symbol">${icon(row?.status === 'approved' ? 'check' : 'lock')}</span><h1>${title}</h1><p>${esc(description)}</p><a class="button secondary" href="/">認証情報を管理</a></section>`);
    return;
  }
  const registeredKey = Boolean(row.agent_name);
  const adapter = row.adapter, name = serviceName(adapter);
  const same = state.credentials.filter(credential => credential.adapter === adapter.id && credential.status !== 'disconnecting');
  const expiry = `<p class="request-expiry">この依頼は ${esc(new Date(row.expires_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }))} まで有効です。</p>`;
  const deny = '<button class="text-button full" type="button" data-action="deny-request">許可しない</button>';
  const screen = registeredKey || requestScreen === 'register' || !same.length ? 'register' : 'approve';
  if (screen === 'register') {
    const connectLabel = adapter.label;
    const unavailable = `<p class="form-error" role="status">現在${esc(name)}を登録できません。</p>`;
    const body = !adapter.available ? unavailable : adapter.register === 'login' ? expoLoginMarkup(row) : adapter.register === 'paste' ? schemaFormMarkup(adapter.form)
      : `${same.filter(credential => credential.status === 'reconnect_required' && adapter.can_reconnect).map(credential => `<button class="button secondary full request-connect" type="button" data-action="request-connect" data-id="${esc(credential.id)}">${esc(credentialLabel(credential))} を登録し直す</button>`).join('')}
        <button class="button primary full request-connect" type="button" data-action="request-connect">${esc(connectLabel)} ${icon('arrow')}</button>
        ${adapter.id === 'openrouter.oauth' && ['failed', 'scope', 'retry', 'changed'].includes(resultCode) ? '<p class="permission-note">登録できなくても、OpenRouterで作成済みのキーが残る場合があります。<a href="https://openrouter.ai/keys" target="_blank" rel="noopener noreferrer">不要なキーはOpenRouterで削除してください ↗</a></p>' : ''}`;
    app.innerHTML = shell(`<section class="approval-card"><header class="approval-heading"><span class="approval-symbol">${icon('lock')}</span><div><p class="approval-eyebrow">${esc(row.requester_name)}の依頼</p><h1>${esc(connectLabel)}</h1></div></header>
      ${row.purpose ? `<dl class="approval-facts"><div><dt>用途</dt><dd>${esc(row.purpose)}</dd></div></dl>` : ''}
      ${guidanceBlock(row.guidance)}${!row.guidance && adapter.instructions ? `<p class="permission-note">${esc(adapter.instructions)}</p>` : ''}
      <div class="register-body">${body}</div>
      ${!registeredKey && same.length ? '<button class="text-button full" type="button" data-action="back-to-approve">登録せずに戻る</button>' : registeredKey ? '<button class="text-button full" type="button" data-action="deny-request">登録しない</button>' : deny}${expiry}</section>`);
    const container = app.querySelector('.register-body');
    if (adapter.available && adapter.register === 'login') bindExpoLogin(container, row);
    if (adapter.available && adapter.register === 'paste') bindSchemaForm(container, adapter.form, async values => {
      let result;
      try { result = await api(`/api/adapters/${adapter.id}/connect`, { method: 'POST', data: { values, purpose: row.purpose, accessRequestId: row.id } }); }
      catch (error) { if ([401, 404].includes(error.status)) await refresh(); throw error; }
      selected = result.credential_id; requestScreen = null;
      await refresh(); toast(`${name}の認証情報を登録しました。`);
    });
    return;
  }
  const usable = state.credentials.filter(credential => credential.status !== 'disconnecting');
  const fresh = same.find(credential => credential.id === row.credential_id);
  const credentialCard = credential => `<div class="approval-credential"><div class="choice"><span><strong>${esc(credential.name)}</strong>${otherLabel(credential) ? `<small>${esc(otherLabel(credential))}</small>` : ''}</span></div>${keyFacts(credential)}${verificationDetails(credential.verification)}</div>`;
  app.innerHTML = shell(`<section class="approval-card"><header class="approval-heading"><span class="approval-symbol">${icon('lock')}</span><div><p class="approval-eyebrow">${esc(name)}へのアクセス</p><h1>このアクセスキーを承認しますか？</h1></div></header>
    <dl class="approval-facts"><div><dt>依頼元</dt><dd>${esc(row.requester_name)}<span class="muted block">新しいアクセスキーです。承認すると、預けた認証情報をすべて使えるようになります。</span></dd></div>${row.purpose ? `<div><dt>用途</dt><dd>${esc(row.purpose)}</dd></div>` : ''}<div><dt>届く範囲</dt><dd>${esc(adapter.access.name)}${adapter.access.restrictions ? `<span class="muted block">${esc(adapter.access.restrictions)}</span>` : ''}</dd></div>${claimRows(adapter, row.details)}</dl>${adapter.declared ? '<p class="permission-note claim-note">サービス名と作成ページはAIの申告です。作成ページのドメインが正しいか確認してください。</p>' : ''}
    <form id="access-request-form">
    ${fresh ? `<h2 class="approval-section">この依頼で登録した認証情報</h2>${credentialCard(fresh)}` : `<h2 class="approval-section">登録済みの${esc(name)}の認証情報</h2>${same.map(credentialCard).join('')}`}
    <p class="permission-note">承認後に使える認証情報: ${usable.map(credential => esc(credential.service) + ' (' + esc(credential.name) + ')').join('、')}</p>
    <button class="text-button full" type="button" data-action="open-register" ${adapter.available ? '' : 'disabled'}>別の認証情報を登録する</button>
    ${codeField()}
    <p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit" disabled>承認する ${icon('arrow')}</button>${deny}</form>${expiry}</section>`);
  const form = document.querySelector('#access-request-form'), submit = form.querySelector('[type="submit"]');
  const update = () => { submit.disabled = !codeComplete(form); };
  form.addEventListener('change', update); form.addEventListener('input', update);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submit.disabled || !form.reportValidity()) return;
    submit.disabled = true;
    const errorElement = form.querySelector('[role="alert"]'); errorElement.textContent = '';
    try {
      await api(`/api/access-requests/${requestId}/approve`, { method: 'POST', data: { confirmationCode: form.elements.confirmationCode.value } });
      await refresh();
    } catch (error) { if (form.isConnected) { errorElement.textContent = error.message; submit.disabled = false; } }
  });
}
// The browser's back gesture returns from the register screen to the approval screen.
window.addEventListener('popstate', () => { if (requestId && requestScreen === 'register') { requestScreen = null; renderRequest(); } });
function openDialog(content) {
  clearPrivateInput();
  dialog.innerHTML = `<button class="dialog-close icon-button" data-action="close-dialog" aria-label="閉じる">${icon('close')}</button>${content}`;
  if (!dialog.open) dialog.showModal();
}
function closeDialog() { clearPrivateInput(); if (dialog.open) dialog.close(); dialog.innerHTML = ''; }
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
// Registering: the name may be left empty and is then taken from what was verified. Editing: the name stays set.
function credentialFields(credential, editing = false) {
  return `<label for="credential-name">表示名${editing ? '' : ' <span class="optional">任意</span>'}</label><input id="credential-name" name="name" ${editing ? 'required' : 'placeholder="空欄なら確かめた内容から付けます"'} maxlength="80" autocomplete="off" value="${esc(credential?.name || '')}"><label for="account-purpose">用途 <span class="optional">任意</span></label><input id="account-purpose" name="purpose" placeholder="この認証情報を使う場面" maxlength="240" value="${esc(credential?.purpose || '')}">`;
}
// The dashboard's add button belongs to a service; with several adapters the owner picks how to register first.
function chooseAdapter(serviceName) {
  const options = state.adapters.filter(adapter => adapter.service?.name === serviceName && adapter.available && !adapter.declared);
  if (options.length === 1) { connect(null, options[0].id); return; }
  openDialog(`<h2 id="dialog-title">${esc(serviceName)}を登録</h2><p>登録の方法を選んでください。</p>${options.map(adapter => `<button class="button secondary full setup-link" data-action="add-adapter" data-adapter="${esc(adapter.id)}"><span>${esc(adapter.access.name)}</span></button>`).join('')}`);
}
function connect(credential, adapterId = credential?.adapter) {
  const adapter = state.adapters.find(item => item.id === adapterId);
  if (!adapter?.available) return;
  const name = serviceName(adapter);
  if (adapter.register === 'login') { openDialog(`<h2 id="dialog-title">${esc(name)}を登録</h2>${expoLoginMarkup(null)}`); bindExpoLogin(dialog, null); return; }
  if (adapter.register === 'paste') {
    openDialog(`<h2 id="dialog-title">${esc(name)}を登録</h2><p>${esc(adapter.intro)}</p>${adapter.instructions ? `<p class="permission-note">${esc(adapter.instructions)}</p>` : ''}${adapter.note ? `<p class="permission-note">${esc(adapter.note)}</p>` : ''}${schemaFormMarkup(adapter.form)}`);
    bindSchemaForm(dialog, adapter.form, async values => {
      const result = await api(`/api/adapters/${adapter.id}/connect`, { method: 'POST', data: { values, purpose: '' } });
      selected = result.credential_id; closeDialog(); await refresh(); toast(`${name}の認証情報を登録しました。`);
    });
    return;
  }
  openDialog(`<h2 id="dialog-title">${esc(name)}を${credential ? '登録し直す' : '登録'}</h2><p>${credential ? esc(credentialLabel(credential)) : esc(adapter.intro)}</p><form>${credentialFields(credential)}
    <p class="permission-note">${esc(adapter.access.name)}。${esc(adapter.access.restrictions)} ${credential ? '' : '登録すると、承認済みのアクセスキーから使えるようになります。'}${adapter.can_revoke ? '' : `キーの停止は${esc(name)}で行います。`}</p><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(adapter.label)} ${icon('arrow')}</button></form>`);
  bindForm(async (form) => {
    const result = await api(`/api/adapters/${adapter.id}/connect`, { method: 'POST', data: { name: form.get('name'), purpose: form.get('purpose'), ...(credential ? { credentialId: credential.id } : {}) } });
    location.assign(result.url);
  });
}
function expoLoginMarkup(request) {
  return `<form class="expo-login-form" autocomplete="off"><div class="expo-password-fields"><label for="expo-username">Expoのメールアドレスまたはユーザー名</label><input id="expo-username" name="username" required maxlength="254" autocomplete="off" autocapitalize="none" spellcheck="false"><label for="expo-password">パスワード</label><input id="expo-password" name="password" type="password" required maxlength="1024" autocomplete="off"></div>
    <div class="expo-otp-fields" hidden><label for="expo-otp">認証コード</label><input id="expo-otp" name="otp" maxlength="64" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" disabled><p class="expo-otp-help permission-note"></p><button type="button" class="text-button expo-reset">ログイン情報を入力し直す</button></div>
    ${request && !request.agent_name ? codeField() : ''}<p class="permission-note auth-privacy">入力内容はFoundationを経由してExpoへ送信します。パスワード・認証コードは保存しません。</p>
    <p class="permission-note auth-permission">${request ? esc(request.adapter.access.description) : 'Expoのログイン状態を保存します。承認済みのアクセスキーから使えるようになります。'}</p><p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit" ${request && !request.adapter.available ? 'disabled' : ''}>${request && !request.agent_name ? 'ログインして承認' : 'ログインして登録'} ${icon('arrow')}</button></form>`;
}
function bindExpoLogin(container, request) {
  clearPrivateInput();
  const form = container.querySelector('.expo-login-form'), button = form.querySelector('[type="submit"]'), errorElement = form.querySelector('[role="alert"]');
  const passwordFields = form.querySelector('.expo-password-fields'), otpFields = form.querySelector('.expo-otp-fields');
  let password = '', username = '', active = true, busy = false, deadline, controller;
  function reset() {
    password = ''; username = ''; clearTimeout(deadline); controller?.abort(); busy = false;
    const code = form.elements.confirmationCode?.value || '';
    form.reset(); if (form.elements.confirmationCode) form.elements.confirmationCode.value = code;
    passwordFields.hidden = false; otpFields.hidden = true;
    form.elements.password.disabled = false; form.elements.username.disabled = false; form.elements.otp.disabled = true; form.elements.otp.required = false;
    button.disabled = Boolean(request && !request.adapter.available); button.textContent = request && !request.agent_name ? 'ログインして承認' : 'ログインして登録';
  }
  disposePrivateInput = () => { active = false; reset(); };
  form.querySelector('.expo-reset').addEventListener('click', () => { reset(); errorElement.textContent = ''; form.elements.username.focus(); });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !active || (request && !request.adapter.available) || !form.reportValidity()) return;
    const initial = !password;
    if (initial) {
      username = form.elements.username.value.trim(); password = form.elements.password.value; form.elements.password.value = '';
      deadline = setTimeout(() => { if (active) { reset(); errorElement.textContent = '時間が経過しました。ログイン情報を入力し直してください。'; } }, Math.max(1, Math.min(300_000, (request?.expires_at || Infinity) - Date.now())));
    }
    const otp = initial ? undefined : form.elements.otp.value.trim(); form.elements.otp.value = '';
    busy = true; button.disabled = true; button.textContent = '確認中…'; errorElement.textContent = ''; controller = new AbortController();
    const signal = controller.signal;
    try {
      const result = await api('/api/adapters/expo.login/connect', { method: 'POST', signal, data: { purpose: request?.purpose || '', username, password, ...(otp === undefined ? {} : { otp }), ...(request ? { accessRequestId: request.id, ...(form.elements.confirmationCode ? { confirmationCode: form.elements.confirmationCode.value } : {}) } : {}) } });
      if (!active || signal.aborted) return;
      if (result.challenge) {
        passwordFields.hidden = true; otpFields.hidden = false;
        form.elements.password.disabled = true; form.elements.username.disabled = true; form.elements.otp.disabled = false; form.elements.otp.required = true;
        form.querySelector('.expo-otp-help').textContent = result.challenge.delivery === 'sms' ? 'Expoから届いたSMSのコード、またはバックアップコードを入力してください。' : '認証アプリのコード、またはバックアップコードを入力してください。';
        if (!initial) errorElement.textContent = '認証コードを確認してください。';
        button.textContent = request && !request.agent_name ? '確認して承認' : '確認して登録'; form.elements.otp.focus();
      } else {
        password = ''; username = ''; clearTimeout(deadline);
        selected = result.credential_id; closeDialog(); await refresh();
        if (!request) toast('Expoの認証情報を登録しました。');
      }
    } catch (error) {
      if (!active || signal.aborted) return;
      if (initial || error.code !== 'expo_login_failed') reset();
      else button.textContent = request && !request.agent_name ? '確認して承認' : '確認して登録';
      errorElement.textContent = error.message;
    } finally { if (active && !signal.aborted) { busy = false; button.disabled = false; } }
  });
}
// The paste body. It draws a schema and its links and hands the collected values to whoever placed it.
// It does not know the service, the page it sits on, or whether a request is involved.
function schemaFormMarkup(form) {
  const links = form.links.map(link => link.declared
    ? `<p class="declared-link"><a href="${esc(link.href)}" target="_blank" rel="noopener noreferrer">${esc(link.href)} ↗</a></p>`
    : `<a class="button secondary full setup-link" href="${esc(link.href)}" target="_blank" rel="noopener noreferrer">${esc(link.label)} ↗</a>`).join('');
  const field = item => {
    const id = 'field-' + esc(item.id), label = `<label for="${id}">${esc(item.label)}</label>`;
    const common = `id="${id}" name="${esc(item.id)}" required maxlength="${item.max}" autocomplete="off" spellcheck="false" autocapitalize="none"`;
    if (item.kind === 'choice') return label + `<select id="${id}" name="${esc(item.id)}" required><option value="">選択してください</option>${item.options.map(option => `<option value="${esc(option.value)}">${esc(option.label)}</option>`).join('')}</select>`;
    if (item.kind === 'multiline') return label + `<textarea ${common} rows="6"></textarea><label class="file-pick"><input type="file" data-field="${esc(item.id)}"><span class="button secondary full">ファイルから読み込む</span></label>`;
    return label + `<input ${common} type="${item.secret ? 'password' : 'text'}"${item.pattern ? ` pattern="${esc(item.pattern)}"` : ''}>`;
  };
  return `<form autocomplete="off" class="schema-form">${links ? `<div class="setup-links">${links}</div>` : ''}${form.schema.map(field).join('')}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">登録する ${icon('arrow')}</button></form>`;
}
function bindSchemaForm(container, form, submit) {
  for (const picker of container.querySelectorAll('input[type="file"][data-field]')) picker.addEventListener('change', async () => {
    const file = picker.files?.[0]; if (!file) return;
    const text = file.size <= 8192 ? await file.text() : '';
    container.querySelector(`[name="${CSS.escape(picker.dataset.field)}"]`).value = text.trim();
    container.querySelector('.form-error').textContent = text ? '' : 'ファイルが大きすぎます。';
    picker.value = '';
  });
  bindForm(async data => {
    const values = Object.fromEntries(form.schema.map(item => [item.id, data.get(item.id) || '']));
    // Secret values leave the page as soon as they are read; the rest stay so a mistake can be corrected.
    for (const item of form.schema) if (item.secret) container.querySelector(`[name="${CSS.escape(item.id)}"]`).value = '';
    await submit(values);
  }, container);
}
function editCredential(credential) {
  openDialog(`<h2 id="dialog-title">認証情報を編集</h2><p>${esc(credentialLabel(credential))}</p><form>${credentialFields(credential, true)}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">保存</button></form>`);
  bindForm(async (form) => { await api(`/api/credentials/${credential.id}`, { method: 'PATCH', data: { name: form.get('name'), purpose: form.get('purpose') } }); closeDialog(); await refresh(); toast('保存しました。'); });
}
function editAgent() {
  openDialog(`<h2 id="dialog-title">アクセスキーを追加</h2><p>AIの実行環境に置くキーを発行します。承認済みのキーと同じく、預けた認証情報をすべて使えます。</p><form><label for="agent-name">アクセスキーの名前</label><input id="agent-name" name="name" placeholder="dev-us など" required maxlength="80" autocomplete="off"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">アクセスキーを発行</button></form>`);
  bindForm(async (form) => {
    const result = await api('/api/agents', { method: 'POST', data: { name: form.get('name') } });
    await refresh(); if (!state) return;
    openDialog(`<h2 id="dialog-title">${esc(result.agent.name)} のアクセスキー</h2><p>キーは一度だけ表示します。AIを動かす環境の秘密情報として保管してください。</p><label for="agent-token">アクセスキー</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.agent.token)}</textarea><button class="button secondary full" data-action="copy-token">キーをコピー</button><label for="api-url">接続先</label><input id="api-url" readonly value="${esc(location.origin)}/v1"><p class="permission-note">キーを会話や共有ファイルに貼り付けないでください。</p><button class="button primary full" data-action="close-dialog">閉じる</button>`);
  });
}
function removeCredential(credential) {
  const adapter = adapterOf(credential), name = credential.service;
  const expoSession = credential.credential_type === 'expo_session';
  const revoke = expoSession ? '<p>この認証情報のExpoログインを無効にします。承認済みのアクセスキーからは使えなくなります。Expoのプロジェクトやデータは削除しません。</p>' : adapter.can_revoke ? `<p>承認済みのアクセスキーからは使えなくなります。メールは削除されません。</p><label class="choice revoke-choice"><input type="checkbox" name="revoke" checked><span><strong>Google側の許可も取り消す</strong><small>このアプリに与えた、ほかのGoogleサービスの許可も取り消されます。反映に時間がかかる場合があります。</small></span></label><p class="permission-note">チェックを外すと、Googleの許可は残ります。${revocationNote}</p>` : `<p>Foundationから、この認証情報を削除します。承認済みのアクセスキーからは使えなくなります。受け渡し済みのAPIキーは、この操作では無効になりません。</p><p><a href="${esc(credential.management_url || adapter.service?.management_url)}" target="_blank" rel="noopener noreferrer">${esc(name)}でキーを削除する ↗</a></p><label class="choice"><input type="checkbox" name="acknowledged" required><span>キーの無効化は${esc(name)}で行うことを確認しました</span></label>`;
  openDialog(`<h2 id="dialog-title">${esc(name)}の認証情報を解除しますか？</h2><p>${esc(credentialLabel(credential))}</p><form>${revoke}<p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">登録を解除</button></div></form>`);
  bindForm(async (form) => {
    try { await api(`/api/credentials/${credential.id}`, { method: 'DELETE', data: { revoke: expoSession || form.has('revoke') } }); }
    catch (error) { await refresh(); throw error; }
    closeDialog(); await refresh(); toast('登録を解除しました。');
  });
}
function renameAgent(agent) {
  openDialog(`<h2 id="dialog-title">アクセスキーの名前を変更</h2><form><label for="agent-name">名前</label><input id="agent-name" name="name" required maxlength="80" autocomplete="off" value="${esc(agent.name)}"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">保存</button></form>`);
  bindForm(async (form) => { await api(`/api/agents/${agent.id}`, { method: 'PATCH', data: { name: form.get('name') } }); closeDialog(); await refresh(); toast('名前を変更しました。'); });
}
function removeAgent(agent) {
  const expiry = agent.issued_nonexpiring ? '<p class="permission-note">このアクセスキーには、有効期限が未指定または不明の認証情報を渡しています。完全に無効にするには、認証情報の登録解除も必要です。</p>' : agent.issued_until > Date.now() ? `<p class="permission-note">受け渡し済みの認証情報の最長有効期限：${esc(new Date(agent.issued_until).toLocaleString('ja-JP'))}</p>` : '';
  openDialog(`<h2 id="dialog-title">アクセスキーを失効させますか？</h2><p>${esc(agent.name)}</p><form><p>このアクセスキーでは認証情報を取得できなくなります。${revocationNote}</p>${expiry}<p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">失効させる</button></div></form>`);
  bindForm(async () => { await api(`/api/agents/${agent.id}`, { method: 'DELETE' }); closeDialog(); await refresh(); toast('アクセスキーを失効させました。'); });
}
document.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-action]'); if (!target || target.disabled) return;
  const { action, id } = target.dataset;
  try {
    if (action === 'close-dialog') closeDialog();
    if (action === 'logout') { clearPrivateInput(); target.disabled = true; await api('/api/session', { method: 'DELETE' }); await showLogin(); }
    if (action === 'open-register') { requestScreen = 'register'; history.pushState({ screen: 'register' }, ''); renderRequest(); window.scrollTo(0, 0); return; }
    if (action === 'back-to-approve') { if (history.state?.screen === 'register') history.back(); else { requestScreen = null; renderRequest(); } return; }
    if (action === 'request-connect') {
      target.disabled = true;
      const credential = state.credentials.find(item => item.id === id);
      const result = await api(`/api/adapters/${accessRequest.adapter.id}/connect`, { method: 'POST', data: { purpose: credential?.purpose || accessRequest.purpose, accessRequestId: requestId, ...(credential ? { credentialId: credential.id } : {}) } });
      location.assign(result.url);
    }
    if (action === 'deny-request') {
      clearPrivateInput();
      target.disabled = true;
      await api(`/api/access-requests/${requestId}/deny`, { method: 'POST', data: {} });
      await refresh();
    }
    if (action === 'add-credential') chooseAdapter(target.dataset.service);
    if (action === 'add-adapter') connect(null, target.dataset.adapter);
    if (action === 'select-credential') { selected = id; render(); }
    if (action === 'reconnect') connect(state.credentials.find((a) => a.id === id));
    if (action === 'edit-credential') editCredential(state.credentials.find((a) => a.id === id));
    if (action === 'remove-credential') removeCredential(state.credentials.find((a) => a.id === id));
    if (action === 'add-agent') editAgent();
    if (action === 'remove-agent') removeAgent(state.agents.find((a) => a.id === id));
    if (action === 'rename-agent') renameAgent(state.agents.find((a) => a.id === id));
    if (action === 'check') {
      target.disabled = true;
      try {
        const result = await api(`/api/credentials/${id}/check`, { method: 'POST', data: {} });
        toast(result.verification?.checks.some(item => item.status !== 'passed' && item.check !== 'permissions') ? '検証結果を更新しました。確認できなかった項目があります。' : state.credentials.find(credential => credential.id === id).service + 'で検証できました。');
      }
      finally { await refresh(); }
    }
    if (action === 'copy-token') {
      const token = document.querySelector('#agent-token');
      try { await navigator.clipboard.writeText(token.value); toast('キーをコピーしました。'); }
      catch { token.select(); toast('キーを選択しました。コピーしてください。'); }
    }
  } catch (error) { if (target.isConnected) target.disabled = false; toast(error.message); }
});
const resultCode = new URL(location.href).searchParams.get('connection');
window.addEventListener('pageshow', event => { if (event.persisted) void refresh().catch(() => {}); });
const resultAdapter = new URL(location.href).searchParams.get('adapter');
if (location.search || location.hash) history.replaceState(null, '', pagePath);
try { await refresh(); } catch (error) { if (error.status !== 401) { await showLogin(); toast(error.message); } }
const connectionMessages = { connected: 'Gmailの認証情報を登録しました。', denied: 'Gmailの登録をキャンセルしました。', expired: '登録の手続きが切れました。ログインして、もう一度お試しください。', wrong_account: '登録し直すには同じGoogleアカウントを選んでください。', already_connected: 'このGmailは登録済みです。', scope: '読み取り範囲とGoogleの許可が一致しません。Google側の許可を確認してください。', retry: '継続利用の許可を取得できませんでした。もう一度登録してください。', changed: '認証情報の状態が変わりました。もう一度お試しください。', failed: 'Gmailを登録できませんでした。もう一度お試しください。' };
if (requestId) {
  const requestMessages = { denied: '登録をキャンセルしました。', expired: '登録の手続きが切れました。もう一度お試しください。', wrong_account: '登録し直すには同じアカウントを選んでください。', already_connected: 'この認証情報は登録済みです。', scope: '依頼された範囲とサービスの許可が一致しません。', retry: '継続利用の許可を取得できませんでした。もう一度登録してください。', changed: '認証情報の状態が変わりました。もう一度お試しください。', failed: '登録できませんでした。もう一度お試しください。' };
  if (requestMessages[resultCode]) toast(requestMessages[resultCode]);
} else if (resultAdapter && !resultAdapter.startsWith('gmail.') && resultCode) {
  const messages = { connected: '認証情報を登録しました。', denied: '登録をキャンセルしました。', expired: '登録の手続きが切れました。もう一度お試しください。', failed: '登録できませんでした。OpenRouterで作成済みのキーは残る場合があります。不要なキーはOpenRouterで削除してください。' };
  toast(messages[resultCode] || '登録を確認し、もう一度お試しください。');
} else if (connectionMessages[resultCode]) toast(connectionMessages[resultCode]);
