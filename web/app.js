const app = document.querySelector('#app'), dialog = document.querySelector('#dialog'), notice = document.querySelector('#notice');
let state = null, selected = null, toastTimer, loginTimer, revision = 0;
const requestId = location.pathname.match(/^\/connect\/([A-Za-z0-9_-]{43})$/)?.[1];
const pagePath = requestId ? '/connect/' + requestId : '/';
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
const accountLabel = account => account?.label || account?.email || '';
const providerFor = account => state.providers.find(provider => provider.id === account.provider);
const icon = (name) => {
  const paths = {
    plus: '<path d="M12 5v14M5 12h14"/>', close: '<path d="m6 6 12 12M6 18 18 6"/>',
    mail: '<rect x="3" y="5" width="18" height="14" rx="3"/><path d="m3 7 9 6 9-6"/>',
    device: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
    arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>', check: '<path d="m5 12 4 4L19 6"/>',
    lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    network: '<circle cx="6" cy="12" r="3"/><circle cx="18" cy="5" r="2"/><circle cx="18" cy="19" r="2"/><path d="m9 11 7-5m-7 7 7 5"/>',
  };
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || ''}</svg>`;
};
const brand = '<a class="brand" href="/" aria-label="Foundation ホーム"><span class="brand-mark" aria-hidden="true">F</span>Foundation</a>';
const statusName = (account) => ({ connected: '接続済み', reconnect_required: '再接続が必要', disconnecting: '解除待ち' }[account.status] || '確認が必要');
const scopeName = account => account.permission?.name || '接続先で許可した権限';
const revocationNote = '停止後も、受け渡し済みの認証情報は有効期限まで使える場合があります。期限のないキーは、接続先で削除するまで無効になりません。';
function keyFacts(account) {
  if (!account.key_info) return '';
  const info = account.key_info, dollars = value => value === null ? '上限なし' : new Intl.NumberFormat('ja-JP', { style: 'currency', currency: 'USD', maximumFractionDigits: 4 }).format(value);
  const reset = { daily: '毎日', weekly: '毎週', monthly: '毎月' }[info.limit_reset] || 'リセットなし';
  return `<dl class="key-facts"><div><dt>キーの利用上限</dt><dd>${esc(dollars(info.limit))} · ${esc(reset)}</dd></div><div><dt>残りの上限額</dt><dd>${info.limit_remaining === null && info.limit !== null ? '情報がありません' : esc(dollars(info.limit_remaining))}</dd></div><div><dt>有効期限</dt><dd>${account.expiry_known === false ? '情報がありません' : account.expires_at === null ? '期限の指定なし' : esc(new Date(account.expires_at).toLocaleString('ja-JP'))}</dd></div><div><dt>持ち込みキーの利用分</dt><dd>${info.include_byok_in_limit ? '上限に含む' : '上限に含まない'}</dd></div></dl><p class="muted key-caption">${esc(new Date(info.checked_at).toLocaleString('ja-JP'))} 時点。上限と期限はOpenRouterで管理します。</p><a class="key-management" href="${esc(account.management_url)}" target="_blank" rel="noopener noreferrer">OpenRouterで上限・期限を確認 ↗</a>`;
}
function toast(text) {
  clearTimeout(toastTimer); notice.textContent = text; notice.hidden = false;
  toastTimer = setTimeout(() => { notice.hidden = true; }, 5500);
}
async function api(path, { method = 'GET', data } = {}) {
  let response;
  try { response = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store', headers: data !== undefined ? { 'content-type': 'application/json' } : {}, ...(data !== undefined ? { body: JSON.stringify(data) } : {}) }); }
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
  app.innerHTML = `<div class="workspace login-shell"><header class="topbar">${brand}</header><main class="login-main"><div class="login-symbol" aria-hidden="true">${icon('mail')}</div>${requestId ? '<p class="login-context">接続依頼の確認</p>' : ''}<h1>${pending ? 'メールを確認' : 'ログイン'}</h1>
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
  if (!state.accounts.some((account) => account.id === selected)) selected = state.accounts[0]?.id || null;
  render();
}
function details(account) {
  if (!account) return '';
  const provider = providerFor(account);
  return `<div class="connection-heading"><span class="status ${account.status === 'connected' ? '' : 'warning'}">${account.status === 'connected' ? icon('check') : ''}${statusName(account)}</span><h3>${esc(account.name)}</h3><p class="account-email">${esc(accountLabel(account))}</p></div>
    <dl class="connection-facts"><div><dt>用途</dt><dd>${esc(account.purpose || '未設定')}</dd></div><div><dt>許可範囲</dt><dd>${esc(scopeName(account))}<span class="muted block">${esc(account.permission?.restrictions)}</span></dd></div></dl>${keyFacts(account)}
    <div class="connection-actions"><button class="button secondary" data-action="check" data-id="${esc(account.id)}" ${account.status !== 'connected' || !provider.available ? 'disabled' : ''}>接続を確認</button>${provider.can_reconnect ? `<button class="text-button" data-action="reconnect" data-id="${esc(account.id)}" ${account.status === 'disconnecting' || !provider.available ? 'disabled' : ''}>再接続</button>` : ''}<button class="text-button" data-action="edit-account" data-id="${esc(account.id)}">編集</button></div>
    <details class="connection-reference"><summary>接続情報</summary><dl><dt>接続ID</dt><dd><code>${esc(account.id)}</code></dd></dl><a href="${esc(provider.api.documentation_url)}" target="_blank" rel="noopener noreferrer">${esc(provider.name)} APIの公式ドキュメント ↗</a></details>
    <div class="connection-footer"><a href="${esc(account.management_url || provider.management_url)}" target="_blank" rel="noopener noreferrer">${esc(provider.name)}の接続管理 ↗</a><button class="text-button danger" data-action="remove-account" data-id="${esc(account.id)}">${account.status === 'disconnecting' ? '接続解除を再試行' : '接続を解除'}</button></div>`;
}
function serviceSection(provider) {
  const accounts = state.accounts.filter(account => account.provider === provider.id);
  const account = accounts.find(item => item.id === selected) || accounts[0];
  return `<section class="resource-section" aria-labelledby="${esc(provider.id)}-title"><div class="section-heading"><div class="section-label"><span class="service-icon">${icon(provider.icon)}</span><div><h2 id="${esc(provider.id)}-title">${esc(provider.name)}</h2><p>${accounts.length ? `${accounts.length}件の接続` : '未接続'}</p></div></div><button class="button primary" data-action="add-account" data-provider="${esc(provider.id)}" ${provider.available ? '' : 'disabled'}>${icon('plus')} ${esc(provider.name)}を接続</button></div>
    ${accounts.length ? `<div class="connection-workspace"><div class="account-list" role="group" aria-label="${esc(provider.name)}の接続済みアカウント">${accounts.map(item => `<button class="account-item ${item.id === account.id ? 'selected' : ''}" data-action="select-account" data-id="${esc(item.id)}" aria-pressed="${item.id === account.id}"><strong>${esc(item.name)}</strong><span>${esc(accountLabel(item))}</span>${item.status !== 'connected' ? `<small class="warning-text">${statusName(item)}</small>` : ''}</button>`).join('')}</div><div class="connection-pane">${details(account)}</div></div>` : `<div class="empty-state"><span class="empty-icon">${icon(provider.icon)}</span><div><h3>${esc(provider.name)}を接続しましょう</h3><p>${esc(provider.intro)}</p><p>接続後に、利用を許可する実行環境を指定します。</p></div></div>`}
    ${provider.available ? '' : '<p class="availability" role="status">現在、新しい接続を追加できません。</p>'}</section>`;
}
function render() {
  if (!state) return;
  if (requestId) { renderRequest(); return; }
  const byId = new Map(state.accounts.map((item) => [item.id, item]));
  app.innerHTML = `<div class="workspace"><header class="topbar">${brand}<div class="user-menu"><span>${esc(state.user.email)}</span><button class="text-button" data-action="logout">ログアウト</button></div></header><main><header class="page-heading"><h1>接続</h1><p>アカウントと利用許可を管理</p></header>
    ${state.providers.filter(provider => provider.available || state.accounts.some(account => account.provider === provider.id) || !state.providers.some(item => item.available)).map(serviceSection).join('')}
    <section class="resource-section" aria-labelledby="access-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('device')}</span><div><h2 id="access-title">実行環境への利用許可</h2><p>AIを動かす環境ごとに接続先を選択</p></div></div><button class="button secondary" data-action="add-agent" ${state.accounts.some((a) => a.status !== 'disconnecting') ? '' : 'disabled'}>${icon('plus')} 実行環境を追加</button></div>
    ${state.agents.length ? `<div class="agent-list">${state.agents.map((agent) => `<article class="agent-row"><div class="agent-name"><h3>${esc(agent.name)}</h3><p>${agent.last_used_at ? '最終利用 ' + esc(new Date(agent.last_used_at).toLocaleString('ja-JP')) : 'まだ利用されていません'}</p></div><div class="agent-permissions">${agent.accountIds.length ? `<ul>${agent.accountIds.map((id) => `<li><span>${esc(byId.get(id)?.name)}</span><small>${esc(accountLabel(byId.get(id)))}</small></li>`).join('')}</ul>` : '<span class="muted">許可なし</span>'}</div><div class="agent-actions"><button class="text-button" data-action="edit-grants" data-id="${esc(agent.id)}">許可を変更</button><button class="text-button danger" data-action="remove-agent" data-id="${esc(agent.id)}">利用を停止</button></div></article>`).join('')}</div>` : '<div class="access-empty"><p>利用を許可した実行環境はありません。</p></div>'}</section></main></div>`;
}
function renderRequest() {
  const row = accessRequest;
  const shell = (content) => `<div class="workspace"><header class="topbar">${brand}<div class="user-menu"><span>${esc(state.user.email)}</span><button class="text-button" data-action="logout">ログアウト</button></div></header><main class="approval-main">${content}</main></div>`;
  const finished = {
    approved: ['利用を許可しました', `${row?.account?.label || row?.account?.email || ''} を、${row?.requester_name || ''}から利用できるようになりました。元の会話に戻って、接続完了を伝えてください。`],
    denied: ['利用を許可しませんでした', 'この依頼による利用許可は追加されていません。'],
    cancelled: ['依頼は取り消されました', '必要な場合は、AIに新しい接続リンクを依頼してください。'],
    revoked: ['利用許可は停止されています', 'この依頼による接続は現在利用できません。'],
    reconnect_required: ['再接続が必要です', '接続画面からアカウントを再接続してください。'],
  };
  if (!row || row.status !== 'pending') {
    const [title, description] = row ? finished[row.status] || ['依頼を確認できません', '接続リンクを開き直してください。'] : ['依頼を確認できません', requestError];
    app.innerHTML = shell(`<section class="approval-card approval-result"><span class="approval-symbol">${icon(row?.status === 'approved' ? 'check' : 'lock')}</span><h1>${title}</h1><p>${esc(description)}</p><a class="button secondary" href="/">接続を管理</a></section>`);
    return;
  }
  const matching = state.accounts.filter(account => row.eligible_account_ids.includes(account.id));
  const available = matching.filter((account) => account.status === 'connected');
  app.innerHTML = shell(`<section class="approval-card"><header class="approval-heading"><span class="approval-symbol">${icon('lock')}</span><div><p class="approval-eyebrow">${esc(row.service.name)}へのアクセス</p><h1>利用を許可しますか？</h1></div></header>
    <dl class="approval-facts"><div><dt>依頼元</dt><dd>${esc(row.requester_name)}</dd></div>${row.purpose ? `<div><dt>用途</dt><dd>${esc(row.purpose)}</dd></div>` : ''}<div><dt>権限</dt><dd>${esc(row.permission.name)}<span class="muted block">${esc(row.permission.description)}</span></dd></div></dl>
    <div class="confirmation-panel"><span>確認コード</span><strong>${esc(row.confirmation_code)}</strong><p>AIとの会話に表示されたコードと照合してください。心当たりのない依頼は許可しないでください。</p></div>
    <form id="access-request-form"><fieldset><legend>利用を許可するアカウント</legend>${available.length ? available.map((account) => `<div class="approval-account"><label class="choice"><input type="radio" name="accountId" value="${esc(account.id)}" ${available.length === 1 ? 'checked' : ''} required><span><strong>${esc(account.name)}</strong><small>${esc(accountLabel(account))}</small></span></label>${keyFacts(account)}</div>`).join('') : '<p class="muted">この権限で利用できる接続済みのアカウントはありません。</p>'}</fieldset>
    ${matching.filter(account => account.status === 'reconnect_required' && row.service.can_reconnect).map(account => `<button class="button secondary full request-connect" type="button" data-action="request-connect" data-id="${esc(account.id)}" ${row.service.available ? '' : 'disabled'}>${esc(accountLabel(account))} を再接続</button>`).join('')}
    <button class="button secondary full request-connect" type="button" data-action="request-connect" ${row.service.available ? '' : 'disabled'}>${icon('plus')} ${esc(row.service.connect_label)}</button>
    ${row.service.available ? '' : `<p class="form-error" role="status">現在${esc(row.service.name)}を接続できません。</p>`}
    ${row.service.id === 'openrouter' && ['failed', 'scope', 'retry', 'changed'].includes(resultCode) ? '<p class="permission-note">接続できなくても、OpenRouterで作成済みのキーが残る場合があります。<a href="https://openrouter.ai/keys" target="_blank" rel="noopener noreferrer">不要なキーはOpenRouterで削除してください ↗</a></p>' : ''}
    <label class="choice confirmation-choice"><input type="checkbox" name="confirmed" required ${available.length ? '' : 'disabled'}><span>会話の確認コードと一致しています</span></label>
    <p class="permission-note">${esc(row.permission.restrictions)} 利用許可は、後から接続画面で取り消せます。${row.service.can_revoke ? '' : `受け渡し済みのAPIキーの停止は、${esc(row.service.name)}のキー管理画面で行ってください。`}</p><p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit" disabled>利用を許可 ${icon('arrow')}</button><button class="text-button full" type="button" data-action="deny-request">許可しない</button></form>
    <p class="request-expiry">この依頼は ${esc(new Date(row.expires_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }))} まで有効です。</p></section>`);
  const form = document.querySelector('#access-request-form'), submit = form.querySelector('[type="submit"]');
  form.addEventListener('change', () => { submit.disabled = !row.service.available || !form.elements.confirmed.checked || !form.querySelector('[name="accountId"]:checked'); });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submit.disabled || !form.reportValidity()) return;
    submit.disabled = true;
    const errorElement = form.querySelector('[role="alert"]'); errorElement.textContent = '';
    try {
      await api(`/api/access-requests/${requestId}/approve`, { method: 'POST', data: { accountId: new FormData(form).get('accountId'), confirmationCode: row.confirmation_code } });
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
function bindForm(handler) {
  dialog.querySelector('form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget, button = form.querySelector('[type="submit"]');
    button.disabled = true; form.querySelector('.form-error').textContent = '';
    try { await handler(new FormData(form)); }
    catch (error) { if (form.isConnected) { form.querySelector('.form-error').textContent = error.message; button.disabled = false; } }
  });
}
function accountFields(account) {
  return `<label for="account-name">表示名</label><input id="account-name" name="name" placeholder="個人用、サービス登録用など" required maxlength="80" autocomplete="off" value="${esc(account?.name || '')}"><label for="account-purpose">用途 <span class="optional">任意</span></label><input id="account-purpose" name="purpose" placeholder="この接続を使う場面" maxlength="240" value="${esc(account?.purpose || '')}">`;
}
function connect(account, providerId = account?.provider) {
  const provider = state.providers.find(item => item.id === providerId);
  if (!provider?.available) return;
  if (provider.connection_method === 'token') { connectToken(provider); return; }
  const mode = account?.permission?.id || provider.permissions[0].id;
  openDialog(`<h2 id="dialog-title">${esc(provider.name)}を${account ? '再接続' : '接続'}</h2><p>${account ? esc(accountLabel(account)) : esc(provider.intro)}</p><form>${accountFields(account || { name: provider.name })}
    <fieldset><legend>利用する権限</legend>${provider.permissions.map(permission => `<label class="choice"><input type="radio" name="mode" value="${esc(permission.id)}" ${mode === permission.id ? 'checked' : ''}><span><strong>${esc(permission.name)}</strong><small>${esc(permission.description)}</small></span></label>`).join('')}</fieldset>
    <p class="permission-note"><span id="permission-restrictions">${esc(provider.permissions.find(permission => permission.id === mode)?.restrictions)}</span> ${account ? '許可範囲を変更した場合は、実行環境への利用許可を設定し直してください。' : '接続するだけでは、実行環境に利用を許可しません。'}${provider.can_revoke ? '' : `キーの停止は${esc(provider.name)}で行います。`}</p><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(provider.connect_label)} ${icon('arrow')}</button></form>`);
  dialog.querySelector('form').addEventListener('change', event => {
    if (event.target.name === 'mode') dialog.querySelector('#permission-restrictions').textContent = provider.permissions.find(permission => permission.id === event.target.value)?.restrictions || '';
  });
  bindForm(async (form) => {
    const result = await api(`/api/connections/${provider.id}/connect`, { method: 'POST', data: { name: form.get('name'), purpose: form.get('purpose'), mode: form.get('mode'), ...(account ? { accountId: account.id } : {}) } });
    location.assign(result.url);
  });
}
function connectToken(provider, request = null) {
  const setup = provider.token_setup, mode = request?.mode || provider.permissions[0].id;
  const permission = provider.permissions.find(item => item.id === mode);
  openDialog(`<h2 id="dialog-title">${esc(provider.name)}を接続</h2><p>パスワードは${esc(provider.name)}の画面で入力します。ここにはアクセストークンだけを登録してください。</p>
    <div class="token-setup"><h3>1. ${esc(provider.name)}でトークンを作成</h3><p>${esc(setup.instructions)}</p><a class="button secondary full" href="${esc(setup.url)}" target="_blank" rel="noopener noreferrer">${esc(provider.name)}のトークン管理を開く ↗</a></div>
    <form autocomplete="off"><h3 class="token-step">2. トークンを登録</h3><label for="connection-token">${esc(setup.label)}</label><input id="connection-token" name="token" type="password" required minlength="20" maxlength="1024" autocomplete="off" spellcheck="false" autocapitalize="none" aria-describedby="token-storage-note"><p class="permission-note" id="token-storage-note">トークンは暗号化して保存し、許可した実行環境だけに渡します。チャットには貼り付けないでください。</p>
    <details class="token-details"><summary>名前・用途を変更</summary>${accountFields({ name: provider.name, purpose: request?.purpose || '' })}</details>
    <div class="token-permission"><strong>${esc(permission.name)}</strong><p>${esc(permission.description)}</p><p>${esc(permission.restrictions)}</p></div>
    <p class="permission-note">登録だけではAIに利用を許可しません。${request ? '登録後、アカウントと確認コードを確認して利用を許可してください。' : '登録後、利用を許可する実行環境を選んでください。'}トークンの無効化は${esc(provider.name)}で行います。</p><p class="form-error" role="alert"></p><button class="button primary full" type="submit">登録する ${icon('arrow')}</button></form>`);
  bindForm(async form => {
    const token = form.get('token').trim();
    form.delete('token');
    const input = dialog.querySelector('[name="token"]');
    input.value = '';
    const result = await api(`/api/connections/${provider.id}/connect`, { method: 'POST', data: { token, name: form.get('name'), purpose: form.get('purpose'), mode, ...(request ? { accessRequestId: request.id } : {}) } });
    selected = result.account_id;
    closeDialog(); await refresh(); toast(`${provider.name}を接続しました。`);
  });
}
function editAccount(account) {
  openDialog(`<h2 id="dialog-title">接続を編集</h2><p>${esc(accountLabel(account))}</p><form>${accountFields(account)}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">保存</button></form>`);
  bindForm(async (form) => { await api(`/api/accounts/${account.id}`, { method: 'PATCH', data: { name: form.get('name'), purpose: form.get('purpose') } }); closeDialog(); await refresh(); toast('保存しました。'); });
}
function editAgent(agent) {
  openDialog(`<h2 id="dialog-title">${agent ? '利用許可を変更' : '実行環境を追加'}</h2><form>${agent ? `<p>${esc(agent.name)}</p>` : '<label for="agent-name">実行環境の名前</label><input id="agent-name" name="name" placeholder="dev-us など" required maxlength="80" autocomplete="off">'}
    <fieldset><legend>利用を許可するアカウント</legend>${state.accounts.filter((account) => account.status !== 'disconnecting').map((account) => `<div class="approval-account"><label class="choice"><input type="checkbox" name="accountIds" value="${esc(account.id)}" ${agent?.accountIds.includes(account.id) ? 'checked' : ''}><span><strong>${esc(account.name)}</strong><small>${esc(accountLabel(account))}</small><small>${esc(scopeName(account))}</small><small>${esc(account.permission?.description)}</small></span></label>${keyFacts(account)}</div>`).join('')}</fieldset><p class="permission-note">選んだ接続の認証情報を取得できるようになります。信頼できる実行環境だけに許可してください。${revocationNote}</p><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${agent ? '許可を保存' : 'アクセスキーを発行'}</button></form>`);
  bindForm(async (form) => {
    if (agent) {
      await api(`/api/agents/${agent.id}/grants`, { method: 'PUT', data: { accountIds: form.getAll('accountIds') } }); closeDialog(); await refresh(); toast('利用許可を更新しました。');
    } else {
      const result = await api('/api/agents', { method: 'POST', data: { name: form.get('name'), accountIds: form.getAll('accountIds') } });
      await refresh(); if (!state) return;
      openDialog(`<h2 id="dialog-title">${esc(result.agent.name)} の接続</h2><p>キーは一度だけ表示します。実行環境の秘密情報として保管してください。</p><label for="agent-token">アクセスキー</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.agent.token)}</textarea><button class="button secondary full" data-action="copy-token">キーをコピー</button><label for="api-url">接続先</label><input id="api-url" readonly value="${esc(location.origin)}/v1"><p class="permission-note">キーを会話や共有ファイルに貼り付けないでください。</p><button class="button primary full" data-action="close-dialog">閉じる</button>`);
    }
  });
}
function removeAccount(account) {
  const provider = providerFor(account);
  const revoke = provider.can_revoke ? `<p>すべての実行環境への利用許可を取り消します。メールは削除されません。</p><label class="choice revoke-choice"><input type="checkbox" name="revoke" checked><span><strong>Google側の許可も取り消す</strong><small>このアプリに与えた、ほかのGoogleサービスの許可も取り消されます。反映に時間がかかる場合があります。</small></span></label><p class="permission-note">チェックを外すと、Googleの許可は残ります。${revocationNote}</p>` : `<p>Foundationから、この接続とすべての利用許可を削除します。受け渡し済みのAPIキーは、この操作では無効になりません。</p><p><a href="${esc(account.management_url || provider.management_url)}" target="_blank" rel="noopener noreferrer">${esc(provider.name)}でキーを削除する ↗</a></p><label class="choice"><input type="checkbox" name="acknowledged" required><span>キーの無効化は${esc(provider.name)}で行うことを確認しました</span></label>`;
  openDialog(`<h2 id="dialog-title">${esc(provider.name)}の接続を解除しますか？</h2><p>${esc(accountLabel(account))}</p><form>${revoke}<p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">接続を解除</button></div></form>`);
  bindForm(async (form) => {
    try { await api(`/api/accounts/${account.id}`, { method: 'DELETE', data: { revoke: form.has('revoke') } }); }
    catch (error) { await refresh(); throw error; }
    closeDialog(); await refresh(); toast('接続を解除しました。');
  });
}
function removeAgent(agent) {
  const expiry = agent.issued_nonexpiring ? '<p class="permission-note">この実行環境には、有効期限が未指定または不明のAPIキーを渡しています。キーの停止は接続先で行ってください。</p>' : agent.issued_until > Date.now() ? `<p class="permission-note">受け渡し済みの認証情報の最長有効期限：${esc(new Date(agent.issued_until).toLocaleString('ja-JP'))}</p>` : '';
  openDialog(`<h2 id="dialog-title">実行環境の利用を停止しますか？</h2><p>${esc(agent.name)}</p><form><p>この実行環境から認証情報を取得できなくなります。${revocationNote}</p>${expiry}<p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">利用を停止</button></div></form>`);
  bindForm(async () => { await api(`/api/agents/${agent.id}`, { method: 'DELETE' }); closeDialog(); await refresh(); toast('利用を停止しました。'); });
}
document.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-action]'); if (!target || target.disabled) return;
  const { action, id } = target.dataset;
  try {
    if (action === 'close-dialog') closeDialog();
    if (action === 'logout') { target.disabled = true; await api('/api/session', { method: 'DELETE' }); await showLogin(); }
    if (action === 'request-connect') {
      if (accessRequest.service.connection_method === 'token') { connectToken(accessRequest.service, accessRequest); return; }
      target.disabled = true;
      const account = state.accounts.find(item => item.id === id);
      const result = await api(`/api/connections/${accessRequest.provider}/connect`, { method: 'POST', data: { name: account?.name || accessRequest.service.name, purpose: account?.purpose || accessRequest.purpose, mode: accessRequest.mode, accessRequestId: requestId, ...(account ? { accountId: account.id } : {}) } });
      location.assign(result.url);
    }
    if (action === 'deny-request') {
      target.disabled = true;
      await api(`/api/access-requests/${requestId}/deny`, { method: 'POST', data: {} });
      await refresh();
    }
    if (action === 'add-account') connect(null, target.dataset.provider);
    if (action === 'select-account') { selected = id; render(); }
    if (action === 'reconnect') connect(state.accounts.find((a) => a.id === id));
    if (action === 'edit-account') editAccount(state.accounts.find((a) => a.id === id));
    if (action === 'remove-account') removeAccount(state.accounts.find((a) => a.id === id));
    if (action === 'add-agent') editAgent();
    if (action === 'edit-grants') editAgent(state.agents.find((a) => a.id === id));
    if (action === 'remove-agent') removeAgent(state.agents.find((a) => a.id === id));
    if (action === 'check') {
      target.disabled = true;
      try { await api(`/api/accounts/${id}/check`, { method: 'POST', data: {} }); toast(providerFor(state.accounts.find(account => account.id === id)).name + 'に接続できました。'); }
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
const resultProvider = new URL(location.href).searchParams.get('provider') || 'gmail';
if (location.search || location.hash) history.replaceState(null, '', pagePath);
try { await refresh(); } catch (error) { if (error.status !== 401) { await showLogin(); toast(error.message); } }
const connectionMessages = { connected: 'Gmailを接続しました。', denied: 'Gmailの接続をキャンセルしました。', expired: '接続の手続きが切れました。ログインして、もう一度お試しください。', wrong_account: '再接続には同じGoogleアカウントを選んでください。', already_connected: 'このGmailは接続済みです。', scope: '読み取り範囲とGoogleの許可が一致しません。Google側の許可を確認してください。', retry: '継続利用の許可を取得できませんでした。もう一度接続してください。', changed: '接続状態が変わりました。もう一度お試しください。', failed: 'Gmailを接続できませんでした。もう一度お試しください。' };
if (requestId) {
  const requestMessages = { denied: '接続をキャンセルしました。', expired: '接続の手続きが切れました。もう一度お試しください。', wrong_account: '再接続には同じアカウントを選んでください。', already_connected: 'このアカウントは接続済みです。下から選んでください。', scope: '依頼された権限と接続先の許可が一致しません。', retry: '継続利用の許可を取得できませんでした。もう一度接続してください。', changed: '接続状態が変わりました。もう一度お試しください。', failed: '接続できませんでした。もう一度お試しください。' };
  if (requestMessages[resultCode]) toast(requestMessages[resultCode]);
} else if (resultProvider !== 'gmail' && resultCode) {
  const messages = { connected: '接続しました。', denied: '接続をキャンセルしました。', expired: '接続の手続きが切れました。もう一度お試しください。', failed: '接続できませんでした。OpenRouterで作成済みのキーは残る場合があります。不要なキーはOpenRouterで削除してください。' };
  toast(messages[resultCode] || '接続を確認し、もう一度お試しください。');
} else if (connectionMessages[resultCode]) toast(connectionMessages[resultCode]);
