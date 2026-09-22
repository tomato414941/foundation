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
const accountLabel = account => account?.label || account?.email || '';
const providerFor = account => state.providers.find(provider => provider.id === account.provider);
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
const statusName = (account) => ({ connected: '接続済み', reconnect_required: '再接続が必要', disconnecting: '解除待ち' }[account.status] || '確認が必要');
const scopeName = account => account.permission?.name || '接続先で許可した権限';
const revocationNote = '停止後も、受け渡し済みの認証情報は有効期限まで使える場合があります。期限のないキーは、接続先で削除するまで無効になりません。';
function verificationDetails(report) {
  if (!report?.checks?.length) return '';
  const attention = report.checks.some(item => item.status === 'failed' || item.status === 'unknown' && item.check !== 'permissions');
  const statuses = { passed: '成功', failed: '失敗', unknown: '未確認' };
  return `<details class="verification-result" ${attention ? 'open' : ''}><summary>検証結果</summary><ul>${report.checks.map(item => `<li><span class="verification-label">${esc(item.label)}<small>${esc(statuses[item.status] || '未確認')}</small></span><p>${esc(item.message)}</p></li>`).join('')}</ul></details>`;
}
function keyFacts(account) {
  if (!account.key_info) return account.credential_type === 'api_key' && account.expiry_known === true ? `<dl class="key-facts"><div><dt>有効期限</dt><dd>${account.expires_at === null ? '期限の指定なし' : esc(new Date(account.expires_at).toLocaleString('ja-JP'))}</dd></div></dl>` : '';
  const info = account.key_info, dollars = value => value === null ? '上限なし' : new Intl.NumberFormat('ja-JP', { style: 'currency', currency: 'USD', maximumFractionDigits: 4 }).format(value);
  const reset = { daily: '毎日', weekly: '毎週', monthly: '毎月' }[info.limit_reset] || 'リセットなし';
  return `<dl class="key-facts"><div><dt>キーの利用上限</dt><dd>${esc(dollars(info.limit))} · ${esc(reset)}</dd></div><div><dt>残りの上限額</dt><dd>${info.limit_remaining === null && info.limit !== null ? '情報がありません' : esc(dollars(info.limit_remaining))}</dd></div><div><dt>有効期限</dt><dd>${account.expiry_known === false ? '情報がありません' : account.expires_at === null ? '期限の指定なし' : esc(new Date(account.expires_at).toLocaleString('ja-JP'))}</dd></div><div><dt>持ち込みキーの利用分</dt><dd>${info.include_byok_in_limit ? '上限に含む' : '上限に含まない'}</dd></div></dl><p class="muted key-caption">${esc(new Date(info.checked_at).toLocaleString('ja-JP'))} 時点。上限と期限はOpenRouterで管理します。</p><a class="key-management" href="${esc(account.management_url)}" target="_blank" rel="noopener noreferrer">OpenRouterで上限・期限を確認 ↗</a>`;
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
  return `<div class="connection-heading"><span class="status ${account.status === 'connected' ? '' : 'warning'}">${account.status === 'connected' ? icon('check') : ''}${statusName(account)}</span>${account.verified === false ? '<span class="status neutral">未検証</span>' : ''}<h3>${esc(account.name)}</h3><p class="account-email">${esc(accountLabel(account))}</p></div>
    <dl class="connection-facts"><div><dt>用途</dt><dd>${esc(account.purpose || '未設定')}</dd></div>${Array.isArray(account.organizations) ? `<div><dt>組織</dt><dd>${account.organizations.length ? account.organizations.map(item => esc(item.name)).join('、') : 'なし'}</dd></div>` : ''}${claimRows(provider, account.details)}<div><dt>許可範囲</dt><dd>${esc(scopeName(account))}<span class="muted block">${esc(account.permission?.restrictions)}</span></dd></div></dl>${keyFacts(account)}
    <div class="connection-actions">${account.verified === false ? '' : `<button class="button secondary" data-action="check" data-id="${esc(account.id)}" ${account.status !== 'connected' || !provider.available ? 'disabled' : ''}>接続を確認</button>`}${provider.can_reconnect ? `<button class="text-button" data-action="reconnect" data-id="${esc(account.id)}" ${account.status === 'disconnecting' || !provider.available ? 'disabled' : ''}>再接続</button>` : ''}<button class="text-button" data-action="edit-account" data-id="${esc(account.id)}">編集</button></div>
    ${verificationDetails(account.verification)}<details class="connection-reference"><summary>接続情報</summary><dl><dt>接続ID</dt><dd><code>${esc(account.id)}</code></dd></dl>${provider.api.documentation_url ? `<a href="${esc(provider.api.documentation_url)}" target="_blank" rel="noopener noreferrer">${esc(provider.name)} APIの公式ドキュメント ↗</a>` : ''}</details>
    <div class="connection-footer">${account.credential_type === 'expo_session' ? '' : `<a href="${esc(account.management_url || provider.management_url)}" target="_blank" rel="noopener noreferrer">${esc(account.details?.service || provider.name)}の${account.details ? 'キー管理ページ' : '接続管理'} ↗</a>`}<button class="text-button danger" data-action="remove-account" data-id="${esc(account.id)}">${account.status === 'disconnecting' ? '接続解除を再試行' : '接続を解除'}</button></div>`;
}
function serviceSection(provider) {
  const accounts = state.accounts.filter(account => account.provider === provider.id);
  const account = accounts.find(item => item.id === selected) || accounts[0];
  return `<section class="resource-section" aria-labelledby="${esc(provider.id)}-title"><div class="section-heading"><div class="section-label"><span class="service-icon">${icon(provider.icon)}</span><div><h2 id="${esc(provider.id)}-title">${esc(provider.name)}</h2><p>${accounts.length ? `${accounts.length}件の接続` : '未接続'}</p></div></div><button class="button primary" data-action="add-account" data-provider="${esc(provider.id)}" ${provider.available ? '' : 'disabled'}>${icon('plus')} ${esc(provider.name)}を接続</button></div>
    ${accounts.length ? `<div class="connection-workspace"><div class="account-list" role="group" aria-label="${esc(provider.name)}の接続済みアカウント">${accounts.map(item => `<button class="account-item ${item.id === account.id ? 'selected' : ''}" data-action="select-account" data-id="${esc(item.id)}" aria-pressed="${item.id === account.id}"><strong>${esc(item.name)}</strong><span>${esc(accountLabel(item))}</span>${item.status !== 'connected' ? `<small class="warning-text">${statusName(item)}</small>` : ''}</button>`).join('')}</div><div class="connection-pane">${details(account)}</div></div>` : `<div class="empty-state"><span class="empty-icon">${icon(provider.icon)}</span><div><h3>${esc(provider.name)}を接続しましょう</h3><p>${esc(provider.intro)}</p><p>接続後に、利用を許可するアクセスキーを指定します。</p></div></div>`}
    ${provider.available ? '' : '<p class="availability" role="status">現在、新しい接続を追加できません。</p>'}</section>`;
}
function render() {
  if (!state) return;
  clearPrivateInput();
  if (requestId) { renderRequest(); return; }
  const byId = new Map(state.accounts.map((item) => [item.id, item]));
  app.innerHTML = `<div class="workspace"><header class="topbar">${brand}<div class="user-menu"><span>${esc(state.user.email)}</span><button class="text-button" data-action="logout">ログアウト</button></div></header><main><header class="page-heading"><h1>接続</h1><p>アカウントとAIのアクセスキーを管理</p></header>
    ${state.providers.filter(provider => provider.available || state.accounts.some(account => account.provider === provider.id) || !state.providers.some(item => item.available)).map(serviceSection).join('')}
    <section class="resource-section" aria-labelledby="access-title"><div class="section-heading"><div class="section-label"><span class="service-icon neutral">${icon('device')}</span><div><h2 id="access-title">AIのアクセスキー</h2><p>承認したキーは、登録済みの接続をすべて使えます</p></div></div><button class="button secondary" data-action="add-agent">${icon('plus')} アクセスキーを追加</button></div>
    ${state.agents.length ? `<div class="agent-list">${state.agents.map((agent) => `<article class="agent-row"><div class="agent-name"><h3>${esc(agent.name)}</h3><p>${agent.last_used_at ? '最終利用 ' + esc(new Date(agent.last_used_at).toLocaleString('ja-JP')) : 'まだ利用されていません'}</p></div><div class="agent-permissions"><span class="muted">承認 ${esc(new Date(agent.created_at).toLocaleDateString('ja-JP'))}</span></div><div class="agent-actions"><button class="text-button" data-action="rename-agent" data-id="${esc(agent.id)}">名前を変更</button><button class="text-button danger" data-action="remove-agent" data-id="${esc(agent.id)}">失効</button></div></article>`).join('')}</div>` : '<div class="access-empty"><p>承認したアクセスキーはありません。AIが接続依頼を作ると、承認後にここに登録されます。</p></div>'}</section></main></div>`;
}
const siteLink = value => { try { const url = new URL(value); return `<a href="${esc(url.href)}" target="_blank" rel="noopener noreferrer"><strong>${esc(url.host)}</strong>${esc(url.pathname === '/' ? '' : url.pathname)} ↗</a>`; } catch { return esc(value); } };
function claimRows(service, details) {
  if (!service.request_fields?.length || !details) return '';
  return service.request_fields.map(field => `<div><dt>${esc(field.label)}</dt><dd>${field.type === 'url' ? siteLink(details[field.id]) : field.type === 'code' ? `<code>${esc(details[field.id])}</code>` : esc(details[field.id])}</dd></div>`).join('');
}
// Guidance the requesting AI wrote for its owner. Framed as the AI's words; line breaks kept, nothing else interpreted.
const guidanceBlock = (text) => text ? `<section class="ai-guidance"><h3>依頼元のAIからの案内</h3>${text.split(/\n{2,}/).map(part => `<p>${esc(part).replace(/\n/g, '<br>')}</p>`).join('')}</section>` : '';
const codeComplete = form => /^[0-9a-fA-F]{8}$/.test((form.elements.confirmationCode?.value || '').replace(/[^0-9a-zA-Z]/g, ''));
function codeField(enabled = true) {
  return `<label for="confirmation-code">確認コード</label><input id="confirmation-code" name="confirmationCode" required maxlength="9" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="0000-0000" aria-describedby="confirmation-help" ${enabled ? '' : 'disabled'}><p class="permission-note" id="confirmation-help">AIとの会話に表示されたコードを入力してください。心当たりのない依頼は許可しないでください。</p>`;
}
// The approval URL shows one of two screens. Registering an account is between the owner and the provider, and
// completes the request of a key the owner already approved. Approving a key is the owner's one-time acknowledgement
// that the key is theirs; from then on it uses every account they registered. The AI's guidance is about registering.
let requestScreen = null;
function renderRequest() {
  const row = accessRequest;
  const shell = (content) => `<div class="workspace"><header class="topbar">${brand}<div class="user-menu"><span>${esc(state.user.email)}</span><button class="text-button" data-action="logout">ログアウト</button></div></header><main class="approval-main">${content}</main></div>`;
  const finished = {
    approved: row?.account ? ['登録しました', `${row.account.label || row.account.email} を、${row.requester_name}から利用できます。この画面は閉じて構いません。`] : ['承認しました', `${row?.requester_name || ''}から、登録済みの接続を利用できるようになりました。この画面は閉じて構いません。`],
    denied: ['利用を許可しませんでした', 'この依頼による変更はありません。'],
    cancelled: ['依頼は取り消されました', '必要な場合は、AIに新しい接続リンクを依頼してください。'],
    revoked: ['アクセスキーは失効しています', 'この依頼元のキーは利用できません。'],
    reconnect_required: ['再接続が必要です', '接続画面からアカウントを再接続してください。'],
  };
  if (!row || row.status !== 'pending') {
    const [title, description] = row ? finished[row.status] || ['依頼を確認できません', '接続リンクを開き直してください。'] : ['依頼を確認できません', requestError];
    app.innerHTML = shell(`<section class="approval-card approval-result"><span class="approval-symbol">${icon(row?.status === 'approved' ? 'check' : 'lock')}</span><h1>${title}</h1><p>${esc(description)}</p><a class="button secondary" href="/">接続を管理</a></section>`);
    return;
  }
  const registeredKey = Boolean(row.agent_name);
  const same = state.accounts.filter(account => account.provider === row.provider && account.status !== 'disconnecting');
  const method = row.permission.connection_method || row.service.connection_method;
  const expiry = `<p class="request-expiry">この依頼は ${esc(new Date(row.expires_at).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit' }))} まで有効です。</p>`;
  const deny = '<button class="text-button full" type="button" data-action="deny-request">許可しない</button>';
  const screen = registeredKey || requestScreen === 'register' || !same.length ? 'register' : 'approve';
  if (screen === 'register') {
    const connectLabel = row.permission.connect_label || row.service.connect_label;
    const unavailable = `<p class="form-error" role="status">現在${esc(row.service.name)}を接続できません。</p>`;
    const body = !row.service.available ? unavailable : method === 'password' ? expoLoginMarkup(row) : method === 'token' ? tokenFormMarkup(row.service, row, true)
      : `${same.filter(account => account.status === 'reconnect_required' && row.service.can_reconnect).map(account => `<button class="button secondary full request-connect" type="button" data-action="request-connect" data-id="${esc(account.id)}">${esc(accountLabel(account))} を再接続</button>`).join('')}
        <button class="button primary full request-connect" type="button" data-action="request-connect">${esc(connectLabel)} ${icon('arrow')}</button>
        ${row.service.id === 'openrouter' && ['failed', 'scope', 'retry', 'changed'].includes(resultCode) ? '<p class="permission-note">接続できなくても、OpenRouterで作成済みのキーが残る場合があります。<a href="https://openrouter.ai/keys" target="_blank" rel="noopener noreferrer">不要なキーはOpenRouterで削除してください ↗</a></p>' : ''}`;
    // A key already approved sees what it already has; the request means it wants another.
    const already = registeredKey && same.length ? `<p class="permission-note">${esc(row.service.name)}は登録済み (${same.map(account => esc(accountLabel(account) || account.name)).join('、')}) で、${esc(row.requester_name)}はそれを使えます。この依頼は別のアカウントを求めています。</p>` : '';
    app.innerHTML = shell(`<section class="approval-card"><header class="approval-heading"><span class="approval-symbol">${icon('lock')}</span><div><p class="approval-eyebrow">${esc(row.requester_name)}の依頼</p><h1>${esc(connectLabel)}</h1></div></header>
      ${row.purpose ? `<dl class="approval-facts"><div><dt>用途</dt><dd>${esc(row.purpose)}</dd></div></dl>` : ''}${already}
      ${guidanceBlock(row.guidance)}
      <div class="register-body">${body}</div>
      ${!registeredKey && same.length ? '<button class="text-button full" type="button" data-action="back-to-approve">登録せずに戻る</button>' : registeredKey ? '<button class="text-button full" type="button" data-action="deny-request">登録しない</button>' : deny}${expiry}</section>`);
    if (row.service.available && method === 'password') bindExpoLogin(app.querySelector('.register-body'), row);
    else if (row.service.available && method === 'token') bindTokenForm(app.querySelector('.register-body'), row.service, row);
    return;
  }
  const usable = state.accounts.filter(account => account.status !== 'disconnecting');
  const fresh = same.find(account => account.id === row.account_id);
  const accountCard = account => `<div class="approval-account"><div class="choice"><span><strong>${esc(account.name)}</strong><small>${esc(accountLabel(account))}</small></span></div>${keyFacts(account)}${verificationDetails(account.verification)}</div>`;
  app.innerHTML = shell(`<section class="approval-card"><header class="approval-heading"><span class="approval-symbol">${icon('lock')}</span><div><p class="approval-eyebrow">${esc(row.service.name)}へのアクセス</p><h1>このアクセスキーを承認しますか？</h1></div></header>
    <dl class="approval-facts"><div><dt>依頼元</dt><dd>${esc(row.requester_name)}<span class="muted block">新しいアクセスキーです。承認すると、登録済みの接続をすべて使えるようになります。</span></dd></div>${row.purpose ? `<div><dt>用途</dt><dd>${esc(row.purpose)}</dd></div>` : ''}<div><dt>権限</dt><dd>${esc(row.permission.name)}${row.permission.restrictions ? `<span class="muted block">${esc(row.permission.restrictions)}</span>` : ''}</dd></div>${claimRows(row.service, row.details)}</dl>${row.service.request_fields?.length ? '<p class="permission-note claim-note">サービス名・作成ページ・環境変数名はAIの申告です。作成ページのドメインが正しいか確認してください。</p>' : ''}
    <form id="access-request-form">
    ${fresh ? `<h2 class="approval-section">この依頼で登録した接続</h2>${accountCard(fresh)}` : `<h2 class="approval-section">${esc(row.service.name)}の登録済みの接続</h2>${same.map(accountCard).join('')}`}
    <p class="permission-note">承認後に使える接続: ${usable.map(account => esc(providerFor(account).name) + ' (' + esc(accountLabel(account) || account.name) + ')').join('、')}</p>
    <button class="text-button full" type="button" data-action="open-register" ${row.service.available ? '' : 'disabled'}>別のアカウントを登録する</button>
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
function accountFields(account) {
  return `<label for="account-name">表示名</label><input id="account-name" name="name" placeholder="個人用、サービス登録用など" required maxlength="80" autocomplete="off" value="${esc(account?.name || '')}"><label for="account-purpose">用途 <span class="optional">任意</span></label><input id="account-purpose" name="purpose" placeholder="この接続を使う場面" maxlength="240" value="${esc(account?.purpose || '')}">`;
}
function connect(account, providerId = account?.provider) {
  const provider = state.providers.find(item => item.id === providerId);
  if (!provider?.available) return;
  if (provider.connection_method === 'password') {
    openDialog(`<h2 id="dialog-title">Expoを接続</h2>${expoLoginMarkup(null)}`);
    bindExpoLogin(dialog, null);
    return;
  }
  if (provider.connection_method === 'token') { connectToken(provider); return; }
  const mode = account?.permission?.id || provider.permissions[0].id;
  openDialog(`<h2 id="dialog-title">${esc(provider.name)}を${account ? '再接続' : '接続'}</h2><p>${account ? esc(accountLabel(account)) : esc(provider.intro)}</p><form>${accountFields(account || { name: provider.name })}
    <fieldset><legend>利用する権限</legend>${provider.permissions.map(permission => `<label class="choice"><input type="radio" name="mode" value="${esc(permission.id)}" ${mode === permission.id ? 'checked' : ''}><span><strong>${esc(permission.name)}</strong><small>${esc(permission.description)}</small></span></label>`).join('')}</fieldset>
    <p class="permission-note"><span id="permission-restrictions">${esc(provider.permissions.find(permission => permission.id === mode)?.restrictions)}</span> ${account ? '' : '接続すると、承認済みのアクセスキーから使えるようになります。'}${provider.can_revoke ? '' : `キーの停止は${esc(provider.name)}で行います。`}</p><p class="form-error" role="alert"></p><button class="button primary full" type="submit">${esc(provider.connect_label)} ${icon('arrow')}</button></form>`);
  dialog.querySelector('form').addEventListener('change', event => {
    if (event.target.name === 'mode') dialog.querySelector('#permission-restrictions').textContent = provider.permissions.find(permission => permission.id === event.target.value)?.restrictions || '';
  });
  bindForm(async (form) => {
    const result = await api(`/api/connections/${provider.id}/connect`, { method: 'POST', data: { name: form.get('name'), purpose: form.get('purpose'), mode: form.get('mode'), ...(account ? { accountId: account.id } : {}) } });
    location.assign(result.url);
  });
}
function expoLoginMarkup(request) {
  return `<form class="expo-login-form" autocomplete="off"><div class="expo-password-fields"><label for="expo-username">Expoのメールアドレスまたはユーザー名</label><input id="expo-username" name="username" required maxlength="254" autocomplete="off" autocapitalize="none" spellcheck="false"><label for="expo-password">パスワード</label><input id="expo-password" name="password" type="password" required maxlength="1024" autocomplete="off"></div>
    <div class="expo-otp-fields" hidden><label for="expo-otp">認証コード</label><input id="expo-otp" name="otp" maxlength="64" autocomplete="one-time-code" autocapitalize="none" spellcheck="false" disabled><p class="expo-otp-help permission-note"></p><button type="button" class="text-button expo-reset">ログイン情報を入力し直す</button></div>
    ${request && !request.agent_name ? codeField() : ''}<p class="permission-note auth-privacy">入力内容はFoundationを経由してExpoへ送信します。パスワード・認証コードは保存しません。</p>
    <p class="permission-note auth-permission">${request ? esc(request.permission.description) : 'Expoのログイン状態を保存します。承認済みのアクセスキーから使えるようになります。'}</p><p class="form-error" role="alert"></p>
    <button class="button primary full" type="submit" ${request && !request.service.available ? 'disabled' : ''}>${request && !request.agent_name ? 'ログインして承認' : 'ログインして接続'} ${icon('arrow')}</button></form>`;
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
    button.disabled = Boolean(request && !request.service.available); button.textContent = request && !request.agent_name ? 'ログインして承認' : 'ログインして接続';
  }
  disposePrivateInput = () => { active = false; reset(); };
  form.querySelector('.expo-reset').addEventListener('click', () => { reset(); errorElement.textContent = ''; form.elements.username.focus(); });
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || !active || (request && !request.service.available) || !form.reportValidity()) return;
    const initial = !password;
    if (initial) {
      username = form.elements.username.value.trim(); password = form.elements.password.value; form.elements.password.value = '';
      deadline = setTimeout(() => { if (active) { reset(); errorElement.textContent = '時間が経過しました。ログイン情報を入力し直してください。'; } }, Math.max(1, Math.min(300_000, (request?.expires_at || Infinity) - Date.now())));
    }
    const otp = initial ? undefined : form.elements.otp.value.trim(); form.elements.otp.value = '';
    busy = true; button.disabled = true; button.textContent = '確認中…'; errorElement.textContent = ''; controller = new AbortController();
    const signal = controller.signal;
    try {
      const result = await api('/api/connections/expo/login', { method: 'POST', signal, data: { username, password, ...(otp === undefined ? {} : { otp }), ...(request ? { accessRequestId: request.id, ...(form.elements.confirmationCode ? { confirmationCode: form.elements.confirmationCode.value } : {}) } : {}) } });
      if (!active || signal.aborted) return;
      if (result.challenge) {
        passwordFields.hidden = true; otpFields.hidden = false;
        form.elements.password.disabled = true; form.elements.username.disabled = true; form.elements.otp.disabled = false; form.elements.otp.required = true;
        form.querySelector('.expo-otp-help').textContent = result.challenge.delivery === 'sms' ? 'Expoから届いたSMSのコード、またはバックアップコードを入力してください。' : '認証アプリのコード、またはバックアップコードを入力してください。';
        if (!initial) errorElement.textContent = '認証コードを確認してください。';
        button.textContent = request && !request.agent_name ? '確認して承認' : '確認して接続'; form.elements.otp.focus();
      } else {
        password = ''; username = ''; clearTimeout(deadline);
        selected = result.account_id; closeDialog(); await refresh();
        if (!request) toast('Expoを接続しました。');
      }
    } catch (error) {
      if (!active || signal.aborted) return;
      if (initial || error.code !== 'expo_login_failed') reset();
      else button.textContent = request && !request.agent_name ? '確認して承認' : '確認して接続';
      errorElement.textContent = error.message;
    } finally { if (active && !signal.aborted) { busy = false; button.disabled = false; } }
  });
}
// The token form is one markup for two places: inline on the approval page, or in a dialog from the dashboard.
// On the approval page the AI's guidance is the only procedure, so Foundation keeps to the links, the fields and one line on storage.
function tokenFormMarkup(provider, request = null, lean = false) {
  const setup = provider.token_setup;
  const fields = provider.request_fields || [], claimed = request?.details || null;
  const fieldInputs = fields.map(field => {
    const value = claimed?.[field.id] || '';
    const attrs = { service: 'maxlength="40" placeholder="Anthropic など"', site: 'type="url" maxlength="300" placeholder="https://"', env: 'maxlength="64" placeholder="ANTHROPIC_API_KEY" autocapitalize="characters" spellcheck="false"' }[field.id] || '';
    return `<label for="field-${esc(field.id)}">${esc(field.label)}</label><input id="field-${esc(field.id)}" name="${esc(field.id)}" required ${attrs} autocomplete="off" value="${esc(value)}" ${claimed ? 'readonly' : ''}>`;
  }).join('');
  const siteUrl = claimed?.site || null;
  const serviceName = claimed?.service || (fields.length ? '' : provider.name);
  const setupFields = setup.fields || [];
  const setupInputs = setupFields.map(field => `<label for="setup-${esc(field.id)}">${esc(field.label)}</label>${Array.isArray(field.options) ? `<select id="setup-${esc(field.id)}" name="setup-${esc(field.id)}" required aria-describedby="setup-${esc(field.id)}-help"><option value="">選択してください</option>${field.options.map(([value, text]) => `<option value="${esc(value)}">${esc(text)}</option>`).join('')}</select>` : `<input id="setup-${esc(field.id)}" name="setup-${esc(field.id)}" required maxlength="${esc(field.max_length)}" pattern="${esc(field.pattern)}" autocomplete="off" autocapitalize="none" spellcheck="false" aria-describedby="setup-${esc(field.id)}-help">`}<p class="permission-note" id="setup-${esc(field.id)}-help">${esc(field.help)}</p>`).join('');
  const intro = setupFields.length ? `${esc(provider.name)}で発行した${esc(setup.label)}と、対象の${setupFields.map(field => esc(field.label)).join('・')}を登録します。` : serviceName === provider.name || !serviceName ? esc(provider.intro) : `${esc(serviceName)}で発行した${esc(setup.label)}を登録します。`;
  if (lean) return `<form autocomplete="off" class="token-form lean">${fields.length && claimed ? '<p class="permission-note claim-note">以下はAIの申告です。作成ページのドメインが正しいか確認してください。</p>' : ''}${fieldInputs}${request?.guidance ? '' : `<p class="permission-note">${esc(setup.instructions)}</p>`}<div class="setup-links">${(setup.links || []).map(link => `<a class="button secondary full setup-link" href="${esc(link.href)}" target="_blank" rel="noopener noreferrer">${esc(link.label)} ↗</a>`).join('')}${fields.length ? `<a class="button secondary full setup-link" href="${esc(siteUrl || '#')}" target="_blank" rel="noopener noreferrer" ${siteUrl ? '' : 'style="display:none"'}>${esc(serviceName || 'サービス')}のキー作成ページを開く ↗</a>` : ''}</div>
    ${setupInputs}<label for="connection-token">${esc(setup.label)}</label>${setup.multiline ? '<textarea id="connection-token" name="token" rows="6" required minlength="8" maxlength="8192" autocomplete="off" spellcheck="false" autocapitalize="none" aria-describedby="token-storage-note" placeholder="-----BEGIN PRIVATE KEY-----"></textarea><label class="file-pick"><input type="file" id="connection-token-file" accept=".p8,.pem,.key,.txt,text/plain"><span class="button secondary full">ファイルを選ぶ (.p8)</span></label>' : '<input id="connection-token" name="token" type="password" required minlength="8" maxlength="4096" autocomplete="off" spellcheck="false" autocapitalize="none" aria-describedby="token-storage-note">'}<p class="permission-note" id="token-storage-note">キーは暗号化して保存し、承認したアクセスキーだけに渡します。</p>
    <input type="hidden" name="name" value="${esc(claimed?.service || provider.name)}"><input type="hidden" name="purpose" value="${esc(request?.purpose || '')}">
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">登録する ${icon('arrow')}</button></form>`;
  return `<p class="token-intro">${intro}</p><form autocomplete="off" class="token-form">${fields.length && claimed ? '<p class="permission-note claim-note">以下はAIの申告です。作成ページのドメインが正しいか確認してください。</p>' : ''}${fieldInputs}
    <div class="token-setup"><h3>1. ${esc(setup.step_label || `${serviceName || 'サービス'}でキーを作成`)}</h3><p>${esc(setup.instructions)}</p>${(setup.links || []).map(link => `<a class="button secondary full setup-link" href="${esc(link.href)}" target="_blank" rel="noopener noreferrer">${esc(link.label)} ↗</a>`).join('')}${fields.length ? `<a class="button secondary full setup-link" href="${esc(siteUrl || '#')}" target="_blank" rel="noopener noreferrer" ${siteUrl ? '' : 'style="display:none"'}>${esc(serviceName || 'サービス')}のキー作成ページを開く ↗</a>` : ''}</div>
    <h3 class="token-step">2. キーを登録</h3>${setupInputs}<label for="connection-token">${esc(setup.label)}</label>${setup.multiline ? '<textarea id="connection-token" name="token" rows="6" required minlength="8" maxlength="8192" autocomplete="off" spellcheck="false" autocapitalize="none" aria-describedby="token-storage-note" placeholder="-----BEGIN PRIVATE KEY-----"></textarea><label class="file-pick"><input type="file" id="connection-token-file" accept=".p8,.pem,.key,.txt,text/plain"><span class="button secondary full">ファイルを選ぶ (.p8)</span></label>' : '<input id="connection-token" name="token" type="password" required minlength="8" maxlength="4096" autocomplete="off" spellcheck="false" autocapitalize="none" aria-describedby="token-storage-note">'}<p class="permission-note" id="token-storage-note">キーは暗号化して保存し、許可したアクセスキーの持ち主だけに渡します。チャットには貼り付けないでください。</p>${setup.note ? `<p class="permission-note">${esc(setup.note)}</p>` : ''}
    <input type="hidden" name="name" value="${esc(claimed?.service || provider.name)}"><input type="hidden" name="purpose" value="${esc(request?.purpose || '')}">
    <p class="form-error" role="alert"></p><button class="button primary full" type="submit">登録する ${icon('arrow')}</button></form>`;
}
function bindTokenForm(container, provider, request = null, done = async () => {}) {
  const setup = provider.token_setup, mode = request?.mode || provider.permissions[0].id;
  const fields = provider.request_fields || [], claimed = request?.details || null, setupFields = setup.fields || [];
  container.querySelector('#connection-token-file')?.addEventListener('change', async event => {
    const file = event.target.files?.[0]; if (!file) return;
    const text = file.size <= 8192 ? await file.text() : '';
    container.querySelector('[name="token"]').value = text.trim();
    container.querySelector('.form-error').textContent = text ? '' : 'ファイルが大きすぎます。.p8 ファイルを選んでください。';
    event.target.value = '';
  });
  if (fields.length && !claimed) {
    const siteInput = container.querySelector('[name="site"]'), link = container.querySelector('.token-setup a');
    const sync = () => { if (link) { const value = siteInput.value.trim(), valid = /^https:\/\/[^\s/]+\.[^\s/]+/.test(value); link.href = valid ? value : '#'; link.style.display = valid ? '' : 'none'; } };
    if (link) siteInput.addEventListener('input', sync);
  }
  bindForm(async form => {
    const token = form.get('token').trim();
    form.delete('token');
    container.querySelector('[name="token"]').value = '';
    const details = fields.length && !claimed ? Object.fromEntries(fields.map(field => [field.id, (form.get(field.id) || '').trim()])) : undefined;
    const connectionFields = setupFields.length ? Object.fromEntries(setupFields.map(field => [field.id, (form.get('setup-' + field.id) || '').trim()])) : undefined;
    let result;
    try { result = await api(`/api/connections/${provider.id}/connect`, { method: 'POST', data: { token, name: form.get('name'), purpose: form.get('purpose'), mode, ...(details ? { details } : {}), ...(connectionFields ? { fields: connectionFields } : {}), ...(request ? { accessRequestId: request.id } : {}) } }); }
    catch (error) { if (request && [401, 404].includes(error.status)) await refresh(); throw error; }
    selected = result.account_id; requestScreen = null;
    await done(); await refresh(); toast(`${provider.name}の認証情報を登録しました。`);
  }, container);
}
function connectToken(provider) {
  openDialog(`<h2 id="dialog-title">${esc(provider.name)}を接続</h2>${tokenFormMarkup(provider)}`);
  bindTokenForm(dialog, provider, null, async () => closeDialog());
}
function editAccount(account) {
  openDialog(`<h2 id="dialog-title">接続を編集</h2><p>${esc(accountLabel(account))}</p><form>${accountFields(account)}<p class="form-error" role="alert"></p><button class="button primary full" type="submit">保存</button></form>`);
  bindForm(async (form) => { await api(`/api/accounts/${account.id}`, { method: 'PATCH', data: { name: form.get('name'), purpose: form.get('purpose') } }); closeDialog(); await refresh(); toast('保存しました。'); });
}
function editAgent() {
  openDialog(`<h2 id="dialog-title">アクセスキーを追加</h2><p>AIの実行環境に置くキーを発行します。承認済みのキーと同じく、登録済みの接続をすべて使えます。</p><form><label for="agent-name">アクセスキーの名前</label><input id="agent-name" name="name" placeholder="dev-us など" required maxlength="80" autocomplete="off"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">アクセスキーを発行</button></form>`);
  bindForm(async (form) => {
    const result = await api('/api/agents', { method: 'POST', data: { name: form.get('name') } });
    await refresh(); if (!state) return;
    openDialog(`<h2 id="dialog-title">${esc(result.agent.name)} の接続</h2><p>キーは一度だけ表示します。AIを動かす環境の秘密情報として保管してください。</p><label for="agent-token">アクセスキー</label><textarea id="agent-token" rows="2" readonly spellcheck="false">${esc(result.agent.token)}</textarea><button class="button secondary full" data-action="copy-token">キーをコピー</button><label for="api-url">接続先</label><input id="api-url" readonly value="${esc(location.origin)}/v1"><p class="permission-note">キーを会話や共有ファイルに貼り付けないでください。</p><button class="button primary full" data-action="close-dialog">閉じる</button>`);
  });
}
function removeAccount(account) {
  const provider = providerFor(account);
  const expoSession = account.credential_type === 'expo_session';
  const revoke = expoSession ? '<p>この接続のExpoログインを無効にします。承認済みのアクセスキーからは使えなくなります。Expoのプロジェクトやデータは削除しません。</p>' : provider.can_revoke ? `<p>承認済みのアクセスキーからは使えなくなります。メールは削除されません。</p><label class="choice revoke-choice"><input type="checkbox" name="revoke" checked><span><strong>Google側の許可も取り消す</strong><small>このアプリに与えた、ほかのGoogleサービスの許可も取り消されます。反映に時間がかかる場合があります。</small></span></label><p class="permission-note">チェックを外すと、Googleの許可は残ります。${revocationNote}</p>` : `<p>Foundationから、この接続を削除します。承認済みのアクセスキーからは使えなくなります。受け渡し済みのAPIキーは、この操作では無効になりません。</p><p><a href="${esc(account.management_url || provider.management_url)}" target="_blank" rel="noopener noreferrer">${esc(provider.name)}でキーを削除する ↗</a></p><label class="choice"><input type="checkbox" name="acknowledged" required><span>キーの無効化は${esc(provider.name)}で行うことを確認しました</span></label>`;
  openDialog(`<h2 id="dialog-title">${esc(provider.name)}の接続を解除しますか？</h2><p>${esc(accountLabel(account))}</p><form>${revoke}<p class="form-error" role="alert"></p><div class="dialog-actions"><button type="button" class="button secondary" data-action="close-dialog">キャンセル</button><button type="submit" class="button destructive">接続を解除</button></div></form>`);
  bindForm(async (form) => {
    try { await api(`/api/accounts/${account.id}`, { method: 'DELETE', data: { revoke: expoSession || form.has('revoke') } }); }
    catch (error) { await refresh(); throw error; }
    closeDialog(); await refresh(); toast('接続を解除しました。');
  });
}
function renameAgent(agent) {
  openDialog(`<h2 id="dialog-title">アクセスキーの名前を変更</h2><form><label for="agent-name">名前</label><input id="agent-name" name="name" required maxlength="80" autocomplete="off" value="${esc(agent.name)}"><p class="form-error" role="alert"></p><button class="button primary full" type="submit">保存</button></form>`);
  bindForm(async (form) => { await api(`/api/agents/${agent.id}`, { method: 'PATCH', data: { name: form.get('name') } }); closeDialog(); await refresh(); toast('名前を変更しました。'); });
}
function removeAgent(agent) {
  const expiry = agent.issued_nonexpiring ? '<p class="permission-note">このアクセスキーには、有効期限が未指定または不明の認証情報を渡しています。完全に無効にするには、接続自体の解除も必要です。</p>' : agent.issued_until > Date.now() ? `<p class="permission-note">受け渡し済みの認証情報の最長有効期限：${esc(new Date(agent.issued_until).toLocaleString('ja-JP'))}</p>` : '';
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
      const account = state.accounts.find(item => item.id === id);
      const result = await api(`/api/connections/${accessRequest.provider}/connect`, { method: 'POST', data: { name: account?.name || accessRequest.service.name, purpose: account?.purpose || accessRequest.purpose, mode: accessRequest.mode, accessRequestId: requestId, ...(account ? { accountId: account.id } : {}) } });
      location.assign(result.url);
    }
    if (action === 'deny-request') {
      clearPrivateInput();
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
    if (action === 'remove-agent') removeAgent(state.agents.find((a) => a.id === id));
    if (action === 'rename-agent') renameAgent(state.agents.find((a) => a.id === id));
    if (action === 'check') {
      target.disabled = true;
      try {
        const result = await api(`/api/accounts/${id}/check`, { method: 'POST', data: {} });
        toast(result.verification?.checks.some(item => item.status !== 'passed' && item.check !== 'permissions') ? '検証結果を更新しました。確認できなかった項目があります。' : providerFor(state.accounts.find(account => account.id === id)).name + 'に接続できました。');
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
