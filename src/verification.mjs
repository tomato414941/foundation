import { HttpError } from './errors.mjs';

// Only locally defined facts cross the browser/runtime boundary. Never copy
// service response bodies, submitted fields, tokens or arbitrary error text.
const messages = {
  completed: '接続先の認証処理が完了しました。',
  active: 'トークンが有効であることを確認しました。',
  not_checked: 'この項目は検証していません。',
  permissions_unknown: 'トークンの権限全体や、余分な権限の有無は未確認です。',
  invalid_account: 'アカウントIDの形式を確認できませんでした。',
  invalid_credential: '認証情報の形式または種類が対応していません。',
  reconnect_required: '接続先が認証情報を受け付けないか、有効期間外です。',
  scope_mismatch: '接続先から得られた権限が、この接続方式の対応範囲と一致しません。',
  service_unavailable: '接続先との通信または処理を完了できませんでした。',
  service_rate_limit: '接続先が確認の回数を制限しています。',
  service_response: '接続先の応答を解釈できませんでした。',
  refresh_missing: '継続利用に必要な認証情報が得られませんでした。',
  invalid_login: 'ログイン情報の形式を確認できませんでした。',
  invalid_otp: '認証コードの形式を確認できませんでした。',
  expo_login_failed: '接続先でログインが成立しませんでした。',
  challenge_required: '接続先が追加の認証を求めています。',
  authorization_denied: '接続先での認証は許可されませんでした。',
  verification_unknown: '検証を完了できませんでした。原因は未確認です。',
  already_connected: '同じ認証情報の接続がすでに登録されています。',
  account_limit: '接続の登録件数が上限に達しています。',
};
const labels = { connection: '接続先の認証', input: '入力形式', credential: 'トークンの有効性', permissions: '権限全体' };

export function verification(checks, checkedAt = Date.now()) {
  const items = Array.isArray(checks) && checks.length ? checks : [{}];
  return { checked_at: Number.isFinite(checkedAt) ? checkedAt : Date.now(), checks: items.slice(0, 8).map(value => {
    const item = value && typeof value === 'object' ? value : {};
    const check = Object.hasOwn(labels, item.check) ? item.check : 'connection';
    const code = Object.hasOwn(messages, item.code) ? item.code : 'verification_unknown';
    const status = ['passed', 'failed', 'unknown'].includes(item.status) ? item.status : 'unknown';
    return { check, label: labels[check], status, code, message: messages[code],
      ...(Number.isInteger(item.http_status) && item.http_status >= 100 && item.http_status <= 599 ? { http_status: item.http_status } : {}) };
  }) };
}

export function failedCheck(error, check = 'connection') {
  const code = error instanceof HttpError && Object.hasOwn(messages, error.code) ? error.code : 'verification_unknown';
  return { check, code, status: ['service_unavailable', 'service_response', 'service_rate_limit', 'verification_unknown'].includes(code) ? 'unknown' : 'failed', http_status: error?.upstreamStatus };
}

export function verificationResult(result, error) {
  const supplied = error?.verification || result?.secret?.verification;
  if (supplied?.checks) return verification(supplied.checks);
  if (error) return verification([failedCheck(error)]);
  if (result?.challenge) return verification([{ check: 'connection', status: 'unknown', code: 'challenge_required' }]);
  return verification([{ check: 'connection', status: 'passed', code: 'completed' }]);
}
