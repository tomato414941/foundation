import { createHash } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';
import { verification, failedCheck } from '../verification.mjs';

export const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';
export const CLOUDFLARE_DOCS = 'https://developers.cloudflare.com/api/resources/r2/subresources/buckets/methods/list/';
export const CLOUDFLARE_TOKENS = 'https://dash.cloudflare.com/profile/api-tokens';
export const CLOUDFLARE_SCOPE = 'cloudflare:r2-api-token';
const digest = token => createHash('sha256').update(token).digest('hex');
const invalidResponse = () => fail(502, 'service_response', 'Cloudflareからの応答を確認できませんでした。');
const accountId = value => {
  if (typeof value !== 'string' || !/^[a-fA-F0-9]{32}$/.test(value.trim())) fail(400, 'invalid_account', 'CloudflareのアカウントIDを32桁の英数字で入力してください。');
  return value.trim().toLowerCase();
};
const timestamp = value => {
  if (value == null) return null;
  const time = typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(time)) invalidResponse();
  return time;
};

// User API tokens, not Global API keys or R2 S3 access keys. Checking one
// bucket-list page proves access, not the absence of any other token grants.
// Bucket names/content are never kept in Foundation.
export class CloudflareClient {
  constructor({ fetcher = fetch } = {}) { this.enabled = true; this.fetcher = fetcher; }
  check() { if (!this.enabled) fail(503, 'cloudflare_unavailable', '現在Cloudflareに接続できません。'); }
  async request(path, token, verify = false) {
    let response;
    try { response = await this.fetcher(CLOUDFLARE_API + path, { method: 'GET', headers: { authorization: 'Bearer ' + token }, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'Cloudflareに接続できませんでした。時間をおいて再度お試しください。'); }
    if (response.status === 429) fail(503, 'service_rate_limit', 'Cloudflareへの確認が続いています。時間をおいて再度お試しください。');
    const denied = () => { const error = new HttpError(409, verify ? 'reconnect_required' : 'r2_unavailable', verify
      ? 'トークンが無効か、失効しています。Cloudflareのプロフィールから作成したAPIトークンを確認してください。'
      : 'R2の一覧を確認できません。アカウントID、対象アカウントの Workers R2 Storage: Read 権限、R2の利用設定を確認してください。'); error.upstreamStatus = response.status; throw error; };
    if ([400, 401, 403, 404].includes(response.status)) denied();
    if (!response.ok) fail(502, 'service_unavailable', 'Cloudflareで処理を完了できませんでした。');
    let data;
    try { data = await response.json(); } catch { invalidResponse(); }
    if (data?.success === false) denied();
    if (data?.success !== true || !data.result || typeof data.result !== 'object' || Array.isArray(data.result)) invalidResponse();
    return data.result;
  }
  async inspect(token, id) {
    id = accountId(id);
    if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{20,256}$/.test(token) || /^cf(?:k|at)_/.test(token)) fail(400, 'invalid_credential', 'Cloudflareのプロフィールから作成したAPIトークンを入力してください。Global API KeyやR2のSecret Access Keyは使えません。');
    const verified = await this.request('/user/tokens/verify', token, true);
    if (!/^[a-f0-9]{32}$/.test(verified.id || '') || !['active', 'disabled', 'expired'].includes(verified.status)) invalidResponse();
    const expiresAt = timestamp(verified.expires_on), notBefore = timestamp(verified.not_before);
    if (verified.status !== 'active' || expiresAt !== null && expiresAt <= Date.now() || notBefore !== null && notBefore > Date.now()) fail(409, 'reconnect_required', 'このAPIトークンは現在使えません。Cloudflareで状態と有効期限を確認してください。');
    // Only a permission probe; never download objects, enumerate all buckets,
    // or grant token-management/account-management permissions to inspect it.
    let r2;
    try {
      const result = await this.request('/accounts/' + id + '/r2/buckets?per_page=1', token);
      if (!Array.isArray(result.buckets) || result.buckets.some(bucket => !bucket || typeof bucket.name !== 'string' || !bucket.name || bucket.name.length > 64)) invalidResponse();
      r2 = { check: 'r2_bucket_list', status: 'passed', code: 'available' };
    } catch (error) {
      // Capability observations are not Foundation access-control decisions.
      r2 = failedCheck(error, 'r2_bucket_list');
    }
    return { access_token: token, credential_type: 'api_key', expires_at: expiresAt, expiry_known: true, scopes: [CLOUDFLARE_SCOPE],
      verification: verification([{ check: 'credential', status: 'passed', code: 'active' }, r2, { check: 'permissions', status: 'unknown', code: 'permissions_unknown' }]),
      details: { token_hash: digest(token), token_id: verified.id, account_id: id, checked_at: Date.now() } };
  }
  async importToken({ values }) {
    const { token, account_id: accountId } = values;
    this.check();
    let secret;
    try { secret = await this.inspect(token, accountId); }
    catch (error) {
      error.verification = verification([failedCheck(error, error.code === 'invalid_account' ? 'input' : 'credential'), { check: 'r2_bucket_list', status: 'unknown', code: 'not_checked' }, { check: 'permissions', status: 'unknown', code: 'permissions_unknown' }]);
      throw error;
    }
    // One token must not appear to be several separately scoped connections.
    return { subject: 'token:' + secret.details.token_hash, secret };
  }
  async token(store, credential) {
    this.check();
    if (credential.status !== 'connected') fail(409, 'reconnect_required', 'Cloudflareでトークンを確認し、新しく登録し直してください。');
    try {
      const previous = store.secret(credential), next = await this.inspect(previous.access_token, previous.details.account_id);
      if (credential.subject !== 'token:' + next.details.token_hash || previous.details.token_id !== next.details.token_id || previous.details.account_id !== next.details.account_id) invalidResponse();
      store.saveSecret(credential, next);
      return next;
    } catch (error) {
      if (error instanceof HttpError && error.code === 'reconnect_required') store.reconnectRequired(credential);
      throw error;
    }
  }
  facts(secret) {
    const detail = secret.details;
    return { label: 'Cloudflare ' + detail.account_id, credential_type: 'api_key', expires_at: secret.expires_at, expiry_known: true,
      management_url: CLOUDFLARE_TOKENS, cloudflare_account_id: detail.account_id, checked_at: detail.checked_at };
  }
  async revoke() { fail(409, 'manual_revocation_required', 'トークンの無効化はCloudflareのAPIトークン管理画面で行ってください。'); }
}
