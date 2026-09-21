import { createHash, createHmac } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';

export const AWS_DOCS = 'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html';
export const AWS_KEYS = 'https://console.aws.amazon.com/iam/home#/security_credentials';
export const AWS_SCOPE = 'aws:assume-role';
const STS_VERSION = '2011-06-15';
const digest = value => createHash('sha256').update(value).digest('hex');
const hmac = (key, value) => createHmac('sha256', key).update(value).digest();
const invalidResponse = () => fail(502, 'provider_response', 'AWSからの応答を確認できませんでした。');

// AWS Signature Version 4 for the STS query API. Kept here so Foundation needs no AWS SDK.
export function signedRequest({ accessKeyId, secretAccessKey, region, params, now = new Date() }) {
  const host = 'sts.' + region + '.amazonaws.com', body = new URLSearchParams(params).toString();
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, ''), date = amzDate.slice(0, 8);
  const headers = { host, 'content-type': 'application/x-www-form-urlencoded; charset=utf-8', 'x-amz-date': amzDate, accept: 'application/json' };
  const signedHeaders = Object.keys(headers).sort().join(';');
  const canonical = ['POST', '/', '', ...Object.keys(headers).sort().map(name => name + ':' + headers[name]), '', signedHeaders, digest(body)].join('\n');
  const scope = date + '/' + region + '/sts/aws4_request';
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, digest(canonical)].join('\n');
  const signingKey = hmac(hmac(hmac(hmac('AWS4' + secretAccessKey, date), region), 'sts'), 'aws4_request');
  const signature = createHmac('sha256', signingKey).update(toSign).digest('hex');
  return { url: 'https://' + host + '/', method: 'POST', body, headers: { ...headers, authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` } };
}

// Foundation keeps the long-lived IAM user key and hands runtimes only temporary
// credentials for one role. How long they last is between the runtime and AWS:
// a requested duration is passed through untouched, none means AWS's default.
export class AwsProvider {
  constructor({ fetcher = fetch } = {}) { this.enabled = true; this.fetcher = fetcher; }
  check() { if (!this.enabled) fail(503, 'aws_unavailable', '現在AWSに接続できません。'); }
  fields(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_account', 'アクセスキーID、ロールARN、リージョンを入力してください。');
    const accessKeyId = String(input.access_key_id ?? '').trim(), roleArn = String(input.role_arn ?? '').trim(), region = String(input.region ?? '').trim().toLowerCase();
    if (!/^AKIA[A-Z0-9]{16}$/.test(accessKeyId)) fail(400, 'invalid_account', 'アクセスキーIDは AKIA で始まる20文字です。一時認証情報 (ASIA...) は登録できません。');
    if (!/^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@\/-]{1,128}$/.test(roleArn)) fail(400, 'invalid_account', 'ロールARNの形式を確認してください (arn:aws:iam::123456789012:role/名前)。');
    if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(region)) fail(400, 'invalid_account', 'リージョンは ap-northeast-1 のような形式です。');
    return { access_key_id: accessKeyId, role_arn: roleArn, region };
  }
  async call(key, action, params = {}) {
    const request = signedRequest({ accessKeyId: key.access_key_id, secretAccessKey: key.secret, region: key.region, params: { Action: action, Version: STS_VERSION, ...params } });
    let response;
    try { response = await this.fetcher(request.url, { method: request.method, headers: request.headers, body: request.body, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'provider_unavailable', 'AWSに接続できませんでした。時間をおいて再度お試しください。'); }
    let data;
    try { data = await response.json(); } catch { data = null; }
    if (response.status === 403) {
      const code = data?.Error?.Code;
      if (action === 'AssumeRole' && code === 'AccessDenied') fail(409, 'role_denied', 'このキーではロールを引き受けられません。ロールの信頼ポリシーと、ユーザーの sts:AssumeRole 権限を確認してください。');
      fail(409, 'reconnect_required', 'AWSがこのアクセスキーを受け付けませんでした。キーが無効化・削除されていないか確認してください。');
    }
    if (response.status === 400 && data?.Error?.Code) {
      // Validation errors (for example a duration above the role's limit) are AWS's decision; pass the code through.
      const error = new HttpError(409, 'aws_' + String(data.Error.Code).replace(/[^A-Za-z]/g, '').toLowerCase(), 'AWSが要求を拒否しました: ' + String(data.Error.Code).slice(0, 64));
      throw error;
    }
    if (response.status === 429 || data?.Error?.Code === 'Throttling') fail(503, 'provider_rate_limit', 'AWSへの要求が続いています。時間をおいて再度お試しください。');
    if (!response.ok) fail(502, 'provider_unavailable', 'AWSで処理を完了できませんでした。');
    if (!data || typeof data !== 'object') invalidResponse();
    return data;
  }
  async inspect(secret, input) {
    const fields = this.fields(input);
    if (typeof secret !== 'string' || !/^[A-Za-z0-9+/]{40}$/.test(secret)) fail(400, 'invalid_credential', 'シークレットアクセスキーは40文字の英数字です。');
    const key = { ...fields, secret };
    const identity = (await this.call(key, 'GetCallerIdentity')).GetCallerIdentityResponse?.GetCallerIdentityResult;
    if (!identity || !/^\d{12}$/.test(identity.Account || '') || typeof identity.Arn !== 'string' || identity.Arn.length > 2048) invalidResponse();
    if (!fields.role_arn.includes(':' + identity.Account + ':')) fail(409, 'role_denied', 'ロールARNのアカウントIDが、このアクセスキーのアカウントと一致しません。');
    // Prove the trust policy once so a wrong role fails at registration, not at first use. The session is discarded.
    await this.assume(key, 'foundation-check', {});
    return { access_token: secret, credential_type: 'api_key', expires_at: null, expiry_known: false, scopes: [AWS_SCOPE],
      details: { ...fields, key_hash: digest(secret), account_id: identity.Account, user_arn: identity.Arn, checked_at: Date.now() } };
  }
  async assume(key, sessionName, { duration } = {}) {
    const params = { RoleArn: key.role_arn, RoleSessionName: sessionName };
    if (duration !== undefined) {
      if (!Number.isInteger(duration) || duration < 1) fail(400, 'invalid_duration', '期間は秒数の整数で指定してください。');
      params.DurationSeconds = String(duration);
    }
    const result = (await this.call(key, 'AssumeRole', params)).AssumeRoleResponse?.AssumeRoleResult?.Credentials;
    const expiresAt = typeof result?.Expiration === 'number' ? result.Expiration * 1000 : Date.parse(result?.Expiration || '');
    if (!result || !/^ASIA[A-Z0-9]{16}$/.test(result.AccessKeyId || '') || typeof result.SecretAccessKey !== 'string' || typeof result.SessionToken !== 'string' || !Number.isFinite(expiresAt) || /[\r\n\x00]/.test(result.SecretAccessKey + result.SessionToken)) invalidResponse();
    return { access_key_id: result.AccessKeyId, secret_access_key: result.SecretAccessKey, session_token: result.SessionToken, expires_at: expiresAt };
  }
  async importToken({ token, mode, fields }) {
    this.check();
    if (mode !== 'assume-role') fail(400, 'invalid_scope', '利用する権限を選び直してください。');
    const credentials = await this.inspect(token, fields);
    return { email: credentials.details.account_id + ':' + credentials.details.role_arn.split('/').pop() + ':' + credentials.details.key_hash.slice(0, 12), credentials };
  }
  // Issuance never returns the stored key: each call assumes the role afresh.
  async token(store, account, force = false, options = {}) {
    this.check();
    if (account.status !== 'connected') fail(409, 'reconnect_required', 'AWSのアクセスキーを確認し、新しい接続を追加してください。');
    const stored = store.secrets(account), key = { ...stored.details, secret: stored.access_token };
    try {
      const session = await this.assume(key, 'foundation-' + account.id.slice(0, 8), { duration: options.duration });
      return { access_token: session.secret_access_key, credential_type: 'aws_temporary', expires_at: session.expires_at, expiry_known: true, scopes: stored.scopes,
        details: { ...stored.details, session_access_key_id: session.access_key_id, session_token: session.session_token }, verification: stored.verification };
    } catch (error) {
      if (error instanceof HttpError && error.code === 'reconnect_required') store.reconnectRequired(account);
      throw error;
    }
  }
  accountInfo(credentials) {
    const detail = credentials.details;
    return { label: detail.account_id + ' / ' + detail.role_arn.split('/').pop(), credential_type: 'api_key', expires_at: null, expiry_known: false, management_url: AWS_KEYS,
      aws: { account_id: detail.account_id, role_arn: detail.role_arn, region: detail.region, user_arn: detail.user_arn }, checked_at: detail.checked_at };
  }
  async revoke() { fail(409, 'manual_revocation_required', 'アクセスキーの無効化はIAMの画面で行ってください。'); }
}
