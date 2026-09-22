import { createHash, createPrivateKey, sign } from 'node:crypto';
import { fail, HttpError } from '../errors.mjs';

export const APPLE_API = 'https://api.appstoreconnect.apple.com/v1';
export const APPLE_DOCS = 'https://developer.apple.com/documentation/appstoreconnectapi';
export const APPLE_KEYS = 'https://appstoreconnect.apple.com/access/integrations/api';
export const APPLE_SCOPE = 'apple:asc-api-key';
export const TEAM_TYPES = ['INDIVIDUAL', 'COMPANY_OR_ORGANIZATION', 'IN_HOUSE'];
const digest = value => createHash('sha256').update(value).digest('hex');
const base64url = value => Buffer.from(value).toString('base64url');
const invalidResponse = () => fail(502, 'service_response', 'Appleからの応答を確認できませんでした。');

// App Store Connect API keys: a .p8 private key plus the identifiers EAS needs.
// Foundation signs one short-lived JWT to confirm the key works, then hands the
// key to the runtime as a file that exists only while the command runs.
export class AppleClient {
  constructor({ fetcher = fetch } = {}) { this.enabled = true; this.fetcher = fetcher; }
  check() { if (!this.enabled) fail(503, 'apple_unavailable', '現在Appleに接続できません。'); }
  fields(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_account', 'Key ID、Issuer ID、Team ID、チーム種別を入力してください。');
    const keyId = String(input.key_id ?? '').trim().toUpperCase(), issuerId = String(input.issuer_id ?? '').trim().toLowerCase();
    const teamId = String(input.team_id ?? '').trim().toUpperCase(), teamType = String(input.team_type ?? '').trim().toUpperCase();
    if (!/^[A-Z0-9]{10}$/.test(keyId)) fail(400, 'invalid_account', 'Key IDは10桁の英数字です。');
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(issuerId)) fail(400, 'invalid_account', 'Issuer IDの形式を確認してください。');
    if (!/^[A-Z0-9]{10}$/.test(teamId)) fail(400, 'invalid_account', 'Team IDは10桁の英数字です。');
    if (!TEAM_TYPES.includes(teamType)) fail(400, 'invalid_account', 'チーム種別は INDIVIDUAL、COMPANY_OR_ORGANIZATION、IN_HOUSE のいずれかです。');
    return { key_id: keyId, issuer_id: issuerId, team_id: teamId, team_type: teamType };
  }
  privateKey(pem) {
    const normalized = typeof pem === 'string' ? pem.replace(/\r\n?/g, '\n').trim() + '\n' : '';
    if (!/^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{40,4000}-----END PRIVATE KEY-----\n$/.test(normalized)) fail(400, 'invalid_credential', 'App Store Connectで作成した .p8 ファイルの中身 (BEGIN PRIVATE KEY から END PRIVATE KEY まで) を貼り付けてください。');
    let key;
    try { key = createPrivateKey(normalized); } catch { fail(400, 'invalid_credential', '.p8 の内容を読み取れませんでした。ファイルを開き直して貼り付けてください。'); }
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') fail(400, 'invalid_credential', 'App Store Connect API キー (P-256) ではありません。');
    return { pem: normalized, key };
  }
  jwt(key, fields, now = Date.now()) {
    const header = base64url(JSON.stringify({ alg: 'ES256', kid: fields.key_id, typ: 'JWT' }));
    const payload = base64url(JSON.stringify({ iss: fields.issuer_id, iat: Math.floor(now / 1000), exp: Math.floor(now / 1000) + 300, aud: 'appstoreconnect-v1' }));
    const signature = sign('sha256', Buffer.from(header + '.' + payload), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    return header + '.' + payload + '.' + signature;
  }
  async inspect(pem, input) {
    const fields = this.fields(input), { pem: normalized, key } = this.privateKey(pem);
    let response;
    try { response = await this.fetcher(APPLE_API + '/apps?limit=1&fields[apps]=bundleId', { headers: { authorization: 'Bearer ' + this.jwt(key, fields) }, redirect: 'error', signal: AbortSignal.timeout(12_000) }); }
    catch { fail(502, 'service_unavailable', 'Appleに接続できませんでした。時間をおいて再度お試しください。'); }
    if (response.status === 401) fail(409, 'reconnect_required', 'Appleがこのキーを受け付けませんでした。Key ID、Issuer ID、.p8 の組み合わせと、キーが失効していないかを確認してください。');
    if (response.status === 403) fail(409, 'reconnect_required', 'このキーにはApp Store Connectを読み取る権限がありません。キーの役割を確認してください。');
    if (response.status === 429) fail(503, 'service_rate_limit', 'Appleへの確認が続いています。時間をおいて再度お試しください。');
    if (!response.ok) fail(502, 'service_unavailable', 'Appleで処理を完了できませんでした。');
    let data;
    try { data = await response.json(); } catch { invalidResponse(); }
    if (!data || typeof data !== 'object' || !Array.isArray(data.data)) invalidResponse();
    return { access_token: normalized, credential_type: 'private_key', expires_at: null, expiry_known: false, scopes: [APPLE_SCOPE],
      details: { ...fields, key_hash: digest(normalized), apps_visible: data.data.length, checked_at: Date.now() } };
  }
  async importToken({ values, permission }) {
    const { key: token, ...fields } = values;
    this.check();
    if (permission !== 'api-key') fail(400, 'invalid_permission', '利用する権限を選び直してください。');
    const credentials = await this.inspect(token, fields);
    return { subject: 'key:' + credentials.details.key_hash, credentials };
  }
  async token(store, account) {
    this.check();
    if (account.status !== 'connected') fail(409, 'reconnect_required', 'Appleでキーを確認し、新しい接続を追加してください。');
    try {
      const previous = store.secrets(account), next = await this.inspect(previous.access_token, previous.details);
      if (account.subject !== 'key:' + next.details.key_hash) invalidResponse();
      store.saveCredentials(account, next);
      return next;
    } catch (error) {
      if (error instanceof HttpError && error.code === 'reconnect_required') store.reconnectRequired(account);
      throw error;
    }
  }
  accountInfo(credentials) {
    const detail = credentials.details;
    return { label: 'Team ' + detail.team_id + ' / Key ' + detail.key_id, credential_type: 'private_key', expires_at: null, expiry_known: false, management_url: APPLE_KEYS,
      apple: { key_id: detail.key_id, issuer_id: detail.issuer_id, team_id: detail.team_id, team_type: detail.team_type }, checked_at: detail.checked_at };
  }
  async revoke() { fail(409, 'manual_revocation_required', 'キーの無効化はApp Store Connectの「統合」画面で行ってください。'); }
}
