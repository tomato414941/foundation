import { createHash } from 'node:crypto';
import { fail } from '../errors.mjs';
import { validRequestedEnvName } from '../env-name.mjs';

export const APIKEY_SCOPE = 'apikey';
const hash = key => createHash('sha256').update(key).digest('hex');
const slug = name => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'service';

// Generic key custody. The runtime names the service, where the user creates a
// key and which environment variable receives it; the user creates and pastes
// the key. Foundation stores it and hands it over, but cannot verify what the
// key can do, so nothing here claims a scope or an identity.
export class ApiKeyProvider {
  constructor() { this.enabled = true; }
  check() {}
  details(input = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_details', 'サービス、キー作成ページ、環境変数名を指定してください。');
    const service = typeof input.service === 'string' ? input.service.trim() : '';
    if (!service || service.length > 40 || /[\x00-\x1f\x7f<>]/.test(service)) fail(400, 'invalid_service', 'サービス名は1〜40文字で指定してください。');
    let site;
    try { site = new URL(input.site); } catch { fail(400, 'invalid_site', 'キー作成ページはhttpsのURLで指定してください。'); }
    if (site.protocol !== 'https:' || site.username || site.password || site.href.length > 300 || !site.hostname.includes('.')) fail(400, 'invalid_site', 'キー作成ページはhttpsのURLで指定してください。');
    if (!validRequestedEnvName(input.env)) fail(400, 'invalid_env', '環境変数名は英大文字・数字・下線で指定してください。予約された名前は使えません。');
    return { service, site: site.href, env: input.env };
  }
  scopes(details) { return [APIKEY_SCOPE, 'service:' + slug(details.service), 'env:' + details.env]; }
  async importToken({ token, mode, details }) {
    if (mode !== 'key') fail(400, 'invalid_scope', '利用する権限を選び直してください。');
    const valid = this.details(details);
    if (typeof token !== 'string' || !/^[\x21-\x7e]{8,4096}$/.test(token)) fail(400, 'invalid_credential', 'キーを確認してください。空白や改行は含められません。');
    const digest = hash(token);
    return { email: slug(valid.service) + ':' + digest, credentials: { access_token: token, credential_type: 'api_key', expires_at: null, expiry_known: false, scopes: this.scopes(valid), details: { ...valid, key_hash: digest, checked_at: Date.now() } } };
  }
  async token(store, account) {
    if (account.status !== 'connected') fail(409, 'reconnect_required', '新しいキーで接続を追加してください。');
    return store.secrets(account);
  }
  accountInfo(credentials) {
    const detail = credentials.details;
    return { label: detail.service + ' キー …' + detail.key_hash.slice(0, 8), credential_type: 'api_key', expires_at: null, expiry_known: false, verified: false, management_url: detail.site, token_env: detail.env, details: { service: detail.service, site: detail.site, env: detail.env } };
  }
  tokenEnv(credentials) { return credentials.details.env; }
  async revoke() { fail(409, 'manual_revocation_required', 'キーの無効化は接続先のキー管理画面で行ってください。'); }
}
