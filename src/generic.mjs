import { createHash } from 'node:crypto';
import { fail } from './errors.mjs';
import { validRequestedEnvName } from './env-name.mjs';
import { defineSchema } from './schema.mjs';
import { verification } from './verification.mjs';

export const GENERIC_SCOPE = 'generic';
const hash = value => createHash('sha256').update(value).digest('hex');
const slug = name => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'service';
const plain = (value, max) => typeof value === 'string' && value.trim() !== '' && value.trim().length <= max && !/[\x00-\x1f\x7f<>]/.test(value);

// The client behind the generic adapter. The runtime declares the service, the page
// where the owner makes the key, and the fields; each field id is the environment
// variable the runtime receives. Foundation stores and hands over the values, but
// cannot tell what they can do, so nothing here claims a scope or an identity.
export class GenericClient {
  constructor() { this.enabled = true; }
  check() {}
  details(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_details', 'サービス、キー作成ページ、受け取る値を指定してください。');
    if (!plain(input.service, 40)) fail(400, 'invalid_service', 'サービス名は1〜40文字で指定してください。');
    let site;
    try { site = new URL(input.site); } catch { fail(400, 'invalid_site', 'キー作成ページはhttpsのURLで指定してください。'); }
    if (site.protocol !== 'https:' || site.username || site.password || site.href.length > 300 || !site.hostname.includes('.')) fail(400, 'invalid_site', 'キー作成ページはhttpsのURLで指定してください。');
    if (!Array.isArray(input.fields) || input.fields.length < 1 || input.fields.length > 8) fail(400, 'invalid_fields', '受け取る値を1〜8個指定してください。');
    const fields = input.fields.map(field => {
      if (!field || typeof field !== 'object' || !validRequestedEnvName(field.id)) fail(400, 'invalid_env', '環境変数名は英大文字・数字・下線で指定してください。予約された名前は使えません。');
      const label = field.label === undefined ? field.id : field.label;
      if (!plain(label, 60)) fail(400, 'invalid_fields', '表示名は60文字以内で指定してください。');
      if (field.kind !== undefined && field.kind !== 'line' && field.kind !== 'multiline') fail(400, 'invalid_fields', '種類は line か multiline です。');
      return { id: field.id, label: label.trim(), kind: field.kind || 'line' };
    });
    if (new Set(fields.map(field => field.id)).size !== fields.length) fail(400, 'invalid_fields', '環境変数名が重複しています。');
    return { service: input.service.trim(), site: site.href, fields };
  }
  schema(details) { return defineSchema(details.fields.map(field => ({ ...field, secret: true }))); }
  fieldsOf(details) { return details.fields.map(field => field.id); }
  serviceScope(details) { return 'service:' + slug(details.service); }
  async importToken({ values, permission, details }) {
    if (permission !== 'key') fail(400, 'invalid_permission', '利用する権限を選び直してください。');
    const declared = this.details(details), ids = this.fieldsOf(declared);
    const digest = hash(ids.map(id => id + '=' + values[id]).join('\n'));
    return { subject: slug(declared.service) + ':' + digest, credentials: { access_token: values[ids[0]], values, credential_type: 'api_key', expires_at: null, expiry_known: false,
      scopes: [GENERIC_SCOPE, this.serviceScope(declared), ...ids.map(id => 'field:' + id)],
      verification: verification([{ check: 'credential', status: 'unknown', code: 'not_checked' }, { check: 'permissions', status: 'unknown', code: 'permissions_unknown' }]),
      details: { service: declared.service, site: declared.site, fields: ids, key_hash: digest, checked_at: Date.now() } } };
  }
  async token(store, account) {
    if (account.status !== 'connected') fail(409, 'reconnect_required', '新しいキーで登録し直してください。');
    return store.secrets(account);
  }
  accountInfo(credentials) {
    const detail = credentials.details;
    return { label: detail.service + ' キー …' + detail.key_hash.slice(0, 8), credential_type: 'api_key', expires_at: null, expiry_known: false, verified: false, management_url: detail.site, details: { service: detail.service, site: detail.site, fields: detail.fields } };
  }
  async revoke() { fail(409, 'manual_revocation_required', 'キーの無効化は接続先のキー管理画面で行ってください。'); }
}
