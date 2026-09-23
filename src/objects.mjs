import { createHash } from 'node:crypto';
import { fail } from './errors.mjs';
import { presignAws, serverCredentials, signAws } from './aws-sigv4.mjs';

// Object storage for an owner who has none of their own.
//
// Getting a bucket means an account, a card and a console, and that is the wall most owners never get
// over. So Foundation lends one: a space under its own bucket, reached by the same API whether the
// bytes end up there or, later, in a bucket of the owner's own. What an agent calls does not change
// when that moves; only where the space points does.
//
// Nothing about it is kept in the database. The bucket is the record: what is listed is what is there.
export const OBJECT_MAX = 25 * 1024 * 1024;
export const OBJECT_COUNT_MAX = 1000;
// What one owner may keep in the space Foundation lends. Lending means paying for it, so there is a ceiling.
export const OBJECT_TOTAL_MAX = 1024 * 1024 * 1024;
export const LINK_MINUTES = 60, MAX_LINK_MINUTES = 7 * 1440;
const KEY = /^(?!\/)(?!.*\/\/)(?!.*\/$)[A-Za-z0-9][A-Za-z0-9._\/-]{0,199}$/;
const TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*(; ?charset=[A-Za-z0-9_-]+)?$/i;

export function objectKey(value) {
  if (typeof value !== 'string' || !KEY.test(value) || value.split('/').length > 10) {
    fail(400, 'invalid_key', '名前は英数字で始まり、/ で区切って200文字までです。');
  }
  return value;
}

// S3 verifies the payload hash it is given in the header, so it must be the one the signature covers.
const payloadHash = body => createHash('sha256').update(body ?? '').digest('hex');
const tags = (xml, name) => [...xml.matchAll(new RegExp('<' + name + '>([\\s\\S]*?)</' + name + '>', 'g'))].map(match => match[1]);
const tag = (xml, name) => tags(xml, name)[0];
const unescape = value => value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

// One bucket reached with one set of credentials. The prefix is the owner's room inside it.
export class S3Space {
  constructor({ bucket, region, credentials = () => serverCredentials(), fetcher = fetch } = {}) {
    this.enabled = Boolean(bucket && region);
    this.region = region; this.credentials = credentials; this.fetcher = fetcher;
    this.host = bucket + '.s3.' + region + '.amazonaws.com';
  }
  // Keys are URI-encoded per segment: the signature is computed over exactly what is sent.
  path(prefix, key) { return '/' + (prefix + key).split('/').map(encodeURIComponent).join('/'); }
  async call({ method, path, query, body, headers = {} }) {
    const request = signAws({ method, service: 's3', region: this.region, host: this.host, path, query, body: body ?? '',
      credentials: await this.credentials(), headers: { ...headers, 'x-amz-content-sha256': payloadHash(body) } });
    let response;
    try {
      response = await this.fetcher(request.url, { method, headers: request.headers,
        ...(body === undefined ? {} : { body }), redirect: 'error', signal: AbortSignal.timeout(30_000) });
    } catch { fail(502, 'space_unavailable', '置き場に届きませんでした。時間をおいて再度お試しください。'); }
    return response;
  }
  async put(prefix, key, body, contentType) {
    const response = await this.call({ method: 'PUT', path: this.path(prefix, key), body, headers: { 'content-type': contentType } });
    if (!response.ok) fail(502, 'space_unavailable', '保存できませんでした。時間をおいて再度お試しください。');
  }
  async get(prefix, key) {
    const response = await this.call({ method: 'GET', path: this.path(prefix, key) });
    if (response.status === 404) fail(404, 'not_found', 'その名前のものは置かれていません。');
    if (!response.ok) fail(502, 'space_unavailable', '取り出せませんでした。時間をおいて再度お試しください。');
    return { content: Buffer.from(await response.arrayBuffer()), contentType: response.headers.get('content-type') || 'application/octet-stream' };
  }
  async remove(prefix, key) {
    const response = await this.call({ method: 'DELETE', path: this.path(prefix, key) });
    if (!response.ok && response.status !== 404) fail(502, 'space_unavailable', '削除できませんでした。時間をおいて再度お試しください。');
  }
  async list(prefix, under, cursor) {
    const query = { 'list-type': '2', prefix: prefix + under, 'max-keys': '1000', ...(cursor ? { 'continuation-token': cursor } : {}) };
    const response = await this.call({ method: 'GET', path: '/', query });
    if (!response.ok) fail(502, 'space_unavailable', '一覧を取得できませんでした。時間をおいて再度お試しください。');
    const xml = await response.text();
    const objects = tags(xml, 'Contents').map(item => ({
      key: unescape(tag(item, 'Key')).slice(prefix.length), size: Number(tag(item, 'Size')), updated_at: Date.parse(tag(item, 'LastModified')),
    }));
    return { objects, cursor: tag(xml, 'IsTruncated') === 'true' ? tag(xml, 'NextContinuationToken') : null };
  }
  async link(prefix, key, seconds) {
    return presignAws({ service: 's3', region: this.region, host: this.host, path: this.path(prefix, key), expires: seconds, credentials: await this.credentials() });
  }
}

// The owner-facing space. Every call names a key; where the bytes live is the space's business.
export class Objects {
  constructor(space) { this.space = space; }
  get enabled() { return Boolean(this.space?.enabled); }
  check() { if (!this.enabled) fail(503, 'space_unavailable', '置き場は現在使えません。'); }
  room(ownerId) { return 'owners/' + ownerId + '/'; }
  minutes(value = LINK_MINUTES) {
    if (!Number.isInteger(value) || value < 1 || value > MAX_LINK_MINUTES) fail(400, 'invalid_minutes', 'リンクの有効期間は1〜10080分で指定してください。');
    return value;
  }
  async list(ownerId, under = '', cursor) {
    this.check();
    if (typeof under !== 'string' || under.length > 200 || under.includes('..')) fail(400, 'invalid_prefix', '絞り込みの指定を確認してください。');
    if (cursor !== undefined && (typeof cursor !== 'string' || cursor.length > 2048)) fail(400, 'invalid_cursor', '続きの指定を確認してください。');
    return this.space.list(this.room(ownerId), under, cursor);
  }
  // What this owner is using. The bucket is the record, so it is counted rather than remembered.
  async usage(ownerId) {
    this.check();
    const { objects } = await this.space.list(this.room(ownerId), '', undefined);
    return { count: objects.length, bytes: objects.reduce((total, item) => total + item.size, 0),
      count_max: OBJECT_COUNT_MAX, bytes_max: OBJECT_TOTAL_MAX, objects };
  }
  async put(ownerId, key, content, type) {
    this.check();
    if (!Buffer.isBuffer(content) || content.length > OBJECT_MAX) fail(413, 'object_too_large', '1件あたり25MBまでです。');
    if (typeof type !== 'string' || type.length > 100 || !TYPE.test(type)) fail(400, 'invalid_type', '種類 (Content-Type) を確認してください。');
    const { objects } = await this.space.list(this.room(ownerId), '', undefined);
    const existing = objects.find(item => item.key === key);
    if (objects.length >= OBJECT_COUNT_MAX && !existing) fail(409, 'object_limit', '置けるのは1000件までです。');
    const bytes = objects.reduce((total, item) => total + item.size, 0) - (existing?.size ?? 0);
    if (bytes + content.length > OBJECT_TOTAL_MAX) fail(409, 'space_full', '置き場の合計が上限に達しました。使わないものを消してください。');
    await this.space.put(this.room(ownerId), objectKey(key), content, type);
    return { key, size: content.length, content_type: type };
  }
  async get(ownerId, key) { this.check(); return this.space.get(this.room(ownerId), objectKey(key)); }
  async remove(ownerId, key) { this.check(); await this.space.remove(this.room(ownerId), objectKey(key)); }
  async link(ownerId, key, minutes) {
    this.check();
    const seconds = this.minutes(minutes) * 60;
    return { key: objectKey(key), url: await this.space.link(this.room(ownerId), objectKey(key), seconds), url_expires_at: Date.now() + seconds * 1000 };
  }
}
