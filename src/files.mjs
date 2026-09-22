import { createHash, randomBytes } from 'node:crypto';
import { fail } from './errors.mjs';
import { presignAws, serverCredentials, signAws } from './aws-sigv4.mjs';

export const FILE_MAX = 5 * 1024 * 1024;
export const FILE_TTL = 7 * 86400_000;
export const LINK_MINUTES = 60, MAX_LINK_MINUTES = 7 * 1440;
const FILE_ID = /^[A-Za-z0-9_-]{32}$/;
const TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*(; ?charset=[A-Za-z0-9_-]+)?$/i;
const digest = value => createHash('sha256').update(value).digest('hex');
const view = row => ({ id: row.id, name: row.name, content_type: row.content_type, size: row.size, sha256: row.sha256, created_at: row.created_at, expires_at: row.expires_at });

// The file space: a tool an approved key may use to put a file somewhere its owner, and anyone the key
// hands a link to, can read it. Nothing in Foundation depends on it. A file is written once and never
// changed; a link is a time-limited URL that reads that one file and nothing else.
export class Files {
  constructor(store, backend) { this.db = store.db; this.backend = backend; }
  get enabled() { return Boolean(this.backend?.enabled); }
  check() { if (!this.enabled) fail(503, 'files_unavailable', 'ファイル置き場は現在使えません。'); }
  async put(agent, { name, contentType, body, minutes }) {
    this.check();
    if (typeof name !== 'string' || !name.trim() || name.length > 120 || /[\x00-\x1f\x7f/\\]/.test(name)) fail(400, 'invalid_name', 'ファイル名は1〜120文字で、/ や制御文字を含めずに指定してください。');
    if (typeof contentType !== 'string' || contentType.length > 100 || !TYPE.test(contentType)) fail(400, 'invalid_type', 'ファイルの種類 (Content-Type) を確認してください。');
    if (!Buffer.isBuffer(body) || body.length > FILE_MAX) fail(413, 'file_too_large', 'ファイルは5MBまでです。');
    minutes = this.minutes(minutes);
    if (this.db.prepare('SELECT count(*) n FROM files WHERE owner_id=?').get(agent.owner_id).n >= 200) fail(409, 'file_limit', '置けるファイルは200件までです。');
    const id = randomBytes(24).toString('base64url'), now = Date.now();
    await this.backend.put(id, body, { contentType, name: name.trim() });
    this.db.prepare('INSERT INTO files (id,owner_id,agent_id,name,content_type,size,sha256,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(id, agent.owner_id, agent.id, name.trim(), contentType, body.length, digest(body), now, now + FILE_TTL);
    return this.link(agent, id, minutes);
  }
  list(ownerId) { return this.db.prepare('SELECT * FROM files WHERE owner_id=? AND expires_at>? ORDER BY created_at DESC, id').all(ownerId, Date.now()).map(view); }
  // Any approved key of the owner may link any of the owner's files, as with credentials.
  async link(agent, id, minutes) {
    this.check();
    const row = typeof id === 'string' && FILE_ID.test(id) ? this.db.prepare('SELECT * FROM files WHERE id=? AND owner_id=? AND expires_at>?').get(id, agent.owner_id, Date.now()) : null;
    if (!row) fail(404, 'not_found', 'ファイルが見つかりません。');
    const seconds = Math.min(this.minutes(minutes) * 60, Math.floor((row.expires_at - Date.now()) / 1000));
    return { file: view(row), url: await this.backend.url(row.id, seconds), url_expires_at: Date.now() + seconds * 1000 };
  }
  minutes(value = LINK_MINUTES) {
    if (!Number.isInteger(value) || value < 1 || value > MAX_LINK_MINUTES) fail(400, 'invalid_minutes', 'リンクの有効期間は1〜10080分で指定してください。');
    return value;
  }
}

// The backend on S3. Objects are created only if absent, so a file can never be replaced; links are
// presigned GET URLs, which is also the form CloudFormation accepts as a template URL.
export class S3Files {
  constructor({ bucket, region, credentials = () => serverCredentials(), fetcher = fetch } = {}) {
    this.enabled = Boolean(bucket && region); this.region = region; this.credentials = credentials; this.fetcher = fetcher;
    this.host = bucket + '.s3.' + region + '.amazonaws.com';
  }
  async put(id, body, { contentType, name }) {
    const request = signAws({ method: 'PUT', service: 's3', region: this.region, host: this.host, path: '/files/' + id, body, credentials: await this.credentials(),
      headers: { 'content-type': contentType, 'content-disposition': "inline; filename*=UTF-8''" + encodeURIComponent(name), 'if-none-match': '*', 'x-amz-content-sha256': digest(body) } });
    let response;
    try { response = await this.fetcher(request.url, { method: 'PUT', headers: request.headers, body, redirect: 'error', signal: AbortSignal.timeout(20_000) }); }
    catch { fail(502, 'files_unavailable', 'ファイルを保存できませんでした。時間をおいて再度お試しください。'); }
    if (!response.ok) fail(502, 'files_unavailable', 'ファイルを保存できませんでした。時間をおいて再度お試しください。');
  }
  async url(id, seconds) {
    return presignAws({ service: 's3', region: this.region, host: this.host, path: '/files/' + id, expires: seconds, credentials: await this.credentials() });
  }
}
