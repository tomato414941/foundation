import { fail, HttpError } from './errors.mjs';
import { scopeFacts } from './scopes.mjs';
import { FOUNDATION_APP, takesApps } from './apps.mjs';
import { randomUUID } from 'node:crypto';
import { validEnvName } from '../cli/env-name.mjs';
import { resourceName } from './resources.mjs';

// A credential is what lets something act at a service on the holder's behalf. It is a resource (resources.mjs) and
// it is one of two:
//   a secret      the holder handed over bytes of their own, for no service Foundation knows; Foundation keeps them
//   for a service a service (services.mjs) and the scheme by which Foundation came to hold it:
//                 oauth  the holder said yes at the service; Foundation keeps what renews it
//                 token  the holder made a token at the service and handed it over
//                 role   the holder made a role Foundation may assume; Foundation keeps only its name
// What a credential yields when used is derived at that moment, never stored: a secret yields its bytes, the others
// ask their scheme. Reading a credential never reaches a service; injecting one may.
export const SECRET_MAX = 1024 * 1024;
export const SECRET_COUNT_MAX = 200;
export const SECRET_TOTAL_MAX = 20 * 1024 * 1024;
export const VALUE_MAX = 16384;
export const CONNECTION_LIMIT = 50;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const COLUMNS = 'r.id,r.holder_id,r.kind,r.name,r.created_at,r.updated_at,c.service,c.auth_scheme,c.app_id,c.subject,c.status,c.generation,c.size';
const FROM = 'FROM resources r JOIN credentials c ON c.resource_id=r.id';
export const isSecret = row => row.service === null;
const invalidResult = () => fail(502, 'service_response', '接続先からの応答を確認できませんでした。');
const now = () => new Date().toISOString();

// The variable and optional filename a value goes to are explicitly chosen by the caller.
export function injectionTarget({ env, filename, reserved = new Set() }) {
  if (env === undefined || env === null || env === '') {
    if (filename) fail(400, 'invalid_injection', 'ファイルとして渡すには、パスを受け取る変数名も指定してください。');
    return { env: null, filename: null };
  }
  if (!validEnvName(env) || reserved.has(env)) fail(400, 'invalid_env', '変数名は英大文字・数字・下線で指定してください。予約された名前は使えません。');
  if (filename === undefined || filename === null || filename === '') return { env, filename: null };
  if (typeof filename !== 'string' || !SEGMENT.test(filename) || filename.startsWith('.')) fail(400, 'invalid_filename', 'ファイル名は英数字で始まり、64文字までです。');
  return { env, filename };
}
// Bytes handed to a command as a variable have to survive being one; bytes handed over as a file do not.
export function injectable(content, { env, filename }) {
  if (!env || filename) return;
  if (content.length > VALUE_MAX) fail(413, 'value_too_large', '環境変数として渡す値は16384バイトまでです。');
  const text = content.toString('utf8');
  if (Buffer.compare(Buffer.from(text, 'utf8'), content) !== 0 || /[\x00\r\n]/.test(text)) {
    fail(400, 'invalid_value', '環境変数として渡す値は、改行を含まない文字列にしてください。ファイルとして渡すこともできます。');
  }
}


export class Credentials {
  // services: where a credential works (services.mjs); apps: the OAuth apps credentials are made through (apps.mjs).
  constructor(store, resources, services, apps) {
    Object.assign(this, { store, db: store.db, vault: store.vault, resources, services, apps, pending: new Map() });
  }
  // The scheme as it speaks for this credential: through the app it was made with, for OAuth.
  schemeFor(row) { return row.auth_scheme === 'oauth' ? this.apps.scheme(row.service, row.app_id) : this.services.scheme(row.service, row.auth_scheme); }
  binding(row) { return `credential:${row.holder_id}:${row.id}`; }

  // Finding. A name finds a secret: the holder's word for what they handed over. The others are found by id.
  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.id=?`).get(id) : undefined; }
  held(holderId, id) { const row = this.get(id); return row && row.holder_id === holderId ? row : undefined; }
  find(holderId, name) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.holder_id=? AND c.service IS NULL AND r.name=?`).get(holderId, resourceName(name)); }
  at(holderId, name) {
    const row = this.find(holderId, name);
    if (!row) fail(404, 'not_found', '見つかりません。');
    return row;
  }
  // By name or by id: the way a caller refers to one when handing it to a command.
  resolve(holderId, reference) {
    if (typeof reference !== 'string' || !reference) fail(400, 'invalid_names', '渡すものは {name, as} で指定してください。');
    const named = reference.length <= 200 && this.find(holderId, reference);
    const row = named || (/^[0-9a-f-]{36}$/.test(reference) ? this.held(holderId, reference) : undefined);
    if (!row) fail(404, 'not_found', '見つかりません。');
    return row;
  }
  // service: one service's credentials; secret: only secrets (true) or only those for a service (false).
  list(holderId, { service, secret, prefix } = {}) {
    const where = ['r.holder_id=?'], params = [holderId];
    if (service !== undefined) { where.push('c.service=?'); params.push(service); }
    if (secret !== undefined) where.push(secret ? 'c.service IS NULL' : 'c.service IS NOT NULL');
    if (prefix !== undefined) { where.push('substr(r.name,1,length(?))=? COLLATE BINARY'); params.push(String(prefix), String(prefix)); }
    return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE ${where.join(' AND ')} ORDER BY r.name, r.created_at, r.id`).all(...params);
  }
  usage(holderId) {
    return this.db.prepare(`SELECT COUNT(*) AS count, COALESCE(SUM(c.size),0) AS bytes ${FROM} WHERE r.holder_id=? AND c.service IS NULL`).get(holderId);
  }

  // Secrets: bytes the holder handed over, sealed to this one resource.
  content(row) {
    if (!isSecret(row)) fail(405, 'method_not_allowed', 'この接続に読める中身はありません。');
    const sealed = this.db.prepare('SELECT state FROM credentials WHERE resource_id=?').get(row.id)?.state;
    if (sealed === undefined) fail(404, 'not_found', '見つかりません。');
    return this.vault.openBytes(sealed, this.binding(row));
  }
  // Writing the same name again replaces what is there. Who may read it is said by the lines onto it, not here.
  put(holderId, { name, content }) {
    if (content.length > SECRET_MAX) fail(413, 'too_large', '1件あたり1MBまでです。');
    resourceName(name);
    return this.store.transaction(() => {
      const existing = this.find(holderId, name), { count, bytes } = this.usage(holderId);
      if (!existing && count >= SECRET_COUNT_MAX) fail(409, 'secret_limit', `預けられるのは${SECRET_COUNT_MAX}件までです。使わないものを消してください。`);
      if (bytes - (existing?.size ?? 0) + content.length > SECRET_TOTAL_MAX) fail(409, 'storage_full', '預けられる合計は20MBまでです。使わないものを消してください。');
      const id = existing?.id ?? randomUUID(), sealed = this.vault.sealBytes(content, `credential:${holderId}:${id}`);
      if (existing) {
        this.db.prepare('UPDATE credentials SET size=?,state=? WHERE resource_id=?').run(content.length, sealed, id);
        this.resources.touch(id);
      } else {
        this.resources.insert(id, holderId, 'credential', name);
        this.db.prepare('INSERT INTO credentials (resource_id,size,state) VALUES (?,?,?)').run(id, content.length, sealed);
      }
      return this.get(id);
    });
  }
  // Writing by id: the same thing, whoever writes it, keeps its name.
  write(row, content) {
    if (!isSecret(row)) fail(405, 'method_not_allowed', 'この接続の中身は書き換えられません。');
    if (content.length > SECRET_MAX) fail(413, 'too_large', '1件あたり1MBまでです。');
    return this.store.transaction(() => {
      const { bytes } = this.usage(row.holder_id);
      if (bytes - row.size + content.length > SECRET_TOTAL_MAX) fail(409, 'storage_full', '預けられる合計は20MBまでです。使わないものを消してください。');
      this.db.prepare('UPDATE credentials SET size=?,state=? WHERE resource_id=?').run(content.length, this.vault.sealBytes(content, this.binding(row)), row.id);
      this.resources.touch(row.id);
      return this.get(row.id);
    });
  }
  rename(row, name) {
    const wanted = isSecret(row) ? resourceName(name) : String(name ?? '').slice(0, 80) || row.name;
    if (isSecret(row) && wanted !== row.name && this.find(row.holder_id, wanted)) fail(409, 'name_taken', 'その名前はすでに使われています。');
    return this.get(this.resources.rename(row, wanted).id);
  }
  remove(row) { this.resources.remove(row); }

  // For a service: what its scheme left with Foundation, and what it says about the account.
  state(row) { return this.vault.open(this.db.prepare('SELECT state FROM credentials WHERE resource_id=?').get(row.id).state, this.binding(row)); }
  context(row) { return row ? { subject: row.subject, privateState: this.state(row).private_state } : undefined; }
  // requested: the scopes this credential asked the service for (null for a scheme without scopes).
  nextState(result, { requested } = {}) {
    if (!result || typeof result.subject !== 'string' || !result.subject || result.subject.length > 512
      || !Object.hasOwn(result, 'privateState') || result.privateState === undefined
      || !result.facts || typeof result.facts !== 'object' || Array.isArray(result.facts)
      || (result.expiresAt !== null && !(Number.isFinite(result.expiresAt) && result.expiresAt > Date.now()))) invalidResult();
    return { private_state: result.privateState, facts: result.facts, expires_at: result.expiresAt, ...(requested ? { requested_scopes: requested } : {}) };
  }
  forServices(holderId) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE r.holder_id=? AND c.service IS NOT NULL ORDER BY r.created_at, r.id`).all(holderId); }
  forService(holderId, id) {
    if (typeof id !== 'string' || !id || id.length > 200 || /[\x00-\x1f\x7f]/.test(id)) fail(400, 'invalid_credential', '接続のIDを指定してください。');
    const row = this.held(holderId, id);
    if (!row || isSecret(row)) fail(404, 'not_found', '接続が見つかりません。');
    return row;
  }
  // The credential a new authorization replaces: the same service and scheme, still there, and one that can be.
  reconnection(holderId, serviceRef, schemeId, id) {
    const row = this.forService(holderId, id);
    if (row.service !== serviceRef || row.auth_scheme !== schemeId) fail(400, 'invalid_service', 'サービスか接続の方法が一致しません。');
    if (this.services.scheme(serviceRef, schemeId).canReconnect === false) fail(400, 'new_connection_required', '新しく登録してください。');
    if (row.status === 'disconnecting') fail(409, 'credential_changed', '接続の解除が進行中です。');
    return row;
  }
  // app: the app it was made through - a held app's id, or Foundation's - for a scheme authorized through apps;
  // none otherwise.
  save(holderId, serviceRef, schemeId, result, { previous, scopes, app = FOUNDATION_APP } = {}) {
    const scheme = this.services.scheme(serviceRef, schemeId);
    const state = this.nextState(result, { requested: scopes });
    const label = String(state.facts.label || result.subject).slice(0, 80);
    return this.keep(holderId, { service: serviceRef, scheme: schemeId, app: takesApps(scheme) ? app : null, subject: result.subject, label, state }, previous);
  }
  // Identity and renewal state belong to the credential, independently of requests. previous: the credential this
  // one replaces - a service credential being connected again, or a secret becoming one for a service.
  keep(holderId, { service, scheme, app = null, subject, label, state }, previous) {
    return this.store.transaction(() => {
      const existing = previous ? this.held(holderId, previous.id) : undefined;
      if (previous) {
        if (!existing || existing.generation !== previous.generation) fail(409, 'credential_changed', '状態が変わりました。もう一度お試しください。');
        if (!isSecret(existing)) this.reconnection(holderId, service, scheme, existing.id);
      }
      if (!previous && this.forServices(holderId).length >= CONNECTION_LIMIT) fail(409, 'connection_limit', `登録できる接続は${CONNECTION_LIMIT}件までです。`);
      const id = existing?.id ?? randomUUID(), sealed = this.vault.seal(state, `credential:${holderId}:${id}`);
      if (existing) {
        this.db.prepare("UPDATE credentials SET service=?,auth_scheme=?,app_id=?,subject=?,state=?,size=0,status='usable',generation=generation+1 WHERE resource_id=?").run(service, scheme, app, subject, sealed, id);
        // A secret becoming one for a service keeps the name its holder gave it.
        if (!isSecret(existing)) this.resources.rename(existing, label); else this.resources.touch(id);
      } else {
        this.resources.insert(id, holderId, 'credential', label);
        this.db.prepare("INSERT INTO credentials (resource_id,service,auth_scheme,app_id,subject,status,state) VALUES (?,?,?,?,?,'usable',?)").run(id, service, scheme, app, subject, sealed);
      }
      return this.get(id);
    });
  }
  saveState(row, state, subject = row.subject) {
    return this.store.transaction(() => {
      this.current(row);
      this.db.prepare('UPDATE credentials SET subject=?,state=? WHERE resource_id=?').run(subject, this.vault.seal(state, this.binding(row)), row.id);
      this.resources.touch(row.id);
    });
  }
  reconnectRequired(row) {
    this.db.prepare("UPDATE credentials SET status='reconnect_required',generation=generation+1 WHERE resource_id=? AND generation=? AND status='usable'").run(row.id, row.generation);
    this.resources.touch(row.id);
  }
  disconnect(holderId, id) {
    return this.store.transaction(() => {
      const row = this.forService(holderId, id);
      this.db.prepare("UPDATE credentials SET status='disconnecting',generation=generation+1 WHERE resource_id=?").run(row.id);
      this.resources.touch(row.id);
      return row;
    });
  }
  current(row) {
    const current = this.held(row.holder_id, row.id);
    if (!current || current.generation !== row.generation) fail(409, 'credential_changed', '接続の状態が変わりました。');
    if (current.status !== 'usable') fail(409, 'reconnect_required', 'この接続は利用できません。接続し直してください。');
    return current;
  }
  outputs(scheme, credentials) {
    if (!credentials || typeof credentials !== 'object') invalidResult();
    const values = new Map();
    const add = (key, content, filename) => {
      if (!scheme.variables.includes(key) || values.has(key)) invalidResult();
      if (content.length > VALUE_MAX * 4) fail(502, 'service_response', '受け取った内容が大きすぎます。');
      values.set(key, { content, ...(filename ? { filename } : {}) });
    };
    for (const [key, value] of Object.entries(credentials.environment || {})) {
      if (typeof value !== 'string') invalidResult();
      add(key, Buffer.from(value, 'utf8'));
    }
    for (const file of credentials.files || []) add(file.env, Buffer.from(file.content, 'utf8'), file.filename);
    return values;
  }
  // One credential operation per generation, including persistence. This also preserves rotated private state when
  // a caller's authorization or snapshot save fails.
  async obtain(row) {
    const current = this.current(row), key = current.id + ':' + current.generation;
    if (!this.pending.has(key)) {
      const pending = this.obtainCurrent(current);
      this.pending.set(key, pending);
      pending.finally(() => { if (this.pending.get(key) === pending) this.pending.delete(key); }).catch(() => {});
    }
    const result = await this.pending.get(key);
    this.current(row);
    return result;
  }
  async obtainCurrent(row) {
    try {
      // Read before asking the service: the credential may be removed while the service answers.
      const requested = this.state(row).requested_scopes, active = this.schemeFor(row);
      const result = await active.obtain(this.context(row));
      const state = this.nextState(result, { requested });
      this.saveState(row, state, result.subject);
      return { state, values: this.outputs(active, result.credentials) };
    } catch (error) {
      if (error instanceof HttpError && ['reconnect_required', 'account_changed', 'refresh_missing'].includes(error.code)) this.reconnectRequired(row);
      throw error;
    }
  }

  // Deriving: what a credential yields right now. A secret yields its bytes; the others ask their scheme.
  // Values are a Map of variable name to {content, filename?}.
  async derive(row) {
    if (isSecret(row)) return { values: new Map([[null, { content: this.content(row) }]]), expires_at: null };
    const result = await this.obtain(row);
    return { values: result.values, expires_at: result.state.expires_at, facts: { ...result.state.facts, ...scopeFacts(result.state) } };
  }
  // Each input and destination is explicit. A secret needs `as`; a scheme's outputs have names of their own, and
  // `as` may rename the one output of a scheme that has exactly one.
  async inject(holderId, asked) {
    const wanted = (Array.isArray(asked) ? asked : []).map(item => typeof item === 'string' ? { name: item } : item);
    if (!wanted.length || wanted.length > 16) fail(400, 'invalid_names', '渡すものを1〜16件で指定してください。');
    for (const item of wanted) if (!item || typeof item !== 'object' || typeof item.name !== 'string') fail(400, 'invalid_names', '渡すものは {name, as} で指定してください。');
    const environment = {}, files = [], taken = new Map(), filenames = new Set();
    let expires = null;
    const place = (row, env, filename, content) => {
      if (!validEnvName(env)) fail(400, 'invalid_env', '変数名は英大文字・数字・下線で指定してください。');
      if (taken.has(env)) fail(409, 'name_conflict', `${taken.get(env)} と ${row.name} が同じ変数名 ${env} を使います。どちらかを as で変えてください。`);
      taken.set(env, row.name);
      if (filename) {
        if (typeof filename !== 'string' || !SEGMENT.test(filename) || filename.startsWith('.')) fail(400, 'invalid_filename', 'ファイル名は英数字で始まり、64文字までです。');
        if (filenames.has(filename)) fail(409, 'filename_conflict', 'ファイル名が重複しています。');
        filenames.add(filename);
        files.push({ env, filename, content: content.toString('base64'), encoding: 'base64' });
      } else {
        injectable(content, { env, filename: null });
        environment[env] = content.toString('utf8');
      }
    };
    const rows = wanted.map(item => ({ item, row: this.resolve(holderId, item.name) }));
    for (const { item, row } of rows) {
      const filename = item.filename === undefined || item.filename === null || item.filename === '' ? null : item.filename;
      if (isSecret(row)) {
        if (!item.as) fail(400, 'no_variable', '渡す環境変数名を as で指定してください。');
        place(row, item.as, filename, this.content(row));
        continue;
      }
      const derived = await this.derive(row);
      if (derived.expires_at !== null) expires = expires === null ? derived.expires_at : Math.min(expires, derived.expires_at);
      const outputs = [...derived.values];
      if (item.as && outputs.length !== 1) fail(400, 'invalid_env', 'この接続は複数の値を渡すので、as では名前を変えられません。');
      for (const [variable, value] of outputs) place(row, item.as || variable, filename ?? value.filename ?? null, value.content);
    }
    return { injection: { environment, files }, expires_at: expires };
  }
  // A single text, for a function that puts one value into a request. A scheme with several outputs must be asked
  // for one by name: "<id>#<VARIABLE>".
  async text(holderId, reference) {
    const [ref, variable] = typeof reference === 'string' ? reference.split('#') : [];
    const row = this.resolve(holderId, ref ?? reference);
    if (isSecret(row)) return this.content(row);
    const derived = await this.derive(row);
    const chosen = variable ? derived.values.get(variable) : derived.values.size === 1 ? [...derived.values.values()][0] : undefined;
    if (!chosen) fail(400, 'invalid_input', 'この接続は複数の値を渡すので、<id>#<変数名> で一つを指定してください。');
    return chosen.content;
  }

  // What is said of a credential. The holder sees everything but the sealed state; whoever acts for them sees what
  // they need to use it. Whether disconnecting can also take it back at the service is as the app it was made
  // through can.
  revocable(row) {
    try { return typeof this.schemeFor(row).revoke === 'function'; } catch { return false; }
  }
  view(row, { owner = false } = {}) {
    const base = { ...this.resources.view(row), service: this.services.summary(row.service), auth_scheme: row.auth_scheme, status: row.status };
    if (isSecret(row)) return { ...base, size: row.size };
    const state = this.state(row);
    let scheme = null;
    try { scheme = this.services.scheme(row.service, row.auth_scheme); } catch {}
    const shared = { label: state.facts.label || row.name, facts: { ...state.facts, ...scopeFacts(state) }, ...(scheme && takesApps(scheme) ? { app: this.apps.reference(row.app_id) } : {}),
      variables: scheme?.variables ?? [] };
    if (!owner) return { ...base, ...shared };
    return { ...base, ...shared, subject: row.subject, generation: row.generation, expires_at: state.expires_at,
      can_reconnect: Boolean(scheme) && scheme.canReconnect !== false, can_revoke: this.revocable(row), available: Boolean(scheme?.available) };
  }
}
