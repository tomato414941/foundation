import { fail, HttpError } from './errors.mjs';
import { randomUUID } from 'node:crypto';
import { validEnvName } from '../cli/env-name.mjs';
import { holdingName } from './holdings.mjs';

// A grant is what a holder let Foundation do at a provider, on their behalf. It is held (holdings.mjs) and it is
// one of three, by how Foundation came to have it:
//   given       the holder handed over the credential itself; Foundation keeps the bytes
//   authorized  the holder said yes at the provider; Foundation keeps what renews the credential (OAuth)
//   delegated   the holder made a role Foundation may assume; Foundation keeps only its name
// What a grant produces when used is derived at that moment, never stored: a given grant yields its bytes, the
// others ask their connector. Reading a grant never reaches a provider; delivering one may.
export const METHODS = ['given', 'authorized', 'delegated'];
export const GRANT_MAX = 1024 * 1024;
export const GRANT_COUNT_MAX = 200;
export const GRANT_TOTAL_MAX = 20 * 1024 * 1024;
export const VALUE_MAX = 16384;
export const CONNECTION_LIMIT = 50;
export const TAG_MAX = 40, TAGS_MAX = 16;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const PROVIDER = /^[a-z][a-z0-9-]{0,39}$/;
const COLUMNS = 'h.id,h.holder_id,h.kind,h.name,h.created_at,h.updated_at,g.method,g.provider,g.connector,g.subject,g.status,g.generation,g.size';
const FROM = 'FROM holdings h JOIN grants g ON g.holding_id=h.id';
const invalidResult = () => fail(502, 'service_response', '接続先からの応答を確認できませんでした。');
const now = () => new Date().toISOString();

export function providerName(value) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || !PROVIDER.test(value)) fail(400, 'invalid_provider', '相手先は英小文字・数字・ハイフンで指定してください。');
  return value;
}
// Tags are the holder's words for grouping: a project, an environment, whatever they sort by. Given as an
// array or as comma-separated text; each is trimmed, and the set is what is kept.
export function tagList(value) {
  const many = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : [];
  if (value !== undefined && value !== null && !Array.isArray(value) && typeof value !== 'string') fail(400, 'invalid_tags', 'タグは文字列の配列で指定してください。');
  const tags = [...new Set(many.map(tag => typeof tag === 'string' ? tag.trim().replace(/\s+/g, ' ') : null).filter(tag => tag !== ''))];
  if (tags.length > TAGS_MAX || tags.some(tag => tag === null || tag.length > TAG_MAX || /[\x00-\x1f\x7f,]/.test(tag))) fail(400, 'invalid_tags', `タグは${TAGS_MAX}件までで、1件は${TAG_MAX}文字以内、カンマは使えません。`);
  return tags;
}

// Delivery variable and optional filename are explicitly chosen by the caller.
export function delivery({ env, filename, reserved = new Set() }) {
  if (env === undefined || env === null || env === '') {
    if (filename) fail(400, 'invalid_delivery', 'ファイルとして渡すには、パスを受け取る変数名も指定してください。');
    return { env: null, filename: null };
  }
  if (!validEnvName(env) || reserved.has(env)) fail(400, 'invalid_env', '変数名は英大文字・数字・下線で指定してください。予約された名前は使えません。');
  if (filename === undefined || filename === null || filename === '') return { env, filename: null };
  if (typeof filename !== 'string' || !SEGMENT.test(filename) || filename.startsWith('.')) fail(400, 'invalid_filename', 'ファイル名は英数字で始まり、64文字までです。');
  return { env, filename };
}
// Bytes handed to a command as a variable have to survive being one; bytes handed over as a file do not.
export function deliverable(content, { env, filename }) {
  if (!env || filename) return;
  if (content.length > VALUE_MAX) fail(413, 'value_too_large', '環境変数として渡す値は16384バイトまでです。');
  const text = content.toString('utf8');
  if (Buffer.compare(Buffer.from(text, 'utf8'), content) !== 0 || /[\x00\r\n]/.test(text)) {
    fail(400, 'invalid_value', '環境変数として渡す値は、改行を含まない文字列にしてください。ファイルとして渡すこともできます。');
  }
}

export class Grants {
  constructor(store, holdings, connectors) {
    this.store = store; this.db = store.db; this.vault = store.vault; this.holdings = holdings; this.connectors = connectors; this.pending = new Map();
  }
  binding(row) { return `grant:${row.holder_id}:${row.id}`; }

  // Finding. A name finds a given grant: the holder's word for what they handed over. The others are found by id.
  get(id) { return typeof id === 'string' ? this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE h.id=?`).get(id) : undefined; }
  held(holderId, id) { const row = this.get(id); return row && row.holder_id === holderId ? row : undefined; }
  find(holderId, name) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE h.holder_id=? AND g.method='given' AND h.name=?`).get(holderId, holdingName(name)); }
  at(holderId, name) {
    const row = this.find(holderId, name);
    if (!row) fail(404, 'not_found', '保管されたものが見つかりません。');
    return row;
  }
  // By name or by id: the way a caller refers to one when handing it to a command.
  resolve(holderId, reference) {
    if (typeof reference !== 'string' || !reference) fail(400, 'invalid_names', '渡すものは {name, as} で指定してください。');
    const named = reference.length <= 200 && this.find(holderId, reference);
    const row = named || (/^[0-9a-f-]{36}$/.test(reference) ? this.held(holderId, reference) : undefined);
    if (!row) fail(404, 'not_found', '保管されたものが見つかりません。');
    return row;
  }
  list(holderId, { method, provider, tag, prefix } = {}) {
    const where = ['h.holder_id=?'], params = [holderId];
    if (method) { where.push('g.method=?'); params.push(method); }
    if (provider) { where.push('g.provider=?'); params.push(provider); }
    if (tag) { where.push('EXISTS (SELECT 1 FROM grant_tags t WHERE t.holding_id=h.id AND t.tag=?)'); params.push(tag); }
    if (prefix !== undefined) { where.push('substr(h.name,1,length(?))=? COLLATE BINARY'); params.push(String(prefix), String(prefix)); }
    return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE ${where.join(' AND ')} ORDER BY h.name, h.created_at, h.id`).all(...params);
  }
  tags(row) { return this.db.prepare('SELECT tag FROM grant_tags WHERE holding_id=? ORDER BY tag').all(row.id).map(item => item.tag); }
  // Every tag a holder has used, so a screen can offer them; nothing defines a tag beyond its use.
  tagsUsed(holderId) {
    return this.db.prepare('SELECT t.tag, COUNT(*) AS count FROM grant_tags t JOIN holdings h ON h.id=t.holding_id WHERE h.holder_id=? GROUP BY t.tag ORDER BY t.tag').all(holderId);
  }
  setTags(id, tags) {
    this.db.prepare('DELETE FROM grant_tags WHERE holding_id=?').run(id);
    const insert = this.db.prepare('INSERT INTO grant_tags (holding_id,tag) VALUES (?,?)');
    for (const tag of tags) insert.run(id, tag);
  }
  usage(holderId) {
    return this.db.prepare(`SELECT COUNT(*) AS count, COALESCE(SUM(g.size),0) AS bytes ${FROM} WHERE h.holder_id=? AND g.method='given'`).get(holderId);
  }

  // Given: bytes the holder handed over, sealed to this one holding.
  content(row) {
    if (row.method !== 'given') fail(405, 'method_not_allowed', 'この委任に読める中身はありません。');
    const sealed = this.db.prepare('SELECT state FROM grants WHERE holding_id=?').get(row.id)?.state;
    if (sealed === undefined) fail(404, 'not_found', '保管されたものが見つかりません。');
    return this.vault.openBytes(sealed, this.binding(row));
  }
  // Writing the same name again replaces what is there. Who may read it is said by the lines onto it, not here.
  put(holderId, { name, content, provider, tags }) {
    if (content.length > GRANT_MAX) fail(413, 'too_large', '1件あたり1MBまでです。');
    holdingName(name);
    const chosenProvider = providerName(provider), chosenTags = tags === undefined ? undefined : tagList(tags);
    return this.store.transaction(() => {
      const existing = this.find(holderId, name), { count, bytes } = this.usage(holderId);
      if (!existing && count >= GRANT_COUNT_MAX) fail(409, 'grant_limit', `預けられるのは${GRANT_COUNT_MAX}件までです。使わないものを消してください。`);
      if (bytes - (existing?.size ?? 0) + content.length > GRANT_TOTAL_MAX) fail(409, 'storage_full', '預けられる合計は20MBまでです。使わないものを消してください。');
      const id = existing?.id ?? randomUUID(), sealed = this.vault.sealBytes(content, `grant:${holderId}:${id}`);
      if (existing) {
        this.db.prepare('UPDATE grants SET size=?,state=?,provider=COALESCE(?,provider) WHERE holding_id=?').run(content.length, sealed, chosenProvider, id);
        this.holdings.touch(id);
      } else {
        this.holdings.insert(id, holderId, 'grant', name);
        this.db.prepare("INSERT INTO grants (holding_id,method,provider,size,state) VALUES (?,'given',?,?,?)").run(id, chosenProvider, content.length, sealed);
      }
      if (chosenTags !== undefined) this.setTags(id, chosenTags);
      return this.get(id);
    });
  }
  // Writing by id: the same thing, whoever writes it, keeps its name.
  write(row, content) {
    if (row.method !== 'given') fail(405, 'method_not_allowed', 'この委任の中身は書き換えられません。');
    if (content.length > GRANT_MAX) fail(413, 'too_large', '1件あたり1MBまでです。');
    return this.store.transaction(() => {
      const { bytes } = this.usage(row.holder_id);
      if (bytes - row.size + content.length > GRANT_TOTAL_MAX) fail(409, 'storage_full', '預けられる合計は20MBまでです。使わないものを消してください。');
      this.db.prepare('UPDATE grants SET size=?,state=? WHERE holding_id=?').run(content.length, this.vault.sealBytes(content, this.binding(row)), row.id);
      this.holdings.touch(row.id);
      return this.get(row.id);
    });
  }
  rename(row, name) {
    const wanted = row.method === 'given' ? holdingName(name) : String(name ?? '').slice(0, 80) || row.name;
    if (row.method === 'given' && wanted !== row.name && this.find(row.holder_id, wanted)) fail(409, 'name_taken', 'その名前はすでに使われています。');
    return this.get(this.holdings.rename(row, wanted).id);
  }
  // Provider and tags are the holder's words about a grant, changed without touching what it holds.
  describe(row, { provider, tags }) {
    return this.store.transaction(() => {
      if (provider !== undefined) this.db.prepare('UPDATE grants SET provider=? WHERE holding_id=?').run(providerName(provider), row.id);
      if (tags !== undefined) this.setTags(row.id, tagList(tags));
      if (provider !== undefined || tags !== undefined) this.holdings.touch(row.id);
      return this.get(row.id);
    });
  }
  remove(row) { this.holdings.remove(row); }

  // Authorized and delegated: what a connector left with Foundation, and what it says about the account.
  state(row) { return this.vault.open(this.db.prepare('SELECT state FROM grants WHERE holding_id=?').get(row.id).state, this.binding(row)); }
  context(row) { return row ? { subject: row.subject, privateState: this.state(row).private_state } : undefined; }
  nextState(result) {
    if (!result || typeof result.subject !== 'string' || !result.subject || result.subject.length > 512
      || !Object.hasOwn(result, 'privateState') || result.privateState === undefined
      || !result.facts || typeof result.facts !== 'object' || Array.isArray(result.facts)
      || (result.expiresAt !== null && !(Number.isFinite(result.expiresAt) && result.expiresAt > Date.now()))) invalidResult();
    return { private_state: result.privateState, facts: result.facts, expires_at: result.expiresAt };
  }
  connections(holderId) { return this.db.prepare(`SELECT ${COLUMNS} ${FROM} WHERE h.holder_id=? AND g.method<>'given' ORDER BY h.created_at, h.id`).all(holderId); }
  connection(holderId, id) {
    if (typeof id !== 'string' || !id || id.length > 200 || /[\x00-\x1f\x7f]/.test(id)) fail(400, 'invalid_connection', '接続IDを指定してください。');
    const row = this.held(holderId, id);
    if (!row || row.method === 'given') fail(404, 'not_found', '接続が見つかりません。');
    return row;
  }
  save(holderId, connectorId, result, { previous, tags } = {}) {
    const connector = this.connectors.get(connectorId);
    const state = this.nextState(result);
    if (previous && result.subject !== previous.subject) fail(409, 'account_changed', '接続先のアカウントが変わりました。');
    const label = String(state.facts.label || result.subject).slice(0, 80);
    const method = connector.authorization?.kind === 'role' ? 'delegated' : 'authorized';
    return this.writeConnection(holderId, { connector: connectorId, method, provider: connector.provider ?? connectorId.split('.')[0], subject: result.subject, label, state, tags }, previous);
  }
  // Identity and renewal state belong to the grant, independently of saved values or requests.
  writeConnection(holderId, { connector, method, provider, subject, label, state, tags }, previous) {
    return this.store.transaction(() => {
      const existing = previous ? this.held(holderId, previous.id) : undefined;
      if (previous) {
        if (!existing || existing.generation !== previous.generation) fail(409, 'connection_changed', '状態が変わりました。もう一度お試しください。');
        if (existing.subject !== subject) fail(409, 'account_changed', '登録し直すには同じアカウントを選んでください。');
      }
      if (!previous && this.db.prepare(`SELECT 1 ${FROM} WHERE h.holder_id=? AND g.connector=? AND g.subject=?`).get(holderId, connector, subject)) fail(409, 'already_connected', 'この認証情報は登録済みです。');
      if (!previous && this.connections(holderId).length >= CONNECTION_LIMIT) fail(409, 'connection_limit', `登録できる接続は${CONNECTION_LIMIT}件までです。`);
      const id = existing?.id ?? randomUUID(), sealed = this.vault.seal(state, `grant:${holderId}:${id}`);
      if (existing) {
        this.db.prepare("UPDATE grants SET connector=?,subject=?,state=?,status='usable',generation=generation+1 WHERE holding_id=?").run(connector, subject, sealed, id);
        this.holdings.rename(existing, label);
      } else {
        this.holdings.insert(id, holderId, 'grant', label);
        this.db.prepare("INSERT INTO grants (holding_id,method,provider,connector,subject,status,state) VALUES (?,?,?,?,?,'usable',?)").run(id, method, provider, connector, subject, sealed);
        if (tags !== undefined) this.setTags(id, tagList(tags));
      }
      return this.get(id);
    });
  }
  saveState(row, state) {
    return this.store.transaction(() => {
      this.current(row);
      this.db.prepare('UPDATE grants SET state=? WHERE holding_id=?').run(this.vault.seal(state, this.binding(row)), row.id);
      this.holdings.touch(row.id);
    });
  }
  reconnectRequired(row) {
    this.db.prepare("UPDATE grants SET status='reconnect_required',generation=generation+1 WHERE holding_id=? AND generation=? AND status='usable'").run(row.id, row.generation);
    this.holdings.touch(row.id);
  }
  disconnect(holderId, id) {
    return this.store.transaction(() => {
      const row = this.connection(holderId, id);
      this.db.prepare("UPDATE grants SET status='disconnecting',generation=generation+1 WHERE holding_id=?").run(row.id);
      this.holdings.touch(row.id);
      return row;
    });
  }
  current(row) {
    const current = this.held(row.holder_id, row.id);
    if (!current || current.generation !== row.generation) fail(409, 'connection_changed', '接続状態が変わりました。');
    if (current.status !== 'usable') fail(409, 'reconnect_required', 'この接続は利用できません。接続し直してください。');
    return current;
  }
  outputs(connector, credentials) {
    if (!credentials || typeof credentials !== 'object') invalidResult();
    const values = new Map();
    const add = (key, content, filename) => {
      if (!connector.variables.includes(key) || values.has(key)) invalidResult();
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
  // One credential operation per grant generation, including persistence. This also preserves rotated private
  // state when a caller's authorization or snapshot save fails.
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
    const connector = this.connectors.get(row.connector);
    try {
      const result = await connector.obtain(this.context(row));
      if (result?.subject !== row.subject) fail(409, 'account_changed', '接続先のアカウントが変わりました。');
      const state = this.nextState(result);
      this.saveState(row, state);
      return { state, values: this.outputs(connector, result.credentials) };
    } catch (error) {
      if (error instanceof HttpError && ['reconnect_required', 'account_changed', 'refresh_missing'].includes(error.code)) this.reconnectRequired(row);
      throw error;
    }
  }

  // Deriving: what a grant yields right now. A given one yields its bytes; the others ask their connector.
  // Values are a Map of variable name to {content, filename?}.
  async derive(row) {
    if (row.method === 'given') return { values: new Map([[null, { content: this.content(row) }]]), expires_at: null };
    const result = await this.obtain(row);
    return { values: result.values, expires_at: result.state.expires_at, facts: result.state.facts };
  }
  // Each input and delivery destination is explicit. A given grant needs `as`; a connector's outputs have names
  // of their own, and `as` may rename the one output of a connector that has exactly one.
  async deliver(holderId, asked) {
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
        deliverable(content, { env, filename: null });
        environment[env] = content.toString('utf8');
      }
    };
    const rows = wanted.map(item => ({ item, row: this.resolve(holderId, item.name) }));
    for (const { item, row } of rows) {
      const filename = item.filename === undefined || item.filename === null || item.filename === '' ? null : item.filename;
      if (row.method === 'given') {
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
    return { delivery: { environment, files }, expires_at: expires };
  }
  // A single text, for a function that puts one value into a request. A connector with several outputs must be
  // asked for one by name: "<id>#<VARIABLE>".
  async text(holderId, reference) {
    const [ref, variable] = typeof reference === 'string' ? reference.split('#') : [];
    const row = this.resolve(holderId, ref ?? reference);
    if (row.method === 'given') return this.content(row);
    const derived = await this.derive(row);
    const chosen = variable ? derived.values.get(variable) : derived.values.size === 1 ? [...derived.values.values()][0] : undefined;
    if (!chosen) fail(400, 'invalid_input', 'この接続は複数の値を渡すので、<id>#<変数名> で一つを指定してください。');
    return chosen.content;
  }

  // What is said of a grant. The holder sees everything but the sealed state; whoever acts for them sees what
  // they need to use it.
  view(row, { owner = false } = {}) {
    const base = { ...this.holdings.view(row), method: row.method, provider: row.provider, tags: this.tags(row), status: row.status };
    if (row.method === 'given') return { ...base, size: row.size };
    const connector = this.connectors.get(row.connector), state = this.state(row);
    const shared = { connector: row.connector, service: connector.service, label: state.facts.label || row.name, facts: state.facts,
      access: connector.access, api: connector.service?.api || { base_url: '', documentation_url: '' }, outputs: connector.variables };
    if (!owner) return { ...base, ...shared };
    return { ...base, ...shared, subject: row.subject, generation: row.generation, expires_at: state.expires_at,
      ...(connector.revocationNote ? { revocation_note: connector.revocationNote } : {}), can_reconnect: connector.canReconnect !== false, can_revoke: typeof connector.revoke === 'function', available: connector.available };
  }
}
