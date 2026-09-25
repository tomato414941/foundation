import { fail } from './errors.mjs';
import { randomUUID } from 'node:crypto';
import { validEnvName } from '../cli/env-name.mjs';

// Bytes stored under an opaque name. Read permission is separate from delivery;
// delivery instructions belong to each invocation, not the stored value.
export const SECRET_MAX = 1024 * 1024;
export const SECRET_COUNT_MAX = 200;
export const SECRET_TOTAL_MAX = 20 * 1024 * 1024;
export const VALUE_MAX = 16384;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// A name identifies a value. It is not a path, a service, or a delivery instruction.
export function secretName(value) {
  if (typeof value !== 'string' || !value.length || value.length > 200 || /[\u0000-\u001f\u007f-\u009f]/u.test(value) || !value.isWellFormed()) fail(400, 'invalid_name', '名前は制御文字を含まない1〜200文字で指定してください。');
  return value;
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

export class Secrets {
  constructor(store) { this.store = store; this.db = store.db; this.vault = store.vault; }
  list(ownerId, prefix) {
    const columns = 'id,name,size,readable,created_at,updated_at';
    return (prefix === undefined
      ? this.db.prepare(`SELECT ${columns} FROM holdings WHERE holder_id=? AND kind='secret' ORDER BY name`).all(ownerId)
      : this.db.prepare(`SELECT ${columns} FROM holdings WHERE holder_id=? AND kind='secret' AND substr(name,1,length(?))=? COLLATE BINARY ORDER BY name`).all(ownerId, String(prefix), String(prefix)))
      .map(row => ({ ...row, readable: row.readable === 1 }));
  }
  find(ownerId, name) {
    const row = this.db.prepare("SELECT id,holder_id AS owner_id,name,size,readable,content,created_at,updated_at FROM holdings WHERE holder_id=? AND kind='secret' AND name=?").get(ownerId, secretName(name));
    return row ? { ...row, readable: row.readable === 1 } : undefined;
  }
  // The thing itself, by its id, whoever holds it.
  byId(id) {
    const row = typeof id === 'string' ? this.db.prepare("SELECT id,holder_id AS owner_id,name,size,readable,content,created_at,updated_at FROM holdings WHERE id=? AND kind='secret'").get(id) : undefined;
    return row ? { ...row, readable: row.readable === 1 } : undefined;
  }
  content(row) { return this.vault.openBytes(row.content, `entry:${row.owner_id}:${row.id}`); }
  usage(ownerId) { return this.db.prepare("SELECT COUNT(*) AS count, COALESCE(SUM(size),0) AS bytes FROM holdings WHERE holder_id=? AND kind='secret'").get(ownerId); }
  // Writing the same name again replaces what is there, including its read permission.
  put(ownerId, { name, content, secret }) {
    if (content.length > SECRET_MAX) fail(413, 'secret_too_large', '1件あたり1MBまでです。');
    secretName(name);
    return this.store.transaction(() => {
      const stamp = new Date().toISOString(), existing = this.find(ownerId, name), { count, bytes } = this.usage(ownerId);
      if (!existing && count >= SECRET_COUNT_MAX) fail(409, 'secret_limit', `保管できるのは${SECRET_COUNT_MAX}件までです。使わないものを消してください。`);
      if (bytes - (existing?.size ?? 0) + content.length > SECRET_TOTAL_MAX) fail(409, 'storage_full', '保管できる合計は20MBまでです。使わないものを消してください。');
      const id = existing?.id ?? randomUUID(), sealed = this.vault.sealBytes(content, `entry:${ownerId}:${id}`);
      if (existing) this.db.prepare('UPDATE holdings SET size=?,readable=?,content=?,updated_at=? WHERE id=?').run(content.length, secret ? 0 : 1, sealed, stamp, id);
      else this.db.prepare("INSERT INTO holdings (id,holder_id,kind,name,size,readable,content,created_at,updated_at) VALUES (?,?,'secret',?,?,?,?,?,?)").run(id, ownerId, name, content.length, secret ? 0 : 1, sealed, stamp, stamp);
      return this.list(ownerId, name)[0];
    });
  }
  // Writing by id: the same thing, whoever writes it, keeps its name and its read permission.
  write(row, content) {
    if (content.length > SECRET_MAX) fail(413, 'secret_too_large', '1件あたり1MBまでです。');
    return this.store.transaction(() => {
      const { bytes } = this.usage(row.owner_id);
      if (bytes - row.size + content.length > SECRET_TOTAL_MAX) fail(409, 'storage_full', '保管できる合計は20MBまでです。使わないものを消してください。');
      this.db.prepare('UPDATE holdings SET size=?,content=?,updated_at=? WHERE id=?').run(content.length, this.vault.sealBytes(content, `entry:${row.owner_id}:${row.id}`), new Date().toISOString(), row.id);
      return this.list(row.owner_id, row.name)[0];
    });
  }
  at(ownerId, name) {
    const row = this.find(ownerId, name);
    if (!row) fail(404, 'not_found', '保管されたものが見つかりません。');
    return row;
  }
  read(ownerId, name) {
    const row = this.at(ownerId, name);
    if (!row.readable) fail(403, 'write_only', 'この値の直接読み出しは許可されていません。');
    return { row, content: this.content(row) };
  }
  // Rename without exposing or modifying content. Lines onto the thing point at its id, so they need no care.
  rename(ownerId, name, { name: to }) {
    const target = secretName(to ?? name);
    return this.store.transaction(() => {
      const row = this.at(ownerId, name);
      if (target !== name && this.find(ownerId, target)) fail(409, 'name_taken', 'その名前はすでに使われています。');
      this.db.prepare('UPDATE holdings SET name=?,updated_at=? WHERE id=?').run(target, new Date().toISOString(), row.id);
      return this.list(ownerId, target)[0];
    });
  }
  // Removing the thing removes the lines onto it: a later thing by the same name is another thing.
  remove(ownerId, name) {
    this.store.transaction(() => {
      const row = this.at(ownerId, name);
      this.db.prepare('DELETE FROM holdings WHERE id=?').run(row.id);
      this.db.prepare("DELETE FROM relations WHERE object_type='holding' AND object_id=?").run(row.id);
    });
  }
  // Each input and delivery destination is explicit.
  deliver(ownerId, asked) {
    const wanted = (Array.isArray(asked) ? asked : []).map(item => typeof item === 'string' ? { name: item } : item);
    if (!wanted.length || wanted.length > 16) fail(400, 'invalid_names', '渡すものを1〜16件で指定してください。');
    const environment = {}, files = [], taken = new Map(), filenames = new Set();
    for (const item of wanted) {
      if (!item || typeof item !== 'object' || typeof item.name !== 'string') fail(400, 'invalid_names', '渡すものは {name, as} で指定してください。');
      const row = this.at(ownerId, item.name);
      const content = this.content(row);
      const name = item.as;
      if (!name) fail(400, 'no_variable', '渡す環境変数名を as で指定してください。');
      if (!validEnvName(name)) fail(400, 'invalid_env', '変数名は英大文字・数字・下線で指定してください。');
      if (taken.has(name)) fail(409, 'name_conflict', `${taken.get(name)} と ${row.name} が同じ変数名 ${name} を使います。どちらかを as で変えてください。`);
      taken.set(name, row.name);
      if (item.filename !== undefined && item.filename !== null && item.filename !== '') {
        if (typeof item.filename !== 'string' || !SEGMENT.test(item.filename) || item.filename.startsWith('.')) fail(400, 'invalid_filename', 'ファイル名は英数字で始まり、64文字までです。');
        if (filenames.has(item.filename)) fail(409, 'filename_conflict', 'ファイル名が重複しています。');
        filenames.add(item.filename);
        files.push({ env: name, filename: item.filename, content: content.toString('base64'), encoding: 'base64' });
      } else {
        deliverable(content, { env: name, filename: null });
        environment[name] = content.toString('utf8');
      }
    }
    return { environment, files };
  }
}
