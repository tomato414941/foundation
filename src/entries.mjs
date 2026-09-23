import { fail } from './errors.mjs';
import { validEnvName } from './env-name.mjs';

// Storage, and the whole of it.
//
// One thing is kept: bytes, at a path the writer chose. Foundation does not read them and has no
// notion of what kinds of thing exist, because that cannot be known in advance. What it keeps beside
// the bytes is only what it needs in order to give them back:
//   media_type  what the writer says these bytes are. Never checked, never parsed. It decides nothing
//               but how the owner's screen tries to show them.
//   env         the environment variable a command receives them as; null when they are not delivered
//   filename    when set, the bytes become a file of that name while a command runs, and `env` holds
//               its path instead of the bytes
//   readable    false when the bytes may only be delivered, never handed back to a key
// A short string delivered as a variable is what other systems call a key and a value; a JSON body with
// no delivery is what they call a document; a PEM delivered as a file is what they call a file. Here
// they are one thing, and a kind of content nobody has thought of yet needs no change.
export const ENTRY_MAX = 1024 * 1024;
export const ENTRY_COUNT_MAX = 200;
export const ENTRY_TOTAL_MAX = 20 * 1024 * 1024;
export const VALUE_MAX = 16384;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MEDIA_TYPE = /^[a-z0-9][a-z0-9.+-]{0,62}\/[a-z0-9][a-z0-9.+-]{0,62}(;\s?charset=[A-Za-z0-9-]{1,20})?$/;

// Paths are the only names. They carry no meaning for Foundation; a leading segment groups what the
// writer wants grouped, and that is all grouping is.
export function entryPath(value) {
  if (typeof value !== 'string' || value.length > 200) fail(400, 'invalid_path', 'パスは200文字までです。');
  const segments = value.split('/');
  if (segments.length < 1 || segments.length > 8 || !segments.every(segment => SEGMENT.test(segment))) {
    fail(400, 'invalid_path', 'パスは英数字で始まる区切りを / でつなぎます。各区切りは64文字まで、全体で8つまでです。');
  }
  return value;
}

export function mediaType(value = 'application/octet-stream') {
  if (typeof value !== 'string' || !MEDIA_TYPE.test(value)) fail(400, 'invalid_media_type', '形式は text/plain のように指定してください。');
  return value;
}

// How the bytes reach a command, declared when they are written. Delivery never consults anything else,
// so everything it needs is decided here, once.
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

export class Entries {
  constructor(store, reserved = new Set()) { this.store = store; this.reserved = reserved; }
  list(ownerId, prefix) { return this.store.entries(ownerId, prefix === undefined ? undefined : String(prefix)); }
  // Writing the same path again replaces what is there, including how it is delivered.
  put(ownerId, { path, content, type, env, filename, secret, keptBy }) {
    const declared = delivery({ env, filename, reserved: this.reserved });
    if (content.length > ENTRY_MAX) fail(413, 'entry_too_large', '1件あたり1MBまでです。');
    deliverable(content, declared);
    return this.store.writeEntry(ownerId, { path: entryPath(path), content, media_type: mediaType(type), ...declared, readable: secret ? 0 : 1, kept_by: keptBy });
  }
  entry(ownerId, path) {
    const row = this.store.entry(ownerId, entryPath(path));
    if (!row) fail(404, 'not_found', '保管されたものが見つかりません。');
    return row;
  }
  read(ownerId, path) {
    const row = this.entry(ownerId, path);
    if (!row.readable) fail(403, 'write_only', 'これは渡すことしかできません。中身は持ち主の画面でのみ確認できます。');
    return { row, content: this.store.entryContent(row) };
  }
  remove(ownerId, path) {
    if (!this.store.removeEntry(ownerId, entryPath(path))) fail(404, 'not_found', '保管されたものが見つかりません。');
  }
  // What a command receives. Foundation reads only what it was told at writing time.
  deliver(ownerId, paths) {
    if (!Array.isArray(paths) || paths.length < 1 || paths.length > 16) fail(400, 'invalid_paths', '渡すものを1〜16件で指定してください。');
    const environment = {}, files = [], taken = new Map();
    for (const path of paths) {
      const row = this.entry(ownerId, path);
      if (!row.env) fail(409, 'not_delivered', `${row.path} は渡す先が決まっていません。変数名を決めて保管し直してください。`);
      if (taken.has(row.env)) fail(409, 'name_conflict', `${taken.get(row.env)} と ${row.path} が同じ変数名 ${row.env} を使います。どちらかにしてください。`);
      taken.set(row.env, row.path);
      const content = this.store.entryContent(row);
      if (row.filename) files.push({ env: row.env, filename: row.filename, content: content.toString('base64'), encoding: 'base64' });
      else environment[row.env] = content.toString('utf8');
    }
    return { environment, files };
  }
}
