import { fail } from './errors.mjs';
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
  constructor(store) { this.store = store; }
  list(ownerId, prefix) { return this.store.secrets(ownerId, prefix === undefined ? undefined : String(prefix)); }
  // Writing the same name again replaces what is there, including its read permission.
  put(ownerId, { name, content, secret }) {
    if (content.length > SECRET_MAX) fail(413, 'secret_too_large', '1件あたり1MBまでです。');
    return this.store.writeSecret(ownerId, { name: secretName(name), content, readable: secret ? 0 : 1 });
  }
  at(ownerId, name) {
    const row = this.store.secret(ownerId, secretName(name));
    if (!row) fail(404, 'not_found', '保管されたものが見つかりません。');
    return row;
  }
  read(ownerId, name) {
    const row = this.at(ownerId, name);
    if (!row.readable) fail(403, 'write_only', 'この値の直接読み出しは許可されていません。');
    return { row, content: this.store.secretContent(row) };
  }
  // Rename without exposing or modifying content.
  rename(ownerId, name, { name: to }) {
    this.at(ownerId, name);
    const moved = this.store.renameSecret(ownerId, name, { name: secretName(to ?? name) });
    if (!moved) fail(404, 'not_found', '保管されたものが見つかりません。');
    return moved;
  }
  remove(ownerId, name) {
    if (!this.store.removeSecret(ownerId, secretName(name))) fail(404, 'not_found', '保管されたものが見つかりません。');
  }
  // Each input and delivery destination is explicit.
  deliver(ownerId, asked) {
    const wanted = (Array.isArray(asked) ? asked : []).map(item => typeof item === 'string' ? { name: item } : item);
    if (!wanted.length || wanted.length > 16) fail(400, 'invalid_names', '渡すものを1〜16件で指定してください。');
    const environment = {}, files = [], taken = new Map(), filenames = new Set();
    for (const item of wanted) {
      if (!item || typeof item !== 'object' || typeof item.name !== 'string') fail(400, 'invalid_names', '渡すものは {name, as} で指定してください。');
      const row = this.at(ownerId, item.name);
      const content = this.store.secretContent(row);
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

// What an AI asks its owner to put into storage. Foundation holds no knowledge of the service involved:
// the AI chooses its name and writes the instructions the owner follows.
// Some things only make sense together: an Apple key is a .p8 and three identifiers, and asking for them
// one screen at a time is four trips for the owner. So a request may declare several, and they are filled
// in and kept in one go. Foundation still knows nothing about what they are for.
export function declarations(input) {
  const many = Array.isArray(input) ? input : [input];
  if (!many.length || many.length > 8) fail(400, 'invalid_declaration', '一度に預けられるのは1〜8件です。');
  const declared = many.map(one => declaration(one));
  const names = new Set(declared.map(one => one.name));
  if (names.size !== declared.length) fail(400, 'invalid_declaration', '同じ保管先を2回指定できません。');
  return declared;
}

export function declaration(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_declaration', '保管するものの申告が必要です。');
  let site;
  if (input.site !== undefined && input.site !== '') {
    try { site = new URL(input.site); } catch { fail(400, 'invalid_site', '作成ページはhttpsのURLで指定してください。'); }
    if (site.protocol !== 'https:' || site.username || site.password || site.href.length > 300 || !site.hostname.includes('.')) fail(400, 'invalid_site', '作成ページはhttpsのURLで指定してください。');
  }
  if (typeof input.label !== 'string' || !input.label.trim() || input.label.trim().length > 60 || /[\x00-\x1f\x7f<>]/.test(input.label)) fail(400, 'invalid_label', '何を入れてもらうかを1〜60文字で指定してください。');
  if (input.multiline !== undefined && typeof input.multiline !== 'boolean') fail(400, 'invalid_declaration', '複数行かどうかは true か false で指定してください。');
  return { name: secretName(input.name), secret: input.secret !== false, label: input.label.trim(), site: site?.href ?? '', multiline: input.multiline === true };
}
