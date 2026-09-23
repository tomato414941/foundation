import { fail } from './errors.mjs';
import { validEnvName } from './env-name.mjs';

// What the agent may not read, kept so that a command can be given it.
//
// One thing is kept: bytes, at a path the writer chose. Foundation does not read them and has no
// notion of what kinds of thing exist, because that cannot be known in advance. What it keeps beside
// the bytes is only what it needs in order to give them back:
//   env         the environment variable a command receives them as; null when they are not delivered
//   filename    when set, the bytes become a file of that name while a command runs, and `env` holds
//               its path instead of the bytes
//   readable    false when the bytes may only be delivered, never handed back to a key
// A short string delivered as a variable is what other systems call a key and a value; a JSON body with
// no delivery is what they call a document; a PEM delivered as a file is what they call a file. Here
// they are one thing, and a kind of content nobody has thought of yet needs no change.
export const SECRET_MAX = 1024 * 1024;
export const SECRET_COUNT_MAX = 200;
export const SECRET_TOTAL_MAX = 20 * 1024 * 1024;
export const VALUE_MAX = 16384;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// Paths are the only names. They carry no meaning for Foundation; a leading segment groups what the
// writer wants grouped, and that is all grouping is.
export function secretPath(value) {
  if (typeof value !== 'string' || value.length > 200) fail(400, 'invalid_path', 'パスは200文字までです。');
  const segments = value.split('/');
  if (segments.length < 1 || segments.length > 8 || !segments.every(segment => SEGMENT.test(segment))) {
    fail(400, 'invalid_path', 'パスは英数字で始まる区切りを / でつなぎます。各区切りは64文字まで、全体で8つまでです。');
  }
  return value;
}


// The name a command receives something under belongs to the command, not to what is kept: `aws` reads
// AWS_ACCESS_KEY_ID whatever Foundation calls the value. So the caller names it at delivery, and when it
// says nothing the last segment of the path is used, which is where the name came from in the first place.
export function variableFor(path) {
  const leaf = path.split('/').pop().replace(/[^A-Za-z0-9]+/g, '_').toUpperCase();
  return /^[A-Z][A-Z0-9_]*$/.test(leaf) ? leaf : null;
}
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
  // Writing the same path again replaces what is there, including how it is delivered.
  put(ownerId, { path, content, secret, keptBy }, ifVersion) {
    if (content.length > SECRET_MAX) fail(413, 'secret_too_large', '1件あたり1MBまでです。');
    return this.store.writeSecret(ownerId, { path: secretPath(path), content, session: null, readable: secret ? 0 : 1, kept_by: keptBy }, ifVersion);
  }
  at(ownerId, path) {
    const row = this.store.secret(ownerId, secretPath(path));
    if (!row) fail(404, 'not_found', '保管されたものが見つかりません。');
    return row;
  }
  read(ownerId, path) {
    const row = this.at(ownerId, path);
    if (!row.readable) fail(403, 'write_only', 'これは渡すことしかできません。中身は持ち主の画面でのみ確認できます。');
    return { row, content: this.store.secretContent(row) };
  }
  // What it is called and how it reaches a command, changed without the value being handed back.
  rename(ownerId, path, { path: to }) {
    this.at(ownerId, path);
    const moved = this.store.renameSecret(ownerId, path, { path: secretPath(to ?? path) });
    if (!moved) fail(404, 'not_found', '保管されたものが見つかりません。');
    return moved;
  }
  remove(ownerId, path) {
    if (!this.store.removeSecret(ownerId, secretPath(path))) fail(404, 'not_found', '保管されたものが見つかりません。');
  }
  // What a command receives. Foundation reads only what it was told at writing time.
  // Each thing asked for is named by the caller, or by its own path when the caller says nothing.
  deliver(ownerId, asked) {
    const wanted = (Array.isArray(asked) ? asked : []).map(item => typeof item === 'string' ? { path: item } : item);
    if (!wanted.length || wanted.length > 16) fail(400, 'invalid_paths', '渡すものを1〜16件で指定してください。');
    const environment = {}, files = [], taken = new Map();
    let session = null;
    for (const item of wanted) {
      if (!item || typeof item !== 'object' || typeof item.path !== 'string') fail(400, 'invalid_paths', '渡すものはパス、または {path, as} で指定してください。');
      const row = this.at(ownerId, item.path);
      const content = this.store.secretContent(row);
      // A session is handed to the command as a tool's own login state. It takes no variable name.
      if (row.session) {
        if (session) fail(409, 'name_conflict', 'ログインセッションは1つだけ渡せます。');
        session = { kind: row.session, value: JSON.parse(content.toString('utf8')) };
        continue;
      }
      const name = item.as ?? variableFor(row.path);
      if (!name) fail(400, 'no_variable', `${row.path} から変数名を導けません。渡すときに as で指定してください。`);
      if (!validEnvName(name)) fail(400, 'invalid_env', '変数名は英大文字・数字・下線で指定してください。');
      if (taken.has(name)) fail(409, 'name_conflict', `${taken.get(name)} と ${row.path} が同じ変数名 ${name} を使います。どちらかを as で変えてください。`);
      taken.set(name, row.path);
      if (item.filename !== undefined && item.filename !== null && item.filename !== '') {
        if (typeof item.filename !== 'string' || !SEGMENT.test(item.filename) || item.filename.startsWith('.')) fail(400, 'invalid_filename', 'ファイル名は英数字で始まり、64文字までです。');
        files.push({ env: name, filename: item.filename, content: content.toString('base64'), encoding: 'base64' });
      } else {
        deliverable(content, { env: name, filename: null });
        environment[name] = content.toString('utf8');
      }
    }
    return { environment, files, ...(session?.kind === 'expo' ? { expo_session: session.value } : {}) };
  }
}

// What an AI asks its owner to put into storage. Foundation holds no knowledge of the service involved:
// the AI says where it goes, how it should be handed over, and writes the instructions the owner follows.
// Some things only make sense together: an Apple key is a .p8 and three identifiers, and asking for them
// one screen at a time is four trips for the owner. So a request may declare several, and they are filled
// in and kept in one go. Foundation still knows nothing about what they are for.
export function declarations(input) {
  const many = Array.isArray(input) ? input : [input];
  if (!many.length || many.length > 8) fail(400, 'invalid_declaration', '一度に預けられるのは1〜8件です。');
  const declared = many.map(one => declaration(one));
  const paths = new Set(declared.map(one => one.path));
  if (paths.size !== declared.length) fail(400, 'invalid_declaration', '同じ保管先を2回指定できません。');
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
  return { path: secretPath(input.path), secret: input.secret !== false, label: input.label.trim(), site: site?.href ?? '', multiline: input.multiline === true };
}
