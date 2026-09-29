import { fail } from './errors.mjs';
import { validEnvName } from '../cli/env-name.mjs';

const VALUE_MAX = 16384;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// Bytes handed to a command as a variable have to survive being one; bytes handed over as a file do not.
function injectable(content, { env, filename }) {
  if (!env || filename) return;
  if (content.length > VALUE_MAX) fail(413, 'value_too_large', '環境変数として渡す値は16384バイトまでです。');
  const text = content.toString('utf8');
  if (Buffer.compare(Buffer.from(text, 'utf8'), content) !== 0 || /[\x00\r\n]/.test(text)) {
    fail(400, 'invalid_value', '環境変数として渡す値は、改行を含まない文字列にしてください。ファイルとして渡すこともできます。');
  }
}

// A delivery operation can take private bytes or obtain current credentials. Storage does not choose how a
// secret is used: its caller names the destination every time.
export class Inputs {
  constructor(secrets, credentials) { Object.assign(this, { secrets, credentials }); }
  resolve(holderId, reference) {
    if (typeof reference !== 'string' || !reference) fail(400, 'invalid_names', '渡すものは {name, as} で指定してください。');
    const named = reference.length <= 200 && this.secrets.find(holderId, reference);
    const row = named || (/^[0-9a-f-]{36}$/.test(reference) ? this.secrets.held(holderId, reference) || this.credentials.held(holderId, reference) : undefined);
    if (!row) fail(404, 'not_found', '見つかりません。');
    return row;
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
      if (row.kind === 'secret') {
        if (!item.as) fail(400, 'no_variable', '渡す環境変数名を as で指定してください。');
        place(row, item.as, filename, this.secrets.content(row));
        continue;
      }
      const derived = await this.credentials.derive(row);
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
    if (row.kind === 'secret') return this.secrets.content(row);
    const derived = await this.credentials.derive(row);
    const chosen = variable ? derived.values.get(variable) : derived.values.size === 1 ? [...derived.values.values()][0] : undefined;
    if (!chosen) fail(400, 'invalid_input', 'この接続は複数の値を渡すので、<id>#<変数名> で一つを指定してください。');
    return chosen.content;
  }
}
