import { fail } from './errors.mjs';
import { validEnvName } from '../cli/env-name.mjs';
import { resourceName } from './resources.mjs';

const VALUE_MAX = 16384;
const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

// References are data, not strings with separators or implicit name/ID detection.
export function inputReference(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).some(key => !['name', 'id', 'output'].includes(key))
    || Object.hasOwn(value, 'name') === Object.hasOwn(value, 'id')) {
    fail(400, 'invalid_input', '参照は name または id のどちらか一方で指定してください。');
  }
  if (Object.hasOwn(value, 'name')) {
    resourceName(value.name);
    if (Object.hasOwn(value, 'output')) fail(400, 'invalid_input', 'output は接続のIDと組み合わせて指定してください。');
    return { name: value.name };
  }
  if (typeof value.id !== 'string' || !/^[0-9a-f-]{36}$/.test(value.id)) fail(400, 'invalid_input', 'id を確認してください。');
  if (Object.hasOwn(value, 'output') && (typeof value.output !== 'string' || !value.output || value.output.length > 200)) {
    fail(400, 'invalid_input', 'output は出力名で指定してください。');
  }
  return { id: value.id, ...(Object.hasOwn(value, 'output') ? { output: value.output } : {}) };
}

// Bytes handed to a command as a variable have to survive being one; bytes handed over as a file do not.
function injectable(content, { env, filename }) {
  if (!env || filename) return;
  if (content.length > VALUE_MAX) fail(413, 'value_too_large', '環境変数として渡す値は16384バイトまでです。');
  const text = content.toString('utf8');
  if (Buffer.compare(Buffer.from(text, 'utf8'), content) !== 0 || /[\x00\r\n]/.test(text)) {
    fail(400, 'invalid_value', '環境変数として渡す値は、改行を含まない文字列にしてください。ファイルとして渡すこともできます。');
  }
}

// A delivery operation can take private bytes or obtain current connections. Storage does not choose how a
// secret is used: its caller names the destination every time.
export class Inputs {
  constructor(secrets, connections) { Object.assign(this, { secrets, connections }); }
  resolve(holderId, reference) {
    const ref = inputReference(reference);
    const row = Object.hasOwn(ref, 'name') ? this.secrets.find(holderId, ref.name)
      : this.secrets.held(holderId, ref.id) || this.connections.held(holderId, ref.id);
    if (!row) fail(404, 'not_found', '見つかりません。');
    if (row.kind === 'secret' && ref.output !== undefined) fail(400, 'invalid_input', 'シークレットには output を指定できません。');
    if (row.kind !== 'secret' && ref.output !== undefined && !this.connections.services.scheme(row.service, row.auth_scheme).variables.includes(ref.output)) {
      fail(400, 'invalid_input', '指定された出力はありません。');
    }
    return row;
  }
  // Each input and destination is explicit. A secret needs `as`; a scheme's outputs have names of their own, and
  // `as` may rename a single output, whether selected explicitly or supplied alone by the scheme.
  async inject(holderId, asked) {
    const wanted = Array.isArray(asked) ? asked : [];
    if (!wanted.length || wanted.length > 16) fail(400, 'invalid_names', '渡すものを1〜16件で指定してください。');
    const rows = wanted.map(item => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) fail(400, 'invalid_names', '渡すものは name または id を持つオブジェクトで指定してください。');
      const { as, filename, ...reference } = item;
      return { item, row: this.resolve(holderId, reference) };
    });
    const environment = {}, files = [], taken = new Map(), filenames = new Set(), obtained = new Map();
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
    for (const { item, row } of rows) {
      const filename = item.filename === undefined || item.filename === null || item.filename === '' ? null : item.filename;
      if (row.kind === 'secret') {
        if (!item.as) fail(400, 'no_variable', '渡す環境変数名を as で指定してください。');
        place(row, item.as, filename, this.secrets.content(row));
        continue;
      }
      if (!obtained.has(row.id)) obtained.set(row.id, await this.connections.derive(row));
      const derived = obtained.get(row.id);
      if (derived.expires_at !== null) expires = expires === null ? derived.expires_at : Math.min(expires, derived.expires_at);
      const outputs = item.output === undefined ? [...derived.values] : [[item.output, derived.values.get(item.output)]];
      if (outputs.some(([, value]) => !value)) fail(400, 'invalid_input', '指定された出力が取得できませんでした。');
      if (item.as && outputs.length !== 1) fail(400, 'invalid_env', 'この接続は複数の値を渡すので、as では名前を変えられません。');
      for (const [variable, value] of outputs) place(row, item.as || variable, filename ?? value.filename ?? null, value.content);
    }
    return { injection: { environment, files }, expires_at: expires };
  }
  // A single value. Connections require an explicit output even if they currently yield only one.
  async text(holderId, reference, cache = new Map()) {
    const row = this.resolve(holderId, reference);
    if (row.kind === 'secret') return this.secrets.content(row);
    if (reference.output === undefined) fail(400, 'invalid_input', '接続から使う値を output で指定してください。');
    if (!cache.has(row.id)) cache.set(row.id, await this.connections.derive(row));
    const derived = cache.get(row.id);
    const chosen = derived.values.get(reference.output);
    if (!chosen) fail(400, 'invalid_input', '指定された出力が取得できませんでした。');
    return chosen.content;
  }
}
