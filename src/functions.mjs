import { fail } from './errors.mjs';
import { secretName, delivery, deliverable } from './secrets.mjs';

// Built-in operations, not user-supplied code. Definitions describe invocation;
// neither a definition nor a stored value implies an execution.
export const FUNCTIONS = [
  { id: 'http.request', description: 'Send one HTTPS request with explicitly referenced secrets.',
    endpoint: '/v1/functions/http.request', input: { url: 'HTTPS URL', method: 'HTTP method', headers: 'header values', body: 'optional body', bindings: 'optional placeholder-to-secret-name map' },
    output: 'response', save: 'optional name for the response body' },
  { id: 'connection.credentials', description: 'Check or refresh an existing OAuth connection and obtain its outputs.',
    endpoint: '/v1/functions/connection.credentials', input: { connection_id: 'ID from GET /v1/acquisitions' },
    output: 'delivery and expiry', save: 'optional map of output identifiers to secret names; when set, only saved metadata is returned' },
];

export function outputNames(save, available) {
  if (save === undefined) return null;
  if (!save || typeof save !== 'object' || Array.isArray(save)) fail(400, 'invalid_output', '保存する出力と名前を指定してください。');
  const entries = Object.entries(save);
  if (!entries.length || entries.length > 16) fail(400, 'invalid_output', '保存する出力は1〜16件で指定してください。');
  const used = new Set();
  return entries.map(([output, name]) => {
    if (!available.includes(output)) fail(400, 'invalid_output', '指定された出力はありません。');
    secretName(name);
    if (used.has(name)) fail(400, 'invalid_output', '出力の保存名が重複しています。');
    used.add(name);
    return { output, name };
  });
}

// The caller chooses the names. This writes exactly those outputs, atomically.
export function saveOutputs(secrets, ownerId, names, values) {
  return secrets.store.transaction(() => names.map(({ output, name }) => {
    const value = values.get(output);
    if (!value) fail(502, 'service_response', '指定された出力が返されませんでした。');
    return secrets.put(ownerId, { name, content: value.content, secret: true });
  }));
}

export function deliveredOutputs(values) {
  const environment = {}, files = [];
  for (const [env, value] of values) {
    const target = delivery({ env, filename: value.filename });
    deliverable(value.content, target);
    if (value.filename) files.push({ env, filename: value.filename, content: value.content.toString('base64'), encoding: 'base64' });
    else environment[env] = value.content.toString('utf8');
  }
  return { environment, files };
}
