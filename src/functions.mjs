import { fail } from './errors.mjs';
import { secretName, delivery, deliverable } from './secrets.mjs';
import { prepare as prepareFetch, send as sendFetch } from './fetch.mjs';

// Built-in operations, not user-supplied code. Definitions describe invocation;
// neither a definition nor a stored value implies an execution.
export const FUNCTIONS = [
  { id: 'http.request', description: 'Send one HTTPS request with explicitly referenced secrets.',
    endpoint: '/v1/functions/http.request', input: { url: 'HTTPS URL', method: 'HTTP method', headers: 'header values', body: 'optional body', bindings: 'optional placeholder-to-secret-name map' },
    output: 'response', save: 'optional name for the response body' },
  { id: 'connection.credentials', description: 'Check or refresh an existing OAuth connection and obtain its outputs.',
    endpoint: '/v1/functions/connection.credentials', input: { connection_id: 'ID from GET /v1/connections' },
    output: 'delivery and expiry', save: 'optional map of output identifiers to secret names; when set, only saved metadata is returned' },
];

// Explicit operations. Their results may be returned or saved; neither choice is inferred
// from a stored name, and neither operation changes a request's completion state.
export class Functions {
  // Run in a holder's name. `still` is asked again after every wait: whether the caller's credential is
  // still good, since an authorization may be withdrawn while a service answers.
  constructor({ connections, secrets, outbound = {} }) { this.connections = connections; this.secrets = secrets; this.outbound = outbound; }
  async credentials({ holderId, still = () => {} }, input) {
    still();
    const connection = this.connections.at(holderId, input.connection_id);
    const outputs = outputNames(input.save, this.connections.connectors.get(connection.connector).variables);
    const result = await this.connections.obtain(connection), expires_at = result.state.expires_at;
    if (expires_at !== null && !(Number.isFinite(expires_at) && expires_at > Date.now())) fail(502, 'service_response', '有効期限を確認できませんでした。');
    still();
    this.connections.current(connection);
    const saved = outputs ? saveOutputs(this.secrets, holderId, outputs, result.values) : null;
    return { ...(saved ? { saved } : { delivery: deliveredOutputs(result.values) }), facts: result.state.facts, expires_at,
      expires_in: expires_at === null ? null : Math.max(0, Math.floor((expires_at - Date.now()) / 1000)) };
  }
  async request({ holderId, still = () => {} }, input, ownHosts) {
    still();
    const prepared = prepareFetch(input, ownHosts), bindings = input.bindings ?? {};
    if (!bindings || typeof bindings !== 'object' || Array.isArray(bindings)) fail(400, 'invalid_input', 'bindings は入力名と保存名の組で指定してください。');
    const names = prepared.names.map(slot => secretName(Object.hasOwn(bindings, slot) ? bindings[slot] : slot));
    const outputs = input.save === undefined ? null : outputNames({ response: input.save }, ['response']);
    const values = new Map(prepared.names.map((slot, at) => {
      const content = this.secrets.content(this.secrets.at(holderId, names[at])), text = content.toString('utf8');
      if (!Buffer.from(text, 'utf8').equals(content)) fail(400, 'not_text', '指定された入力は文字列ではないため、リクエストには入れられません。');
      return [slot, text];
    }));
    const response = await sendFetch(prepared, values, { ...this.outbound, ownHosts });
    still();
    const saved = outputs ? saveOutputs(this.secrets, holderId, outputs,
      new Map([['response', { content: Buffer.from(response.body, response.body_encoding === 'base64' ? 'base64' : 'utf8') }]])) : null;
    return saved ? { response: { status: response.status, headers: response.headers }, saved } : { response };
  }
}

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
    return secrets.put(ownerId, { name, content: value.content });
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
