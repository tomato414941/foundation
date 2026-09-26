import { fail } from './errors.mjs';
import { holdingName } from './holdings.mjs';
import { prepare as prepareFetch, send as sendFetch } from './fetch.mjs';

// Built-in operations, not user-supplied code. Definitions describe invocation;
// neither a definition nor a stored value implies an execution.
export const FUNCTIONS = [
  { id: 'http.request', description: 'Send one HTTPS request with explicitly referenced grants.',
    endpoint: '/v1/functions/http.request', input: { url: 'HTTPS URL', method: 'HTTP method', headers: 'header values', body: 'optional body', bindings: 'optional placeholder-to-grant map' },
    output: 'response', save: 'optional name to keep the response body under, as a given grant' },
];

// Explicit operations. Their results may be returned or saved; neither choice is inferred
// from a stored name, and neither operation changes a request's completion state.
export class Functions {
  // Run in a holder's name. `still` is asked again after every wait: whether the caller's credential is
  // still good, since an authorization may be withdrawn while a service answers.
  constructor({ grants, outbound = {} }) { this.grants = grants; this.outbound = outbound; }
  async request({ holderId, still = () => {} }, input, ownHosts) {
    still();
    const prepared = prepareFetch(input, ownHosts), bindings = input.bindings ?? {};
    if (!bindings || typeof bindings !== 'object' || Array.isArray(bindings)) fail(400, 'invalid_input', 'bindings は入力名と保存名の組で指定してください。');
    const references = prepared.names.map(slot => Object.hasOwn(bindings, slot) ? bindings[slot] : slot);
    const outputs = input.save === undefined ? null : outputNames({ response: input.save }, ['response']);
    // Each bound grant yields one text: a given one its bytes, a connected one what its connector derives now.
    const values = new Map();
    for (const [at, slot] of prepared.names.entries()) {
      const content = await this.grants.text(holderId, references[at]), text = content.toString('utf8');
      if (!Buffer.from(text, 'utf8').equals(content)) fail(400, 'not_text', '指定された入力は文字列ではないため、リクエストには入れられません。');
      values.set(slot, text);
    }
    still();
    const response = await sendFetch(prepared, values, { ...this.outbound, ownHosts });
    still();
    const saved = outputs ? saveOutputs(this.grants, holderId, outputs,
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
    holdingName(name);
    if (used.has(name)) fail(400, 'invalid_output', '出力の保存名が重複しています。');
    used.add(name);
    return { output, name };
  });
}

// The caller chooses the names. This writes exactly those outputs, atomically, as given grants.
export function saveOutputs(grants, ownerId, names, values) {
  return grants.store.transaction(() => names.map(({ output, name }) => {
    const value = values.get(output);
    if (!value) fail(502, 'service_response', '指定された出力が返されませんでした。');
    return grants.put(ownerId, { name, content: value.content });
  }));
}
