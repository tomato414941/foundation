import { fail } from './errors.mjs';
import { matchRoute, validateBody } from './api.mjs';

// What a request asks for: calls of this API, each as the one asked would send it - a method, a path and a body - in
// the order they are to be made. Where the one asked must supply something (a value only they have, a secret they
// type), the call says where it goes and how to ask for it; that is all a request may leave open. A later call may use
// what an earlier one answered - the id of what it made - written {$N/pointer} in its path or in a string of its body:
// N the earlier call, the pointer into what it answered.
export const CALLS_MAX = 8, INPUTS_MAX = 16;
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const BODY_MAX = 64 * 1024;
// What only the one who makes a call can do: prove something with their own device, pay, take part in a flow begun
// elsewhere, or answer requests. A request cannot ask for these.
const OWN = new Set(['becomePrincipal', 'beginCredential', 'completeCredential', 'keepWrap', 'issueLink', 'mergeOptions', 'mergeBegin', 'mergeComplete',
  'beginPayment', 'completePayment', 'getConfirmation', 'acceptConfirmation', 'cancelConfirmation', 'completeRole']);
// How the one asked supplies a value: typed and shown (text), typed and hidden (hidden), or typed and sealed by their
// own client for those who may open it, the value placed as a sealed secret (sealed).
const KINDS = ['text', 'hidden', 'sealed'];
const POINTER = /^(\/([^~/]|~[01])*)*$/;
const REFERENCE = /\{\$(\d)((?:\/(?:[^~/{}]|~[01])*)*)\}/g;
const segments = pointer => pointer.slice(1).split('/').map(part => part.replace(/~1/g, '/').replace(/~0/g, '~'));
// Every string a call carries, where references may be: its path, and the strings of its body.
const strings = value => typeof value === 'string' ? [value] : value && typeof value === 'object' ? Object.values(value).flatMap(strings) : [];

// The route a call reaches, when a request may ask for it.
export function requestable(method, path) {
  if (!METHODS.includes(method) || typeof path !== 'string' || !path.startsWith('/v1/') || path.length > 1000 || /[\s#]/.test(path)) return null;
  const route = matchRoute(new URL(path, 'http://x').pathname, method);
  if (!route?.operation || OWN.has(route.operation.operationId) || !/^\/v1\/(principals|resources)\b/.test(route.path)) return null;
  return route;
}

// The route a call asked for reaches, a reference standing for the one segment it will be: an id, as what calls answer
// and what paths take are.
const STANDING = '00000000-0000-4000-8000-000000000000';
export const routeOf = call => requestable(call.method, typeof call.path === 'string' ? call.path.replace(REFERENCE, STANDING) : call.path);

export function requestCalls(value) {
  if (!Array.isArray(value) || !value.length || value.length > CALLS_MAX) fail(400, 'invalid_operations', `operations に依頼する操作を1〜${CALLS_MAX}件指定してください。`);
  return value.map((call, index) => {
    if (!call || typeof call !== 'object' || Array.isArray(call) || Object.keys(call).some(key => !['method', 'path', 'body', 'inputs'].includes(key))) fail(400, 'invalid_operations', '操作は method・path・body・inputs で指定してください。');
    const route = routeOf(call);
    if (!route) fail(400, 'operation_unavailable', `${call.method + ' ' + call.path} は依頼できる操作ではありません。`);
    if (call.body !== undefined && (call.body === null || typeof call.body !== 'object' || Array.isArray(call.body) || JSON.stringify(call.body).length > BODY_MAX)) fail(400, 'invalid_operations', 'body はJSONのオブジェクトで指定してください。');
    const inputs = call.inputs === undefined ? [] : call.inputs;
    if (!Array.isArray(inputs) || inputs.length > INPUTS_MAX) fail(400, 'invalid_operations', `inputs は${INPUTS_MAX}件までの配列で指定してください。`);
    const declared = inputs.map(input);
    if (new Set(declared.map(one => one.at)).size !== declared.length) fail(400, 'invalid_operations', '同じ場所に2つの入力を指定できません。');
    for (const text of [call.path, ...strings(call.body)]) for (const [, earlier] of text.matchAll(REFERENCE)) {
      if (Number(earlier) >= index) fail(400, 'invalid_operations', '参照できるのは、それより前の操作の結果だけです。');
    }
    const made = { method: call.method, path: call.path, ...(call.body === undefined ? {} : { body: call.body }), ...(declared.length ? { inputs: declared } : {}) };
    // The shape is checked now, with every input standing in as the kind of value it will be, so a mistake reaches
    // the one asking and never the one asked.
    validateBody(route, fill(made, Object.fromEntries(declared.map(one => [one.at, one.kind === 'sealed' ? { content: 'x' } : 'x']))), new URL(call.path, 'http://x').searchParams.get('kind'));
    return made;
  });
}

function input(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['at', 'label', 'kind', 'multiline', 'site'].includes(key))) fail(400, 'invalid_operations', '入力は at・label・kind・multiline・site で指定してください。');
  const kind = value.kind ?? 'text';
  if (!KINDS.includes(kind)) fail(400, 'invalid_operations', 'kind は text / hidden / sealed のいずれかです。');
  // The whole body may be left open only for a sealed secret, which is the body of the call that keeps it.
  if (typeof value.at !== 'string' || !POINTER.test(value.at) || (value.at === '' && kind !== 'sealed')) fail(400, 'invalid_operations', 'at は body の中の場所を JSON Pointer で指定してください。');
  if (typeof value.label !== 'string' || !value.label.trim() || value.label.trim().length > 60 || /[\x00-\x1f\x7f<>]/.test(value.label)) fail(400, 'invalid_operations', 'label は1〜60文字で指定してください。');
  if (value.multiline !== undefined && typeof value.multiline !== 'boolean') fail(400, 'invalid_operations', 'multiline は true か false で指定してください。');
  let site;
  if (value.site !== undefined) {
    try { site = new URL(value.site); } catch { fail(400, 'invalid_site', 'site はhttpsのURLで指定してください。'); }
    if (site.protocol !== 'https:' || site.username || site.password || site.href.length > 300 || !site.hostname.includes('.')) fail(400, 'invalid_site', 'site はhttpsのURLで指定してください。');
  }
  return { at: value.at, label: value.label.trim(), kind, ...(value.multiline ? { multiline: true } : {}), ...(site ? { site: site.href } : {}) };
}

// The body a call is made with: what was asked, and what the one asked supplied, each where its input said. A sealed
// input supplies a sealed secret (content and envelopes), made by the client of the one asked; the others, a string.
export function fill(call, values = {}) {
  let body = structuredClone(call.body ?? {});
  for (const one of call.inputs ?? []) {
    const value = values[one.at];
    if (one.kind === 'sealed' ? !value || typeof value !== 'object' || Array.isArray(value) : typeof value !== 'string' || !value.length) fail(400, 'input_required', `「${one.label}」を入力してください。`);
    if (one.at === '') { body = structuredClone(value); continue; }
    const parts = segments(one.at);
    let at = body;
    for (const part of parts.slice(0, -1)) {
      if (['__proto__', 'constructor', 'prototype'].includes(part)) fail(400, 'invalid_operations', 'at を確認してください。');
      if (at[part] === undefined) at[part] = {};
      if (!at[part] || typeof at[part] !== 'object' || Array.isArray(at[part])) fail(400, 'invalid_operations', 'at を確認してください。');
      at = at[part];
    }
    const last = parts.at(-1);
    if (['__proto__', 'constructor', 'prototype'].includes(last)) fail(400, 'invalid_operations', 'at を確認してください。');
    at[last] = value;
  }
  return body;
}

// A call with what earlier calls answered put where it refers to them: only a string or a number, and in the path as
// one segment's text, so that it can name a thing and never another call.
export function resolve(call, results) {
  const replace = (text, encode = value => value) => text.replace(REFERENCE, (_, earlier, pointer) => {
    let value = results[Number(earlier)]?.body;
    for (const part of pointer ? segments(pointer) : []) value = value && typeof value === 'object' && Object.hasOwn(value, part) ? value[part] : undefined;
    if (typeof value !== 'string' && typeof value !== 'number') fail(409, 'reference_missing', '前の操作の結果に、参照された値がありません。');
    return encode(String(value));
  });
  const walk = value => typeof value === 'string' ? replace(value) : Array.isArray(value) ? value.map(walk) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, walk(item)])) : value;
  const path = replace(call.path, encodeURIComponent);
  if (!requestable(call.method, path)) fail(409, 'reference_missing', '前の操作の結果から、依頼できる操作になりませんでした。');
  return { ...call, path, ...(call.body === undefined ? {} : { body: walk(call.body) }) };
}
