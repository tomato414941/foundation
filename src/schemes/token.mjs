import { randomUUID } from 'node:crypto';
import { fail } from '../errors.mjs';
import { publicFetch, fill, inject, at } from './oauth.mjs';

// A token the holder made at the service and hands over: the service's definition says which fields it takes, how
// to check it (who it belongs to, asked of the service with it), and what an AI is handed. Nothing renews it; it
// lasts until the holder revokes it at the service.
export const FIELD_MAX = 8192;
const invalid = label => fail(400, 'invalid_fields', `${label}を確認してください。`);
const refused = () => fail(400, 'token_refused', '接続先がこのトークンを受け付けませんでした。トークンと権限を確認してください。');

export function tokenScheme(definition, { fetcher = publicFetch } = {}) {
  const spec = definition.auth_schemes.token;
  const values = input => {
    const given = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
    const fields = {};
    for (const field of spec.fields) {
      const value = typeof given[field.name] === 'string' ? given[field.name].trim() : '';
      if (!value || value.length > FIELD_MAX || /[\x00-\x1f\x7f]/.test(value) || (field.pattern && !new RegExp(field.pattern).test(value))) invalid(field.label);
      fields[field.name] = value;
    }
    return fields;
  };
  // Who the token belongs to, when the service can say: asked with the token, or a field the holder gave.
  async function identity(fields) {
    const how = spec.identity;
    if (!how) return null;
    if (how.from === 'fields') return { id: fields[how.id], label: fields[how.id] };
    let answer;
    try {
      answer = await fetcher(fill(how.url, fields), { method: how.method || 'GET',
        headers: { accept: 'application/json', ...Object.fromEntries(Object.entries(how.headers ?? {}).map(([name, template]) => [name, fill(template, fields)])),
          ...('json' in how ? { 'content-type': 'application/json' } : {}) }, ...('json' in how ? { body: JSON.stringify(how.json) } : {}) });
    } catch (error) { if (error?.status) throw error; fail(502, 'service_unavailable', '接続先に接続できませんでした。時間をおいて再度お試しください。'); }
    if (typeof Response === 'function' && answer instanceof Response) answer = { ok: answer.ok, status: answer.status, text: await answer.text() };
    let body;
    try { body = JSON.parse(answer.text); } catch { body = null; }
    if (answer.status === 401 || answer.status === 403 || !answer.ok || !body || (how.ok_field && body[how.ok_field] !== true)) refused();
    const id = [].concat(how.id).map(path => at(body, path));
    if (!id.every(value => (typeof value === 'string' && value && value.length <= 255) || Number.isSafeInteger(value))) fail(502, 'service_response', '接続先からの応答を確認できませんでした。');
    const label = [].concat(how.label ?? []).map(path => at(body, path)).find(value => typeof value === 'string' && value && value.length <= 200);
    return { id: id.map(String).join(':'), label: label || id.map(String).join(':') };
  }
  const result = (subject, fields, who) => ({ subject, privateState: { fields, identity: who }, expiresAt: null,
    facts: { label: who?.label || definition.name, account: who?.id ?? null, checked_at: who ? Date.now() : null },
    credentials: { environment: inject(spec.injection, { ...fields, account: who?.id }) } });
  return {
    kind: 'token', available: true, variables: Object.keys(spec.injection), fields: spec.fields,
    authorization: {
      // The holder's fields, checked with the service when it can say whose they are. Handing over a new token for
      // the same account keeps the connection; one for another account is refused.
      complete: async ({ fields: input }, previous) => {
        const fields = values(input), who = await identity(fields);
        const subject = who ? (spec.subject_prefix ?? 'user:') + who.id : previous?.subject ?? 'token:' + randomUUID();
        if (who && previous && previous.subject !== subject) fail(409, 'account_changed', '同じアカウントのトークンを指定してください。');
        return result(subject, fields, who);
      },
    },
    obtain: async ({ subject, privateState }) => result(subject, privateState.fields, privateState.identity),
  };
}
