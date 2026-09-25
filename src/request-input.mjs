import { fail } from './errors.mjs';
import { secretName } from './secrets.mjs';

export function requestInput(kind, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_request', '依頼内容を指定してください。');
  if (kind === 'connect' && Object.keys(input).every(key => key === 'connector') && typeof input.connector === 'string') return { connector: input.connector };
  // Asking to act for someone: only what the asker wants to be called.
  if (kind === 'actor' && Object.keys(input).every(key => key === 'name') && typeof input.name === 'string' && input.name.trim() && input.name.length <= 80) return { name: input.name.trim() };
  if (kind === 'store' && Object.keys(input).every(key => key === 'fields')) return { fields: declarations(input.fields) };
  fail(400, 'invalid_request', '依頼の種類と内容が一致しません。');
}

export function requestResult(kind, result) {
  if (kind === 'connect' && typeof result?.connection_id === 'string' && result.connection_id) return { connection_id: result.connection_id };
  if (kind === 'store' && Array.isArray(result?.names) && result.names.length) return { names: result.names.map(secretName), replaced: (result.replaced ?? []).map(secretName) };
  if (kind === 'actor' && typeof result?.principal_id === 'string' && result.principal_id) return { principal_id: result.principal_id };
  throw new Error('The result does not match the request');
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
  // Replacing is a property of the request, declared up front, so the owner sees it before deciding.
  if (input.replace !== undefined && typeof input.replace !== 'boolean') fail(400, 'invalid_declaration', '置き換えかどうかは true か false で指定してください。');
  return { name: secretName(input.name), secret: input.secret !== false, label: input.label.trim(), site: site?.href ?? '', multiline: input.multiline === true, replace: input.replace === true };
}
