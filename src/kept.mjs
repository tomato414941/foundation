import { fail } from './errors.mjs';
import { validEnvName } from './env-name.mjs';

// Storage stands on its own: a key keeps values and documents here without any service behind them,
// and reads them back later. Foundation checks only that what it is asked to hold can be held and
// handed back safely. What the values mean, and whether they still work, is the key's own business.
export const VALUE_MAX = 16384;
export const DOCUMENT_MAX = 256 * 1024;
// Both are sent as JSON with names and quoting around them, so the request may be larger than
// what it carries. The limits below leave room for that without letting either route be used
// to send something far bigger than it can hold.
export const VALUE_BODY_MAX = 64 * 1024;
export const DOCUMENT_BODY_MAX = DOCUMENT_MAX + 4096;
const plain = (value, max) => typeof value === 'string' && value.trim() !== '' && value.trim().length <= max && !/[\x00-\x1f\x7f<>]/.test(value);

// The name of the group a kept thing belongs to. The owner may rename it at any time.
export function serviceName(value) {
  if (!plain(value, 40)) fail(400, 'invalid_service', 'サービス名は1〜40文字で指定してください。');
  return value.trim();
}

// Values are kept under the names the command will read them as, so delivery needs no translation.
// `reserved` holds the names built-in adapters deliver, which a kept value may not take.
export function keptValues(input, reserved = new Set()) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail(400, 'invalid_values', '保管する値を指定してください。');
  const names = Object.keys(input);
  if (names.length < 1 || names.length > 16) fail(400, 'invalid_values', '保管する値は1〜16個で指定してください。');
  for (const name of names) {
    if (!validEnvName(name) || reserved.has(name)) fail(400, 'invalid_env', '値の名前は英大文字・数字・下線で指定してください。予約された名前は使えません。');
    const value = input[name];
    if (typeof value !== 'string' || value === '' || value.length > VALUE_MAX || /[\x00\r\n]/.test(value)) fail(400, 'invalid_values', '値は改行を含まない1〜16384文字の文字列で指定してください。');
  }
  return Object.fromEntries(names.map(name => [name, input[name]]));
}

export function documentPath(collection, name) {
  for (const part of [collection, name]) if (typeof part !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(part)) fail(400, 'invalid_document', '記録の名前は英数字・ドット・下線・ハイフンで、64文字までです。');
  return { collection, name };
}

export function documentBody(value) {
  if (value === undefined) fail(400, 'invalid_document', '記録の内容を指定してください。');
  let text;
  try { text = JSON.stringify(value); } catch { fail(400, 'invalid_document', '記録の内容はJSONで指定してください。'); }
  if (text === undefined) fail(400, 'invalid_document', '記録の内容はJSONで指定してください。');
  if (Buffer.byteLength(text) > DOCUMENT_MAX) fail(413, 'document_too_large', '記録は256KBまでです。');
  return value;
}
