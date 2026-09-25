import { digest } from './crypto.mjs';
import { RUNTIME_KEY } from './keys.mjs';
import { fail } from './errors.mjs';

export const MAX_REQUEST_TTL = 24 * 60 * 60_000;
export const REQUEST_ID = /^[A-Za-z0-9_-]{43}$/;
export const CODE_ATTEMPTS = 5;

export function requestKey(token) {
  if (typeof token !== 'string' || !RUNTIME_KEY.test(token)) fail(401, 'invalid_token', 'アクセスキーの形式が無効です。');
  return digest(token);
}
export function validity(minutes) {
  if (!Number.isInteger(minutes) || minutes < 1 || minutes * 60_000 > MAX_REQUEST_TTL) fail(400, 'invalid_validity', '有効期間は1〜1440分で指定してください。');
  return minutes * 60_000;
}
// Temporary feedback to the requesting AI. Values entered by the owner never belong here.
export function progress(previous, event, detail = {}) {
  const entry = { at: Date.now(), event: String(event).slice(0, 40) };
  for (const name of ['connector', 'code']) if (detail[name] != null) entry[name] = String(detail[name]).slice(0, 64);
  if (detail.message != null) entry.message = String(detail.message).slice(0, 300);
  return JSON.stringify([...events(previous), entry].slice(-40));
}
export const events = previous => previous ? JSON.parse(previous) : [];
