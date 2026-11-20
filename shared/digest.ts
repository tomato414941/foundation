import { z } from 'zod';
import { base64url, encode } from './encryption.js';

// A SHA-256 digest, base64url-encoded.
export const Digest = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

// JSON written one way only: object members sorted, no spaces, so that equal values read the same.
export function canonical(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (typeof value === 'string' && !/[\uD800-\uDFFF]/u.test(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + Array.from(value, canonical).join(',') + ']';
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(key => {
      if (/[\uD800-\uDFFF]/u.test(key)) throw new Error('Use Unicode property names.');
      return JSON.stringify(key) + ':' + canonical((value as Record<string, unknown>)[key]);
    }).join(',') + '}';
  }
  throw new Error('Use finite numbers, Unicode strings, arrays, and plain JSON objects.');
}

export async function hash(value: unknown): Promise<string> {
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', encode(canonical(value)))));
}
