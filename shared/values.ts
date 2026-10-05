import type { JsonValue } from './contracts.js';

export function pointerParts(pointer: string): string[] {
  if (pointer === '') return [];
  if (!pointer.startsWith('/') || /~(?![01])/u.test(pointer)) throw new Error('Invalid JSON pointer.');
  const parts = pointer
    .slice(1)
    .split('/')
    .map((value) => value.replaceAll('~1', '/').replaceAll('~0', '~'));
  if (parts.some((value) => ['__proto__', 'prototype', 'constructor'].includes(value)))
    throw new Error('Invalid JSON pointer.');
  return parts;
}
export function atPointer(value: unknown, pointer: string): unknown {
  for (const part of pointerParts(pointer)) {
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, part)) return undefined;
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}
export function setPointer(value: unknown, pointer: string, replacement: JsonValue): void {
  const parts = pointerParts(pointer),
    last = parts.pop();
  if (last === undefined) throw new Error('Choose a property within the object.');
  for (const part of parts) {
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, part))
      throw new Error('JSON pointer target does not exist.');
    value = (value as Record<string, unknown>)[part];
  }
  if (value === null || typeof value !== 'object') throw new Error('JSON pointer target does not exist.');
  if (Array.isArray(value) && (!/^(0|[1-9][0-9]*)$/.test(last) || Number(last) >= value.length))
    throw new Error('Invalid array index.');
  (value as Record<string, JsonValue>)[last] = replacement;
}
export function textValue(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  throw new Error('The selected value is not text.');
}
export function redact(text: string, values: string[]): string {
  const variants = new Set<string>();
  for (const value of values)
    if (value) {
      variants.add(value);
      variants.add(encodeURIComponent(value));
      variants.add(JSON.stringify(value).slice(1, -1));
    }
  for (const value of [...variants].sort((a, b) => b.length - a.length))
    text = text.split(value).join('[redacted]');
  return text;
}
