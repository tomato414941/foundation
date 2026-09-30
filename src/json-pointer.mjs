// JSON Pointer (RFC 6901), in its JSON string form. Only own JSON members are traversed;
// a missing member is undefined, never an inherited JavaScript property.
export function pointerTokens(pointer) {
  if (typeof pointer !== 'string' || (pointer !== '' && !pointer.startsWith('/')) || /~(?![01])/u.test(pointer)) {
    throw new TypeError('Invalid JSON Pointer');
  }
  return pointer === '' ? [] : pointer.slice(1).split('/').map(token => token.replace(/~1/g, '/').replace(/~0/g, '~'));
}

function member(value, key) {
  return value !== null && typeof value === 'object' && Object.hasOwn(value, key)
    && (!Array.isArray(value) || /^(0|[1-9][0-9]*)$/.test(key));
}

export function valueAt(value, pointer) {
  for (const key of pointerTokens(pointer)) {
    if (!member(value, key)) return undefined;
    value = value[key];
  }
  return value;
}

// A binding replaces an existing value; it never creates a path or appends to an array.
export function replaceAt(value, pointer, replacement) {
  const keys = pointerTokens(pointer), key = keys.pop();
  if (key === undefined) throw new TypeError('A binding must select a member');
  for (const part of keys) {
    if (!member(value, part)) throw new TypeError('JSON Pointer does not resolve');
    value = value[part];
  }
  if (!member(value, key)) throw new TypeError('JSON Pointer does not resolve');
  Object.defineProperty(value, key, { value: replacement, writable: true, enumerable: true, configurable: true });
}
