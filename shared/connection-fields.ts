import safeRegex from 'safe-regex2';
import type { ConnectionField } from './connection-methods.js';

export class ConnectionFieldError extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}

export function connectionFields(definitions: ConnectionField[], input: Record<string, string>, defaults = {}) {
  const reject = (code: string, message: string): never => { throw new ConnectionFieldError(code, message); };
  const values: Record<string, string> = { ...defaults, ...input };
  for (const field of definitions) {
    if (field.required !== false && !values[field.name]) reject('missing_field', 'Complete the required service fields.');
    if (values[field.name]?.includes('\0')) reject('invalid_field', 'Check the service fields.');
    if (field.pattern && (field.pattern.length > 200 || !safeRegex(field.pattern)))
      reject('invalid_pattern', 'Use a simple field validation pattern.');
    if (field.pattern && values[field.name] && !new RegExp(field.pattern, 'u').test(values[field.name]!.slice(0, 1000)))
      reject('invalid_field', 'Check the service fields.');
  }
  if (Object.keys(input).some(key => !definitions.some(field => field.name === key)))
    reject('invalid_field', 'Remove unrecognized service fields.');
  return values;
}
