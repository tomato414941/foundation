import safeRegex from 'safe-regex2';
import type { ConnectionField } from '../shared/connection-methods.js';
import { fail } from '../server/errors.js';

export function connectionFields(definitions: ConnectionField[], input: Record<string, string>, defaults = {}) {
  const values: Record<string, string> = { ...defaults, ...input };
  for (const field of definitions) {
    if (field.required !== false && !values[field.name]) fail(400, 'missing_field', 'Complete the required service fields.');
    if (values[field.name]?.includes('\0')) fail(400, 'invalid_field', 'Check the service fields.');
    if (field.pattern && (field.pattern.length > 200 || !safeRegex(field.pattern)))
      fail(400, 'invalid_pattern', 'Use a simple field validation pattern.');
    if (field.pattern && values[field.name] && !new RegExp(field.pattern, 'u').test(values[field.name]!.slice(0, 1000)))
      fail(400, 'invalid_field', 'Check the service fields.');
  }
  if (Object.keys(input).some(key => !definitions.some(field => field.name === key)))
    fail(400, 'invalid_field', 'Remove unrecognized service fields.');
  return values;
}
