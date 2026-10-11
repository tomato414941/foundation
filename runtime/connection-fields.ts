import { connectionFields as validate, ConnectionFieldError } from '../shared/connection-fields.js';
import type { ConnectionField } from '../shared/connection-methods.js';
import { fail } from '../server/errors.js';

export function connectionFields(definitions: ConnectionField[], input: Record<string, string>, defaults = {}) {
  try { return validate(definitions, input, defaults); }
  catch (error) { if (error instanceof ConnectionFieldError) fail(400, error.code, error.message); throw error; }
}
