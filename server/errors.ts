import { z } from 'zod';
import type { JsonValue } from '../shared/contracts.js';

export class DomainError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly details?: JsonValue) { super(message); }
}
export function fail(status: number, code: string, message: string, details?: JsonValue): never { throw new DomainError(status, code, message, details); }
export function required<T>(value: T | null | undefined, message = 'The requested item was not found.'): T {
  if (value === null || value === undefined) fail(404, 'not_found', message);
  return value;
}
export function failure(error: unknown): DomainError {
  if (error instanceof DomainError) return error;
  if (error instanceof z.ZodError) return new DomainError(400, 'invalid_input', 'Check the supplied values.', error.issues.map(issue => ({ path: issue.path.map(String).join('.'), message: issue.message })));
  const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
  if (code === '23505') return new DomainError(409, 'already_exists', 'An item with this name or identity already exists.');
  if (code === '23503') return new DomainError(409, 'in_use', 'Another item still uses this item.');
  if (code === '23514' || code === '22P02') return new DomainError(400, 'invalid_input', 'Check the supplied values.');
  return new DomainError(500, 'internal_error', 'The operation could not be completed.');
}
