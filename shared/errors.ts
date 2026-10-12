import type { JsonValue } from './contracts.js';

export class DomainError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: JsonValue,
  ) {
    super(message);
  }
}
export function fail(status: number, code: string, message: string, details?: JsonValue): never {
  throw new DomainError(status, code, message, details);
}
