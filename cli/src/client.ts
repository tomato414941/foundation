import { z } from 'zod';
import { Session } from '../../shared/session.js';
import type { IdentityConfig } from './config.js';

export class ApiError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
    readonly details?: unknown,
    // The Foundation server that answered, when one did.
    readonly origin?: string,
  ) {
    super(message);
  }
}
// A server answer this CLI cannot read, as when the server was released with another CLI.
export class UnreadableResponse extends Error {
  constructor(readonly origin: string, readonly path: string, readonly error: z.ZodError) {
    super('Foundation answered ' + path + ' in a form this CLI does not read.');
  }
}
export class Client {
  constructor(readonly identity: IdentityConfig) {}
  async response(
    path: string,
    options: { method?: string; body?: unknown; raw?: Uint8Array; signal?: AbortSignal } = {},
  ): Promise<Response> {
    if (!path.startsWith('/api/') || path.includes('\\') || /[\u0000-\u001f]/.test(path))
      throw new Error('Use a path beginning with /api/.');
    const url = new URL(path, this.identity.origin);
    if (url.origin !== this.identity.origin)
      throw new Error('Use a path on the configured Foundation origin.');
    let response: Response;
    try {
      response = await fetch(url, {
        method: options.method ?? 'GET',
        headers: {
          authorization: 'Bearer ' + this.identity.token,
          ...(options.raw
            ? { 'content-type': 'application/octet-stream' }
            : options.body !== undefined
              ? { 'content-type': 'application/json' }
              : {}),
        },
        body: options.raw
          ? new Uint8Array(options.raw)
          : options.body !== undefined
            ? JSON.stringify(options.body)
            : undefined,
        redirect: 'error',
        signal: AbortSignal.any([AbortSignal.timeout(90_000), ...(options.signal ? [options.signal] : [])]),
      });
    } catch {
      throw new Error('Could not reach Foundation. Check the origin and your network connection.');
    }
    if (!response.ok) {
      let detail;
      try {
        detail = z
          .object({ error: z.object({ code: z.string(), message: z.string(), details: z.unknown().optional() }) })
          .parse(await response.json());
      } catch {
        throw new ApiError(
          'http_error',
          response.status,
          'Foundation returned HTTP ' + response.status + '.',
          undefined,
          this.identity.origin,
        );
      }
      throw new ApiError(detail.error.code, response.status, detail.error.message, detail.error.details, this.identity.origin);
    }
    return response;
  }
  async json<T = unknown>(
    path: string,
    options: { method?: string; body?: unknown; raw?: Uint8Array; signal?: AbortSignal } = {},
    schema?: z.ZodType<T>,
  ): Promise<T> {
    const response = await this.response(path, options);
    const value: unknown = response.status === 204 ? null : await response.json();
    if (!schema) return value as T;
    const parsed = schema.safeParse(value);
    if (!parsed.success) throw new UnreadableResponse(this.identity.origin, path, parsed.error);
    return parsed.data;
  }
  async session() {
    return this.json('/api/session', {}, Session);
  }
}
