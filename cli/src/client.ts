import { createInterface } from 'node:readline/promises';
import { z } from 'zod';
import { Session } from '../../shared/session.js';
import { ConfirmationNeeded, confirmOperation, confirmationCodes, confirmationHeader, decryptionContext, signConfirmation } from '../../shared/confirmations.js';
import { decode, open } from '../../shared/encryption.js';
import type { ConfirmationView } from '../../shared/confirmations.js';
import type { IdentityConfig } from './config.js';

export class ApiError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}
export class Client {
  constructor(readonly identity: IdentityConfig) {}
  async response(
    path: string,
    options: { method?: string; body?: unknown; raw?: Uint8Array; signal?: AbortSignal; confirmation?: string } = {},
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
          ...(options.confirmation ? { [confirmationHeader]: options.confirmation } : {}),
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
        );
      }
      const needed = ConfirmationNeeded.safeParse(detail.error.details);
      if (!options.confirmation && confirmationCodes.includes(detail.error.code) && needed.success)
        return this.response(path, { ...options, confirmation: await this.confirm(needed.data) });
      throw new ApiError(detail.error.code, response.status, detail.error.message, detail.error.details);
    }
    return response;
  }
  // Confirms a change with this identity's keys, or with a code sent by email when someone is at the terminal. When
  // neither is possible here, the error names the confirmation started for the change, so that it can be proved
  // through the API elsewhere and the same request sent again with it.
  private confirm(needed: ConfirmationNeeded) {
    return confirmOperation(this, needed, async (view: ConfirmationView) => {
      const { keys, binding } = this.identity;
      if (view.methods.includes('signature') && keys && binding?.id === view.challenge.bindingId)
        return { method: 'signature', signature: await signConfirmation(view, keys.signing) };
      if (view.methods.includes('decryption') && keys && view.sealed)
        return { method: 'decryption', secret: decode(await open(view.sealed, keys.encryption, view.id, decryptionContext(view.id))) };
      if (view.methods.includes('email') && process.stdin.isTTY && process.stderr.isTTY) {
        const { email } = await this.json<{ email: string }>('/api/confirmations/' + view.id + '/email', { method: 'POST', body: {} });
        const terminal = createInterface({ input: process.stdin, output: process.stderr });
        try { return { method: 'email', code: await terminal.question('Enter the confirmation code sent to ' + email + ': ') }; }
        finally { terminal.close(); }
      }
      throw new ApiError('confirmation_required', 403, 'Prove confirmation ' + view.id + ' with ' + view.methods.join(' or ') +
        ' through /api/confirmations/' + view.id + ', then send the same request again with it' +
        ' (foundation api --confirmation ' + view.id + ').', { ...needed, confirmationId: view.id });
    });
  }
  async json<T = unknown>(
    path: string,
    options: { method?: string; body?: unknown; raw?: Uint8Array; signal?: AbortSignal; confirmation?: string } = {},
    schema?: z.ZodType<T>,
  ): Promise<T> {
    const response = await this.response(path, options);
    const value: unknown = response.status === 204 ? null : await response.json();
    return schema ? schema.parse(value) : (value as T);
  }
  async session() {
    return this.json('/api/session', {}, Session);
  }
}
