import { redirect } from 'react-router';
import { z } from 'zod';
import { Ok } from '../../shared/contracts';
import { Session } from '../../shared/session';
import type { SessionView } from '../../shared/session';
import { ClientFailure, SubmissionPending } from '../../shared/client';
import { Execution } from '../../shared/executions';
import { getIdentity } from './keys';

export class ApiFailure extends Error {
  constructor(
    public code: string,
    public status = 400,
  ) {
    super(code);
  }
}
export async function api<T = unknown>(
  path: string,
  options: { method?: string; body?: unknown; signal?: AbortSignal } = {},
  schema?: z.ZodType<T>,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch('/api' + path, {
      method: options.method ?? 'GET',
      credentials: 'same-origin',
      signal: options.signal,
      ...(options.body !== undefined
        ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(options.body) }
        : {}),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiFailure('network', 0);
  }
  const value: unknown = response.status === 204 ? null : await response.json();
  if (!response.ok)
    throw new ApiFailure(
      response.status === 429
        ? 'rate_limit'
        : ((value as { error?: { code?: string } }).error?.code ?? 'failure'),
      response.status,
    );
  return schema ? schema.parse(value) : (value as T);
}
// A change returns its result or an execution awaiting input or consent.
export const Changed = z.union([Ok, Execution]);
export async function session(request?: Request): Promise<SessionView> {
  return api('/session', { signal: request?.signal }, Session);
}
// Where to come back to. A link's fragment never reaches the loader, so the address bar's is kept when it is this page's.
function here(request: Request) {
  const url = new URL(request.url);
  return encodeURIComponent(url.pathname + url.search + (location.pathname === url.pathname ? location.hash : ''));
}
// Every page past sign-in works with the private key, so a browser that does not hold it stops at one page first.
// A request link's session answers only its own request without the private key, so it does not stop.
export async function holdingKeys(request: Request, principalId: string) {
  if (!(await getIdentity(principalId))) throw redirect('/keys?returnTo=' + here(request));
}
export async function signedIn(request: Request) {
  const data = await session(request);
  if (!data.principal) throw redirect('/signin?returnTo=' + here(request));
  if (data.requestId && new URL(request.url).pathname !== '/requests/' + data.requestId)
    throw redirect('/requests/' + data.requestId);
  if (!data.requestId) await holdingKeys(request, data.principal.id);
  return data;
}
export function safeReturn(value: string | null | undefined, fallback = '/') {
  return value?.startsWith('/') && !value.startsWith('//') && !/[\\\u0000-\u001f]/.test(value)
    ? value
    : fallback;
}
export function formText(form: FormData, name: string) {
  return String(form.get(name) ?? '').trim();
}
export function jsonField<T>(form: FormData, name: string, fallback: T): T {
  const value = formText(form, name);
  try {
    return value ? (JSON.parse(value) as T) : fallback;
  } catch {
    throw new ApiFailure('invalid_json');
  }
}
export function errorCode(error: unknown) {
  return error instanceof SubmissionPending ? 'submission_pending' : error instanceof ApiFailure || error instanceof ClientFailure
    ? error.code
    : error instanceof Error && ['NotAllowedError', 'AbortError', 'WebAuthnError'].includes(error.name)
      ? 'passkey_cancelled'
      : 'failure';
}
export async function actionResult<T>(action: () => Promise<T>) {
  try {
    return await action();
  } catch (error) {
    if (error instanceof Response) throw error;
    return { error: errorCode(error) };
  }
}
export async function upload(
  owner: string,
  file: File,
  name: string,
  existing?: { id: string; version: number },
) {
  const query = new URLSearchParams({
    contentType: file.type || 'application/octet-stream',
    ...(existing ? { version: String(existing.version) } : { name }),
  });
  const response = await fetch(
    existing ? `/api/resources/${existing.id}/content?${query}` : `/api/principals/${owner}/objects?${query}`,
    {
      method: existing ? 'PUT' : 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: file,
    },
  );
  const value = await response.json();
  if (!response.ok) throw new ApiFailure(value.error?.code ?? 'failure', response.status);
  return value as { id: string };
}
