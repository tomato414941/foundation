import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import type { AppState, ConnectionState } from '../shared/connections.js';
import { tokenConnectionFacts } from '../shared/connection-facts.js';
import { connectionValues } from '../shared/connection-fields.js';
import { responseJson } from '../shared/http.js';
import type { Transport } from '../shared/http.js';
import { credentialOutput } from '../shared/values.js';
import { fail } from '../shared/errors.js';
import { hash } from '../shared/authority.js';
import type { ConnectionProvider } from './connection-provider.js';

const Session = z.object({ accessToken: z.string().min(1).max(16384).regex(/^\S+$/),
  expiresAt: z.number().int().positive() }).strict();

export async function vultrIdentityToken(source: 'oidc' | 'instance', signal: AbortSignal) {
  if (source === 'oidc') {
    const path = process.env.VULTR_OIDC_TOKEN_FILE;
    const token = path ? await readFile(path, 'utf8') : process.env.VULTR_OIDC_TOKEN;
    if (!token || token.length > 16384) fail(409, 'authentication_required', 'Provide the current OIDC token to this executor.');
    return token.trim();
  }
  // This fixed metadata destination is used only by explicitly approved instance authentication.
  const response = await fetch('http://169.254.169.254/v1/identity/token', {
    redirect: 'error', credentials: 'omit', signal: AbortSignal.any([signal, AbortSignal.timeout(3000)]),
  });
  if (!response.ok) fail(409, 'authentication_required', 'Use a Vultr instance with an IAM role trust.');
  const token = (await response.text()).trim();
  if (!token || token.length > 16384) fail(502, 'invalid_response', 'The instance did not return a valid identity token.');
  return token;
}

function specification(value: ConnectionState) {
  if (value.method.kind !== 'token' || value.method.config.resolver !== 'vultr-role')
    throw new Error('Use a Vultr IAM role connection.');
  return value.method.config;
}

export class VultrRoleConnection implements ConnectionProvider {
  facts = tokenConnectionFacts;
  private sessions = new Map<string, z.infer<typeof Session>>();
  private pending = new Map<string, Promise<z.infer<typeof Session>>>();
  constructor(readonly transport: Transport,
    readonly identityToken: typeof vultrIdentityToken = vultrIdentityToken) {}
  needsRenewal() { return false; }
  private async obtain(value: ConnectionState, signal: AbortSignal) {
    const fields = connectionValues(specification(value).fields, value.fields!);
    const source = fields.authentication;
    if (!['api_key', 'oidc', 'instance'].includes(source!))
      fail(400, 'invalid_field', 'Choose a Vultr authentication source.');
    const credential = source === 'api_key' ? fields.token : fields.credential ||
      await this.identityToken(source as 'oidc' | 'instance', signal);
    if (!credential || credential.length > 16384 || /\s/.test(credential))
      fail(409, 'authentication_required', 'Provide current credentials for the selected authentication source.');
    const duration = Number(fields.duration);
    if (!Number.isSafeInteger(duration) || duration <= 0 || duration > 315_576_000)
      fail(400, 'invalid_field', 'Enter a valid session duration in seconds.');
    const response = await this.transport.send({ url: 'https://api.vultr.com/v2/assumed-roles/assume',
      method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + credential },
      signal, body: JSON.stringify({ role_id: fields.roleId,
        session_name: fields.sessionName, duration, auth_method: source === 'instance' ? 'jwt' : source,
        ...(source === 'api_key' ? { user_id: fields.userId } : {}),
        ...(source === 'oidc' ? { oidc_issuer_id: fields.issuerId } : {}),
      }) });
    if (response.status >= 400) fail(409, 'role_denied', 'Check the role trust, permissions and authentication source in Vultr.');
    const received = responseJson(response);
    if (received.role_id !== undefined && received.role_id !== fields.roleId ||
      source === 'api_key' && received.user_id !== undefined && received.user_id !== fields.userId)
      fail(409, 'role_changed', 'Reconnect to approve the returned role and authentication source.');
    const session = Session.parse({ accessToken: received.session_token,
      expiresAt: typeof received.expires_at === 'string' ? Date.parse(received.expires_at) : NaN });
    if (session.expiresAt <= Date.now()) fail(502, 'invalid_response', 'Vultr returned an expired role session.');
    return session;
  }
  async outputs(value: ConnectionState, _app: AppState | null, signal: AbortSignal) {
    const spec = specification(value);
    signal.throwIfAborted();
    // A generation is caller-supplied; cache credentials by the complete approved material.
    const key = await hash(value);
    let session = this.sessions.get(key);
    if (!session || session.expiresAt < Date.now() + 60_000) {
      let pending = this.pending.get(key);
      if (!pending) {
        pending = this.obtain(value, signal);
        this.pending.set(key, pending);
      }
      try {
        session = await pending;
        this.sessions.set(key, session);
      } finally { if (this.pending.get(key) === pending) this.pending.delete(key); }
    }
    return Object.fromEntries(Object.entries(spec.outputs)
      .map(([key, output]) => [key, credentialOutput(session, output)]));
  }
}
