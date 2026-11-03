import { randomUUID } from 'node:crypto';
import { decodeProtectedHeader } from 'jose';
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthenticatorTransport, RegistrationResponseJSON } from '@simplewebauthn/server';
import type { z } from 'zod';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor, Authorization } from './authorization.js';
import type { Audit } from './audit.js';
import { WrappedKey } from '../shared/contracts.js';
import { verifyBinding } from '../shared/authority.js';
import { bindFirst } from './bindings.js';
import type { Configuration } from './config.js';
import type { PublicEncryptionKey } from '../shared/contracts.js';
import type { KeyResetCompletion } from '../shared/session.js';
import { fail, required } from './errors.js';

// Whoever lost every copy of the private key makes new keys. Nothing tells them from whoever took over their email, so
// the request waits a week, and meanwhile anyone signed in as the principal, as on a device that still holds the
// private key, can cancel it. Once ready, the sign-in that asked for it completes it within a month: it registers the
// passkey that will hold the new keys, which the reset keeps aside, and the passkey becomes a way in only together
// with the new keys when the reset completes. Cancelling the reset discards it.
const waiting = 7 * 86_400_000, lasting = 30 * 86_400_000;
interface Pending { name: string; identifier: string; publicKey: string; counter: number; transports: AuthenticatorTransport[]; backedUp: boolean }
interface Reset {
  id: string;
  created_at: Date;
  data: { readyAt: string; requestedBy: { id: string; credentialId: string | null };
    registration?: { challenge: string; name: string }; passkey?: Pending };
}

export class KeyResets {
  readonly rpId: string;
  constructor(readonly db: Database, readonly authorization: Authorization, readonly audit: Audit, readonly config: Configuration) {
    this.rpId = new URL(config.origin).hostname;
  }
  async get(principalId: string, connection: Queryable = this.db.pool) {
    const row = await this.db.one<{ created_at: Date; data: { readyAt: string } }>(
      "SELECT created_at,data FROM challenges WHERE kind='key-reset' AND principal_id=$1 AND expires_at>now()",
      [principalId], connection);
    return row ? { requestedAt: iso(row.created_at), readyAt: iso(row.data.readyAt) } : null;
  }
  async request(actor: Actor, principalId: string) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    if (actor.id !== principalId || !actor.credentialId) fail(403, 'forbidden', 'Sign in as this principal to make its keys again.');
    return this.db.transaction(async connection => {
      const principal = required(await this.db.one<{ public_key: PublicEncryptionKey | null }>(
        'SELECT public_key FROM principals WHERE id=$1 FOR UPDATE', [principalId], connection));
      if (!principal.public_key) fail(409, 'key_missing', 'Register a passkey to make the keys.');
      const pending = await this.get(principalId, connection);
      if (pending) return pending;
      const readyAt = new Date(Date.now() + waiting);
      await connection.query("DELETE FROM challenges WHERE kind='key-reset' AND principal_id=$1", [principalId]);
      await connection.query(
        "INSERT INTO challenges(id,kind,principal_id,data,expires_at) VALUES($1,'key-reset',$2,$3,$4)",
        [randomUUID(), principalId, JSON.stringify({ readyAt: readyAt.toISOString(),
          requestedBy: { id: actor.id, credentialId: actor.credentialId } }), new Date(readyAt.getTime() + lasting)]);
      await this.audit.record(principalId, actor.id, 'principal.requestKeyReset', principalId, {}, connection);
      return required(await this.get(principalId, connection));
    });
  }
  async cancel(actor: Actor, principalId: string) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    const removed = await this.db.pool.query("DELETE FROM challenges WHERE kind='key-reset' AND principal_id=$1", [principalId]);
    if (removed.rowCount) await this.audit.record(principalId, actor.id, 'principal.cancelKeyReset', principalId);
  }
  // The ready reset of the principal, for the sign-in that asked for it while that sign-in remains.
  private async ready(actor: Actor, principalId: string, connection: Queryable, lock = false) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials', connection);
    const reset = await this.db.one<Reset>(
      "SELECT id,created_at,data FROM challenges WHERE kind='key-reset' AND principal_id=$1 AND expires_at>now()" + (lock ? ' FOR UPDATE' : ''),
      [principalId], connection);
    if (!reset || Date.parse(reset.data.readyAt) > Date.now()) fail(409, 'key_reset_waiting', 'Wait until the request to make new keys is ready.');
    if (actor.id !== principalId || !actor.credentialId || reset.data.requestedBy?.credentialId !== actor.credentialId ||
      !await this.db.one('SELECT 1 FROM credentials WHERE id=$1 AND principal_id=$2' + (lock ? ' FOR SHARE' : ''),
        [actor.credentialId, principalId], connection))
      fail(403, 'forbidden', 'Make the new keys with the sign-in that asked for them.');
    return reset;
  }
  // WebAuthn options for the passkey that will hold the new keys.
  async passkeyOptions(actor: Actor, principalId: string, name: string) {
    return this.db.transaction(async connection => {
      const reset = await this.ready(actor, principalId, connection, true);
      const existing = await this.db.all<{ identifier: string; data: { transports: AuthenticatorTransport[] } }>(
        "SELECT identifier,data FROM credentials WHERE principal_id=$1 AND kind='passkey'", [principalId], connection);
      const options = await generateRegistrationOptions({
        rpName: 'Foundation', rpID: this.rpId, userID: new TextEncoder().encode(principalId), userName: name,
        attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: existing.map(row => ({ id: row.identifier, transports: row.data.transports })),
        supportedAlgorithmIDs: [-7, -257],
      });
      await connection.query('UPDATE challenges SET data=(data-\'passkey\')||$2 WHERE id=$1',
        [reset.id, JSON.stringify({ registration: { challenge: options.challenge, name } })]);
      return { options };
    });
  }
  // Keeps the registered passkey with the reset until the reset completes.
  async registerPasskey(actor: Actor, principalId: string, response: unknown) {
    return this.db.transaction(async connection => {
      const reset = await this.ready(actor, principalId, connection, true);
      if (!reset.data.registration) fail(409, 'invalid_challenge', 'Start registering the passkey again.');
      let verification;
      try {
        verification = await verifyRegistrationResponse({ response: response as RegistrationResponseJSON,
          expectedChallenge: reset.data.registration.challenge, expectedOrigin: this.config.origin, expectedRPID: this.rpId,
          requireUserVerification: true });
      } catch { fail(400, 'invalid_passkey', 'The passkey could not be verified.'); }
      if (!verification.verified || !verification.registrationInfo) fail(400, 'invalid_passkey', 'The passkey could not be verified.');
      const { credential, credentialBackedUp } = verification.registrationInfo;
      const passkey: Pending = { name: reset.data.registration.name, identifier: credential.id,
        publicKey: Buffer.from(credential.publicKey).toString('base64url'), counter: credential.counter,
        transports: (credential.transports ?? []) as AuthenticatorTransport[], backedUp: credentialBackedUp };
      await connection.query("UPDATE challenges SET data=(data-'registration')||$2 WHERE id=$1", [reset.id, JSON.stringify({ passkey })]);
      return { identifier: passkey.identifier };
    });
  }
  // Replaces the keys with new ones held by the passkey kept with the reset, which becomes a way in at the same time.
  // The keys that passkeys and API keys held before no longer belong to the principal, and what only they opened is
  // entered again with the new keys, which are bound as an identity's first keys.
  async complete(actor: Actor, principalId: string, input: z.infer<typeof KeyResetCompletion>) {
    const binding = await verifyBinding(input.binding);
    if (binding.principalId !== principalId || decodeProtectedHeader(input.wrappedKey).sub !== principalId)
      fail(400, 'invalid_key_binding', 'Bind and wrap the new keys for this principal.');
    await this.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
      const reset = await this.ready(actor, principalId, connection, true);
      const passkey = reset.data.passkey;
      if (!passkey) fail(409, 'passkey_required', 'Register the passkey that will hold the new keys.');
      await connection.query('DELETE FROM challenges WHERE id=$1', [reset.id]);
      const credentialId = randomUUID();
      await connection.query(
        "INSERT INTO credentials(id,principal_id,kind,name,identifier,data) VALUES($1,$2,'passkey',$3,$4,$5)",
        [credentialId, principalId, passkey.name, passkey.identifier, JSON.stringify({ publicKey: passkey.publicKey,
          counter: passkey.counter, transports: passkey.transports, backedUp: passkey.backedUp })]);
      await connection.query('UPDATE principal_key_bindings SET retired_at=now() WHERE principal_id=$1 AND retired_at IS NULL', [principalId]);
      await connection.query('UPDATE principals SET public_key=NULL WHERE id=$1', [principalId]);
      await bindFirst(connection, this.db, this.audit, actor.id, input.binding);
      await connection.query('UPDATE credentials SET private_wrap=CASE WHEN id=$2 THEN $3 END WHERE principal_id=$1',
        [principalId, credentialId, WrappedKey.parse(input.wrappedKey)]);
      await this.audit.record(principalId, actor.id, 'credential.passkey', credentialId, {}, connection);
      await this.audit.record(principalId, actor.id, 'principal.resetKeys', principalId, {}, connection);
    });
  }
}
