import { randomUUID } from 'node:crypto';
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  AuthenticatorTransport,
} from '@simplewebauthn/server';
import { decodeProtectedHeader } from 'jose';
import { z } from 'zod';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Principals } from './principals.js';
import type { Authorization, Actor } from './authorization.js';
import type { Audit } from './audit.js';
import type { Mailer } from './mail.js';
import type { Configuration } from './config.js';
import { Credential, PublicKey, WrappedKey } from '../shared/contracts.js';
import type { PublicEncryptionKey, WrappedEncryptionKey } from '../shared/contracts.js';
import { digest, token } from './vault.js';
import { fail, required } from './errors.js';
import { samePublicKey } from './encryption-validation.js';
import { bindFirst } from './bindings.js';
import type { Confirmations } from './confirmations.js';
import { SignedBinding, verifyBinding } from '../shared/authority.js';

interface PasskeyData {
  publicKey: string;
  counter: number;
  transports: AuthenticatorTransport[];
  backedUp: boolean;
}
interface CredentialRow {
  id: string;
  principal_id: string;
  kind: 'email' | 'passkey' | 'key';
  name: string;
  identifier: string;
  data: PasskeyData;
  private_wrap: string | null;
  created_at: Date;
  last_used_at: Date | null;
  expires_at: Date | null;
}
interface ChallengeRow {
  id: string;
  principal_id: string | null;
  kind: string;
  data: Record<string, unknown>;
  browser_hash: string | null;
  expires_at: Date;
}
export interface SigninResult {
  actor: Actor;
  token: string;
  expiresAt: string;
  returnTo: string;
}
export class Authentication {
  readonly rpId: string;
  constructor(
    readonly db: Database,
    readonly principals: Principals,
    readonly authorization: Authorization,
    readonly audit: Audit,
    readonly mailer: Mailer,
    readonly config: Configuration,
    readonly confirmations: Confirmations,
  ) {
    this.rpId = new URL(config.origin).hostname;
  }
  private returnTo(path = '/') {
    if (!path.startsWith('/') || path.startsWith('//') || path.includes('\\') || /[\u0000-\u001f]/.test(path))
      fail(400, 'invalid_return', 'Choose a page within Foundation.');
    return path;
  }
  async authenticate(value?: string): Promise<Actor | null> {
    if (!value || value.length > 200) return null;
    const hash = digest(value);
    const session = await this.db.one<{
      id: string;
      principal_id: string;
      credential_id: string | null;
      request_id: string | null;
    }>('SELECT * FROM sessions WHERE token_hash=$1 AND expires_at>now()', [hash]);
    if (session) {
      const actor: Actor = {
        id: session.principal_id,
        sessionId: session.id,
        ...(session.credential_id ? { credentialId: session.credential_id } : {}),
        ...(session.request_id ? { requestId: session.request_id } : {}),
      };
      try {
        await this.authorization.active(actor);
        return actor;
      } catch {
        return null;
      }
    }
    const credential = await this.db.one<CredentialRow>(
      "UPDATE credentials SET last_used_at=now() WHERE kind='key' AND identifier=$1 AND (expires_at IS NULL OR expires_at>now()) RETURNING *",
      [hash],
    );
    if (!credential) return null;
    const actor: Actor = { id: credential.principal_id, credentialId: credential.id };
    try {
      await this.authorization.active(actor);
      return actor;
    } catch {
      return null;
    }
  }
  async session(
    principalId: string,
    credentialId?: string,
    connection: Queryable = this.db.pool,
    requestId?: string,
  ): Promise<SigninResult> {
    const raw = 'fs_' + token(),
      id = randomUUID(),
      expires = new Date(Date.now() + (requestId ? 30 * 60_000 : 14 * 86400_000));
    await connection.query(
      'INSERT INTO sessions(id,token_hash,principal_id,credential_id,request_id,expires_at) VALUES($1,$2,$3,$4,$5,$6)',
      [id, digest(raw), principalId, credentialId ?? null, requestId ?? null, expires],
    );
    return {
      actor: {
        id: principalId,
        sessionId: id,
        ...(credentialId ? { credentialId } : {}),
        ...(requestId ? { requestId } : {}),
      },
      token: raw,
      expiresAt: iso(expires),
      returnTo: '/',
    };
  }
  async signout(actor: Actor | null) {
    if (actor?.sessionId) await this.db.pool.query('DELETE FROM sessions WHERE id=$1', [actor.sessionId]);
  }
  async issueKey(
    principalId: string,
    name: string,
    expiresAt: string | null = null,
    environmentId: string | null = null,
    connection: Queryable = this.db.pool,
    encryptionKey?: PublicEncryptionKey,
  ) {
    const raw = 'fk_' + token(),
      id = randomUUID();
    const count = await this.db.one<{ count: string }>(
      'SELECT count(*) FROM credentials WHERE principal_id=$1',
      [principalId],
      connection,
    );
    if (Number(count?.count) >= 100)
      fail(409, 'credential_limit', 'Remove an unused credential before adding another.');
    const result = await this.db.one<CredentialRow>(
      `INSERT INTO credentials(id,principal_id,kind,name,identifier,expires_at,environment_id,data)
      VALUES($1,$2,'key',$3,$4,$5,$6,$7) RETURNING *`,
      [
        id,
        principalId,
        name,
        digest(raw),
        expiresAt,
        environmentId,
        JSON.stringify(encryptionKey ? { publicKey: PublicKey.parse(encryptionKey) } : {}),
      ],
      connection,
    );
    return { credential: this.credentialView(required(result)), token: raw };
  }
  // Registers an identity with the keys it signed for itself, and the API key it signs in with.
  async enroll(name: string, input: z.infer<typeof SignedBinding>) {
    const binding = await verifyBinding(input);
    return this.db.transaction(async (connection) => {
      const principal = await this.principals.create(name, binding.encryption, undefined, connection, binding.principalId);
      await bindFirst(connection, this.db, this.audit, principal.id, input);
      const result = await this.issueKey(principal.id, name, null, null, connection);
      await this.audit.record(principal.id, principal.id, 'principal.enroll', principal.id, {}, connection);
      return { principal: { id: principal.id, name: principal.name }, ...result };
    });
  }
  async credentials(actor: Actor, id: string) {
    await this.authorization.requirePrincipal(actor, id, 'manage_credentials');
    return (
      await this.db.all<CredentialRow>(
        'SELECT * FROM credentials WHERE principal_id=$1 ORDER BY created_at,id',
        [id],
      )
    ).map((row) => this.credentialView(row));
  }
  private credentialView(row: CredentialRow) {
    return Credential.parse({
      id: row.id,
      kind: row.kind,
      name: row.name,
      createdAt: iso(row.created_at),
      lastUsedAt: row.last_used_at ? iso(row.last_used_at) : null,
      expiresAt: row.expires_at ? iso(row.expires_at) : null,
      canOpen: row.private_wrap !== null,
    });
  }
  // Issues an API key, wrapping the private keys for it when given, once the actor confirms it.
  async issue(actor: Actor, principalId: string, input: {
    name: string; expiresAt: string | null; wrap?: { wrappedKey: WrappedEncryptionKey; publicKey: PublicEncryptionKey };
  }) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    if (input.expiresAt && Date.parse(input.expiresAt) <= Date.now()) fail(400, 'invalid_expiry', 'Choose a future expiry.');
    if (input.wrap && decodeProtectedHeader(input.wrap.wrappedKey).sub !== principalId)
      fail(400, 'invalid_envelope', 'Wrap the key for this account.');
    return this.db.transaction(async (connection) => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
      await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials', connection);
      await this.confirmations.consume(connection, actor, { action: 'credential.issue', principalId, name: input.name,
        expiresAt: input.expiresAt, ...(input.wrap ? { wrap: input.wrap } : {}) });
      if (input.wrap && !samePublicKey((await this.principals.get(principalId, connection)).public_key, input.wrap.publicKey))
        fail(409, 'encryption_key_changed', 'The encryption key changed. Unlock it again.');
      const issued = await this.issueKey(principalId, input.name, input.expiresAt, null, connection);
      if (input.wrap)
        await connection.query('UPDATE credentials SET private_wrap=$2 WHERE id=$1',
          [issued.credential.id, WrappedKey.parse(input.wrap.wrappedKey)]);
      await this.audit.record(principalId, actor.id, 'credential.issue', issued.credential.id, {}, connection);
      return { credential: { ...issued.credential, canOpen: !!input.wrap }, token: issued.token };
    });
  }
  // Removes a sign-in method, with a confirmation made by a way in other than the identity's keys where the principal
  // has one when it removes such a way in.
  async removeCredential(actor: Actor, principalId: string, id: string) {
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    await this.db.transaction(async (connection) => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
      await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials', connection);
      const target = required(
        await this.db.one<{ kind: string; environment_id: string | null; expires_at: Date | null }>(
          'SELECT kind,environment_id,expires_at FROM credentials WHERE id=$1 AND principal_id=$2',
          [id, principalId],
          connection,
        ),
      );
      // Only the API key making the call gives itself up without a confirmation. A passkey or email address is a way
      // back in, which a session signed in with it must not remove on its own.
      if (target.kind !== 'key' || id !== actor.credentialId)
        await this.confirmations.consume(connection, actor, { action: 'credential.remove', principalId, credentialId: id });
      const count = await this.db.one<{ count: string }>(
        'SELECT count(*) FROM credentials WHERE principal_id=$1 AND environment_id IS NULL AND (expires_at IS NULL OR expires_at>now())',
        [principalId],
        connection,
      );
      if (
        Number(count?.count) <= 1 &&
        !target.environment_id &&
        (!target.expires_at || target.expires_at.getTime() > Date.now())
      )
        fail(409, 'last_credential', 'Add another sign-in method before removing the last one.');
      await connection.query('DELETE FROM credentials WHERE id=$1 AND principal_id=$2', [id, principalId]);
      await this.audit.record(principalId, actor.id, 'credential.remove', id, {}, connection);
    });
  }
  async beginEmail(
    address: string,
    browser: string,
    returnTo = '/',
    locale: 'ja' | 'en' = 'ja',
    actor?: Actor,
    principalId?: string,
    mergeTo?: string,
  ) {
    if (!this.mailer.enabled) fail(503, 'email_unavailable', 'Email sign-in is not configured.');
    const email = z.email().max(254).parse(address).trim().toLowerCase();
    if (principalId) {
      if (!actor) fail(401, 'unauthenticated', 'Sign in to add an email address.');
      await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    }
    if (mergeTo && (!actor || actor.id !== mergeTo || actor.requestId))
      fail(403, 'forbidden', 'Sign in to the account you want to keep.');
    const browserHash = digest(browser);
    const recent = await this.db.one<{ created_at: Date }>(
      "SELECT created_at FROM challenges WHERE kind='email' AND data->>'email'=$1 AND created_at>now()-interval '1 minute' ORDER BY created_at DESC LIMIT 1",
      [email],
    );
    if (recent) fail(429, 'wait_before_retry', 'Wait a minute before sending another email.');
    const id = randomUUID(),
      secret = token(),
      expires = new Date(Date.now() + 15 * 60_000),
      path = this.returnTo(returnTo);
    const link = new URL('/signin/email', this.config.origin);
    link.hash = new URLSearchParams({ challenge: id, token: secret }).toString();
    // Adding an address takes a confirmation, used only once the link is on its way; the link then adds it while
    // the sign-in that confirmed it remains.
    await this.db.transaction(async (connection) => {
      if (principalId) {
        await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
        await this.authorization.requirePrincipal(actor!, principalId, 'manage_credentials', connection);
        await this.confirmations.consume(connection, actor!, { action: 'credential.addEmail', principalId, email });
      }
      await connection.query(
        "INSERT INTO challenges(id,kind,browser_hash,principal_id,data,expires_at) VALUES($1,'email',$2,$3,$4,$5)",
        [
          id,
          browserHash,
          principalId ?? null,
          JSON.stringify({ email, tokenHash: digest(secret), returnTo: path, ...(mergeTo ? { mergeTo } : {}),
            ...(principalId ? { addedBy: { id: actor!.id, credentialId: actor!.credentialId } } : {}) }),
          expires,
        ],
      );
      try {
        await this.mailer.send(email, link.href, locale);
      } catch {
        fail(502, 'email_failed', 'The email could not be sent. Try again.');
      }
    });
    return { email, expiresAt: iso(expires), resendAt: new Date(Date.now() + 60_000).toISOString() };
  }
  async pendingEmail(browser: string) {
    const row = await this.db.one<ChallengeRow>(
      "SELECT * FROM challenges WHERE kind='email' AND browser_hash=$1 AND expires_at>now() ORDER BY created_at DESC LIMIT 1",
      [digest(browser)],
    );
    return row ? { email: String(row.data.email), expiresAt: iso(row.expires_at) } : null;
  }
  async verifyEmail(
    id: string,
    secret: string,
  ): Promise<
    | SigninResult
    | { attached: true; returnTo: string }
    | { mergeProof: string; returnTo: string }
    | { registrationProof: string; email: string; returnTo: string }
  > {
    const attempted = await this.db.one<ChallengeRow>(
      "UPDATE challenges SET attempts=attempts+1 WHERE id=$1 AND kind='email' AND expires_at>now() AND attempts<5 RETURNING *",
      [id],
    );
    if (!attempted || attempted.data.tokenHash !== digest(secret))
      fail(400, 'invalid_link', 'This link is invalid or has expired.');
    return this.db.transaction(async (connection) => {
      const challenge = required(
        await this.db.one<ChallengeRow>('DELETE FROM challenges WHERE id=$1 RETURNING *', [id], connection),
        'This link has already been used.',
      );
      const email = String(challenge.data.email);
      const credential = await this.db.one<CredentialRow>(
        "SELECT * FROM credentials WHERE kind='email' AND identifier=$1",
        [email],
        connection,
      );
      if (typeof challenge.data.mergeTo === 'string') {
        if (!credential) fail(400, 'account_not_found', 'This email address is not registered.');
        if (credential.principal_id === challenge.data.mergeTo)
          fail(400, 'same_account', 'This address already belongs to the account you are keeping.');
        const proof = randomUUID();
        await connection.query(
          "INSERT INTO challenges(id,kind,principal_id,data,expires_at) VALUES($1,'merge',$2,$3,now()+interval '10 minutes')",
          [
            proof,
            challenge.data.mergeTo,
            JSON.stringify({ from: credential.principal_id, credentialId: credential.id }),
          ],
        );
        return { mergeProof: proof, returnTo: '/account?merge=' + proof };
      }
      if (challenge.principal_id) {
        await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [challenge.principal_id]);
        const addedBy = challenge.data.addedBy as { id: string; credentialId: string } | undefined;
        if (!addedBy || !await this.db.one('SELECT 1 FROM credentials WHERE id=$1 AND principal_id=$2 FOR SHARE',
          [addedBy.credentialId, addedBy.id], connection) ||
          !await this.authorization.holds(addedBy.id, { type: 'principal', id: challenge.principal_id }, 'manage_credentials', connection))
          fail(400, 'invalid_link', 'The sign-in that added this address no longer manages this principal.');
        if (credential && credential.principal_id !== challenge.principal_id)
          fail(
            409,
            'email_in_use',
            'This address belongs to another principal. Merge the accounts to use it here.',
          );
        if (!credential)
          await connection.query(
            "INSERT INTO credentials(id,principal_id,kind,name,identifier) VALUES($1,$2,'email',$3,$3)",
            [randomUUID(), challenge.principal_id, email],
          );
        await this.audit.record(
          challenge.principal_id,
          challenge.principal_id,
          'credential.email',
          null,
          {},
          connection,
        );
        return { attached: true, returnTo: String(challenge.data.returnTo) };
      }
      const returnTo = String(challenge.data.returnTo);
      // An unregistered address proves who it is but does not sign up until the person asks to.
      if (!credential) {
        const proof = randomUUID();
        await connection.query(
          "INSERT INTO challenges(id,kind,data,expires_at) VALUES($1,'email-registration',$2,now()+interval '15 minutes')",
          [proof, JSON.stringify({ email, returnTo })],
        );
        return { registrationProof: proof, email, returnTo };
      }
      await connection.query('UPDATE credentials SET last_used_at=now() WHERE id=$1', [credential.id]);
      await this.audit.record(
        credential.principal_id,
        credential.principal_id,
        'session.signin',
        credential.id,
        {},
        connection,
      );
      return { ...(await this.session(credential.principal_id, credential.id, connection)), returnTo };
    });
  }
  async registerEmail(proof: string, name?: string): Promise<SigninResult> {
    return this.db.transaction(async (connection) => {
      const challenge = await this.db.one<ChallengeRow>(
        "DELETE FROM challenges WHERE id=$1 AND kind='email-registration' AND expires_at>now() RETURNING *",
        [proof],
        connection,
      );
      if (!challenge) fail(400, 'invalid_proof', 'This registration has expired. Sign in with your email again.');
      const email = String(challenge.data.email);
      if (
        await this.db.one(
          "SELECT id FROM credentials WHERE kind='email' AND identifier=$1",
          [email],
          connection,
        )
      )
        fail(409, 'email_in_use', 'This address is already registered. Sign in instead.');
      const principal = await this.principals.create(
        name || email.split('@')[0] || 'Foundation',
        null,
        undefined,
        connection,
      );
      const credential = required(
        await this.db.one<CredentialRow>(
          "INSERT INTO credentials(id,principal_id,kind,name,identifier,last_used_at) VALUES($1,$2,'email',$3,$3,now()) RETURNING *",
          [randomUUID(), principal.id, email],
          connection,
        ),
      );
      await this.audit.record(principal.id, principal.id, 'session.signin', credential.id, {}, connection);
      return {
        ...(await this.session(principal.id, credential.id, connection)),
        returnTo: String(challenge.data.returnTo),
      };
    });
  }
  async passkeyOptions(
    browser: string,
    input: { intent: 'register' | 'authenticate'; name?: string; principalId?: string; credentialId?: string; returnTo?: string },
    actor?: Actor,
  ) {
    if (input.credentialId && (input.intent !== 'authenticate' || !input.principalId))
      fail(400, 'invalid_input', 'Name the principal whose passkey authenticates.');
    const id = randomUUID(),
      browserHash = digest(browser),
      returnTo = this.returnTo(input.returnTo);
    if (input.intent === 'register') {
      if (input.principalId) {
        if (!actor) fail(401, 'unauthenticated', 'Sign in to add a passkey.');
        await this.authorization.requirePrincipal(actor, input.principalId, 'manage_credentials');
      }
      const principalId = input.principalId ?? randomUUID(),
        name = input.name?.trim() || 'Foundation ' + principalId.slice(0, 6);
      const existing = input.principalId
        ? await this.db.all<CredentialRow>(
            "SELECT * FROM credentials WHERE principal_id=$1 AND kind='passkey'",
            [principalId],
          )
        : [];
      const options = await generateRegistrationOptions({
        rpName: 'Foundation',
        rpID: this.rpId,
        userID: new TextEncoder().encode(principalId),
        userName: name,
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        excludeCredentials: existing.map((row) => ({ id: row.identifier, transports: row.data.transports })),
        supportedAlgorithmIDs: [-7, -257],
      });
      await this.db.pool.query(
        "INSERT INTO challenges(id,kind,browser_hash,principal_id,data,expires_at) VALUES($1,'passkey-register',$2,$3,$4,now()+interval '5 minutes')",
        [
          id,
          browserHash,
          input.principalId ?? null,
          JSON.stringify({ challenge: options.challenge, principalId, name, returnTo,
            publicKey: input.principalId ? (await this.principals.get(principalId)).public_key : null,
            // A passkey for an existing principal is added by the sign-in that asked, wherever it calls from.
            ...(input.principalId ? { signin: { credentialId: actor!.credentialId ?? null, sessionId: actor!.sessionId ?? null } } : {}) }),
        ],
      );
      return { challengeId: id, principalId, options };
    }
    const credentials = input.principalId ? await this.answering(input.principalId, input.credentialId) : null;
    const options = await generateAuthenticationOptions({
      rpID: this.rpId,
      userVerification: 'required',
      ...(credentials
        ? {
            allowCredentials: credentials.map((row) => ({
              id: row.identifier,
              transports: row.data.transports,
            })),
          }
        : {}),
    });
    await this.db.pool.query(
      "INSERT INTO challenges(id,kind,browser_hash,data,expires_at) VALUES($1,'passkey-authenticate',$2,$3,now()+interval '5 minutes')",
      [
        id,
        browserHash,
        JSON.stringify({ challenge: options.challenge, principalId: input.principalId ?? null, returnTo }),
      ],
    );
    return { challengeId: id, principalId: input.principalId ?? null, options };
  }
  // The passkeys that may answer for a principal: the one named, to be handed the private key, or else those that hold
  // the private key, since the principal's other passkeys cannot open it.
  private async answering(principalId: string, credentialId?: string) {
    const passkeys = await this.db.all<CredentialRow>(
      "SELECT * FROM credentials WHERE principal_id=$1 AND kind='passkey'",
      [principalId],
    );
    if (credentialId) return [required(passkeys.find((row) => row.id === credentialId), 'The passkey was not found.')];
    if (!passkeys.length) fail(409, 'passkey_required', 'Add a passkey to this principal.');
    if (!(await this.principals.get(principalId)).public_key) return passkeys;
    const holding = passkeys.filter((row) => row.private_wrap !== null);
    if (!holding.length) fail(409, 'wrapped_key_required', 'None of the passkeys holds the private key.');
    return holding;
  }
  async verifyPasskey(
    browser: string,
    input: { challengeId: string; credential: unknown; binding?: z.infer<typeof SignedBinding>; existingPublicKey?: PublicEncryptionKey;
      wrappedKey?: WrappedEncryptionKey },
    actor?: Actor,
  ): Promise<
    SigninResult & {
      credentialId: string;
      principalId: string;
      wrappedKey: string | null;
      publicKey: PublicEncryptionKey | null;
    }
  > {
    const found = await this.db.one<ChallengeRow>(
      "SELECT * FROM challenges WHERE id=$1 AND kind LIKE 'passkey-%' AND expires_at>now() AND (browser_hash=$2 OR principal_id IS NOT NULL)",
      [input.challengeId, digest(browser)],
    );
    // A passkey for an existing principal is added by the sign-in that asked for it, once that sign-in confirms the
    // change, and its challenge is used up with the change. Other ceremonies use theirs up at once.
    const adding = found?.kind === 'passkey-register' && !!found.principal_id;
    if (adding) {
      const signin = found!.data.signin as { credentialId: string | null; sessionId: string | null } | undefined;
      if (!actor || !signin || signin.credentialId !== (actor.credentialId ?? null) || signin.sessionId !== (actor.sessionId ?? null))
        fail(400, 'invalid_challenge', 'Start the passkey operation again.');
    }
    const row = adding ? found : found && await this.db.one<ChallengeRow>(
      'DELETE FROM challenges WHERE id=$1 AND browser_hash=$2 RETURNING *', [input.challengeId, digest(browser)]);
    if (!row) fail(400, 'invalid_challenge', 'Start the passkey operation again.');
    let principalId: string, credentialId: string, wrappedKey: string | null;
    if (row.kind === 'passkey-register') {
      if (row.principal_id) {
        if (!actor) fail(401, 'unauthenticated', 'Sign in to add a passkey.');
        await this.authorization.requirePrincipal(actor, row.principal_id, 'manage_credentials');
      }
      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: input.credential as RegistrationResponseJSON,
          expectedChallenge: String(row.data.challenge),
          expectedOrigin: this.config.origin,
          expectedRPID: this.rpId,
          requireUserVerification: true,
        });
      } catch {
        fail(400, 'invalid_passkey', 'The passkey could not be verified.');
      }
      if (!verification.verified || !verification.registrationInfo)
        fail(400, 'invalid_passkey', 'The passkey could not be verified.');
      const info = verification.registrationInfo;
      principalId = String(row.data.principalId);
      credentialId = randomUUID();
      wrappedKey = input.wrappedKey ? WrappedKey.parse(input.wrappedKey) : null;
      const binding = input.binding ? await verifyBinding(input.binding) : null;
      if (binding && binding.principalId !== principalId) fail(400, 'invalid_key_binding', 'Bind the keys to this principal.');
      await this.db.transaction(async (connection) => {
        if (row.principal_id) {
          await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
          await this.authorization.requirePrincipal(actor!, principalId, 'manage_credentials', connection);
          await this.confirmations.consume(connection, actor!, { action: 'credential.addPasskey', principalId,
            challengeId: row.id, ...(input.binding ? { binding: input.binding } : {}), ...(wrappedKey ? { wrappedKey } : {}),
            ...(input.existingPublicKey ? { existingPublicKey: input.existingPublicKey } : {}) });
          if (!await this.db.one('DELETE FROM challenges WHERE id=$1 RETURNING id', [row.id], connection))
            fail(400, 'invalid_challenge', 'Start the passkey operation again.');
          const current = await this.principals.get(principalId, connection);
          if (wrappedKey && !binding && !samePublicKey(current.public_key, (row.data.publicKey ?? null) as PublicEncryptionKey | null))
            fail(409, 'encryption_key_changed', 'The encryption key changed. Add the passkey again.');
          if (wrappedKey && current.public_key && !samePublicKey(current.public_key, input.existingPublicKey ?? null))
            fail(409, 'encryption_key_changed', 'The encryption key changed. Add the passkey again.');
        } else
          await this.principals.create(String(row.data.name), binding?.encryption ?? null, undefined, connection, principalId);
        if (input.binding) await bindFirst(connection, this.db, this.audit, actor?.id ?? principalId, input.binding);
        await connection.query(
          "INSERT INTO credentials(id,principal_id,kind,name,identifier,data,private_wrap) VALUES($1,$2,'passkey',$3,$4,$5,$6)",
          [
            credentialId,
            principalId,
            String(row.data.name),
            info.credential.id,
            JSON.stringify({
              publicKey: Buffer.from(info.credential.publicKey).toString('base64url'),
              counter: info.credential.counter,
              transports: info.credential.transports ?? [],
              backedUp: info.credentialBackedUp,
            }),
            wrappedKey,
          ],
        );
        await this.audit.record(
          principalId,
          actor?.id ?? principalId,
          'credential.passkey',
          credentialId,
          {},
          connection,
        );
      });
    } else {
      const response = input.credential as AuthenticationResponseJSON;
      const credential = await this.db.one<CredentialRow>(
        "SELECT * FROM credentials WHERE kind='passkey' AND identifier=$1",
        [typeof response?.id === 'string' ? response.id : ''],
      );
      if (!credential || (row.data.principalId && credential.principal_id !== row.data.principalId))
        fail(400, 'invalid_passkey', 'The passkey could not be verified.');
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response,
          expectedChallenge: String(row.data.challenge),
          expectedOrigin: this.config.origin,
          expectedRPID: this.rpId,
          requireUserVerification: true,
          credential: {
            id: credential.identifier,
            publicKey: new Uint8Array(Buffer.from(credential.data.publicKey, 'base64url')),
            counter: credential.data.counter,
            transports: credential.data.transports,
          },
        });
      } catch {
        fail(400, 'invalid_passkey', 'The passkey could not be verified.');
      }
      if (!verification.verified) fail(400, 'invalid_passkey', 'The passkey could not be verified.');
      const changed = await this.db.pool.query(
        "UPDATE credentials SET data=$2,last_used_at=now() WHERE id=$1 AND (data->>'counter')::bigint=$3",
        [
          credential.id,
          JSON.stringify({ ...credential.data, counter: verification.authenticationInfo.newCounter }),
          credential.data.counter,
        ],
      );
      if (!changed.rowCount) fail(409, 'passkey_changed', 'Another passkey operation completed. Try again.');
      principalId = credential.principal_id;
      credentialId = credential.id;
      wrappedKey = credential.private_wrap;
      await this.audit.record(principalId, principalId, 'session.signin', credentialId);
    }
    const principal = await this.principals.get(principalId);
    return {
      ...(await this.session(principalId, credentialId)),
      returnTo: String(row.data.returnTo),
      principalId,
      credentialId,
      wrappedKey,
      publicKey: principal.public_key,
    };
  }
  async setWrap(actor: Actor, principalId: string, credentialId: string, value: WrappedEncryptionKey, publicKey: PublicEncryptionKey) {
    if (actor.id !== principalId) fail(403, 'forbidden', 'Sign in as this principal to wrap its key.');
    await this.db.transaction(async connection => {
      await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [principalId]);
      const principal = await this.principals.get(principalId, connection);
      if (!samePublicKey(principal.public_key, publicKey))
        fail(409, 'encryption_key_changed', 'The encryption key changed. Unlock it again.');
      if (decodeProtectedHeader(value).sub !== principalId)
        fail(400, 'invalid_envelope', 'Wrap the key for this account.');
      if (!await this.db.one('SELECT 1 FROM credentials WHERE id=$1 AND principal_id=$2', [credentialId, principalId], connection))
        fail(404, 'not_found', 'The credential was not found.');
      await this.confirmations.consume(connection, actor, { action: 'credential.wrap', principalId, credentialId,
        wrappedKey: WrappedKey.parse(value), publicKey });
      const changed = await connection.query(
        'UPDATE credentials SET private_wrap=$3 WHERE id=$1 AND principal_id=$2',
        [credentialId, principalId, WrappedKey.parse(value)],
      );
      if (!changed.rowCount) fail(404, 'not_found', 'The credential was not found.');
    });
  }
  async wrapOf(actor: Actor | null): Promise<WrappedEncryptionKey | null> {
    if (!actor?.credentialId) return null;
    const row = await this.db.one<{ private_wrap: string | null }>(
      'SELECT private_wrap FROM credentials WHERE id=$1 AND principal_id=$2',
      [actor.credentialId, actor.id],
    );
    return row?.private_wrap ? WrappedKey.parse(row.private_wrap) : null;
  }
}
