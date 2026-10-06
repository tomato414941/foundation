import { randomUUID } from 'node:crypto';
import { generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, AuthenticatorTransport } from '@simplewebauthn/server';
import { decodeProtectedHeader, importJWK } from 'jose';
import type { Database, Queryable } from './database.js';
import type { Actor } from './authorization.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Authentication } from './authentication.js';
import type { P256PublicKey, PublicEncryptionKey } from '../shared/contracts.js';
import type { KeyMigrationInput } from '../shared/key-migration.js';
import { base64url, encode } from '../shared/encryption.js';
import { digest } from './vault.js';
import { fail } from './errors.js';
import { validateRecipientKeys } from './encryption-validation.js';

interface PasskeyRow {
  id: string;
  name: string;
  identifier: string;
  private_wrap: string;
  data: { publicKey: string; counter: number; transports: AuthenticatorTransport[] };
}
interface MigrationState {
  actorId: string;
  sessionId: string;
  fingerprint: string;
  publicKey: P256PublicKey;
  challenges: Record<string, string>;
}

export class KeyMigration {
  readonly db: Database;
  constructor(readonly resources: Resources, readonly authentication: Authentication) {
    this.db = resources.db;
  }
  private async access(actor: Actor, id: string, connection: Queryable) {
    if (actor.id !== id || !actor.sessionId || actor.requestId)
      fail(403, 'forbidden', 'Sign in as this account to update its encryption key.');
    await this.resources.authorization.active(actor, connection);
    const session = await this.db.one(
      'SELECT id FROM sessions WHERE id=$1 AND principal_id=$2 AND expires_at>now()',
      [actor.sessionId, id], connection,
    );
    if (!session) fail(401, 'unauthenticated', 'Sign in to continue.');
  }
  private async snapshot(actor: Actor, id: string, connection: Queryable) {
    await connection.query('SELECT id FROM principals WHERE id=$1 FOR UPDATE', [id]);
    const principal = await this.resources.principals.get(id, connection);
    if (principal.public_key?.crv !== 'X25519')
      fail(409, 'encryption_key_changed', 'The encryption key is already up to date.');
    const credentials = await this.db.all<PasskeyRow>(
      "SELECT * FROM credentials WHERE principal_id=$1 AND kind='passkey' AND private_wrap IS NOT NULL ORDER BY id FOR UPDATE",
      [id], connection,
    );
    if (!credentials.length) fail(409, 'key_unavailable', 'Use an encryption-capable passkey.');
    const rows = await this.db.all<ResourceRow>(
      `SELECT * FROM resources WHERE kind='secret' AND sealed->'recipients' @> $1::jsonb ORDER BY id FOR UPDATE`,
      [JSON.stringify([{ header: { kid: id } }])], connection,
    );
    const items = [];
    for (const row of rows) {
      await this.resources.authorization.requireResource(actor, row, 'reveal', connection);
      await this.resources.authorization.requireResource(actor, row, 'update', connection);
      const ids = row.sealed!.recipients.map(recipient => recipient.header.kid);
      const keys = await this.db.all<{ id: string; name: string; public_key: PublicEncryptionKey }>(
        'SELECT id,name,public_key FROM principals WHERE id=ANY($1::uuid[]) AND public_key IS NOT NULL ORDER BY id',
        [ids], connection,
      );
      if (keys.length !== ids.length || new Set(ids).size !== ids.length)
        fail(409, 'key_unavailable', 'Every recipient needs an encryption key.');
      items.push({ id: row.id, name: row.name, version: row.version, sealed: row.sealed!,
        recipients: keys.map(key => ({ id: key.id, name: key.name, publicKey: key.public_key })) });
    }
    const fingerprint = digest(JSON.stringify({ publicKey: principal.public_key,
      credentials: credentials.map(credential => [credential.id, credential.identifier, credential.private_wrap, credential.data.publicKey]), items }));
    return { publicKey: principal.public_key, credentials, items, fingerprint };
  }
  async start(actor: Actor, id: string, browser: string, publicKey: P256PublicKey) {
    await importJWK(publicKey, 'ECDH-ES+A256KW');
    return this.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      await this.access(actor, id, connection);
      const snapshot = await this.snapshot(actor, id, connection);
      if (snapshot.items.length > 1000 || Buffer.byteLength(JSON.stringify(snapshot.items)) > 24 * 1024 * 1024)
        fail(409, 'migration_size', 'The encrypted content is too large to update in one operation.');
      const challenges: Record<string, string> = {};
      const credentials = [];
      for (const credential of snapshot.credentials) {
        const options = await generateAuthenticationOptions({
          rpID: this.authentication.rpId, userVerification: 'required',
          allowCredentials: [{ id: credential.identifier, transports: credential.data.transports }],
        });
        challenges[credential.id] = options.challenge;
        credentials.push({ id: credential.id, name: credential.name, wrappedKey: credential.private_wrap,
          options: JSON.parse(JSON.stringify(options)) });
      }
      const challengeId = randomUUID();
      const state: MigrationState = { actorId: actor.id, sessionId: actor.sessionId!, publicKey,
        fingerprint: snapshot.fingerprint, challenges };
      await connection.query(
        "INSERT INTO challenges(id,kind,browser_hash,principal_id,data,expires_at) VALUES($1,'key-migration',$2,$3,$4,now()+interval '15 minutes')",
        [challengeId, digest(browser), id, JSON.stringify(state)],
      );
      return { challengeId, publicKey: snapshot.publicKey, credentials, items: snapshot.items };
    });
  }
  async commit(actor: Actor, id: string, browser: string, input: KeyMigrationInput) {
    await this.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(736023743)');
      await this.access(actor, id, connection);
      const challenge = await this.db.one<{ data: MigrationState }>(
        "DELETE FROM challenges WHERE id=$1 AND kind='key-migration' AND browser_hash=$2 AND principal_id=$3 AND expires_at>now() RETURNING data",
        [input.challengeId, digest(browser), id], connection,
      );
      if (!challenge || challenge.data.actorId !== actor.id || challenge.data.sessionId !== actor.sessionId)
        fail(400, 'invalid_challenge', 'Start the key update again.');
      const state = challenge.data;
      const current = await this.snapshot(actor, id, connection);
      if (current.fingerprint !== state.fingerprint)
        fail(409, 'migration_changed', 'A secret or passkey changed. Start the key update again.');
      if (input.credentials.length !== current.credentials.length ||
          new Set(input.credentials.map(item => item.id)).size !== current.credentials.length ||
          input.items.length !== current.items.length || new Set(input.items.map(item => item.id)).size !== current.items.length)
        fail(400, 'migration_incomplete', 'Include every encrypted secret and passkey.');
      for (const credential of current.credentials) {
        const update = input.credentials.find(item => item.id === credential.id);
        if (!update || decodeProtectedHeader(update.wrappedKey).sub !== id)
          fail(400, 'migration_incomplete', 'Include every encrypted secret and passkey.');
        let verification;
        try {
          const response = update.credential as unknown as AuthenticationResponseJSON;
          if (response.id !== credential.identifier) throw new Error('Credential mismatch');
          verification = await verifyAuthenticationResponse({
            response, expectedChallenge: state.challenges[credential.id]!,
            expectedOrigin: this.authentication.config.origin, expectedRPID: this.authentication.rpId,
            requireUserVerification: true,
            credential: { id: credential.identifier,
              publicKey: new Uint8Array(Buffer.from(credential.data.publicKey, 'base64url')),
              counter: credential.data.counter, transports: credential.data.transports },
          });
        } catch { fail(400, 'invalid_passkey', 'The passkey could not be verified.'); }
        if (!verification.verified) fail(400, 'invalid_passkey', 'The passkey could not be verified.');
        await connection.query('UPDATE credentials SET private_wrap=$2,data=$3,last_used_at=now() WHERE id=$1',
          [credential.id, update.wrappedKey, JSON.stringify({ ...credential.data, counter: verification.authenticationInfo.newCounter })]);
      }
      for (const item of current.items) {
        const update = input.items.find(value => value.id === item.id);
        if (!update || update.version !== item.version) fail(409, 'migration_changed', 'Start the key update again.');
        const addressed = new Set(update.sealed.recipients.map(recipient => recipient.header.kid));
        if (update.sealed.aad !== base64url(encode('resource:' + item.id)) ||
            addressed.size !== item.recipients.length || update.sealed.recipients.length !== addressed.size ||
            item.recipients.some(recipient => !addressed.has(recipient.id)))
          fail(400, 'missing_recipient', 'Keep all current recipients when updating the key.');
        validateRecipientKeys(update.sealed, item.recipients.map(recipient => recipient.id === id
          ? { ...recipient, publicKey: state.publicKey } : recipient));
        await connection.query('UPDATE resources SET sealed=$2,version=version+1,updated_at=now() WHERE id=$1',
          [item.id, JSON.stringify(update.sealed)]);
      }
      await connection.query('UPDATE principals SET public_key=$2 WHERE id=$1', [id, JSON.stringify(state.publicKey)]);
      await this.resources.audit.record(id, actor.id, 'encryption.migrate', id,
        { secrets: current.items.length, passkeys: current.credentials.length }, connection);
    });
  }
}
