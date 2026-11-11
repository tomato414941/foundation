import { randomInt, randomUUID } from 'node:crypto';
import { generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { AuthenticationResponseJSON, AuthenticatorTransport } from '@simplewebauthn/server';
import type { Database, Queryable } from './database.js';
import { iso } from './database.js';
import type { Actor } from './authorization.js';
import type { Mailer } from './mail.js';
import type { Configuration } from './config.js';
import { hash, thumbprint, verify } from '../shared/authority.js';
import { encode, seal } from '../shared/encryption.js';
import type { PublicEncryptionKey, SealedContent } from '../shared/contracts.js';
import type { BoundKeys } from '../shared/authority.js';
import { ConfirmationOperation, decryptionContext } from '../shared/confirmations.js';
import type { ConfirmationMethod, ConfirmationProof, ConfirmationView } from '../shared/confirmations.js';
import { digest, token } from './vault.js';
import { fail, required } from './errors.js';

// What a change takes besides its token: any proof the token alone cannot give, or a way in other than the identity's
// keys where the principal has one, for changes that would let whoever holds its device lock the principal out.
type Level = 'proof' | 'factor';
const levels: Record<string, Level | ((operation: ConfirmationOperation, connection: Queryable, db: Database) => Promise<Level>)> = {
  'credential.issue': 'proof',
  // Replacing what a passkey holds could leave it unable to open the keys; setting it first gives nothing away.
  'credential.wrap': async (operation, connection, db) => {
    const row = await db.one<{ kind: string; private_wrap: string | null }>(
      'SELECT kind,private_wrap FROM credentials WHERE id=$1 AND principal_id=$2',
      [String(operation.credentialId), operation.principalId], connection);
    return row?.kind === 'passkey' && row.private_wrap !== null ? 'factor' : 'proof';
  },
  'credential.remove': async (operation, connection, db) => {
    const row = await db.one<{ kind: string }>('SELECT kind FROM credentials WHERE id=$1 AND principal_id=$2',
      [String(operation.credentialId), operation.principalId], connection);
    return row?.kind === 'key' ? 'proof' : 'factor';
  },
  'credential.addPasskey': 'factor',
  'credential.addEmail': 'factor',
  'oauth.authorize': 'proof',
  'account.merge': 'factor',
  'relation.draw': 'factor',
  'principal.transfer': 'factor',
  'principal.invite': 'factor',
  'keys.bind': 'proof',
  // Which keys a server lets in, where it is reached and how it proves itself decide who gets into it.
  'ssh.grant': 'factor',
  'ssh.revoke': 'factor',
  'ssh.keyRevoke': 'factor',
  'ssh.hostChange': 'factor',
  'ssh.hostDelete': 'factor',
};
interface Row {
  id: string;
  principal_id: string;
  attempts: number;
  expires_at: Date;
  data: {
    credentialId: string;
    sessionId: string | null;
    decryption?: { secretHash: string; sealed: SealedContent; key: string };
    operation: ConfirmationOperation;
    digest: string;
    nonce: string;
    bindingId: string | null;
    state: 'pending' | 'confirmed' | 'held';
    method?: ConfirmationMethod;
    factor?: string;
    email?: { credentialId: string; codeHash: string; sentAt: string };
    passkey?: { challenge: string };
  };
}
const pending = 10 * 60_000, confirmed = 5 * 60_000;
const alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';

// Confirmations of changes to how a principal is reached: who may sign in as it, manage it, or hold its keys. Each is
// made by one sign-in of the actor for one change it names exactly, used once within minutes, and checked again when
// the change is made, in the same transaction, so that a change that fails leaves it to be used again.
export class Confirmations {
  readonly rpId: string;
  constructor(readonly db: Database, readonly mailer: Mailer, readonly config: Configuration) {
    this.rpId = new URL(config.origin).hostname;
  }
  private async level(operation: ConfirmationOperation, connection: Queryable) {
    const level = levels[operation.action];
    if (!level) fail(400, 'invalid_operation', 'Confirm a change that requires confirmation.');
    return typeof level === 'function' ? level(operation, connection, this.db) : level;
  }
  // How the actor can confirm a change of this level. What the level requires follows from the ways in the actor has;
  // which of them can be used now is separate, so that an email outage or setting never lets a weaker method stand in.
  // exists says whether the actor has any way to confirm at all.
  async methods(actor: Actor, level: Level, connection: Queryable = this.db.pool) {
    const ways = new Set((await this.db.all<{ kind: string }>(
      "SELECT DISTINCT kind FROM credentials WHERE principal_id=$1 AND kind IN ('email','passkey')", [actor.id], connection))
      .map(row => row.kind));
    const keys = await this.db.one<{ bound: boolean; encryption: boolean }>(
      `SELECT EXISTS(SELECT 1 FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL) AS bound,
        public_key IS NOT NULL AS encryption FROM principals WHERE id=$1`, [actor.id], connection);
    // The identity's keys prove themselves by signing, or by opening a sealed secret before a signing key is bound.
    const held: ConfirmationMethod[] = keys?.bound ? ['signature'] : keys?.encryption ? ['decryption'] : [];
    const others: ConfirmationMethod[] = [...(ways.has('email') && this.mailer.enabled ? ['email' as const] : []),
      ...(ways.has('passkey') ? ['passkey' as const] : [])];
    const exists = held.length > 0 || ways.size > 0;
    if (level === 'factor' && ways.size) return { exists, methods: others };
    return { exists, methods: [...held, ...others] };
  }
  private unavailable(exists: boolean, details: { operation: ConfirmationOperation; methods: ConfirmationMethod[] }): never {
    fail(409, 'confirmation_unavailable', exists
      ? 'None of the ways to confirm this change can be used now. Try again later.'
      : 'This principal has no way to confirm changes. Ask a principal that manages it to make this change.', details);
  }
  private bearer(actor: Actor) {
    if (!actor.credentialId || actor.requestId)
      fail(403, 'confirmation_unavailable', 'Sign in as this principal to confirm changes to it.');
    return actor.credentialId;
  }
  private challenge(row: Row) {
    return { confirmationId: row.id, principalId: row.principal_id, credentialId: row.data.credentialId,
      bindingId: row.data.bindingId, operation: row.data.digest, nonce: row.data.nonce };
  }
  private async view(row: Row): Promise<ConfirmationView> {
    const actor = { id: row.principal_id, credentialId: row.data.credentialId };
    return {
      id: row.id, operation: row.data.operation, state: row.data.state, expiresAt: iso(row.expires_at),
      methods: (await this.methods(actor, await this.level(row.data.operation, this.db.pool))).methods,
      challenge: this.challenge(row),
      sealed: row.data.decryption?.sealed ?? null,
    };
  }
  private async row(actor: Actor, id: string, connection: Queryable = this.db.pool, lock = false) {
    const row = await this.db.one<Row>(
      "SELECT * FROM challenges WHERE id=$1 AND kind='confirmation' AND principal_id=$2 AND expires_at>now()" +
      (lock ? ' FOR UPDATE' : ''), [id, actor.id], connection);
    if (!row || !this.sameSignin(row, actor)) fail(404, 'not_found', 'This confirmation has expired or does not exist.');
    return row;
  }
  // The same sign-in that started the confirmation: its credential and, for a session, that session.
  private sameSignin(row: Row, actor: Actor) {
    return row.data.credentialId === actor.credentialId && row.data.sessionId === (actor.sessionId ?? null);
  }
  async start(actor: Actor, input: ConfirmationOperation) {
    const credentialId = this.bearer(actor), operation = ConfirmationOperation.parse(input);
    const ways = await this.methods(actor, await this.level(operation, this.db.pool));
    if (!ways.methods.length) this.unavailable(ways.exists, { operation, methods: [] });
    const binding = await this.db.one<{ id: string }>(
      'SELECT id FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL', [actor.id]);
    const id = randomUUID();
    let decryption;
    if (ways.methods.includes('decryption')) {
      const publicKey = required((await this.db.one<{ public_key: PublicEncryptionKey | null }>(
        'SELECT public_key FROM principals WHERE id=$1', [actor.id]))?.public_key), secret = token();
      decryption = { secretHash: digest(secret), key: await thumbprint(publicKey),
        sealed: await seal(encode(secret), [{ id, publicKey }], decryptionContext(id)) };
    }
    await this.db.pool.query(
      "INSERT INTO challenges(id,kind,principal_id,data,expires_at) VALUES($1,'confirmation',$2,$3,$4)",
      [id, actor.id, JSON.stringify({ credentialId, sessionId: actor.sessionId ?? null, operation, digest: await hash(operation), nonce: token(),
        bindingId: binding?.id ?? null, state: 'pending', ...(decryption ? { decryption } : {}) }), new Date(Date.now() + pending)]);
    return this.get(actor, id);
  }
  async get(actor: Actor, id: string) {
    this.bearer(actor);
    return this.view(await this.row(actor, id));
  }
  // Sends a code to one of the actor's email addresses.
  async sendEmail(actor: Actor, id: string, input: { credentialId?: string; locale: 'ja' | 'en' }) {
    this.bearer(actor);
    const row = await this.row(actor, id);
    if (row.data.state !== 'pending') fail(409, 'confirmation_answered', 'This confirmation is already complete.');
    if (!(await this.methods(actor, await this.level(row.data.operation, this.db.pool))).methods.includes('email'))
      fail(400, 'method_unavailable', 'Confirm this change with another method.');
    if (row.data.email && Date.parse(row.data.email.sentAt) > Date.now() - 60_000)
      fail(429, 'wait_before_retry', 'Wait a minute before sending another code.');
    const address = await this.db.one<{ id: string; identifier: string }>(
      "SELECT id,identifier FROM credentials WHERE principal_id=$1 AND kind='email' AND ($2::uuid IS NULL OR id=$2) ORDER BY created_at,id LIMIT 1",
      [actor.id, input.credentialId ?? null]);
    if (!address) fail(404, 'not_found', 'Choose an email address of this principal.');
    const code = Array.from({ length: 8 }, () => alphabet[randomInt(alphabet.length)]).join('');
    const sent = await this.db.pool.query(
      "UPDATE challenges SET data=data||$2 WHERE id=$1 AND data->>'state'='pending' AND data->'email' IS NOT DISTINCT FROM $3::jsonb",
      [id, JSON.stringify({ email: { credentialId: address.id, codeHash: digest(code), sentAt: new Date().toISOString() } }),
        row.data.email ? JSON.stringify(row.data.email) : null]);
    if (!sent.rowCount) fail(409, 'confirmation_changed', 'Another code was sent for this confirmation.');
    try { await this.mailer.sendCode(address.identifier, code, input.locale); }
    catch { fail(502, 'email_failed', 'The email could not be sent. Try again.'); }
    return { email: address.identifier, resendAt: new Date(Date.now() + 60_000).toISOString() };
  }
  // WebAuthn options for one of the actor's passkeys to confirm the change.
  async passkeyOptions(actor: Actor, id: string) {
    this.bearer(actor);
    const row = await this.row(actor, id);
    if (row.data.state !== 'pending') fail(409, 'confirmation_answered', 'This confirmation is already complete.');
    const passkeys = await this.db.all<{ identifier: string; data: { transports: AuthenticatorTransport[] } }>(
      "SELECT identifier,data FROM credentials WHERE principal_id=$1 AND kind='passkey' ORDER BY created_at,id", [actor.id]);
    if (!passkeys.length) fail(400, 'method_unavailable', 'Confirm this change with another method.');
    const options = await generateAuthenticationOptions({ rpID: this.rpId, userVerification: 'required',
      allowCredentials: passkeys.map(passkey => ({ id: passkey.identifier, transports: passkey.data.transports })) });
    await this.db.pool.query("UPDATE challenges SET data=data||$2 WHERE id=$1 AND data->>'state'='pending'",
      [id, JSON.stringify({ passkey: { challenge: options.challenge } })]);
    return { options };
  }
  async prove(actor: Actor, id: string, proof: ConfirmationProof) {
    this.bearer(actor);
    await this.row(actor, id);
    // Each attempt counts, whether or not its proof holds.
    if (!await this.db.one('UPDATE challenges SET attempts=attempts+1 WHERE id=$1 AND attempts<5 RETURNING id', [id]))
      fail(429, 'confirmation_attempts', 'Start a new confirmation for this change.');
    await this.db.transaction(async connection => {
      const row = await this.row(actor, id, connection, true);
      if (row.data.state !== 'pending') fail(409, 'confirmation_answered', 'This confirmation is already complete.');
      const { methods } = await this.methods(actor, await this.level(row.data.operation, connection), connection);
      if (!methods.includes(proof.method)) fail(400, 'method_unavailable', 'Confirm this change with another method.');
      let factor: string | null = null;
      if (proof.method === 'signature') {
        const binding = await this.db.one<{ id: string; binding: BoundKeys }>(
          'SELECT id,binding FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL', [actor.id], connection);
        if (binding && binding.id === row.data.bindingId)
          factor = await verify(this.challenge(row), proof.signature, binding.binding.signing, 'operation-confirmation')
            .then(() => binding.id, () => null);
      } else if (proof.method === 'decryption') {
        const decryption = row.data.decryption;
        if (decryption && digest(proof.secret) === decryption.secretHash && decryption.key === await this.encryptionKey(actor, connection))
          factor = decryption.key;
      } else if (proof.method === 'email') {
        const email = row.data.email;
        if (email && digest(proof.code.replaceAll('-', '').trim().toUpperCase()) === email.codeHash &&
          await this.db.one("SELECT 1 FROM credentials WHERE id=$1 AND principal_id=$2 AND kind='email'", [email.credentialId, actor.id], connection))
          factor = email.credentialId;
      } else factor = await this.passkey(actor, row, proof.credential, connection);
      if (!factor) fail(400, 'invalid_proof', 'The proof does not confirm this change.');
      await connection.query('UPDATE challenges SET data=data||$2,expires_at=$3 WHERE id=$1',
        [id, JSON.stringify({ state: 'confirmed', method: proof.method, factor }), new Date(Date.now() + confirmed)]);
    });
    return this.get(actor, id);
  }
  private async passkey(actor: Actor, row: Row, response: unknown, connection: Queryable) {
    const assertion = response as AuthenticationResponseJSON;
    const credential = await this.db.one<{ id: string; identifier: string; data: { publicKey: string; counter: number; transports: AuthenticatorTransport[] } }>(
      "SELECT id,identifier,data FROM credentials WHERE kind='passkey' AND principal_id=$1 AND identifier=$2 FOR UPDATE",
      [actor.id, typeof assertion?.id === 'string' ? assertion.id : ''], connection);
    if (!credential || !row.data.passkey) return null;
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: assertion, expectedChallenge: row.data.passkey.challenge, expectedOrigin: this.config.origin,
        expectedRPID: this.rpId, requireUserVerification: true,
        credential: { id: credential.identifier, publicKey: new Uint8Array(Buffer.from(credential.data.publicKey, 'base64url')),
          counter: credential.data.counter, transports: credential.data.transports },
      });
    } catch { return null; }
    if (!verification.verified) return null;
    await connection.query("UPDATE credentials SET data=data||jsonb_build_object('counter',$2::bigint),last_used_at=now() WHERE id=$1",
      [credential.id, verification.authenticationInfo.newCounter]);
    return credential.id;
  }
  // The confirmation the actor sent for this change, when it still holds: made for exactly this change by the same
  // sign-in, within its time, by a method the change still accepts, with that way in and the actor's sign-in still in
  // place. Locks them when given a transaction, so that neither changes until the change is made.
  private async valid(actor: Actor, operation: ConfirmationOperation, connection: Queryable, lock: boolean) {
    const level = await this.level(operation, connection), { exists, methods } = await this.methods(actor, level, connection);
    const details = { operation, methods };
    if (!methods.length) this.unavailable(exists, details);
    if (!actor.confirmation || !actor.credentialId || actor.requestId)
      fail(403, 'confirmation_required', 'Confirm this change through POST /api/confirmations, then send it again with the Foundation-Confirmation header.', details);
    const share = lock ? ' FOR SHARE' : '';
    const row = await this.db.one<Row>(
      "SELECT * FROM challenges WHERE id=$1 AND kind='confirmation' AND principal_id=$2 AND expires_at>now()" + (lock ? ' FOR UPDATE' : ''),
      [actor.confirmation, actor.id], connection);
    const holds = row && this.sameSignin(row, actor) && ['confirmed', 'held'].includes(row.data.state) &&
      row.data.digest === await hash(operation) && row.data.method && methods.includes(row.data.method) && row.data.factor &&
      (row.data.method === 'decryption' ? row.data.factor === await this.encryptionKey(actor, connection, share)
        : await this.db.one(row.data.method === 'signature'
          ? 'SELECT 1 FROM principal_key_bindings WHERE id=$1 AND principal_id=$2 AND retired_at IS NULL' + share
          : 'SELECT 1 FROM credentials WHERE id=$1 AND principal_id=$2' + share, [row.data.factor, actor.id], connection)) &&
      await this.db.one('SELECT 1 FROM credentials WHERE id=$1 AND principal_id=$2 AND (expires_at IS NULL OR expires_at>now())' + share,
        [actor.credentialId, actor.id], connection) &&
      (!actor.sessionId || await this.db.one('SELECT 1 FROM sessions WHERE id=$1 AND expires_at>now()' + share, [actor.sessionId], connection));
    if (!holds) fail(403, 'confirmation_invalid', 'Confirm this change again: the confirmation does not apply to it.', details);
    return row;
  }
  // The thumbprint of the actor's encryption key, which a confirmation by decryption holds only while it stays.
  private async encryptionKey(actor: Actor, connection: Queryable, share = '') {
    const row = await this.db.one<{ public_key: PublicEncryptionKey | null }>('SELECT public_key FROM principals WHERE id=$1' + share,
      [actor.id], connection);
    return row?.public_key ? thumbprint(row.public_key) : null;
  }
  // Uses the confirmation for the change being made in this transaction, and returns how it was confirmed.
  async consume(connection: Queryable, actor: Actor, operation: ConfirmationOperation) {
    const row = await this.valid(actor, operation, connection, true);
    await connection.query('DELETE FROM challenges WHERE id=$1', [row.id]);
    return { method: row.data.method!, factor: row.data.factor! };
  }
  // Whether the confirmation holds, before a change starts that is made later.
  async check(actor: Actor, operation: ConfirmationOperation) {
    await this.valid(actor, operation, this.db.pool, false);
  }
  // Keeps the confirmation for a change that waits on another side's agreement until it can be made.
  async hold(actor: Actor, operation: ConfirmationOperation, until: Date) {
    await this.db.transaction(async connection => {
      const row = await this.valid(actor, operation, connection, true);
      await connection.query("UPDATE challenges SET data=data||'{\"state\":\"held\"}',expires_at=$2 WHERE id=$1", [row.id, until]);
    });
  }
}
