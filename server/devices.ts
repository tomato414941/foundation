import { randomInt, randomUUID } from 'node:crypto';
import type { Database } from './database.js';
import type { Authorization, Actor } from './authorization.js';
import type { Audit } from './audit.js';
import { PublicKey, Sealed } from '../shared/contracts.js';
import type { PublicEncryptionKey, SealedContent } from '../shared/contracts.js';
import { digest, token } from './vault.js';
import { fail, required } from './errors.js';

interface DeviceRow {
  id: string;
  principal_id: string | null;
  data: {
    name: string;
    publicKey: PublicEncryptionKey;
    codeHash: string;
    pollHash: string;
    state: 'pending' | 'approving' | 'approved';
    sealed?: SealedContent;
  };
  attempts: number;
  expires_at: Date;
  created_at: Date;
}
const alphabet = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
const lifetime = 10 * 60_000;

// A device (a machine without a browser) asks to be let in as a principal. A person
// approves it in a browser, which issues a key for the chosen principal and seals the
// key's token to the device's one-time public key. The server only relays the envelope.
export class Devices {
  constructor(
    readonly db: Database,
    readonly authorization: Authorization,
    readonly audit: Audit,
    readonly origin: string,
  ) {}
  async begin(name: string, publicKey: PublicEncryptionKey) {
    const id = randomUUID(),
      code = Array.from({ length: 8 }, () => alphabet[randomInt(alphabet.length)]).join(''),
      poll = 'fd_' + token(),
      expiresAt = new Date(Date.now() + lifetime);
    await this.db.pool.query(
      "INSERT INTO challenges(id,kind,data,expires_at) VALUES($1,'device',$2,$3)",
      [
        id,
        JSON.stringify({ name, publicKey: PublicKey.parse(publicKey), codeHash: digest(code), pollHash: digest(poll), state: 'pending' }),
        expiresAt,
      ],
    );
    return { id, code, poll, url: this.origin + '/devices/' + id, expiresAt: expiresAt.toISOString() };
  }
  private async row(id: string) {
    const row = await this.db.one<DeviceRow>(
      "SELECT * FROM challenges WHERE id=$1 AND kind='device' AND expires_at>now()",
      [id],
    );
    if (!row) fail(404, 'not_found', 'This device request has expired or does not exist.');
    return row;
  }
  async view(id: string) {
    const row = await this.row(id);
    return {
      id: row.id,
      name: row.data.name,
      publicKey: row.data.publicKey,
      state: row.data.state,
      principalId: row.principal_id,
      createdAt: row.created_at.toISOString(),
      expiresAt: row.expires_at.toISOString(),
    };
  }
  async approve(actor: Actor, id: string, code: string, principalId: string) {
    if (actor.requestId) fail(403, 'forbidden', 'Sign in to let a device in.');
    await this.authorization.requirePrincipal(actor, principalId, 'manage_credentials');
    const row = await this.row(id);
    if (row.data.state !== 'pending') fail(409, 'device_answered', 'This device request is already being handled.');
    const attempted = await this.db.one<{ attempts: number }>(
      'UPDATE challenges SET attempts=attempts+1 WHERE id=$1 AND attempts<5 RETURNING attempts',
      [id],
    );
    if (!attempted || digest(code.replaceAll('-', '').toUpperCase()) !== row.data.codeHash)
      fail(400, 'invalid_code', 'Enter the code shown by the device.');
    const claimed = await this.db.pool.query(
      `UPDATE challenges SET principal_id=$2,data=data||'{"state":"approving"}' WHERE id=$1 AND data->>'state'='pending'`,
      [id, principalId],
    );
    if (!claimed.rowCount) fail(409, 'device_answered', 'This device request is already being handled.');
    return this.view(id);
  }
  async complete(actor: Actor, id: string, sealed: SealedContent) {
    const row = await this.row(id);
    if (row.data.state !== 'approving' || !row.principal_id)
      fail(409, 'device_not_approved', 'Approve the device before completing it.');
    await this.authorization.requirePrincipal(actor, row.principal_id, 'manage_credentials');
    const envelope = Sealed.parse(sealed);
    if (envelope.recipients.length !== 1 || envelope.recipients[0]!.header.kid !== id)
      fail(400, 'invalid_envelope', 'Seal the token for this device only.');
    await this.db.pool.query(
      `UPDATE challenges SET data=data||$2 WHERE id=$1 AND data->>'state'='approving'`,
      [id, JSON.stringify({ state: 'approved', sealed: envelope })],
    );
    await this.audit.record(row.principal_id, actor.id, 'device.approve', id, { name: row.data.name });
    return this.view(id);
  }
  async poll(id: string, poll: string) {
    const row = await this.row(id);
    if (digest(poll) !== row.data.pollHash) fail(403, 'forbidden', 'This device request belongs to another device.');
    if (row.data.state !== 'approved') return { state: row.data.state, principalId: null, sealed: null };
    await this.db.pool.query('DELETE FROM challenges WHERE id=$1', [id]);
    return { state: 'approved' as const, principalId: required(row.principal_id), sealed: required(row.data.sealed) };
  }
}
