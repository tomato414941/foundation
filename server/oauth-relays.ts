import type { Actor } from './authorization.js';
import type { Resources } from './resources.js';
import type { Bindings } from './bindings.js';
import type { Operations } from './operations.js';
import type { SealedContent } from '../shared/contracts.js';
import { hash } from '../shared/authority.js';
import { encode, seal } from '../shared/encryption.js';
import { relayContext } from '../shared/protocol.js';
import { fail, required } from './errors.js';
import { iso } from './database.js';

interface RelayRow {
  id: string; operation_id: string; actor_id: string; binding_id: string; state_digest: string;
  callback_digest: string | null; sealed: SealedContent | null; expires_at: Date; received_at: Date | null;
}
export class OAuthRelays {
  constructor(readonly resources: Resources, readonly bindings: Bindings, readonly origin: string, readonly operations: () => Operations) {}
  get db() { return this.resources.db; }
  // The connection an operation waits on its service for, which the callback is relayed to.
  private async active(actor: Actor, row: Pick<RelayRow, 'operation_id' | 'id'>) {
    const { row: operation, snapshot } = await this.operations().waiting(actor, row.operation_id);
    if (operation.name !== 'connection.connect' || snapshot.continuation?.kind !== 'connection' || snapshot.continuation.id !== row.id)
      fail(409, 'connection_expired', 'Start the connection again.');
    return operation;
  }
  async register(actor: Actor, input: { id: string; operationId: string; stateDigest: string; expiresAt: string }) {
    const operation = await this.active(actor, { operation_id: input.operationId, id: input.id }).catch(() =>
      fail(403, 'forbidden', 'Create a callback for the connection that is awaiting authorization.'));
    if (Date.parse(input.expiresAt) <= Date.now() || Date.parse(input.expiresAt) > Date.now() + 600_000 ||
      operation.expires_at && Date.parse(input.expiresAt) > operation.expires_at.getTime())
      fail(403, 'forbidden', 'Create a callback for the connection that is awaiting authorization.');
    const { binding } = await this.bindings.current(actor.id);
    const row = await this.db.one<RelayRow>(
      `INSERT INTO oauth_relays(id,operation_id,actor_id,binding_id,state_digest,expires_at)
       VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET state_digest=$5,expires_at=$6,
       sealed=CASE WHEN oauth_relays.state_digest=$5 THEN oauth_relays.sealed ELSE NULL END,
       callback_digest=CASE WHEN oauth_relays.state_digest=$5 THEN oauth_relays.callback_digest ELSE NULL END,
       received_at=CASE WHEN oauth_relays.state_digest=$5 THEN oauth_relays.received_at ELSE NULL END
       WHERE oauth_relays.operation_id=$2 AND oauth_relays.actor_id=$3 AND oauth_relays.binding_id=$4 RETURNING *`,
      [input.id, input.operationId, actor.id, binding.id, input.stateDigest, input.expiresAt]);
    if (!row) fail(409, 'flow_exists', 'Use a new connection.');
    return this.view(row);
  }
  private view(row: RelayRow) {
    return { id: row.id, operationId: row.operation_id, context: relayContext(this.origin, row.id),
      sealed: row.sealed, expiresAt: iso(row.expires_at), receivedAt: row.received_at ? iso(row.received_at) : null };
  }
  async get(actor: Actor, id: string) {
    const row = required(await this.db.one<RelayRow>('SELECT * FROM oauth_relays WHERE id=$1 AND expires_at>now()', [id]));
    if (row.actor_id !== actor.id) fail(403, 'forbidden', 'Open a connection belonging to this identity.');
    await this.active(actor, row);
    const { binding } = await this.bindings.current(actor.id);
    if (binding.id !== row.binding_id) fail(409, 'connection_expired', 'Start the connection again.');
    return this.view(row);
  }
  async receive(parameters: URLSearchParams) {
    if (parameters.toString().length > 20000 || parameters.getAll('state').length !== 1)
      fail(400, 'invalid_state', 'Start the connection again.');
    const digest = await hash(parameters.get('state')!), callback = parameters.toString();
    const row = await this.db.one<RelayRow>('SELECT * FROM oauth_relays WHERE state_digest=$1 AND expires_at>now()', [digest]);
    if (!row) fail(400, 'invalid_state', 'Start the connection again.');
    await this.active({ id: row.actor_id }, row);
    const { binding } = await this.bindings.current(row.actor_id);
    if (binding.id !== row.binding_id) fail(409, 'connection_expired', 'Start the connection again.');
    const sealed = await seal(encode(callback), [{ id: binding.id, publicKey: binding.encryption }], relayContext(this.origin, row.id));
    const callbackDigest = await hash(callback);
    const updated = await this.db.one<RelayRow>(
      'UPDATE oauth_relays SET sealed=$2,callback_digest=$3,received_at=now() WHERE id=$1 AND state_digest=$4 AND sealed IS NULL AND expires_at>now() RETURNING *',
      [row.id, JSON.stringify(sealed), callbackDigest, digest]);
    if (!updated) {
      const current = required(await this.db.one<RelayRow>('SELECT * FROM oauth_relays WHERE id=$1', [row.id]));
      if (current.state_digest !== digest || current.callback_digest !== callbackDigest)
        fail(409, 'callback_received', 'This connection already received an authorization response.');
    }
    return { id: row.id };
  }
}
