import type { Actor } from './authorization.js';
import type { Delegation } from './delegation.js';
import type { Executions } from './executions.js';
import type { SealedContent } from '../shared/contracts.js';
import { hash } from '../shared/authority.js';
import { encode, seal } from '../shared/encryption.js';
import { relayContext } from '../shared/protocol.js';
import { fail, required } from './errors.js';
import { iso } from './database.js';

interface RelayRow {
  id: string; execution_id: string; operation_index: number; actor_id: string; binding_id: string; state_digest: string;
  callback_digest: string | null; sealed: SealedContent | null; expires_at: Date; received_at: Date | null;
}
export class OAuthRelays {
  constructor(readonly delegation: Delegation, readonly executions: () => Executions) {}
  get db() { return this.delegation.resources.db; }
  private async active(actor: Actor, row: Pick<RelayRow, 'execution_id' | 'operation_index' | 'id'>) {
    const { plan } = await this.executions().input(actor, row.execution_id);
    if (plan.index !== row.operation_index || plan.invocation.name !== 'connection.connect' ||
      plan.continuation?.kind !== 'connection' || plan.continuation.id !== row.id)
      fail(409, 'connection_expired', 'Start the connection again.');
  }
  async register(actor: Actor, input: { id: string; executionId: string; index: number; stateDigest: string; expiresAt: string }) {
    const { row: execution, plan } = await this.executions().input(actor, input.executionId);
    if (plan.index !== input.index || plan.invocation.name !== 'connection.connect' ||
      plan.continuation?.kind !== 'connection' || plan.continuation.id !== input.id ||
      Date.parse(input.expiresAt) <= Date.now() || Date.parse(input.expiresAt) > Date.now() + 600_000 ||
      Date.parse(input.expiresAt) > execution.expires_at.getTime())
      fail(403, 'forbidden', 'Create a callback for the connection that is awaiting authorization.');
    const { binding } = await this.delegation.bindings.current(actor.id);
    const row = await this.db.one<RelayRow>(
      `INSERT INTO oauth_relays(id,execution_id,operation_index,actor_id,binding_id,state_digest,expires_at)
       VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET state_digest=$6,expires_at=$7,
       sealed=CASE WHEN oauth_relays.state_digest=$6 THEN oauth_relays.sealed ELSE NULL END,
       callback_digest=CASE WHEN oauth_relays.state_digest=$6 THEN oauth_relays.callback_digest ELSE NULL END,
       received_at=CASE WHEN oauth_relays.state_digest=$6 THEN oauth_relays.received_at ELSE NULL END
       WHERE oauth_relays.execution_id=$2 AND oauth_relays.operation_index=$3 AND oauth_relays.actor_id=$4 AND oauth_relays.binding_id=$5 RETURNING *`,
      [input.id, input.executionId, input.index, actor.id, binding.id, input.stateDigest, input.expiresAt]);
    if (!row) fail(409, 'flow_exists', 'Use a new connection.');
    return this.view(row);
  }
  private view(row: RelayRow) {
    return { id: row.id, executionId: row.execution_id, context: relayContext(this.delegation.origin, row.id),
      sealed: row.sealed, expiresAt: iso(row.expires_at), receivedAt: row.received_at ? iso(row.received_at) : null };
  }
  async get(actor: Actor, id: string) {
    const row = required(await this.db.one<RelayRow>('SELECT * FROM oauth_relays WHERE id=$1 AND expires_at>now()', [id]));
    if (row.actor_id !== actor.id) fail(403, 'forbidden', 'Open a connection belonging to this identity.');
    await this.active(actor, row);
    const { binding } = await this.delegation.bindings.current(actor.id);
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
    const { binding } = await this.delegation.bindings.current(row.actor_id);
    if (binding.id !== row.binding_id) fail(409, 'connection_expired', 'Start the connection again.');
    const sealed = await seal(encode(callback), [{ id: binding.id, publicKey: binding.encryption }], relayContext(this.delegation.origin, row.id));
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
