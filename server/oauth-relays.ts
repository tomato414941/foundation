import type { Actor } from './authorization.js';
import type { Delegation } from './delegation.js';
import type { SealedRun } from '../shared/custody.js';
import type { SealedContent } from '../shared/contracts.js';
import { canonical, hash } from '../shared/authority.js';
import { encode, seal } from '../shared/encryption.js';
import { relayContext } from '../shared/protocol.js';
import { fail, required } from './errors.js';
import { iso } from './database.js';

interface RelayRow {
  id: string; run_id: string; actor_id: string; executor_id: string; state_digest: string;
  callback_digest: string | null; sealed: SealedContent | null; expires_at: Date; received_at: Date | null;
}
export class OAuthRelays {
  constructor(readonly delegation: Delegation) {}
  get db() { return this.delegation.resources.db; }
  async register(actor: Actor, input: { id: string; runId: string; stateDigest: string; expiresAt: string }) {
    await this.delegation.resources.authorization.active(actor);
    const task = required(await this.db.one<{ request: SealedRun; phase: string; state: string }>(
      'SELECT request,phase,state FROM execution_tasks WHERE id=$1', [input.runId],
    ));
    const intent = task.request.intent;
    if (intent.executor.principalId !== actor.id || intent.operation !== 'connect' ||
      task.phase !== 'dispatched' || task.state !== 'running' || Date.parse(input.expiresAt) <= Date.now() ||
      Date.parse(input.expiresAt) > Date.now() + 600_000 || Date.parse(input.expiresAt) > Date.parse(intent.expiresAt))
      fail(403, 'forbidden', 'Create a callback only for the authorized connection request.');
    await this.delegation.bindings.requireCurrent(intent.executor);
    await this.db.pool.query(
      'INSERT INTO oauth_relays(id,run_id,actor_id,executor_id,state_digest,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING',
      [input.id, input.runId, intent.actor.principalId, actor.id, input.stateDigest, input.expiresAt],
    );
    const row = required(await this.db.one<RelayRow>('SELECT * FROM oauth_relays WHERE id=$1', [input.id]));
    if (row.run_id !== input.runId || row.executor_id !== actor.id || row.state_digest !== input.stateDigest ||
      iso(row.expires_at) !== input.expiresAt)
      fail(409, 'flow_exists', 'Use a new connection request.');
    return this.view(row);
  }
  private view(row: RelayRow) {
    return { id: row.id, runId: row.run_id, context: relayContext(this.delegation.origin, row.id),
      sealed: row.sealed, expiresAt: iso(row.expires_at), receivedAt: row.received_at ? iso(row.received_at) : null };
  }
  async get(actor: Actor, id: string) {
    await this.delegation.resources.authorization.active(actor);
    const row = required(await this.db.one<RelayRow>('SELECT * FROM oauth_relays WHERE id=$1 AND expires_at>now()', [id]));
    if (![row.actor_id, row.executor_id].includes(actor.id)) fail(403, 'forbidden', 'Open a connection request belonging to this identity.');
    return this.view(row);
  }
  async receive(parameters: URLSearchParams) {
    if (parameters.toString().length > 20000 || parameters.getAll('state').length !== 1 ||
      (!parameters.has('code') && !parameters.has('error')))
      fail(400, 'invalid_state', 'Start the connection again.');
    const state = parameters.get('state')!, digest = await hash(state), callback = parameters.toString();
    const row = await this.db.one<RelayRow>('SELECT * FROM oauth_relays WHERE state_digest=$1 AND expires_at>now()', [digest]);
    if (!row) fail(400, 'invalid_state', 'Start the connection again.');
    const task = required(await this.db.one<{ request: SealedRun; state: string }>('SELECT request,state FROM execution_tasks WHERE id=$1', [row.run_id]));
    if (!['running', 'succeeded'].includes(task.state)) fail(409, 'connection_expired', 'Start the connection again.');
    const recipients = [...new Map([task.request.intent.actor, task.request.intent.executor].map(binding => [binding.id, binding])).values()];
    const sealed = await seal(encode(callback), recipients.map(binding => ({ id: binding.id, publicKey: binding.encryption })),
      relayContext(this.delegation.origin, row.id));
    const callbackDigest = await hash(callback);
    const updated = await this.db.one<RelayRow>(
      'UPDATE oauth_relays SET sealed=$2,callback_digest=$3,received_at=now() WHERE id=$1 AND sealed IS NULL AND expires_at>now() RETURNING *',
      [row.id, JSON.stringify(sealed), callbackDigest],
    );
    if (!updated) {
      const current = required(await this.db.one<RelayRow>('SELECT * FROM oauth_relays WHERE id=$1', [row.id]));
      if (canonical(current.callback_digest) !== canonical(callbackDigest))
        fail(409, 'callback_received', 'This connection request already received an authorization response.');
    }
    return { id: row.id };
  }
}
