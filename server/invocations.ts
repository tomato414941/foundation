import { randomUUID } from 'node:crypto';
import type { z } from 'zod';
import type { Actor } from './authorization.js';
import type { Functions } from './functions.js';
import type { Custody } from './custody.js';
import type { Delegation } from './delegation.js';
import { iso } from './database.js';
import { fail, required } from './errors.js';
import { canonical, hash, verify } from '../shared/authority.js';
import type { BoundKeys } from '../shared/authority.js';
import type { JsonValue } from '../shared/contracts.js';
import { Invocation, InvocationInput, InvocationRequest } from '../shared/function-api.js';
import type { Completion, InvocationView, Publication } from '../shared/function-api.js';
import { functionArguments } from '../shared/functions.js';
import { ContentTypes, functionOperations, grantExpiration, verifyPolicyApproval } from '../shared/custody.js';
import { pointerParts } from '../shared/values.js';

interface InvocationRow {
  id: string; function_id: string; function_owner_id: string; owner_id: string; actor_id: string;
  executor_id: string; environment_id: string; executor: BoundKeys; actor: Actor;
  input_digest: string; request: z.infer<typeof InvocationRequest>; publication: Publication;
  state: InvocationView['state']; completion: Completion | null; error: InvocationView['error'];
  phase: 'queued' | 'claimed' | 'dispatched' | 'settled'; cancel_requested: boolean; lease_token: string | null;
  created_at: Date; started_at: Date | null; finished_at: Date | null;
}
export class Invocations {
  constructor(readonly functions: Functions, readonly custody: Custody, readonly delegation: Delegation) {}
  get resources() { return this.functions.resources; }
  private row(id: string) { return this.resources.db.one<InvocationRow>('SELECT * FROM function_invocations WHERE id=$1', [id]).then(required); }
  private view(row: InvocationRow): InvocationView {
    return Invocation.parse({ id: row.id, functionId: row.function_id, functionVersion: row.request.functionVersion,
      ownerId: row.owner_id, actorId: row.actor_id, state: row.state,
      result: row.completion?.result ?? null, error: row.completion?.error ?? row.error,
      createdAt: iso(row.created_at), startedAt: row.started_at ? iso(row.started_at) : null,
      finishedAt: row.finished_at ? iso(row.finished_at) : null });
  }
  private async validate(row: InvocationRow) {
    await this.resources.authorization.active(row.actor);
    if (Date.parse(row.request.expiresAt) <= Date.now()) fail(409, 'invocation_expired', 'This invocation has expired.');
    const current = await this.functions.execution(row.actor, row.function_id, this.custody, this.delegation);
    if (await hash(current.definition) !== row.request.definitionDigest ||
      canonical(current.publication.executor) !== canonical(row.executor) || current.row.owner_id !== row.function_owner_id)
      fail(409, 'function_changed', 'The function changed before this invocation started.');
    return current;
  }
  async create(actor: Actor, functionId: string, input: z.infer<typeof InvocationInput>) {
    const id = input.id ?? randomUUID(), ownerId = input.ownerId ?? actor.id;
    const inputDigest = await hash({ functionId, ownerId, arguments: input.arguments, outputs: input.outputs });
    return this.resources.db.transaction(async connection => {
      await connection.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', ['invocation:' + id]);
      await this.resources.authorization.active(actor, connection);
      const previous = await this.resources.db.one<InvocationRow>('SELECT * FROM function_invocations WHERE id=$1', [id], connection);
      if (previous) {
        if (previous.actor_id !== actor.id || previous.input_digest !== inputDigest)
          fail(409, 'invocation_conflict', 'Use a new invocation ID for different input.');
        return this.view(previous);
      }
      await this.resources.authorization.requirePrincipal(actor, ownerId, 'execute', connection);
      const current = await this.functions.execution(actor, functionId, this.custody, this.delegation);
      const environmentId = current.definition.environmentId;
      await connection.query('SELECT id FROM resources WHERE id=$1 FOR UPDATE', [environmentId]);
      const environment = await this.delegation.environment(environmentId, connection);
      if (!environment.heartbeat_at || Date.now() - environment.heartbeat_at.getTime() > 90_000)
        fail(503, 'environment_unavailable', 'The function’s execution environment is not responding.');
      let arguments_: Record<string, JsonValue>;
      try { arguments_ = functionArguments(current.definition, input.arguments); }
      catch (error) { fail(400, 'invalid_function_arguments', error instanceof Error ? error.message : 'Use the declared function inputs.'); }
      const binding = await this.resources.db.one<{ binding: BoundKeys }>(
        'SELECT binding FROM principal_key_bindings WHERE principal_id=$1 AND retired_at IS NULL', [actor.id], connection);
      for (const [pointer, output] of Object.entries(input.outputs)) {
        try { pointerParts(pointer); } catch { fail(400, 'invalid_pointer', 'Use a valid JSON pointer for the output.'); }
        const approval = await verifyPolicyApproval(output.approval), policy = approval.policy;
        if (!binding || policy.origin !== this.functions.origin || policy.ownerId !== ownerId || policy.contentType !== ContentTypes.value ||
          canonical(policy.authorities.find(value => value.id === approval.authorityId)) !== canonical(binding.binding) ||
          !policy.producers.some(value => value.runId === id && canonical(value.executor) === canonical(current.publication.executor) &&
            Date.parse(value.expiresAt) > Date.now()))
          fail(400, 'invalid_output_authorization', 'Approve each encrypted output for this invocation.');
      }
      const definitionDigest = await hash(current.definition);
      const expiresAt = new Date(Math.min(Date.now() + 3_600_000, grantExpiration(current.definition.inputAccess), ...current.sources.map(source =>
        Math.max(...source.policy.grants.filter(grant => 'function' in grant && grant.function.id === functionId &&
          grant.function.digest === definitionDigest && canonical(grant.executor) === canonical(current.publication.executor) &&
          functionOperations(source.policy.contentType).every(operation => grant.operations.includes(operation)))
          .map(grant => grantExpiration(grant)))))).toISOString();
      const request = InvocationRequest.parse({ id, functionId, functionVersion: current.row.version,
        ownerId, actorId: actor.id, actor: binding?.binding ?? null, arguments: arguments_, outputs: input.outputs,
        definitionDigest, createdAt: new Date().toISOString(), expiresAt });
      const active = await this.resources.db.one<{ count: string }>(
        "SELECT count(*) FROM function_invocations WHERE environment_id=$1 AND state IN ('queued','running')", [environmentId], connection);
      if (Number(active?.count) >= 20) fail(429, 'invocation_limit', 'Wait for an existing invocation to finish.');
      const row = required(await this.resources.db.one<InvocationRow>(
        `INSERT INTO function_invocations(id,function_id,function_owner_id,owner_id,actor_id,executor_id,environment_id,
          executor,actor,input_digest,request,publication,state) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'queued') RETURNING *`,
        [id, functionId, current.row.owner_id, ownerId, actor.id, environment.executor_id, environmentId,
          JSON.stringify(current.publication.executor), JSON.stringify(actor), inputDigest, JSON.stringify(request), JSON.stringify(current.publication)], connection));
      await this.resources.audit.record(current.row.owner_id, actor.id, 'function.invoke', id, { functionId }, connection);
      return this.view(row);
    });
  }
  async get(actor: Actor, id: string) {
    const row = await this.row(id);
    if (row.actor_id === actor.id) await this.resources.authorization.active(actor);
    else await this.resources.authorization.requirePrincipal(actor, row.owner_id, 'read');
    return this.view(row);
  }
  async list(actor: Actor, ownerId: string, limit = 100, after?: string) {
    await this.resources.authorization.requirePrincipal(actor, ownerId, 'read');
    const rows = await this.resources.db.all<InvocationRow>(
      'SELECT * FROM function_invocations WHERE owner_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3', [ownerId, after ?? null, limit + 1]);
    return { items: rows.slice(0, limit).map(row => this.view(row)), next: rows.length > limit ? rows[limit - 1]!.id : null };
  }
  async claim(actor: Actor, environmentId: string) {
    await this.delegation.heartbeat(actor, environmentId);
    const lease = randomUUID();
    const row = await this.delegation.claimGate(environmentId, connection => this.resources.db.one<InvocationRow>(
      `UPDATE function_invocations SET state='running',phase='claimed',lease_token=$2,lease_until=now()+interval '60 seconds'
       WHERE id=(SELECT id FROM function_invocations WHERE environment_id=$1 AND state='queued'
       ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *`, [environmentId, lease], connection));
    if (!row) return null;
    try {
      const current = await this.validate(row);
      return { lease, request: row.request, publication: row.publication, sources: current.sources };
    } catch {
      await this.resources.db.pool.query(
        `UPDATE function_invocations SET state='failed',phase='settled',error=$3,finished_at=now(),lease_until=NULL
         WHERE id=$1 AND lease_token=$2 AND phase='claimed' AND state='running' AND cancel_requested=false`,
        [row.id, lease, JSON.stringify({ code: 'authorization_changed', message: 'The function or its permission changed before execution.' })]);
      return null;
    }
  }
  async dispatch(actor: Actor, id: string, lease: string) {
    const row = await this.row(id);
    await this.delegation.requireExecutor(actor, row.environment_id);
    await this.validate(row);
    const updated = await this.resources.db.one(
      `UPDATE function_invocations SET phase='dispatched',started_at=now() WHERE id=$1 AND lease_token=$2
       AND phase='claimed' AND state='running' AND cancel_requested=false AND lease_until>now() RETURNING id`, [id, lease]);
    if (!updated) fail(409, 'lease_lost', 'This invocation can no longer be started with that lease.');
    await this.activity(row.environment_id);
    return { ok: true as const };
  }
  private activity(id: string) {
    return this.resources.db.pool.query("UPDATE resources SET data=jsonb_set(data,'{lastActiveAt}',to_jsonb($2::text)) WHERE id=$1",
      [id, new Date().toISOString()]);
  }
  async renew(actor: Actor, id: string, lease: string) {
    const row = await this.row(id);
    await this.delegation.heartbeat(actor, row.environment_id);
    if (row.cancel_requested) return { active: false, reason: 'cancelled' as const };
    try { await this.validate(row); } catch { return { active: false, reason: 'authorization_changed' as const }; }
    const updated = await this.resources.db.one(
      `UPDATE function_invocations SET lease_until=now()+interval '60 seconds' WHERE id=$1 AND lease_token=$2
       AND state='running' AND cancel_requested=false AND lease_until>now() RETURNING id`, [id, lease]);
    if (updated) await this.activity(row.environment_id);
    if (updated) return { active: true };
    return { active: false, reason: (await this.row(id)).cancel_requested ? 'cancelled' as const : 'lease_lost' as const };
  }
  async finish(actor: Actor, id: string, lease: string, completion: Completion) {
    const row = await this.row(id);
    await this.resources.authorization.active(actor);
    if (row.executor_id !== actor.id) fail(403, 'forbidden', 'Only the selected executor can complete this invocation.');
    const { signature, ...value } = completion;
    try { await verify(value, signature, row.executor.signing, 'function-result'); }
    catch { fail(400, 'invalid_result', 'Return a result signed by the selected executor.'); }
    if (completion.id !== id || completion.requestDigest !== await hash(row.request) ||
      (completion.state === 'succeeded' ? completion.error !== null : completion.result !== null || completion.error === null))
      fail(400, 'invalid_result', 'Return a signed result for this invocation.');
    if (row.phase === 'settled' || row.lease_token !== lease) return this.view(row);
    if (completion.state === 'succeeded' && row.phase !== 'dispatched')
      fail(400, 'invalid_result', 'Start the invocation before completing it.');
    const updated = await this.resources.db.one<InvocationRow>(
      `UPDATE function_invocations SET state=$3,phase='settled',completion=$4,error=NULL,finished_at=$5,lease_until=NULL
       WHERE id=$1 AND lease_token=$2 AND state IN ('queued','running','uncertain') RETURNING *`,
      [id, lease, completion.state, JSON.stringify(completion), completion.finishedAt]);
    if (!updated) return this.view(await this.row(id));
    await this.activity(row.environment_id);
    return this.view(updated);
  }
  async cancel(actor: Actor, id: string) {
    const row = await this.row(id);
    if (row.actor_id === actor.id) await this.resources.authorization.active(actor);
    else await this.resources.authorization.requirePrincipal(actor, row.owner_id, 'execute');
    await this.resources.db.pool.query(
      `UPDATE function_invocations SET cancel_requested=true,
       state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'cancelled' END,
       phase=CASE WHEN phase='dispatched' THEN phase ELSE 'settled' END,
       error=CASE WHEN phase='dispatched' THEN $2::jsonb ELSE $3::jsonb END,
       finished_at=CASE WHEN phase='dispatched' THEN NULL ELSE now() END,
       lease_until=CASE WHEN phase='dispatched' THEN now()+interval '60 seconds' ELSE NULL END
       WHERE id=$1 AND state IN ('queued','running')`, [id,
        JSON.stringify({ code: 'cancellation_pending', message: 'Cancellation is waiting for the executor to confirm.' }),
        JSON.stringify({ code: 'invocation_cancelled', message: 'The invocation was cancelled before it started.' })]);
    return this.get(actor, id);
  }
  async recover() {
    await this.resources.db.pool.query(
      `UPDATE function_invocations i SET state='failed',phase='settled',error=$1,finished_at=now(),lease_until=NULL
       WHERE state='queued' AND ((request->>'expiresAt')::timestamptz<=now()
       OR NOT EXISTS(SELECT 1 FROM resources f WHERE f.id=i.function_id)
       OR NOT EXISTS(SELECT 1 FROM executor_environments e WHERE e.resource_id=i.environment_id AND e.stopped_at IS NULL))`,
      [JSON.stringify({ code: 'invocation_unavailable', message: 'The function or its environment is no longer available for this invocation.' })]);
    await this.resources.db.pool.query(
      `UPDATE function_invocations SET state=CASE WHEN phase='dispatched' THEN 'uncertain' ELSE 'queued' END,
       error=CASE WHEN phase='dispatched' THEN $1::jsonb ELSE NULL END,
       phase=CASE WHEN phase='dispatched' THEN phase ELSE 'queued' END,
       finished_at=CASE WHEN phase='dispatched' THEN now() ELSE NULL END,lease_until=NULL
       WHERE lease_until<now() AND (state='running' OR
       (state='uncertain' AND cancel_requested=true AND phase='dispatched' AND finished_at IS NULL))`,
      [JSON.stringify({ code: 'execution_interrupted', message: 'Check the result before invoking this function again.' })]);
  }
}
