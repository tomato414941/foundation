import { z } from 'zod';
import type { JsonApi } from '../shared/client.js';
import { hash, sign } from '../shared/authority.js';
import { Invocation, ClaimedInvocation, InvocationCompletion, verifyFunction } from '../shared/function-api.js';
import type { Completion } from '../shared/function-api.js';
import type { CustodyContent, ExecutionIntent } from '../shared/custody.js';
import { ContentTypes, Operations } from '../shared/custody.js';
import { FunctionOperation } from '../shared/execution.js';
import { authorizeEnvironment } from '../shared/execution.js';
import type { Journal } from './journal.js';
import { DeliveryPending, Executor } from './executor.js';
import { DomainError } from '../server/errors.js';

export class FunctionBroker {
  readonly api: JsonApi;
  constructor(api: JsonApi) {
    this.api = { async json<T>(path: string, options = {}, schema?: z.ZodType<T>): Promise<T> {
      try { return await api.json(path, options, schema); }
      catch (error) {
        if (error instanceof Error && 'status' in error && typeof error.status === 'number' &&
          'code' in error && typeof error.code === 'string')
          throw new DomainError(error.status, error.code, error.message);
        throw error;
      }
    } };
  }
  claim(id: string) { return this.api.json('/api/environments/' + id + '/invocations/claim', { method: 'POST', body: {} }, ClaimedInvocation); }
  dispatch(id: string, lease: string) { return this.api.json('/api/invocations/' + id + '/dispatch', { method: 'POST', body: { lease } }); }
  renew(id: string, lease: string) { return this.api.json('/api/invocations/' + id + '/renew', { method: 'POST', body: { lease } },
    z.object({ active: z.boolean(), reason: z.enum(['cancelled', 'authorization_changed', 'lease_lost']).optional() })); }
  finish(lease: string, completion: Completion) { return this.api.json('/api/invocations/' + completion.id + '/finish',
    { method: 'POST', body: { lease, completion } }, Invocation); }
}
interface Record {
  id: string; digest: string; lease: string; phase: 'prepared' | 'dispatched' | 'settled';
  delivered: boolean; completion: Completion | null;
}
export class FunctionExecutor {
  constructor(readonly executor: Executor, readonly broker: FunctionBroker, readonly journal: Journal,
    readonly renewalMilliseconds = 15_000) {}
  private async complete(record: Record, state: Completion['state'], result: Completion['result'], error: Completion['error']) {
    const value = { id: record.id, requestDigest: record.digest, state, result, error, finishedAt: new Date().toISOString() };
    record.completion = InvocationCompletion.parse({ ...value,
      signature: await sign(value, this.executor.keys.signing, 'function-result') });
    record.phase = 'settled';
    await this.journal.write('invocation_' + record.id, record);
  }
  private async deliver(record: Record) {
    await this.broker.finish(record.lease, record.completion!);
    record.delivered = true;
    await this.journal.write('invocation_' + record.id, record);
  }
  async reconcile() {
    const pending: string[] = [];
    for (const key of await this.journal.keys('invocation_')) {
      try {
        const record = await this.journal.read<Record>(key);
        if (!record || record.delivered || record.phase === 'prepared') continue;
        if (!record.completion) await this.complete(record, 'uncertain', null,
          { code: 'execution_interrupted', message: 'Check the result before invoking this function again.' });
        await this.deliver(record);
      } catch { pending.push(key.slice('invocation_'.length)); }
    }
    return pending;
  }
  async tick(signal: AbortSignal = new AbortController().signal) {
    signal.throwIfAborted();
    const claim = await this.broker.claim(this.executor.environment.manifest.id);
    if (!claim) return false;
    const { request, publication, sources, lease } = claim, digest = await hash(request);
    const key = 'invocation_' + request.id;
    let record = await this.journal.read<Record>(key);
    if (record && record.digest !== digest) throw new Error('An invocation ID was reused for different input.');
    if (record?.completion) { record.lease = lease; await this.deliver(record); return true; }
    if (record?.phase === 'dispatched') {
      record.lease = lease;
      await this.complete(record, 'uncertain', null, { code: 'execution_interrupted', message: 'Check the result before invoking this function again.' });
      await this.deliver(record); return true;
    }
    record = { id: request.id, digest, lease, phase: 'prepared', delivered: false, completion: null };
    await this.journal.write(key, record);
    const controller = new AbortController(), runningSignal = AbortSignal.any([signal, controller.signal]);
    let cancellationRequested = false, renewing = false;
    const heartbeat = setInterval(() => {
      if (renewing) return;
      renewing = true;
      void this.broker.renew(request.id, lease).then(value => {
        if (!value.active) { cancellationRequested ||= value.reason === 'cancelled'; controller.abort(); }
      }, () => controller.abort()).finally(() => { renewing = false; });
    }, this.renewalMilliseconds);
    heartbeat.unref();
    try {
      await verifyFunction(publication, this.executor.binding);
      if (publication.functionId !== request.functionId || publication.definition.environmentId !== this.executor.environment.manifest.id ||
        await hash(publication.definition) !== request.definitionDigest || Date.parse(request.expiresAt) <= Date.now())
        throw new Error('Run the current approved function in its configured environment.');
      const checkpointKey = 'function_' + publication.functionId;
      const checkpoint = await this.journal.read<{ revision: number; digest: string }>(checkpointKey);
      const publicationDigest = await hash(publication);
      if (checkpoint && (publication.revision < checkpoint.revision ||
        (publication.revision === checkpoint.revision && checkpoint.digest !== publicationDigest)))
        throw new Error('The function definition is older than this executor has already observed.');
      await this.journal.write(checkpointKey, { revision: publication.revision, digest: publicationDigest });
      const operation = FunctionOperation.parse({ kind: 'function', functionId: request.functionId,
        definition: publication.definition, arguments: request.arguments, outputs: request.outputs });
      const intent: ExecutionIntent = { format: 2, id: request.id, origin: this.executor.environment.manifest.origin,
        ownerId: request.ownerId, actor: request.actor ?? this.executor.binding,
        executor: this.executor.binding, environmentId: publication.definition.environmentId,
        environmentDigest: await hash(this.executor.environment.manifest), operation: Operations.function,
        operationDigest: await hash(operation), functionId: request.functionId, functionDigest: request.definitionDigest,
        sources: await Promise.all(sources.map(async (content: CustodyContent) => ({ id: content.policy.id,
          policyDigest: await hash(content.policy), materialRevision: content.materialRevision,
          ...(content.policy.contentType === ContentTypes.tokenSet && typeof content.metadata.authorizationDigest === 'string'
            ? { authorizationDigest: content.metadata.authorizationDigest } : {}) }))),
        resultRecipients: [this.executor.binding], createdAt: request.createdAt, expiresAt: request.expiresAt };
      await authorizeEnvironment(this.executor.environment, intent);
      await this.executor.validateOperation(operation, intent, sources);
      runningSignal.throwIfAborted();
      await this.broker.dispatch(request.id, lease);
      record.phase = 'dispatched';
      await this.journal.write(key, record);
      runningSignal.throwIfAborted();
      const result = await this.executor.executeOperation(operation, intent, sources, runningSignal);
      if (new TextEncoder().encode(JSON.stringify(result)).byteLength > 1_000_000)
        throw new DomainError(413, 'result_too_large', 'The function completed, but its result exceeded the output limit.');
      await this.complete(record, 'succeeded', result, null);
    } catch (error) {
      if (error instanceof DeliveryPending) throw error;
      const dispatched = record.phase === 'dispatched';
      const state = runningSignal.aborted && cancellationRequested ? 'cancelled'
        : dispatched && (runningSignal.aborted || !(error instanceof DomainError)) ? 'uncertain' : 'failed';
      await this.complete(record, state, null, !runningSignal.aborted && error instanceof DomainError ? { code: error.code, message: error.message }
        : { code: state === 'uncertain' ? 'execution_uncertain' : state === 'cancelled' ? 'invocation_cancelled' : 'invalid_function',
          message: state === 'uncertain' ? 'Check the result before invoking this function again.'
            : state === 'cancelled' ? 'The function was cancelled.' : 'The executor could not authorize this function.' });
    } finally { clearInterval(heartbeat); }
    try { await this.deliver(record); } catch { throw new DeliveryPending(); }
    return true;
  }
}
