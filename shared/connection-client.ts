import { z } from 'zod';
import type { CustodyClient } from './client.js';
import { ApprovalRequest, Id, JsonObject, Name } from './contracts.js';
import type { JsonValue, MethodDescription } from './contracts.js';
import { canonical, hash } from './authority.js';
import { AccessPolicy, approvePolicy } from './custody.js';
import type { CustodyPolicy } from './custody.js';
import { ConnectionPlan, OAuthRelay, relayContext } from './protocol.js';
import { Task } from './execution.js';
import type { TaskView } from './execution.js';
import { decode, open } from './encryption.js';
import { ConnectionMaterial, requiresApp } from './connections.js';

const Review = z.object({ kind: z.literal('review'), flowId: Id, name: Name, metadata: JsonObject }).strict();
export const FlowRecord = z.object({
  id: Id, ownerId: Id, environmentId: Id, name: Name, appId: Id.nullable(),
  policy: AccessPolicy, previousPolicyDigest: z.string().nullable(),
  step: z.enum(['start', 'authorize', 'exchange', 'review', 'commit', 'connected', 'cancelled']),
  taskId: Id, createdAt: z.iso.datetime(),
  approval: z.object({ id: Id, index: z.number().int().min(0).max(7) }).strict().optional(),
  approvalCompleted: z.boolean().optional(),
  url: z.url().nullable(), review: Review.nullable(), connectionId: Id.nullable(),
}).strict();
export type ConnectionFlow = z.infer<typeof FlowRecord>;
export interface FlowStore {
  get(id: string): Promise<ConnectionFlow | null>;
  put(flow: ConnectionFlow): Promise<void>;
}
export type FlowProgress = { kind: 'pending'; flow: ConnectionFlow; task: TaskView }
  | { kind: 'authorize'; flow: ConnectionFlow; url: string }
  | { kind: 'review'; flow: ConnectionFlow; metadata: Record<string, JsonValue> }
  | { kind: 'connected'; flow: ConnectionFlow; id: string }
  | { kind: 'cancelled'; flow: ConnectionFlow }
  | { kind: 'failed'; flow: ConnectionFlow; task: TaskView; error: JsonValue };

export class ConnectionClient {
  constructor(readonly custody: CustodyClient, readonly store: FlowStore) {}
  private async flow(id: string) {
    const found = await this.store.get(Id.parse(id));
    if (!found) throw new Error('Continue this connection from the browser or terminal that started it.');
    const flow = FlowRecord.parse(found);
    if (flow.policy.origin !== this.custody.origin ||
      !flow.policy.authorities.some(authority => canonical(authority) === canonical(this.custody.binding)))
      throw new Error('Open this connection request with its initiating identity.');
    return flow;
  }
  async start(input: { ownerId: string; environmentId: string; name: string; methodId: string; method: MethodDescription;
    appId?: string; fields?: Record<string, string>; scopes?: string[]; role?: z.infer<typeof ConnectionMaterial.shape.role>;
    connectionId?: string; environments?: string[]; redirectUri?: string; approvalId?: string }) {
    const id = crypto.randomUUID();
    const plan = input.approvalId ? await this.custody.api.json('/api/requests/' + input.approvalId + '/connection', {}, ConnectionPlan) : null;
    if (plan && (plan.input.ownerId !== input.ownerId || plan.input.methodId !== input.methodId ||
      plan.input.connectionId !== input.connectionId ||
      (plan.input.environmentId && plan.input.environmentId !== input.environmentId)))
      throw new Error('Use the connection method and executor approved by this request.');
    const approval = plan ? { id: plan.id, index: plan.index } : undefined;
    const previous = input.connectionId ? await this.custody.read(input.connectionId) : null;
    if (previous && (previous.content.policy.kind !== 'connection' || previous.content.policy.ownerId !== input.ownerId ||
      previous.content.metadata.methodId !== input.methodId)) throw new Error('Choose the existing connection and its method.');
    const environments = await Promise.all((input.environments ?? [input.environmentId]).map(id => this.custody.environment(id)));
    const policy = await this.custody.policy(input.ownerId, 'connection', environments, {
      previous: previous?.content.policy,
    });
    const appId = requiresApp(input.method) ? Id.parse(input.appId) : null;
    const request = await this.custody.prepare(input.ownerId, input.environmentId, { kind: 'connect', input: {
      action: 'start', flowId: id, name: input.name, methodId: input.methodId, method: input.method, appId,
      fields: input.fields ?? {}, scopes: input.scopes ?? [],
      ...(input.role ? { role: input.role } : {}),
      ...(input.method.kind === 'oauth' ? { redirectUri: input.redirectUri ?? this.custody.origin + '/oauth/callback' } : {}),
    } }, { sourceIds: appId ? [appId] : [], approval });
    const flow: ConnectionFlow = { id, ownerId: input.ownerId, environmentId: input.environmentId, name: input.name,
      appId, policy, previousPolicyDigest: previous ? await hash(previous.content.policy) : null,
      step: 'start', taskId: request.intent.id, createdAt: new Date().toISOString(), url: null, review: null, connectionId: null,
      ...(approval ? { approval, approvalCompleted: false } : {}) };
    await this.store.put(flow);
    const task = await this.custody.submitPrepared(request);
    return { kind: 'pending' as const, flow, task };
  }
  async progress(id: string, relay = true): Promise<FlowProgress> {
    const flow = await this.flow(id);
    if (flow.step === 'connected') {
      if (flow.approval && !flow.approvalCompleted) {
        await this.custody.api.json('/api/requests/' + flow.approval.id + '/connection', {
          method: 'POST', body: { runId: flow.taskId, resourceId: flow.connectionId },
        }, ApprovalRequest);
        flow.approvalCompleted = true; await this.store.put(flow);
      }
      return { kind: 'connected', flow, id: flow.connectionId! };
    }
    if (flow.step === 'cancelled') return { kind: 'cancelled', flow };
    if (flow.step === 'review') return { kind: 'review', flow, metadata: flow.review!.metadata };
    if (flow.step === 'authorize') {
      if (relay) {
        const response = await this.custody.api.json('/api/oauth/relays/' + id, {}, OAuthRelay);
        if (response.id !== id || response.runId !== flow.taskId || response.context !== relayContext(this.custody.origin, id))
          throw new Error('The authorization response belongs to another connection request.');
        if (response.sealed) {
          const parameters = decode(await open(response.sealed, this.custody.keys.encryption,
            this.custody.binding.id, response.context));
          return this.complete(id, parameters);
        }
      }
      return { kind: 'authorize', flow, url: flow.url! };
    }
    const task = await this.custody.api.json('/api/executions/' + flow.taskId, {}, Task);
    if (['queued', 'running'].includes(task.state)) return { kind: 'pending', flow, task };
    const result = await this.custody.result(task);
    if (!result?.ok) return { kind: 'failed', flow, task, error: result?.error ?? task.error };
    if (flow.step === 'start') {
      const authorized = z.object({ kind: z.literal('authorize'), flowId: Id, url: z.url() }).strict().safeParse(result.result);
      if (authorized.success) {
        if (authorized.data.flowId !== id) throw new Error('The result belongs to another connection request.');
        flow.step = 'authorize'; flow.url = authorized.data.url;
        await this.store.put(flow);
        return { kind: 'authorize', flow, url: flow.url };
      }
    }
    if (flow.step === 'start' || flow.step === 'exchange') {
      const review = Review.parse(result.result);
      if (review.flowId !== id) throw new Error('The result belongs to another connection request.');
      flow.step = 'review'; flow.review = review;
      await this.store.put(flow);
      return { kind: 'review', flow, metadata: review.metadata };
    }
    const connected = z.object({ kind: z.literal('connected'), id: Id }).strict().parse(result.result);
    if (connected.id !== flow.policy.id) throw new Error('The connection was saved to another destination.');
    flow.step = 'connected'; flow.connectionId = connected.id;
    await this.store.put(flow);
    return this.progress(id);
  }
  async complete(id: string, parameters: string): Promise<FlowProgress> {
    const flow = await this.flow(id);
    if (flow.step !== 'authorize') return this.progress(id, false);
    const query = new URLSearchParams(parameters);
    if (query.getAll('state').length !== 1 || query.get('state') !== new URL(flow.url!).searchParams.get('state'))
      throw new Error('The authorization response does not match this connection request.');
    if (query.has('error')) {
      flow.step = 'cancelled'; await this.store.put(flow);
      return { kind: 'cancelled', flow };
    }
    const request = await this.custody.prepare(flow.ownerId, flow.environmentId, { kind: 'connect', input: {
      action: 'exchange', flowId: id, parameters,
    } }, { sourceIds: flow.appId ? [flow.appId] : [], approval: flow.approval });
    flow.step = 'exchange'; flow.taskId = request.intent.id;
    await this.store.put(flow);
    const task = await this.custody.submitPrepared(request);
    return { kind: 'pending', flow, task };
  }
  async accept(id: string): Promise<FlowProgress> {
    const flow = await this.flow(id);
    if (flow.step !== 'review') throw new Error('Review the connection account and permissions before saving.');
    const previous = flow.previousPolicyDigest ? await this.custody.read(flow.policy.id) : null;
    if (previous && await hash(previous.content.policy) !== flow.previousPolicyDigest)
      throw new Error('The connection recipients changed. Start again to approve the current recipients.');
    const environment = await this.custody.environment(flow.environmentId), runId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 600_000).toISOString();
    const policy: CustodyPolicy = { ...flow.policy, producers: [{ executor: environment.manifest.executor,
      runId, expiresAt, materialRevision: (previous?.content.materialRevision ?? 0) + 1 }] };
    const request = await this.custody.prepare(flow.ownerId, flow.environmentId, { kind: 'connect', input: {
      action: 'commit', flowId: id, authorizationDigest: flow.review!.metadata.authorizationDigest!,
      approval: await approvePolicy(policy, this.custody.binding, this.custody.keys, previous?.content),
    } }, { id: runId, expiresAt, approval: flow.approval });
    flow.step = 'commit'; flow.taskId = request.intent.id;
    await this.store.put(flow);
    const task = await this.custody.submitPrepared(request);
    return { kind: 'pending', flow, task };
  }
  async cancel(id: string) {
    const flow = await this.flow(id);
    if (['start', 'exchange', 'commit'].includes(flow.step))
      await this.custody.api.json('/api/executions/' + flow.taskId + '/cancel', { method: 'POST', body: {} }, Task);
    flow.step = 'cancelled';
    await this.store.put(flow);
    return { kind: 'cancelled' as const, flow };
  }
}
