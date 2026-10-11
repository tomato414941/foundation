import { randomBytes, randomUUID } from 'node:crypto';
import { canonical, hash } from '../shared/authority.js';
import type { BoundKeys, IdentityKeys } from '../shared/authority.js';
import type { JsonValue, MethodDescription } from '../shared/contracts.js';
import { AppMaterial, ConnectionAction, ConnectionMaterial, connectionLabels, connectionMetadata, requiresApp } from '../shared/connections.js';
import type { AppState, ConnectionCommand, ConnectionLabelValues, ConnectionState } from '../shared/connections.js';
import { connectionMethod } from '../shared/connection-methods.js';
import { ContentTypes, Operations, authorizeUse, produceContent, renewContent, useContent, verifyPolicyApproval } from '../shared/custody.js';
import type { CustodyContent, ExecutionIntent } from '../shared/custody.js';
import { encode } from '../shared/encryption.js';
import type { ConnectionOperation } from '../server/connection-operations.js';
import type { Transport } from '../server/transport.js';
import { DomainError, fail } from '../server/errors.js';
import type { ExecutionExtension } from './executor.js';
import { DeliveryPending } from './executor.js';
import type { Journal } from './journal.js';
import { AwsConnections } from './aws.js';
import type { AwsConnectionProvider } from './aws.js';
import { connectionProviders } from './connection-providers.js';
import type { AuthorizationContext, ConnectionCheckpoint, ConnectionProvider, ConnectionStart } from './connection-provider.js';
import { utf8 } from './inputs.js';

export interface ConnectionBroker {
  relay?(input: { id: string; runId: string; stateDigest: string; expiresAt: string }): Promise<unknown>;
  capture(name: string, content: CustodyContent, labels: ConnectionLabelValues): Promise<{ id: string }>;
  prepare(id: string, resourceId: string, expectedRevision: number): Promise<ConnectionOperation>;
  dispatch(id: string, fence: string): Promise<unknown>;
  commit(id: string, fence: string, content: CustodyContent): Promise<CustodyContent>;
  uncertain(id: string, fence: string): Promise<unknown>;
  abort(id: string, fence: string): Promise<unknown>;
  state(resourceId: string): Promise<ConnectionOperation | null>;
}
interface Flow {
  actor: BoundKeys;
  ownerId: string;
  input: Extract<ConnectionCommand, { action: 'start' }>;
  app: AppState | null;
  state: string;
  verifier: string;
  expiresAt: number;
  phase: 'authorize' | 'exchanging' | 'received' | 'review' | 'committing' | 'committed';
  checkpoint?: ConnectionCheckpoint;
  material?: ConnectionState;
  content?: CustodyContent;
}
interface Renewal {
  operation: ConnectionOperation;
  previous: CustodyContent;
  material: ConnectionState;
  app: AppState | null;
  phase: 'prepared' | 'dispatched' | 'received' | 'settled';
  checkpoint?: ConnectionCheckpoint;
  content?: CustodyContent;
  delivered: boolean;
}
export class Connections implements ExecutionExtension {
  private active = new Set<string>();
  private readonly providers: ReturnType<typeof connectionProviders>;
  constructor(
    readonly binding: BoundKeys, readonly keys: IdentityKeys, readonly broker: ConnectionBroker,
    readonly journal: Journal, transport: Transport,
    aws: AwsConnectionProvider = new AwsConnections(),
  ) { this.providers = connectionProviders(transport, aws); }

  private provider(method: MethodDescription): ConnectionProvider {
    return this.providers[connectionMethod(method).family];
  }
  private source(id: string, type: typeof ContentTypes.clientCredential | typeof ContentTypes.tokenSet, sources: CustodyContent[]) {
    const content = sources.find(source => source.policy.id === id && source.policy.contentType === type);
    if (!content) fail(409, 'input_required', 'Include the connection and its application in this execution.');
    return content;
  }
  private async material(content: CustodyContent, intent: ExecutionIntent, destination?: string) {
    const material = ConnectionMaterial.safeParse(JSON.parse(utf8(await useContent(content, intent, this.keys, { destination }))));
    if (!material.success) fail(409, 'reconnect_required', 'Reconnect this service with the current connection format.');
    const result = material.data;
    if ((await connectionMetadata(result)).authorizationDigest !== content.metadata.authorizationDigest)
      fail(409, 'connection_changed', 'Approve the current service account and permissions before using this connection.');
    if (result.state === 'reconnect' && intent.operation !== Operations.revoke)
      fail(409, 'reconnect_required', 'Reconnect this service before using it.');
    return result;
  }
  private async app(id: string, methodId: string, intent: ExecutionIntent, sources: CustodyContent[]) {
    const content = this.source(id, ContentTypes.clientCredential, sources);
    const value = AppMaterial.parse(JSON.parse(utf8(await useContent(content, intent, this.keys))));
    if (value.methodId !== methodId) fail(400, 'wrong_app', 'Choose an application for this connection method.');
    return value;
  }
  private async connectionApp(state: ConnectionState, intent: ExecutionIntent, sources: CustodyContent[]) {
    if (connectionMethod(state.method).application === 'none') return null;
    if (!requiresApp(state.method)) return AppMaterial.parse({ format: 1, methodId: state.methodId,
      generation: state.generation, clientId: '', fields: {} });
    const operation = intent.operation === Operations.revoke ? Operations.revoke : Operations.refresh;
    const app = await this.app(state.appId!, state.methodId, { ...intent, operation }, sources);
    if (app.generation !== state.appGeneration)
      fail(409, 'app_changed', 'Reconnect this service with the current application.');
    return app;
  }
  private async flow(id: string, intent: ExecutionIntent) {
    const flow = await this.readFlow(id);
    if (!flow || flow.expiresAt <= Date.now() || canonical(flow.actor) !== canonical(intent.actor) || flow.ownerId !== intent.ownerId)
      fail(409, 'connection_expired', 'Start the connection again.');
    return flow;
  }
  private async readFlow(id: string) {
    const flow = await this.journal.read<Flow>('connect_' + id);
    if (flow && (!ConnectionAction.safeParse(flow.input).success ||
      (flow.material && !ConnectionMaterial.safeParse(flow.material).success)))
      fail(409, 'connection_expired', 'Start the connection again.');
    return flow;
  }
  private writeFlow(id: string, flow: Flow) { return this.journal.write('connect_' + id, flow); }
  private async startApp(input: ConnectionStart, intent: ExecutionIntent, sources: CustodyContent[]) {
    if (connectionMethod(input.method).application === 'none') return null;
    return input.appId ? this.app(input.appId, input.methodId, intent, sources)
      : AppMaterial.parse({ format: 1, methodId: input.methodId, generation: input.flowId, clientId: '', fields: {} });
  }
  private authorization(id: string, flow: Flow, signal: AbortSignal): AuthorizationContext {
    return { input: flow.input, app: flow.app, state: flow.state, verifier: flow.verifier, signal,
      dispatch: async () => { flow.phase = 'exchanging'; await this.writeFlow(id, flow); },
      receive: async checkpoint => { flow.checkpoint = checkpoint; flow.phase = 'received'; await this.writeFlow(id, flow); },
    };
  }

  async validate(input: JsonValue, intent: ExecutionIntent, sources: CustodyContent[]) {
    const action = ConnectionAction.parse(input);
    const expected = Operations[action.action === 'refresh' || action.action === 'revoke' ? action.action : 'connect'];
    if (intent.operation !== expected) fail(400, 'wrong_operation', 'Use the approved connection operation.');
    if (action.action === 'start') {
      if (requiresApp(action.method) && !action.appId)
        fail(400, 'app_required', 'Choose an OAuth application.');
      if (connectionMethod(action.method).browserAuthorization) {
        if (!action.redirectUri) fail(400, 'invalid_redirect', 'Choose a callback URL.');
        const redirect = new URL(action.redirectUri);
        if (redirect.username || redirect.password || redirect.hash || redirect.search ||
          !(action.redirectUri === intent.origin + '/oauth/callback' ||
            (redirect.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(redirect.hostname))))
          fail(400, 'invalid_redirect', 'Use the Foundation callback or a callback on this computer.');
      }
      this.provider(action.method).validate(action, await this.startApp(action, intent, sources));
    } else if (action.action === 'commit') {
      const flow = await this.flow(action.flowId, intent), approval = await verifyPolicyApproval(action.approval);
      if (!flow.material || action.authorizationDigest !== (await connectionMetadata(flow.material)).authorizationDigest ||
        approval.policy.contentType !== ContentTypes.tokenSet || approval.policy.ownerId !== intent.ownerId || approval.policy.origin !== intent.origin ||
        canonical(approval.policy.authorities.find(authority => authority.id === approval.authorityId)) !== canonical(intent.actor) ||
        !approval.policy.producers.some(producer => producer.runId === intent.id &&
          canonical(producer.executor) === canonical(this.binding) && Date.parse(producer.expiresAt) > Date.now()))
        fail(403, 'approval_required', 'Review the connection and approve its recipients before saving.');
    } else if (action.action === 'exchange') {
      const flow = await this.flow(action.flowId, intent);
      if (flow.app && flow.input.appId) {
        const app = await this.app(flow.input.appId!, flow.input.methodId, intent, sources);
        if (canonical(app) !== canonical(flow.app)) fail(409, 'app_changed', 'Start the connection again with the current application.');
      }
    } else {
      const content = this.source(action.id, ContentTypes.tokenSet, sources);
      const state = await this.material(content, intent);
      await this.connectionApp(state, intent, sources);
    }
  }

  async execute(input: JsonValue, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal): Promise<JsonValue> {
    const action = ConnectionAction.parse(input), lock = 'flowId' in action ? action.flowId : action.id;
    if (this.active.has(lock)) fail(409, 'connection_busy', 'Another operation is updating this connection.');
    this.active.add(lock);
    try {
      signal.throwIfAborted();
      if (action.action === 'start') return await this.start(action, intent, sources, signal);
      if (action.action === 'exchange') return await this.exchange(action, intent, signal);
      if (action.action === 'commit') return await this.commit(action, intent);
      const content = this.source(action.id, ContentTypes.tokenSet, sources), state = await this.material(content, intent);
      if (action.action === 'refresh') {
        await this.provider(state.method).check?.(state, signal);
        const refreshed = await this.refresh(content, state, intent, sources, signal);
        return { kind: 'refreshed', id: content.policy.id, ...(await connectionMetadata(refreshed)) };
      }
      const provider = this.provider(state.method);
      if (!provider.revoke) fail(409, 'manual_revoke', 'Remove access in the service settings, then remove this connection.');
      await provider.revoke(state, await this.connectionApp(state, intent, sources), signal);
      return { kind: 'revoked', id: content.policy.id };
    } finally { this.active.delete(lock); }
  }

  private async review(id: string, flow: Flow): Promise<JsonValue> {
    // The person reviewing reads the account and method by name; only the signed metadata is committed.
    return { kind: 'review', flowId: id, name: flow.input.name,
      metadata: { ...await connectionMetadata(flow.material!), ...connectionLabels(flow.material!) } };
  }
  private async start(input: Extract<ConnectionCommand, { action: 'start' }>, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal) {
    if (await this.readFlow(input.flowId)) fail(409, 'flow_exists', 'Use a new connection request.');
    const flow: Flow = { actor: intent.actor, ownerId: intent.ownerId, input,
      app: await this.startApp(input, intent, sources),
      state: randomBytes(32).toString('base64url'), verifier: randomBytes(32).toString('base64url'),
      expiresAt: Math.min(Date.now() + 600_000, Date.parse(intent.expiresAt)), phase: 'authorize' };
    await this.writeFlow(input.flowId, flow);
    const result = await this.provider(input.method).start(this.authorization(input.flowId, flow, signal));
    if (result.kind === 'ready') {
      flow.material = result.material; flow.phase = 'review';
      await this.writeFlow(input.flowId, flow);
      return this.review(input.flowId, flow);
    }
    if (input.redirectUri === intent.origin + '/oauth/callback') await this.broker.relay?.({ id: input.flowId,
      runId: intent.id, stateDigest: await hash(flow.state), expiresAt: new Date(flow.expiresAt).toISOString() });
    return { kind: 'authorize', flowId: input.flowId,
      url: result.url };
  }
  private async exchange(action: Extract<ConnectionCommand, { action: 'exchange' }>, intent: ExecutionIntent, signal: AbortSignal) {
    const flow = await this.flow(action.flowId, intent);
    if (flow.phase === 'review') return this.review(action.flowId, flow);
    const provider = this.provider(flow.input.method);
    if (!provider.exchange || !['authorize', 'received'].includes(flow.phase))
      fail(409, 'connection_uncertain', 'Check the connection before authorizing it again.');
    flow.material = await provider.exchange(this.authorization(action.flowId, flow, signal), action.parameters,
      flow.phase === 'received' ? flow.checkpoint : undefined);
    flow.phase = 'review';
    await this.writeFlow(action.flowId, flow);
    return this.review(action.flowId, flow);
  }
  private async commit(action: Extract<ConnectionCommand, { action: 'commit' }>, intent: ExecutionIntent) {
    const flow = await this.flow(action.flowId, intent);
    if (flow.phase === 'committed') return { kind: 'connected', id: flow.content!.policy.id };
    if (!['review', 'committing'].includes(flow.phase)) fail(409, 'approval_required', 'Review this connection before saving.');
    if (!flow.content) {
      flow.content = await produceContent(encode(canonical(flow.material)), action.approval, intent.id,
        this.binding, this.keys, await connectionMetadata(flow.material!));
      flow.phase = 'committing';
      await this.writeFlow(action.flowId, flow);
    } else if (canonical(flow.content.policy) !== canonical(action.approval.policy) || flow.content.creationRunId !== intent.id) {
      fail(409, 'connection_uncertain', 'Finish saving the previously approved connection before starting another save.');
    }
    let resource;
    try { resource = await this.broker.capture(flow.input.name, flow.content, connectionLabels(flow.material!)); }
    catch (error) {
      if (error instanceof DomainError && error.status < 500) throw error;
      throw new DeliveryPending();
    }
    flow.phase = 'committed';
    await this.writeFlow(action.flowId, flow);
    return { kind: 'connected', id: resource.id };
  }
  async recover(input: JsonValue, intent: ExecutionIntent): Promise<JsonValue | null> {
    const action = ConnectionAction.parse(input);
    if (action.action !== 'commit') return null;
    const flow = await this.readFlow(action.flowId);
    if (!flow?.content || flow.ownerId !== intent.ownerId || canonical(flow.actor) !== canonical(intent.actor) ||
      flow.content.creationRunId !== intent.id || canonical(flow.content.policy) !== canonical(action.approval.policy) ||
      !['committing', 'committed'].includes(flow.phase)) return null;
    try { await this.broker.capture(flow.input.name, flow.content, connectionLabels(flow.material!)); }
    catch (error) {
      if (error instanceof DomainError && error.status < 500) return null;
      throw new DeliveryPending();
    }
    flow.phase = 'committed'; await this.writeFlow(action.flowId, flow);
    return { kind: 'connected', id: flow.content.policy.id };
  }

  async outputs(content: CustodyContent, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal,
    destination?: string): Promise<Record<string, string>> {
    let state = await this.material(content, intent, destination);
    if (this.provider(state.method).renew && await this.broker.state(content.policy.id))
      fail(409, 'connection_busy', 'Resolve the current token update before using this connection.');
    state = await this.refresh(content, state, intent, sources, signal, destination);
    return this.provider(state.method).outputs(state, await this.connectionApp(state, intent, sources), signal);
  }

  private async refreshed(record: Renewal, material: ConnectionState) {
    const metadata = await connectionMetadata(material);
    if (metadata.authorizationDigest !== record.previous.metadata.authorizationDigest)
      fail(409, 'connection_review', 'Review the changed service account or permissions before sharing the updated connection.');
    record.material = material;
    record.content = await renewContent(record.previous, encode(canonical(material)), this.binding, this.keys, metadata);
    record.phase = 'settled';
    await this.journal.write('refresh_' + record.operation.id, record);
    await this.broker.commit(record.operation.id, record.operation.fence, record.content);
    record.delivered = true;
    await this.journal.write('refresh_' + record.operation.id, record);
    return material;
  }
  private async refresh(content: CustodyContent, material: ConnectionState, intent: ExecutionIntent,
    sources: CustodyContent[], signal: AbortSignal, destination?: string) {
    const provider = this.provider(material.method);
    if (!provider.needsRenewal(material)) return material;
    if (!provider.renew) fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
    try { await authorizeUse(content, { ...intent, operation: Operations.refresh }, { destination }); }
    catch { fail(403, 'refresh_required', 'Authorize this requester and executor to renew the connection for this destination.'); }
    const app = await this.connectionApp(material, intent, sources), id = randomUUID();
    const operation = await this.broker.prepare(id, content.policy.id, content.materialRevision);
    const record: Renewal = { operation, previous: content, material, app, phase: 'prepared', delivered: false };
    await this.journal.write('refresh_' + id, record);
    try {
      signal.throwIfAborted();
      record.phase = 'dispatched';
      await this.journal.write('refresh_' + id, record);
      await this.broker.dispatch(id, operation.fence);
      signal.throwIfAborted();
      const updated = await provider.renew({ material, app, signal, receive: async checkpoint => {
        record.checkpoint = checkpoint; record.phase = 'received';
        await this.journal.write('refresh_' + id, record);
      } });
      return await this.refreshed(record, updated);
    } catch (error) {
      if (record.phase === 'prepared') await this.broker.abort(id, operation.fence);
      else await this.broker.uncertain(id, operation.fence).catch(() => {});
      if (error instanceof DomainError && ['connection_review', 'reconnect_required', 'account_changed'].includes(error.code)) throw error;
      fail(409, 'connection_uncertain', 'Check the token update before using this connection again.');
    }
  }

  async reconcile() {
    const pending: string[] = [];
    for (const id of await this.journal.keys('refresh_')) {
      try {
      const record = (await this.journal.read<Renewal>(id))!;
      if (record.delivered) continue;
      if (record.content) {
        await this.broker.commit(record.operation.id, record.operation.fence, record.content);
        record.delivered = true;
        await this.journal.write(id, record);
        continue;
      }
      const active = await this.broker.state(record.operation.resource_id);
      if (!active || active.id !== record.operation.id || active.state === 'prepared') {
        if (active?.id === record.operation.id && active.state === 'prepared')
          await this.broker.abort(record.operation.id, record.operation.fence);
        record.delivered = true;
        await this.journal.write(id, record);
      } else if (record.checkpoint && this.provider(record.material.method).recover) {
        const updated = await this.provider(record.material.method).recover!(record.material, record.app, record.checkpoint);
        await this.refreshed(record, updated);
      } else {
        await this.broker.uncertain(record.operation.id, record.operation.fence);
        record.delivered = true; await this.journal.write(id, record);
      }
      } catch { pending.push(id.slice(8)); }
    }
    return pending;
  }
}
