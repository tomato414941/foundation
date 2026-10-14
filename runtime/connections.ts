import { randomUUID } from 'node:crypto';
import { canonical } from '../shared/authority.js';
import type { BoundKeys, IdentityKeys } from '../shared/authority.js';
import type { JsonValue, MethodDescription } from '../shared/contracts.js';
import { AppMaterial, ConnectionAction, ConnectionMaterial, connectionMetadata, requiresApp } from '../shared/connections.js';
import type { AppState, ConnectionState } from '../shared/connections.js';
import { connectionMethod } from '../shared/connection-methods.js';
import { visibleConnectionFields } from '../shared/connection-fields.js';
import { ContentTypes, Operations, authorizeUse, renewContent, useContent } from '../shared/custody.js';
import type { CustodyContent, ExecutionIntent } from '../shared/custody.js';
import { encode } from '../shared/encryption.js';
import type { ConnectionOperation } from '../server/connection-operations.js';
import type { Transport } from '../server/transport.js';
import { DomainError, fail } from '../server/errors.js';
import type { ExecutionExtension } from './executor.js';
import type { Journal } from './journal.js';
import { AwsConnections } from './aws.js';
import type { AwsConnectionProvider } from './aws.js';
import { connectionProviders } from './connection-providers.js';
import type { ConnectionCheckpoint, ConnectionProvider } from './connection-provider.js';
import { utf8 } from './inputs.js';

export interface ConnectionBroker {
  prepare(id: string, resourceId: string, expectedRevision: number): Promise<ConnectionOperation>;
  dispatch(id: string, fence: string): Promise<unknown>;
  commit(id: string, fence: string, content: CustodyContent): Promise<CustodyContent>;
  uncertain(id: string, fence: string): Promise<unknown>;
  abort(id: string, fence: string): Promise<unknown>;
  state(resourceId: string): Promise<ConnectionOperation | null>;
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
    return this.providers(method);
  }
  private metadata(material: ConnectionState) {
    return connectionMetadata(material, this.provider(material.method).facts(material));
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
    if ((await this.metadata(result)).authorizationDigest !== content.metadata.authorizationDigest)
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
    if (!requiresApp(state.method)) return 'implicitApp' in state && state.implicitApp ? state.implicitApp : AppMaterial.parse({ format: 1, methodId: state.methodId,
      generation: state.generation, clientId: '', fields: {} });
    const operation = intent.operation === Operations.revoke ? Operations.revoke : Operations.refresh;
    const app = await this.app(state.appId!, state.methodId, { ...intent, operation }, sources);
    if (app.generation !== state.appGeneration)
      fail(409, 'app_changed', 'Reconnect this service with the current application.');
    if (connectionMethod(state.method).requiresApp && state.method.kind !== 'aws' &&
      Object.entries(visibleConnectionFields(state.method.config.fields, state.fields ?? {})).some(([key, value]) => app.fields[key] !== value))
      fail(409, 'app_changed', 'Reconnect this service with the current application settings.');
    return app;
  }
  async validate(input: JsonValue, intent: ExecutionIntent, sources: CustodyContent[]) {
    const action = ConnectionAction.parse(input);
    if (intent.operation !== Operations[action.action]) fail(400, 'wrong_operation', 'Use the approved connection operation.');
    const state = await this.material(this.source(action.id, ContentTypes.tokenSet, sources), intent);
    if (action.action === 'refresh' || connectionMethod(state.method).revocable) await this.connectionApp(state, intent, sources);
  }
  async execute(input: JsonValue, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal): Promise<JsonValue> {
    const action = ConnectionAction.parse(input);
    if (this.active.has(action.id)) fail(409, 'connection_busy', 'Another operation is updating this connection.');
    this.active.add(action.id);
    try {
      signal.throwIfAborted();
      const content = this.source(action.id, ContentTypes.tokenSet, sources), state = await this.material(content, intent);
      if (action.action === 'refresh') {
        const refreshed = await this.refresh(content, state, intent, sources, signal);
        return { kind: 'refreshed', id: content.policy.id, ...(await this.metadata(refreshed)) };
      }
      const provider = this.provider(state.method), revoked = connectionMethod(state.method).revocable && Boolean(provider.revoke);
      if (revoked) await provider.revoke!(state, await this.connectionApp(state, intent, sources), signal);
      return { kind: 'disconnected', id: content.policy.id, revoked };
    } finally { this.active.delete(action.id); }
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
    const metadata = await this.metadata(material);
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
      if (error instanceof DomainError && ['connection_review', 'reconnect_required', 'account_changed', 'authorization_failed', 'service_rate_limit'].includes(error.code)) throw error;
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
