import { randomUUID } from 'node:crypto';
import type { MethodDescription } from '../shared/contracts.js';
import { AppMaterial, connectionMetadata, openConnection, requiresApp, sealedConnection } from '../shared/connections.js';
import type { AppState, ConnectionState } from '../shared/connections.js';
import { connectionMethod } from '../shared/connection-methods.js';
import { visibleConnectionFields } from '../shared/connection-fields.js';
import { sealedFor } from '../shared/custody.js';
import type { SealedItemValue } from '../shared/custody.js';
import type { CustodyClient } from '../shared/client.js';
import type { ConnectionOperation } from '../server/connection-operations.js';
import type { Transport } from '../server/transport.js';
import { DomainError, fail } from '../server/errors.js';
import type { Journal } from './journal.js';
import { AwsConnections } from './aws.js';
import type { AwsConnectionProvider } from './aws.js';
import { connectionProviders } from './connection-providers.js';
import type { ConnectionCheckpoint, ConnectionOutputs, ConnectionProvider } from './connection-provider.js';
import { utf8 } from './inputs.js';

export interface ConnectionBroker {
  method(connectionId: string): Promise<MethodDescription>;
  prepare(id: string, resourceId: string, expectedRevision: number): Promise<ConnectionOperation>;
  dispatch(id: string, fence: string): Promise<unknown>;
  commit(id: string, fence: string, content: SealedItemValue): Promise<SealedItemValue>;
  uncertain(id: string, fence: string): Promise<unknown>;
  abort(id: string, fence: string): Promise<unknown>;
  state(resourceId: string): Promise<ConnectionOperation | null>;
}
// The items a command opens, by id.
export type Sources = Map<string, { kind: string; content: SealedItemValue }>;
// A token update as this machine records it, until Foundation has the renewed tokens.
interface Renewal {
  operation: ConnectionOperation;
  previous: SealedItemValue;
  material: ConnectionState;
  app: AppState | null;
  phase: 'prepared' | 'dispatched' | 'received' | 'settled';
  checkpoint?: ConnectionCheckpoint;
  delivered: boolean;
}
export class Connections {
  private readonly providers: ReturnType<typeof connectionProviders>;
  constructor(
    readonly custody: CustodyClient, readonly broker: ConnectionBroker,
    readonly journal: Journal, transport: Transport,
    aws: AwsConnectionProvider = new AwsConnections(),
  ) { this.providers = connectionProviders(transport, aws); }

  private provider(method: MethodDescription): ConnectionProvider {
    return this.providers(method);
  }
  private metadata(material: ConnectionState) {
    return connectionMetadata(material, this.provider(material.method).facts(material));
  }
  private source(id: string, kind: 'app' | 'connection', sources: Sources) {
    const source = sources.get(id);
    if (!source || source.kind !== kind) fail(409, 'input_required', 'Include the connection and its application in the inputs.');
    return source.content;
  }
  // A connection is used with the method the server keeps for it now.
  private async material(id: string, content: SealedItemValue) {
    const method = await this.broker.method(id);
    const result = openConnection(await this.custody.open(content), content.metadata, method);
    if (result.state === 'reconnect')
      fail(409, 'reconnect_required', 'Reconnect this service before using it.');
    return result;
  }
  private async app(id: string, methodId: string, sources: Sources) {
    const content = this.source(id, 'app', sources);
    if (!await sealedFor(content, this.custody.keys.publicKey))
      fail(403, 'refresh_required', 'Only one its application is sealed for can renew this connection.');
    const value = AppMaterial.parse(JSON.parse(utf8(await this.custody.open(content))));
    if (value.methodId !== methodId) fail(400, 'wrong_app', 'Choose an application for this connection method.');
    return value;
  }
  private async connectionApp(state: ConnectionState, sources: Sources) {
    if (connectionMethod(state.method).application === 'none') return null;
    if (!requiresApp(state.method)) return 'implicitApp' in state && state.implicitApp ? state.implicitApp : AppMaterial.parse({ format: 1, methodId: state.methodId,
      generation: state.generation, clientId: '', fields: {} });
    const app = await this.app(state.appId!, state.methodId, sources);
    if (app.generation !== state.appGeneration)
      fail(409, 'app_changed', 'Reconnect this service with the current application.');
    if (connectionMethod(state.method).requiresApp && state.method.kind !== 'aws' &&
      Object.entries(visibleConnectionFields(state.method.config.fields, state.fields ?? {})).some(([key, value]) => app.fields[key] !== value))
      fail(409, 'app_changed', 'Reconnect this service with the current application settings.');
    return app;
  }
  async outputs(id: string, sources: Sources, signal: AbortSignal): Promise<ConnectionOutputs> {
    const content = this.source(id, 'connection', sources);
    let state = await this.material(id, content);
    if (this.provider(state.method).renew && await this.broker.state(id))
      fail(409, 'connection_busy', 'Resolve the current token update before using this connection.');
    state = await this.refresh(id, content, state, sources, signal);
    const values = await this.provider(state.method).outputs(state, await this.connectionApp(state, sources), signal);
    return { values, files: state.method.kind === 'token' ? state.method.config.files ?? [] : [] };
  }

  // Gives Foundation the renewed tokens, sealed for everyone who may open the connection now.
  private async deliver(record: Renewal) {
    const { operation, material } = record, metadata = await this.metadata(material);
    for (let attempt = 1; ; attempt++) {
      const content = await this.custody.seal(operation.resource_id, sealedConnection(material), record.previous.revision + 1, metadata);
      try {
        await this.broker.commit(operation.id, operation.fence, content);
        break;
      } catch (error) {
        if (attempt < 3 && error instanceof DomainError && error.code === 'recipients_changed') continue;
        throw error;
      }
    }
    record.delivered = true;
    await this.journal.write('refresh_' + operation.id, record);
  }
  private async refreshed(record: Renewal, material: ConnectionState) {
    record.material = material;
    record.phase = 'settled';
    await this.journal.write('refresh_' + record.operation.id, record);
    await this.deliver(record);
    return material;
  }
  private async refresh(resourceId: string, content: SealedItemValue, material: ConnectionState, sources: Sources, signal: AbortSignal) {
    const provider = this.provider(material.method);
    if (!provider.needsRenewal(material)) return material;
    if (!provider.renew) fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
    const app = await this.connectionApp(material, sources), id = randomUUID();
    const operation = await this.broker.prepare(id, resourceId, content.revision);
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
      if (error instanceof DomainError && ['reconnect_required', 'account_changed', 'authorization_failed', 'service_rate_limit'].includes(error.code)) throw error;
      fail(409, 'connection_uncertain', 'Check the token update before using this connection again.');
    }
  }

  async reconcile() {
    const pending: string[] = [];
    for (const id of await this.journal.pending('refresh_')) {
      try {
      const record = (await this.journal.read<Renewal>(id))!;
      if (record.delivered) continue;
      if (record.phase === 'settled') {
        await this.deliver(record);
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
