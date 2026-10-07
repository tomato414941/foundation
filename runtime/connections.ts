import { randomBytes, randomUUID } from 'node:crypto';
import safeRegex from 'safe-regex2';
import { canonical, hash } from '../shared/authority.js';
import type { BoundKeys, IdentityKeys } from '../shared/authority.js';
import type { JsonValue, MethodDescription } from '../shared/contracts.js';
import { AppMaterial, ConnectionAction, ConnectionMaterial, connectionMetadata, requiresApp } from '../shared/connections.js';
import type { AppState, ConnectionCommand, ConnectionState } from '../shared/connections.js';
import { produceContent, renewContent, useContent, verifyPolicyApproval } from '../shared/custody.js';
import type { CustodyContent, ExecutionIntent } from '../shared/custody.js';
import { encode } from '../shared/encryption.js';
import { atPointer, textValue } from '../shared/values.js';
import { OAuth } from '../server/oauth.js';
import type { OAuthToken } from '../server/oauth.js';
import type { ConnectionOperation } from '../server/connection-operations.js';
import type { Transport } from '../server/transport.js';
import { DomainError, fail } from '../server/errors.js';
import type { ExecutionExtension } from './executor.js';
import { DeliveryPending } from './executor.js';
import type { Journal } from './journal.js';
import type { RoleProvider } from './roles.js';
import { AwsRoles } from './roles.js';
import { utf8 } from './inputs.js';

export interface ConnectionBroker {
  relay?(input: { id: string; runId: string; stateDigest: string; expiresAt: string }): Promise<unknown>;
  capture(name: string, content: CustodyContent): Promise<{ id: string }>;
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
  checkpoint?: { token: OAuthToken; response: Record<string, unknown> };
  material?: ConnectionState;
  content?: CustodyContent;
}
interface Renewal {
  operation: ConnectionOperation;
  previous: CustodyContent;
  material: ConnectionState;
  app: AppState;
  phase: 'prepared' | 'dispatched' | 'received' | 'settled';
  checkpoint?: { token: OAuthToken; response: Record<string, unknown> };
  content?: CustodyContent;
  delivered: boolean;
}
function fields(method: MethodDescription, input: Record<string, string>) {
  if (method.kind === 'role') return {};
  const definitions = method.config.fields;
  const values = { ...(method.kind === 'oauth' ? method.config.defaults : {}), ...input };
  for (const field of definitions) {
    if (field.required !== false && !values[field.name]) fail(400, 'missing_field', 'Complete the required service fields.');
    if (values[field.name]?.includes('\0')) fail(400, 'invalid_field', 'Check the service fields.');
    if (field.pattern && (field.pattern.length > 200 || !safeRegex(field.pattern)))
      fail(400, 'invalid_pattern', 'Use a simple field validation pattern.');
    if (field.pattern && values[field.name] && !new RegExp(field.pattern, 'u').test(values[field.name]!.slice(0, 1000)))
      fail(400, 'invalid_field', 'Check the service fields.');
  }
  if (Object.keys(input).some(key => !definitions.some(field => field.name === key)))
    fail(400, 'invalid_field', 'Remove unrecognized service fields.');
  return values;
}

export class Connections implements ExecutionExtension {
  private active = new Set<string>();
  constructor(
    readonly binding: BoundKeys, readonly keys: IdentityKeys, readonly broker: ConnectionBroker,
    readonly journal: Journal, readonly transport: Transport, readonly roles: RoleProvider = new AwsRoles(),
  ) {}

  private oauth(signal?: AbortSignal) {
    return new OAuth({ send: request => this.transport.send({ ...request,
      ...(signal ? { signal: AbortSignal.any([signal, ...(request.signal ? [request.signal] : [])]) } : {}),
    }) });
  }
  private source(id: string, kind: 'app' | 'connection', sources: CustodyContent[]) {
    const content = sources.find(source => source.policy.id === id && source.policy.kind === kind);
    if (!content) fail(409, 'input_required', 'Include the connection and its application in this execution.');
    return content;
  }
  private async material(content: CustodyContent, intent: ExecutionIntent, destination?: string) {
    const result = ConnectionMaterial.parse(JSON.parse(utf8(await useContent(content, intent, this.keys, { destination }))));
    if ((await connectionMetadata(result)).authorizationDigest !== content.metadata.authorizationDigest)
      fail(409, 'connection_changed', 'Approve the current service account and permissions before using this connection.');
    return result;
  }
  private async app(id: string, methodId: string, intent: ExecutionIntent, sources: CustodyContent[]) {
    const content = this.source(id, 'app', sources);
    const value = AppMaterial.parse(JSON.parse(utf8(await useContent(content, intent, this.keys))));
    if (value.methodId !== methodId) fail(400, 'wrong_app', 'Choose an application for this connection method.');
    return value;
  }
  private async connectionApp(state: ConnectionState, intent: ExecutionIntent, sources: CustodyContent[]) {
    if (!requiresApp(state.method)) return AppMaterial.parse({ format: 1, methodId: state.methodId,
      generation: state.generation, clientId: '', fields: {} });
    const operation = intent.operation === 'revoke' ? 'revoke' : 'refresh';
    const app = await this.app(state.appId!, state.methodId, { ...intent, operation }, sources);
    if (app.generation !== state.appGeneration)
      fail(409, 'app_changed', 'Reconnect this service with the current application.');
    return app;
  }
  private async flow(id: string, intent: ExecutionIntent) {
    const flow = await this.journal.read<Flow>('oauth_' + id);
    if (!flow || flow.expiresAt <= Date.now() || canonical(flow.actor) !== canonical(intent.actor) || flow.ownerId !== intent.ownerId)
      fail(409, 'connection_expired', 'Start the connection again.');
    return flow;
  }

  async validate(input: JsonValue, intent: ExecutionIntent, sources: CustodyContent[]) {
    const action = ConnectionAction.parse(input);
    const expected = action.action === 'refresh' || action.action === 'revoke' ? action.action : 'connect';
    if (intent.operation !== expected) fail(400, 'wrong_operation', 'Use the approved connection operation.');
    if (action.action === 'start') {
      if (action.method.kind === 'oauth') {
        if ((requiresApp(action.method) && !action.appId) || !action.redirectUri)
          fail(400, 'app_required', 'Choose an OAuth application and callback URL.');
        const redirect = new URL(action.redirectUri);
        if (redirect.username || redirect.password || redirect.hash || redirect.search ||
          !(action.redirectUri === intent.origin + '/oauth/callback' ||
            (redirect.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(redirect.hostname))))
          fail(400, 'invalid_redirect', 'Use the Foundation callback or a callback on this computer.');
        const app = action.appId ? await this.app(action.appId, action.methodId, intent, sources)
          : AppMaterial.parse({ format: 1, methodId: action.methodId, generation: action.flowId, clientId: '', fields: {} });
        fields(action.method, app.fields);
        if (requiresApp(action.method) && action.method.config.clientAuth !== 'none' && !app.clientSecret)
          fail(409, 'app_required', 'Add a client secret to this OAuth application.');
      } else if (action.method.kind === 'token') fields(action.method, action.fields);
      else if (!action.role) fail(400, 'role_required', 'Choose a role trusted for this executor.');
    } else if (action.action === 'commit') {
      const flow = await this.flow(action.flowId, intent), approval = await verifyPolicyApproval(action.approval);
      if (!flow.material || action.authorizationDigest !== (await connectionMetadata(flow.material)).authorizationDigest ||
        approval.policy.kind !== 'connection' || approval.policy.ownerId !== intent.ownerId || approval.policy.origin !== intent.origin ||
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
      const content = this.source(action.id, 'connection', sources);
      const state = await this.material(content, intent);
      if (state.method.kind === 'oauth') await this.connectionApp(state, intent, sources);
    }
  }

  async execute(input: JsonValue, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal): Promise<JsonValue> {
    const action = ConnectionAction.parse(input), lock = 'flowId' in action ? action.flowId : action.id;
    if (this.active.has(lock)) fail(409, 'connection_busy', 'Another operation is updating this connection.');
    this.active.add(lock);
    try {
      signal.throwIfAborted();
      if (action.action === 'start') return await this.start(action, intent, sources);
      if (action.action === 'exchange') return await this.exchange(action, intent, signal);
      if (action.action === 'commit') return await this.commit(action, intent);
      const content = this.source(action.id, 'connection', sources), state = await this.material(content, intent);
      if (action.action === 'refresh') {
        const refreshed = state.method.kind === 'oauth' ? await this.refresh(content, state, intent, sources, signal) : state;
        return { kind: 'refreshed', id: content.policy.id, ...(await connectionMetadata(refreshed)) };
      }
      if (state.method.kind !== 'oauth') fail(409, 'manual_revoke', 'Remove access in the service settings, then remove this connection.');
      await this.oauth(signal).revoke(state.method.config, await this.connectionApp(state, intent, sources), state.oauth!);
      return { kind: 'revoked', id: content.policy.id };
    } finally { this.active.delete(lock); }
  }

  private async review(id: string, flow: Flow): Promise<JsonValue> {
    return { kind: 'review', flowId: id, name: flow.input.name, metadata: await connectionMetadata(flow.material!) };
  }
  private async start(input: Extract<ConnectionCommand, { action: 'start' }>, intent: ExecutionIntent, sources: CustodyContent[]) {
    const id = 'oauth_' + input.flowId;
    if (await this.journal.read(id)) fail(409, 'flow_exists', 'Use a new connection request.');
    const flow: Flow = { actor: intent.actor, ownerId: intent.ownerId, input,
      app: input.method.kind !== 'oauth' ? null : input.appId
        ? await this.app(input.appId, input.methodId, intent, sources)
        : AppMaterial.parse({ format: 1, methodId: input.methodId, generation: input.flowId, clientId: '', fields: {} }),
      state: randomBytes(32).toString('base64url'), verifier: randomBytes(32).toString('base64url'),
      expiresAt: Math.min(Date.now() + 600_000, Date.parse(intent.expiresAt)), phase: input.method.kind === 'oauth' ? 'authorize' : 'review' };
    if (input.method.kind !== 'oauth') {
      if (input.method.kind === 'role') await this.roles.obtain(input.role!.arn, input.role!.externalId, input.role!.region);
      flow.material = ConnectionMaterial.parse({ format: 1, methodId: input.methodId, method: input.method,
        generation: randomUUID(), appId: null, appGeneration: null,
        ...(input.method.kind === 'role' ? { role: input.role } : { fields: fields(input.method, input.fields) }) });
    }
    await this.journal.write(id, flow);
    if (input.method.kind !== 'oauth') return this.review(input.flowId, flow);
    if (input.redirectUri === intent.origin + '/oauth/callback') await this.broker.relay?.({ id: input.flowId,
      runId: intent.id, stateDigest: await hash(flow.state), expiresAt: new Date(flow.expiresAt).toISOString() });
    const scopes = [...new Set([...input.method.config.scopes.default, ...input.scopes])];
    return { kind: 'authorize', flowId: input.flowId,
      url: await this.oauth().authorize(input.method.config, flow.app!, flow.state, flow.verifier, input.redirectUri!, scopes) };
  }
  private async exchange(action: Extract<ConnectionCommand, { action: 'exchange' }>, intent: ExecutionIntent, signal: AbortSignal) {
    const flow = await this.flow(action.flowId, intent), id = 'oauth_' + action.flowId;
    if (flow.phase === 'review') return this.review(action.flowId, flow);
    if (flow.input.method.kind !== 'oauth' || !flow.app || !['authorize', 'received'].includes(flow.phase))
      fail(409, 'connection_uncertain', 'Check the connection before authorizing it again.');
    const oauth = this.oauth(signal), spec = flow.input.method.config;
    const parameters = new URLSearchParams(action.parameters);
    if (parameters.getAll('state').length !== 1 || parameters.get('state') !== flow.state)
      fail(400, 'invalid_state', 'Start the connection again.');
    let token: OAuthToken;
    if (flow.phase === 'received') {
      token = await oauth.inspect(spec, flow.app, flow.checkpoint!.token, flow.checkpoint!.response);
    } else {
      flow.phase = 'exchanging';
      await this.journal.write(id, flow);
      token = await oauth.exchange(spec, flow.app, { parameters, state: flow.state }, flow.verifier,
        flow.input.redirectUri!, [...new Set([...spec.scopes.default, ...flow.input.scopes])], undefined,
        async (token, response) => {
          flow.checkpoint = { token, response }; flow.phase = 'received';
          await this.journal.write(id, flow);
        });
    }
    flow.material = ConnectionMaterial.parse({ format: 1, methodId: flow.input.methodId, method: flow.input.method,
      generation: randomUUID(), appId: flow.input.appId, appGeneration: flow.input.appId ? flow.app.generation : null, oauth: token });
    flow.phase = 'review';
    await this.journal.write(id, flow);
    return this.review(action.flowId, flow);
  }
  private async commit(action: Extract<ConnectionCommand, { action: 'commit' }>, intent: ExecutionIntent) {
    const flow = await this.flow(action.flowId, intent), id = 'oauth_' + action.flowId;
    if (flow.phase === 'committed') return { kind: 'connected', id: flow.content!.policy.id };
    if (!['review', 'committing'].includes(flow.phase)) fail(409, 'approval_required', 'Review this connection before saving.');
    if (!flow.content) {
      flow.content = await produceContent(encode(canonical(flow.material)), action.approval, intent.id,
        this.binding, this.keys, await connectionMetadata(flow.material!));
      flow.phase = 'committing';
      await this.journal.write(id, flow);
    } else if (canonical(flow.content.policy) !== canonical(action.approval.policy) || flow.content.creationRunId !== intent.id) {
      fail(409, 'connection_uncertain', 'Finish saving the previously approved connection before starting another save.');
    }
    let resource;
    try { resource = await this.broker.capture(flow.input.name, flow.content); }
    catch (error) {
      if (error instanceof DomainError && error.status < 500) throw error;
      throw new DeliveryPending();
    }
    flow.phase = 'committed';
    await this.journal.write(id, flow);
    return { kind: 'connected', id: resource.id };
  }
  async recover(input: JsonValue, intent: ExecutionIntent): Promise<JsonValue | null> {
    const action = ConnectionAction.parse(input);
    if (action.action !== 'commit') return null;
    const id = 'oauth_' + action.flowId, flow = await this.journal.read<Flow>(id);
    if (!flow?.content || flow.ownerId !== intent.ownerId || canonical(flow.actor) !== canonical(intent.actor) ||
      flow.content.creationRunId !== intent.id || canonical(flow.content.policy) !== canonical(action.approval.policy) ||
      !['committing', 'committed'].includes(flow.phase)) return null;
    try { await this.broker.capture(flow.input.name, flow.content); }
    catch (error) {
      if (error instanceof DomainError && error.status < 500) return null;
      throw new DeliveryPending();
    }
    flow.phase = 'committed'; await this.journal.write(id, flow);
    return { kind: 'connected', id: flow.content.policy.id };
  }

  async outputs(content: CustodyContent, intent: ExecutionIntent, sources: CustodyContent[], signal: AbortSignal,
    destination?: string): Promise<Record<string, string>> {
    let state = await this.material(content, intent, destination);
    if (state.method.kind === 'token') return Object.fromEntries(Object.entries(state.method.config.outputs)
      .map(([key, pointer]) => [key, textValue(atPointer(state.fields!, pointer))]));
    if (state.method.kind === 'role') return this.roles.obtain(state.role!.arn, state.role!.externalId, state.role!.region);
    if (await this.broker.state(content.policy.id))
      fail(409, 'connection_busy', 'Resolve the current token update before using this connection.');
    state = await this.refresh(content, state, intent, sources, signal);
    if (state.method.kind !== 'oauth') throw new Error('Use an OAuth connection.');
    return this.oauth(signal).outputs(state.method.config, await this.connectionApp(state, intent, sources), state.oauth!);
  }

  private async refreshed(record: Renewal, token: OAuthToken) {
    const material = ConnectionMaterial.parse({ ...record.material, oauth: token });
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
    sources: CustodyContent[], signal: AbortSignal) {
    if (material.method.kind !== 'oauth') return material;
    if (material.oauth!.expiresAt === null || material.oauth!.expiresAt! >= Date.now() + 60_000) return material;
    if (!(content.policy.authorities.some(authority => canonical(authority) === canonical(this.binding)) ||
      content.policy.grants.some(grant => canonical(grant.executor) === canonical(this.binding) &&
      grant.operations.includes('refresh') && Date.parse(grant.expiresAt) > Date.now())))
      fail(403, 'refresh_required', 'Authorize this executor to renew the connection.');
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
      const token = await this.oauth(signal).refresh(material.method.config, app, material.oauth!, async (token, response) => {
        record.checkpoint = { token, response }; record.phase = 'received';
        await this.journal.write('refresh_' + id, record);
      });
      return await this.refreshed(record, token);
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
      } else if (record.checkpoint && record.material.method.kind === 'oauth') {
        const token = await this.oauth().inspect(record.material.method.config, record.app,
          record.checkpoint.token, record.checkpoint.response);
        await this.refreshed(record, token);
      } else {
        await this.broker.uncertain(record.operation.id, record.operation.fence);
        record.delivered = true; await this.journal.write(id, record);
      }
      } catch { pending.push(id.slice(8)); }
    }
    return pending;
  }
}
