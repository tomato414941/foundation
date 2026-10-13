import { z } from 'zod';
import type { CustodyClient } from './client.js';
import { Id, MethodDefinition, Name, Resource } from './contracts.js';
import type { MethodDescription } from './contracts.js';
import { canonical, hash } from './authority.js';
import { AccessPolicy, ContentTypes } from './custody.js';
import { OAuthRelay, ProtectedWrite, relayContext } from './protocol.js';
import { decode, open, encode, base64url } from './encryption.js';
import { AppMaterial, ConnectionMaterial, connectionMetadata, connectionLabels } from './connections.js';
import { connectionMethod, selectScopes } from './connection-methods.js';
import { Execution, WaitingOperation } from './executions.js';
import { BrowserTransport } from './http.js';
import type { Transport } from './http.js';
import { connectionPolicy } from './connection-policy.js';
import { OvhAuthorization, authorizeRegistration, exchangeRegistration, registrationApplication } from './connection-registration.js';
import { browserExchange } from './connection-methods.js';
import { RunPodApproval, startRunPodApproval, pollRunPodApproval } from './runpod-authorization.js';

export const FlowRecord = z.object({
  id: Id, ownerId: Id, name: Name,
  registration: z.object({ methodId: z.string().min(1), method: MethodDefinition, appId: Id.nullable(), app: AppMaterial.nullable(),
    fields: z.record(z.string(), z.string()), scopes: z.array(z.string()) }).strict(),
  policy: AccessPolicy, previousPolicyDigest: z.string().nullable(),
  step: z.enum(['start', 'cli', 'authorize', 'exchange', 'commit', 'connected', 'cancelled', 'failed']),
  createdAt: z.iso.datetime(), expiresAt: z.number(),
  execution: z.object({ id: Id, index: z.number().int().nonnegative() }).strict(),
  url: z.url().nullable(), connectionId: Id.nullable(),
  authorizationState: z.string(), verifier: z.string(), redirectUri: z.url(),
  ovh: OvhAuthorization.optional(), material: ConnectionMaterial.optional(), proof: ProtectedWrite.optional(),
  approval: RunPodApproval.optional(),
  error: z.string().optional(),
  exchangeStartedAt: z.number().optional(),
  exchangeDevice: z.enum(['browser', 'cli']),
}).strict();
export type ConnectionFlow = z.infer<typeof FlowRecord>;
export interface FlowStore { get(id: string): Promise<ConnectionFlow | null>; put(flow: ConnectionFlow): Promise<void> }
export const FlowView = FlowRecord.pick({ id: true, ownerId: true, name: true, execution: true, error: true }).strip();
export type ConnectionFlowView = z.infer<typeof FlowView>;
export type FlowProgress = { kind: 'authorize'; flow: ConnectionFlowView; url: string }
  | { kind: 'pending'; flow: ConnectionFlowView }
  | { kind: 'failed'; flow: ConnectionFlowView; error: string }
  | { kind: 'cli'; flow: ConnectionFlowView; command: string }
  | { kind: 'connected'; flow: ConnectionFlowView; id: string }
  | { kind: 'cancelled'; flow: ConnectionFlowView };
const nonce = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

export class ConnectionClient {
  private approvalPolls = new Map<string, Promise<FlowProgress>>();
  constructor(readonly custody: CustodyClient, readonly store: FlowStore,
    readonly transport: Transport = new BrowserTransport(custody.origin), readonly device: 'browser' | 'cli' = 'browser') {}
  private async flow(id: string) {
    const found = await this.store.get(Id.parse(id));
    if (!found) throw new Error('The saved progress for this connection is unavailable.');
    const flow = FlowRecord.parse(found);
    if (flow.policy.origin !== this.custody.origin ||
      !flow.policy.authorities.some(authority => canonical(authority) === canonical(this.custody.binding)))
      throw new Error('Open this connection with its initiating identity.');
    return flow;
  }
  async start(input: { ownerId: string; name: string; methodId: string; method: MethodDescription;
    appId?: string; fields?: Record<string, string>; scopes?: string[]; users?: string[];
    connectionId?: string; redirectUri?: string; execution: { id: string; index: number } }): Promise<FlowProgress> {
    const active = await this.custody.api.json('/api/executions/' + input.execution.id + '/input', {}, WaitingOperation.extend({ id: Id }));
    if (active.index !== input.execution.index || active.invocation.name !== 'connection.connect' ||
      active.invocation.input.ownerId !== input.ownerId || active.invocation.input.methodId !== input.methodId ||
      active.invocation.input.methodDigest !== await hash(input.method) ||
      active.invocation.input.appId && active.invocation.input.appId !== input.appId ||
      active.invocation.input.name && active.invocation.input.name !== input.name)
      throw new Error('Use the connection prepared by this operation.');
    for (const [key, value] of Object.entries(active.invocation.input.fields as Record<string, string> ?? {}))
      if (value && input.fields?.[key] !== value) throw new Error('Use the service settings prepared by this operation.');
    if (!connectionMethod(input.method).browserAuthorization || input.method.kind === 'token' || input.method.kind === 'aws')
      throw new Error('Choose a browser authorization method.');
    const scopes = selectScopes(input.method.config.scopes, input.scopes);
    if (active.invocation.input.scopes && canonical(scopes.slice().sort()) !==
      canonical(selectScopes(input.method.config.scopes, active.invocation.input.scopes as string[]).sort()))
      throw new Error('Use the service permissions prepared by this operation.');
    const values = { ...(!active.invocation.input.appId && input.appId ? { appId: input.appId } : {}),
      ...(!active.invocation.input.name ? { name: input.name } : {}) };
    if (Object.keys(values).length) await this.custody.api.json('/api/executions/' + input.execution.id + '/input',
      { method: 'PATCH', body: { index: input.execution.index, values } }, Execution);
    const previous = input.connectionId ? await this.custody.read(input.connectionId) : undefined;
    if (previous && (previous.content.policy.contentType !== ContentTypes.tokenSet || previous.content.policy.ownerId !== input.ownerId))
      throw new Error('Choose a connection belonging to this owner.');
    const appId = connectionMethod(input.method).requiresApp ? Id.parse(input.appId) : null;
    const savedApp = appId ? AppMaterial.parse(JSON.parse(decode(await this.custody.reveal(appId)))) : null;
    const app = registrationApplication({ ...input, app: savedApp });
    const policy = await connectionPolicy(this.custody, input.ownerId, previous?.content, input.users);
    const execution = await this.custody.api.json('/api/executions/' + input.execution.id, {}, Execution);
    const id = crypto.randomUUID(), flow: ConnectionFlow = {
      id, ownerId: input.ownerId, name: input.name, registration: { methodId: input.methodId, method: input.method, appId, app,
        fields: input.fields ?? {}, scopes }, policy, previousPolicyDigest: previous ? await hash(previous.content.policy) : null,
      step: this.device === 'browser' && browserExchange(input.method) === 'unavailable' ? 'cli' : 'start',
      createdAt: new Date().toISOString(), expiresAt: Math.min(Date.now() + 600_000, Date.parse(execution.expiresAt)), execution: input.execution,
      url: null, connectionId: null, authorizationState: nonce(), verifier: nonce(), redirectUri: input.redirectUri ?? this.custody.origin + '/oauth/callback',
      exchangeDevice: this.device,
    };
    const redirect = new URL(flow.redirectUri);
    if (flow.redirectUri !== this.custody.origin + '/oauth/callback' &&
      !(this.device === 'cli' && redirect.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(redirect.hostname) &&
        !redirect.username && !redirect.password && !redirect.hash && !redirect.search))
      throw new Error('Use the Foundation callback or a callback on this computer.');
    await this.store.put(flow);
    await this.custody.api.json('/api/executions/' + flow.execution.id + '/continuation', { method: 'PUT',
      body: { index: flow.execution.index, continuation: { kind: 'connection', id } } }, Execution);
    return this.progress(id);
  }
  private view(flow: ConnectionFlow) { return FlowView.parse(flow); }
  private async awaitingAuthorization(flow: ConnectionFlow) {
    const active = await this.custody.api.json('/api/executions/' + flow.execution.id + '/input', {}, WaitingOperation.extend({ id: Id }));
    if (active.index !== flow.execution.index || active.continuation?.id !== flow.id ||
      active.invocation.input.methodDigest !== await hash(flow.registration.method))
      throw new Error('Continue the connection that is awaiting authorization.');
  }
  private async pollApproval(flow: ConnectionFlow): Promise<FlowProgress> {
    if (flow.expiresAt <= Date.now()) throw new Error('Start the connection again.');
    await this.awaitingAuthorization(flow);
    const token = await pollRunPodApproval(this.transport, RunPodApproval.parse(flow.approval));
    if (!token) return { kind: 'authorize', flow: this.view(flow), url: flow.url! };
    await this.awaitingAuthorization(flow);
    flow.material = ConnectionMaterial.parse({ format: 2, methodId: flow.registration.methodId,
      method: flow.registration.method, generation: crypto.randomUUID(), appId: null, appGeneration: null,
      fields: { token } });
    flow.step = 'commit'; await this.store.put(flow);
    return this.accept(flow.id);
  }
  private cli(flow: ConnectionFlow): FlowProgress {
    return { kind: 'cli', flow: this.view(flow), command: (flow.step === 'authorize' ? 'foundation connect wait ' : 'foundation execution continue ') + flow.execution.id };
  }
  private async authorize(flow: ConnectionFlow) {
    if (flow.expiresAt <= Date.now()) throw new Error('Start the connection again.');
    if (flow.registration.method.kind === 'approval') {
      const started = await startRunPodApproval(this.transport);
      flow.approval = started.approval;
      flow.expiresAt = Math.min(flow.expiresAt, started.approval.expiresAt);
      flow.step = 'authorize'; flow.url = started.url;
      await this.store.put(flow);
      return { kind: 'authorize' as const, flow: this.view(flow), url: flow.url };
    }
    if (flow.redirectUri === this.custody.origin + '/oauth/callback') await this.custody.api.json('/api/oauth/relays', { method: 'POST',
      body: { id: flow.id, executionId: flow.execution.id, index: flow.execution.index,
        stateDigest: await hash(flow.authorizationState), expiresAt: new Date(flow.expiresAt).toISOString() } }, OAuthRelay);
    const result = await authorizeRegistration(flow.registration, this.transport, flow.authorizationState, flow.verifier, flow.redirectUri);
    flow.step = 'authorize'; flow.url = result.url;
    if ('ovh' in result) flow.ovh = result.ovh;
    await this.store.put(flow);
    return { kind: 'authorize' as const, flow: this.view(flow), url: flow.url };
  }
  async progress(id: string, relay = true): Promise<FlowProgress> {
    const flow = await this.flow(id);
    if (flow.step === 'connected') {
      if (flow.proof) await this.custody.api.json('/api/executions/' + flow.execution.id + '/complete',
        { method: 'POST', body: { index: flow.execution.index, proof: flow.proof } }, Execution);
      return { kind: 'connected', flow: this.view(flow), id: flow.connectionId! };
    }
    if (flow.step === 'cancelled') return { kind: 'cancelled', flow: this.view(flow) };
    if (flow.step === 'failed') return { kind: 'failed', flow: this.view(flow), error: flow.error ?? 'authorization_failed' };
    if (flow.step === 'commit') return this.accept(id);
    if (flow.step === 'exchange') {
      if (Date.now() - (flow.exchangeStartedAt ?? Date.now()) < 30_000) return { kind: 'pending', flow: this.view(flow) };
      flow.step = 'cli'; flow.error = 'browser_exchange_unavailable';
      await this.store.put(flow);
    }
    if (flow.step === 'cli') {
      if (this.device === 'browser') return this.cli(flow);
      const execution = await this.custody.api.json('/api/executions/' + flow.execution.id, {}, Execution);
      flow.step = 'start'; flow.exchangeDevice = 'cli'; flow.authorizationState = nonce(); flow.verifier = nonce(); flow.expiresAt = Math.min(Date.now() + 600_000, Date.parse(execution.expiresAt));
      delete flow.error; await this.store.put(flow);
    }
    if (flow.step === 'start') return this.authorize(flow);
    if (flow.exchangeDevice === 'cli' && this.device === 'browser') return this.cli(flow);
    if (flow.registration.method.kind === 'approval') {
      let pending = this.approvalPolls.get(id);
      if (!pending) {
        pending = this.pollApproval(flow);
        this.approvalPolls.set(id, pending);
      }
      try { return await pending; }
      finally { if (this.approvalPolls.get(id) === pending) this.approvalPolls.delete(id); }
    }
    if (relay && flow.redirectUri === this.custody.origin + '/oauth/callback') {
      const response = await this.custody.api.json('/api/oauth/relays/' + id, {}, OAuthRelay);
      if (response.id !== id || response.executionId !== flow.execution.id || response.context !== relayContext(this.custody.origin, id))
        throw new Error('The authorization response belongs to another connection.');
      if (response.sealed) return this.complete(id, decode(await open(response.sealed, this.custody.keys.encryption,
        this.custody.binding.id, response.context)));
    }
    return { kind: 'authorize', flow: this.view(flow), url: flow.url! };
  }
  async complete(id: string, parameters: string): Promise<FlowProgress> {
    const flow = await this.flow(id);
    if (flow.step !== 'authorize') return this.progress(id, false);
    if (flow.exchangeDevice === 'cli' && this.device === 'browser') return this.cli(flow);
    if (flow.expiresAt <= Date.now()) throw new Error('Start the connection again.');
    await this.awaitingAuthorization(flow);
    const query = new URLSearchParams(parameters);
    if (query.getAll('state').length !== 1 || query.get('state') !== flow.authorizationState)
      throw new Error('The authorization response does not match this connection.');
    if (query.has('error')) return this.cancel(id);
    if (flow.registration.appId) {
      const current = AppMaterial.parse(JSON.parse(decode(await this.custody.reveal(flow.registration.appId))));
      const previous = flow.registration.app!;
      if (current.methodId !== previous.methodId || current.generation !== previous.generation ||
        current.clientId !== previous.clientId || canonical(current.fields) !== canonical(previous.fields))
        throw new Error('Start authorization again with the current application.');
      flow.registration.app = current;
    }
    flow.step = 'exchange'; flow.exchangeStartedAt = Date.now(); await this.store.put(flow);
    try {
      flow.material = await exchangeRegistration(flow.registration, this.transport, parameters, flow.authorizationState, flow.verifier, flow.redirectUri, flow.ovh);
    } catch (error) {
      flow.error = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : 'authorization_failed';
      flow.step = flow.error === 'browser_exchange_unavailable' ? 'cli' : 'failed'; await this.store.put(flow);
      if (flow.step === 'cli' && this.device === 'browser') return this.cli(flow);
      throw error;
    }
    flow.step = 'commit'; await this.store.put(flow);
    return this.accept(id);
  }
  async accept(id: string): Promise<FlowProgress> {
    const flow = await this.flow(id);
    if (flow.step !== 'commit' || !flow.material) throw new Error('Complete authorization before saving this connection.');
    const previous = flow.previousPolicyDigest ? await this.custody.read(flow.policy.id) : undefined;
    if (previous && await hash(previous.content.policy) !== flow.previousPolicyDigest)
      throw new Error('The connection recipients changed. Start again to approve the current recipients.');
    const commit = async (write: z.infer<typeof ProtectedWrite>) => {
      flow.proof = write; await this.store.put(flow);
      await this.custody.api.json('/api/executions/' + flow.execution.id + '/complete',
        { method: 'POST', body: { index: flow.execution.index, proof: write } }, Execution);
      return this.custody.api.json('/api/resources/' + flow.policy.id, {}, Resource);
    };
    if (flow.proof) await commit(flow.proof);
    else await this.custody.save(flow.name, encode(canonical(flow.material)), flow.policy,
      { previous, metadata: await connectionMetadata(flow.material), labels: connectionLabels(flow.material), commit });
    flow.step = 'connected'; flow.connectionId = flow.policy.id; await this.store.put(flow);
    return { kind: 'connected', flow: this.view(flow), id: flow.connectionId };
  }
  async cancel(id: string): Promise<FlowProgress> {
    const flow = await this.flow(id);
    await this.custody.api.json('/api/executions/' + flow.execution.id + '/cancel', { method: 'POST', body: {} }, Execution);
    flow.step = 'cancelled'; await this.store.put(flow);
    return { kind: 'cancelled', flow: this.view(flow) };
  }
}
