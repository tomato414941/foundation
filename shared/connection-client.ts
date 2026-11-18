import { z } from 'zod';
import type { CustodyClient } from './client.js';
import { CatalogMethod, DEVICE_CODE_GRANT, Id, JsonObject, Name, Resource, listOf } from './contracts.js';
import type { MethodDescription } from './contracts.js';
import { canonical, hash } from './authority.js';
import { AccessPolicy, ContentTypes } from './custody.js';
import { OAuthRelay, ProtectedWrite, relayContext } from './protocol.js';
import { decode, open, base64url } from './encryption.js';
import { AppMaterial, ConnectionMaterial, connectionMetadata, connectionLabels, keptConnection, sealedConnection, withMethod } from './connections.js';
import type { ConnectionState } from './connections.js';
import { catalogDefinition, connectionMethod, selectScopes } from './connection-methods.js';
import { ConnectService, OperationView, serviceStep } from './operations.js';
import type { KeyholderPlan } from './operation-client.js';
import { BrowserTransport } from './http.js';
import type { Transport } from './http.js';
import { connectionPolicy } from './connection-policy.js';
import { OvhAuthorization, authorizeRegistration, exchangeRegistration, registrationApplication, registrationMaterial } from './connection-registration.js';
import { browserExchange } from './connection-methods.js';
import { RunPodApproval, startRunPodApproval, pollRunPodApproval } from './runpod-authorization.js';
import { DeviceAuthorization } from './oauth-device.js';
import { OAuth } from './oauth.js';

// The progress of a connection being made, sealed for the device that makes it. It names its method by id, and keeps
// what it has of the connection and of the write that saves it without the method and without the names and labels
// Foundation keeps.
export const FlowRecord = z.object({
  id: Id, ownerId: Id,
  registration: z.object({ methodId: z.string().min(1), appId: Id.nullable(), app: AppMaterial.nullable(),
    fields: z.record(z.string(), z.string()), scopes: z.array(z.string()) }).strict(),
  policy: AccessPolicy, previousPolicyDigest: z.string().nullable(),
  step: z.enum(['start', 'cli', 'authorize', 'exchange', 'commit', 'connected', 'cancelled', 'failed']),
  createdAt: z.iso.datetime(), expiresAt: z.number(),
  operationId: Id,
  url: z.url().nullable(), connectionId: Id.nullable(),
  authorizationState: z.string(), verifier: z.string(), redirectUri: z.url(),
  ovh: OvhAuthorization.optional(), material: JsonObject.optional(), proof: ProtectedWrite.omit({ name: true, labels: true }).optional(),
  approval: RunPodApproval.optional(),
  deviceAuthorization: DeviceAuthorization.optional(),
  error: z.string().optional(),
  exchangeStartedAt: z.number().optional(),
  exchangeDevice: z.enum(['browser', 'cli']),
}).strict();
export type ConnectionFlow = z.infer<typeof FlowRecord>;
export interface FlowStore { get(id: string): Promise<ConnectionFlow | null>; put(flow: ConnectionFlow): Promise<void> }
export const FlowView = FlowRecord.pick({ id: true, ownerId: true, operationId: true, error: true }).strip();
export type ConnectionFlowView = z.infer<typeof FlowView>;
export type FlowProgress = { kind: 'authorize'; flow: ConnectionFlowView; url: string;
    device?: { userCode: string; verificationUri: string; expiresAt: number } }
  | { kind: 'pending'; flow: ConnectionFlowView }
  | { kind: 'failed'; flow: ConnectionFlowView; error: string }
  | { kind: 'cli'; flow: ConnectionFlowView; command: string }
  | { kind: 'connected'; flow: ConnectionFlowView; id: string }
  | { kind: 'cancelled'; flow: ConnectionFlowView };
const nonce = () => base64url(crypto.getRandomValues(new Uint8Array(32)));

export class ConnectionClient {
  private approvalPolls = new Map<string, Promise<FlowProgress>>();
  private devicePolls = new Map<string, Promise<FlowProgress>>();
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
  // Starts authorizing at the service for the operation that makes the connection, which then waits on it.
  async start(plan: KeyholderPlan, method: MethodDescription, fields: Record<string, string>): Promise<FlowProgress> {
    const input = ConnectService.parse(plan.input);
    if (plan.name !== 'connection.connect' || !input.name)
      throw new Error('Use the connection prepared by this operation.');
    for (const [key, value] of Object.entries(input.fields ?? {}))
      if (value && fields[key] !== value) throw new Error('Use the service settings prepared by this operation.');
    if (!connectionMethod(method).browserAuthorization || method.kind === 'token' || method.kind === 'aws')
      throw new Error('Choose a browser authorization method.');
    const scopes = selectScopes(method.config.scopes, input.scopes);
    const previous = input.connectionId ? await this.custody.latest(input.connectionId) : undefined;
    if (previous && (previous.content.policy.contentType !== ContentTypes.tokenSet || previous.content.policy.ownerId !== input.ownerId))
      throw new Error('Choose a connection belonging to this owner.');
    const appId = connectionMethod(method).requiresApp ? Id.parse(input.appId) : null;
    const savedApp = appId ? AppMaterial.parse(JSON.parse(decode(await this.custody.reveal(appId)))) : null;
    const app = registrationApplication({ methodId: input.methodId, method, appId: appId ?? undefined, app: savedApp });
    const policy = await connectionPolicy(this.custody, input.ownerId, previous, input.users);
    const id = crypto.randomUUID(), flow: ConnectionFlow = {
      id, ownerId: input.ownerId, registration: { methodId: input.methodId, appId, app,
        fields, scopes }, policy, previousPolicyDigest: previous ? await hash(previous.content.policy) : null,
      step: this.device === 'browser' && browserExchange(method) === 'unavailable' ? 'cli' : 'start',
      createdAt: new Date().toISOString(), expiresAt: Date.now() + this.window(method), operationId: plan.id,
      url: null, connectionId: null, authorizationState: nonce(), verifier: nonce(), redirectUri: input.redirectUri ?? this.custody.origin + '/oauth/callback',
      exchangeDevice: this.device,
    };
    const redirect = new URL(flow.redirectUri);
    if (flow.redirectUri !== this.custody.origin + '/oauth/callback' &&
      !(this.device === 'cli' && redirect.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(redirect.hostname) &&
        !redirect.username && !redirect.password && !redirect.hash && !redirect.search))
      throw new Error('Use the Foundation callback or a callback on this computer.');
    await this.store.put(flow);
    const continuation = { kind: 'connection' as const, id };
    await (plan.held
      ? this.custody.api.json('/api/operations/' + plan.id + '/continuation', { method: 'PUT', body: { continuation } }, OperationView)
      : this.custody.api.json('/api/operations', { method: 'POST',
        body: { id: plan.id, name: plan.name, input: plan.input, continuation } }, OperationView));
    return this.progress(id);
  }
  // How long authorizing at the service may take: a code entered on another device may take as long as the operation
  // waits on its service.
  private window(method: MethodDescription) {
    return method.kind === 'oauth' && method.config.grantType === DEVICE_CODE_GRANT ? serviceStep : 600_000;
  }
  private operation(flow: ConnectionFlow) {
    return this.custody.api.json('/api/operations/' + flow.operationId, {}, OperationView);
  }
  private async perform(flow: ConnectionFlow, proof: z.infer<typeof ProtectedWrite>) {
    await this.custody.api.json('/api/operations/' + flow.operationId + '/perform', { method: 'POST', body: { proof } }, OperationView);
  }
  private view(flow: ConnectionFlow) { return FlowView.parse(flow); }
  // The method a connection is made through, read from where it is kept.
  private async method(flow: ConnectionFlow): Promise<MethodDescription> {
    const selected = (await this.custody.api.json('/api/connection-methods', {}, listOf(CatalogMethod))).items
      .find(item => item.id === flow.registration.methodId);
    if (!selected) throw new Error('The connection method is no longer available. Start the connection again.');
    return catalogDefinition(selected);
  }
  private async registration(flow: ConnectionFlow) {
    return { ...flow.registration, method: await this.method(flow) };
  }
  // The connection made so far, with the method it is made through.
  private async state(flow: ConnectionFlow) {
    return withMethod(flow.material, flow.registration.methodId, await this.method(flow));
  }
  // The name the connection gets: a label Foundation keeps with the operation that makes it.
  private async name(flow: ConnectionFlow, method: MethodDescription) {
    return Name.parse((await this.operation(flow)).input.name ?? method.name);
  }
  // The write that saves the connection, as it was first sent: what is kept of it, with the connection's name and labels.
  private async write(flow: ConnectionFlow, state: ConnectionState) {
    return ProtectedWrite.parse({ ...flow.proof, name: await this.name(flow, state.method), labels: connectionLabels(state) });
  }
  private authorizing(flow: ConnectionFlow): FlowProgress {
    const device = flow.deviceAuthorization;
    return { kind: 'authorize', flow: this.view(flow), url: flow.url!,
      ...(device ? { device: { userCode: device.userCode, verificationUri: device.verificationUri, expiresAt: flow.expiresAt } } : {}) };
  }
  private async awaitingAuthorization(flow: ConnectionFlow) {
    const active = await this.operation(flow);
    if (active.state !== 'in_progress' || active.continuation?.id !== flow.id)
      throw new Error('Continue the connection that is awaiting authorization.');
  }
  private async currentApplication(flow: ConnectionFlow) {
    if (!flow.registration.appId) return;
    const current = AppMaterial.parse(JSON.parse(decode(await this.custody.reveal(flow.registration.appId))));
    const previous = flow.registration.app!;
    if (current.methodId !== previous.methodId || current.generation !== previous.generation ||
      current.clientId !== previous.clientId || canonical(current.fields) !== canonical(previous.fields))
      throw new Error('Start authorization again with the current application.');
    flow.registration.app = current;
  }
  private async pollDevice(flow: ConnectionFlow): Promise<FlowProgress> {
    const authorization = DeviceAuthorization.parse(flow.deviceAuthorization), registration = await this.registration(flow);
    const method = registration.method;
    if (method.kind !== 'oauth' || method.config.grantType !== DEVICE_CODE_GRANT)
      throw new Error('Choose a device authorization connection method.');
    if (flow.expiresAt <= Date.now()) {
      flow.step = 'failed'; flow.error = 'device_code_expired'; await this.store.put(flow);
      return { kind: 'failed', flow: this.view(flow), error: flow.error };
    }
    if (authorization.nextPollAt > Date.now()) return this.authorizing(flow);
    await this.awaitingAuthorization(flow);
    await this.currentApplication(flow);
    authorization.nextPollAt = Date.now() + authorization.intervalSeconds * 1000;
    flow.deviceAuthorization = authorization;
    await this.store.put(flow);
    let result: Awaited<ReturnType<OAuth['deviceToken']>>;
    try {
      result = await new OAuth(this.transport).deviceToken(method.config, flow.registration.app!, authorization.deviceCode, flow.registration.scopes);
    } catch (error) {
      const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' ? error.code : 'authorization_failed';
      if (code === 'service_unavailable' || code === 'service_rate_limit') {
        authorization.intervalSeconds *= 2;
        authorization.nextPollAt = Date.now() + authorization.intervalSeconds * 1000;
        await this.store.put(flow);
        return this.authorizing(flow);
      }
      flow.error = code;
      flow.step = code === 'browser_exchange_unavailable' ? 'cli' : 'failed';
      await this.store.put(flow);
      return flow.step === 'cli' ? this.cli(flow) : { kind: 'failed', flow: this.view(flow), error: code };
    }
    if (result.kind === 'pending') {
      authorization.intervalSeconds = Math.max(authorization.intervalSeconds + (result.slowDown ? 5 : 0), result.intervalSeconds ?? 0);
      authorization.nextPollAt = Date.now() + authorization.intervalSeconds * 1000;
      await this.store.put(flow);
      return this.authorizing(flow);
    }
    await this.awaitingAuthorization(flow);
    flow.material = keptConnection(ConnectionMaterial.parse({ ...registrationMaterial(registration), oauth: result.token }));
    flow.step = 'commit'; await this.store.put(flow);
    return this.accept(flow.id);
  }
  private async pollApproval(flow: ConnectionFlow): Promise<FlowProgress> {
    if (flow.expiresAt <= Date.now()) throw new Error('Start the connection again.');
    await this.awaitingAuthorization(flow);
    const token = await pollRunPodApproval(this.transport, RunPodApproval.parse(flow.approval));
    if (!token) return { kind: 'authorize', flow: this.view(flow), url: flow.url! };
    await this.awaitingAuthorization(flow);
    flow.material = keptConnection(ConnectionMaterial.parse({ format: 3, methodId: flow.registration.methodId,
      method: await this.method(flow), generation: crypto.randomUUID(), appId: null, appGeneration: null,
      fields: { token } }));
    flow.step = 'commit'; await this.store.put(flow);
    return this.accept(flow.id);
  }
  private cli(flow: ConnectionFlow): FlowProgress {
    return { kind: 'cli', flow: this.view(flow), command: (flow.step === 'authorize' ? 'foundation connect wait ' : 'foundation operation continue ') + flow.operationId };
  }
  private async authorize(flow: ConnectionFlow) {
    if (flow.expiresAt <= Date.now()) throw new Error('Start the connection again.');
    const registration = await this.registration(flow);
    if (registration.method.kind === 'oauth' && registration.method.config.grantType === DEVICE_CODE_GRANT) {
      try {
        const device = await new OAuth(this.transport).deviceAuthorization(registration.method.config, flow.registration.app!, flow.registration.scopes);
        flow.deviceAuthorization = device; flow.expiresAt = Math.min(flow.expiresAt, device.expiresAt);
        flow.step = 'authorize'; flow.url = device.verificationUriComplete ?? device.verificationUri;
        await this.store.put(flow);
        return this.authorizing(flow);
      } catch (error) {
        if (!(error && typeof error === 'object' && 'code' in error && error.code === 'browser_exchange_unavailable')) throw error;
        flow.step = 'cli'; flow.error = 'browser_exchange_unavailable'; await this.store.put(flow);
        return this.cli(flow);
      }
    }
    if (registration.method.kind === 'approval') {
      const started = await startRunPodApproval(this.transport);
      flow.approval = started.approval;
      flow.expiresAt = Math.min(flow.expiresAt, started.approval.expiresAt);
      flow.step = 'authorize'; flow.url = started.url;
      await this.store.put(flow);
      return { kind: 'authorize' as const, flow: this.view(flow), url: flow.url };
    }
    if (flow.redirectUri === this.custody.origin + '/oauth/callback') await this.custody.api.json('/api/oauth/relays', { method: 'POST',
      body: { id: flow.id, operationId: flow.operationId,
        stateDigest: await hash(flow.authorizationState), expiresAt: new Date(flow.expiresAt).toISOString() } }, OAuthRelay);
    const result = await authorizeRegistration(registration, this.transport, flow.authorizationState, flow.verifier, flow.redirectUri);
    flow.step = 'authorize'; flow.url = result.url;
    if ('ovh' in result) flow.ovh = result.ovh;
    await this.store.put(flow);
    return { kind: 'authorize' as const, flow: this.view(flow), url: flow.url };
  }
  async progress(id: string, relay = true): Promise<FlowProgress> {
    const flow = await this.flow(id);
    if (flow.step === 'connected') {
      if (flow.proof) await this.perform(flow, await this.write(flow, await this.state(flow)));
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
      const waiting = await this.operation(flow);
      flow.step = 'start'; flow.exchangeDevice = 'cli'; flow.authorizationState = nonce(); flow.verifier = nonce();
      flow.expiresAt = Math.min(Date.now() + this.window(await this.method(flow)), Date.parse(waiting.expiresAt ?? new Date().toISOString()));
      delete flow.error; await this.store.put(flow);
    }
    if (flow.step === 'start') return this.authorize(flow);
    if (flow.exchangeDevice === 'cli' && this.device === 'browser') return this.cli(flow);
    if (flow.deviceAuthorization) {
      let pending = this.devicePolls.get(id);
      if (!pending) {
        pending = this.pollDevice(flow);
        this.devicePolls.set(id, pending);
      }
      try { return await pending; }
      finally { if (this.devicePolls.get(id) === pending) this.devicePolls.delete(id); }
    }
    if (flow.approval) {
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
      if (response.id !== id || response.operationId !== flow.operationId || response.context !== relayContext(this.custody.origin, id))
        throw new Error('The authorization response belongs to another connection.');
      if (response.sealed) return this.complete(id, decode(await open(response.sealed, this.custody.keys.encryption,
        this.custody.binding.id, response.context)));
    }
    return this.authorizing(flow);
  }
  async complete(id: string, parameters: string): Promise<FlowProgress> {
    const flow = await this.flow(id);
    if (flow.step !== 'authorize') return this.progress(id, false);
    if (flow.exchangeDevice === 'cli' && this.device === 'browser') return this.cli(flow);
    if (flow.deviceAuthorization) throw new Error('Device authorization completes after the code is approved at the service.');
    if (flow.expiresAt <= Date.now()) throw new Error('Start the connection again.');
    await this.awaitingAuthorization(flow);
    const query = new URLSearchParams(parameters);
    if (query.getAll('state').length !== 1 || query.get('state') !== flow.authorizationState)
      throw new Error('The authorization response does not match this connection.');
    if (query.has('error')) return this.cancel(id);
    await this.currentApplication(flow);
    flow.step = 'exchange'; flow.exchangeStartedAt = Date.now(); await this.store.put(flow);
    try {
      flow.material = keptConnection(await exchangeRegistration(await this.registration(flow), this.transport, parameters,
        flow.authorizationState, flow.verifier, flow.redirectUri, flow.ovh));
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
    const previous = flow.previousPolicyDigest ? await this.custody.latest(flow.policy.id) : undefined;
    if (previous && await hash(previous.content.policy) !== flow.previousPolicyDigest)
      throw new Error('The connection recipients changed. Start again to approve the current recipients.');
    const state = await this.state(flow);
    const commit = async (write: z.infer<typeof ProtectedWrite>) => {
      const { name: _name, labels: _labels, ...proof } = write;
      flow.proof = proof; await this.store.put(flow);
      await this.perform(flow, write);
      return this.custody.api.json('/api/resources/' + flow.policy.id, {}, Resource);
    };
    if (flow.proof) await commit(await this.write(flow, state));
    else await this.custody.save(await this.name(flow, state.method), sealedConnection(state), flow.policy,
      { previous, metadata: await connectionMetadata(state), labels: connectionLabels(state), commit });
    flow.step = 'connected'; flow.connectionId = flow.policy.id; await this.store.put(flow);
    return { kind: 'connected', flow: this.view(flow), id: flow.connectionId };
  }
  async cancel(id: string): Promise<FlowProgress> {
    const flow = await this.flow(id);
    await this.custody.api.json('/api/operations/' + flow.operationId + '/cancel', { method: 'POST', body: {} }, OperationView);
    flow.step = 'cancelled'; await this.store.put(flow);
    return { kind: 'cancelled', flow: this.view(flow) };
  }
}
