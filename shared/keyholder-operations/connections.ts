import { z } from 'zod';
import { AppSave, AuthorizeConnection, ConnectService, Execution } from '../executions.js';
import { CatalogMethod, Id, Resource, listOf } from '../contracts.js';
import type { JsonValue } from '../contracts.js';
import { canonical, hash } from '../authority.js';
import { AccessPolicy, ContentTypes, permittedOperations } from '../custody.js';
import { AppMaterial, ConnectionMaterial, connectionLabels, connectionMetadata, requiresApp } from '../connections.js';
import { suppliedConnectionFields, visibleConnectionFields } from '../connection-fields.js';
import { decode, encode } from '../encryption.js';
import { connectionMethod, selectScopes } from '../connection-methods.js';
import { connectionPolicy } from '../connection-policy.js';
import { registrationMaterial, registrationApplication } from '../connection-registration.js';
import type { ExecutionResultView, PrivateOperationInput } from '../execution-client.js';
import type { KeyholderClient, KeyholderOperation, KeyholderPlan } from './types.js';

class ConnectionOperations {
  private readonly connectionNames = new Map<string, string>();
  constructor(readonly client: KeyholderClient) {}
  private async method(id: string) {
    const selected = (await this.client.custody.api.json('/api/connection-methods', {}, listOf(CatalogMethod))).items.find(item => item.id === id);
    if (!selected) throw new Error('Choose an available connection method.');
    this.connectionNames.set(id, selected.defaultName);
    const { id: _id, builtin: _builtin, availability: _availability, registration: _registration, defaultName: _defaultName, ...definition } = selected;
    return definition;
  }
  private async userPolicy(policy: z.infer<typeof AccessPolicy>, users: string[], expiresAt?: string, advance = true) {
    const expiry = expiresAt ?? new Date(Date.now() + 30 * 86_400_000).toISOString();
    const bindings = await Promise.all([...new Set(users)].map(async id => {
      const { binding } = await this.client.custody.inspectIdentity(id);
      await this.client.custody.trusted(binding);
      return binding;
    }));
    return AccessPolicy.parse({ ...policy, revision: policy.revision + (advance ? 1 : 0),
      grants: [...policy.grants.filter(grant => !('actor' in grant)), ...bindings.map(binding => ({ actor: binding, executor: binding,
        operations: [...permittedOperations(policy.contentType)], origins: [], functionDigests: [], callerProgram: true, expiresAt: expiry }))] });
  }
  private async prepareFields(plan: KeyholderPlan, material: PrivateOperationInput): Promise<ExecutionResultView | null> {
    const id = plan.id, { name, input } = plan.invocation;
    const method = await this.method(String(input.methodId)), definitions = method.kind === 'aws' ? [] : method.config.fields;
    let fields = visibleConnectionFields(definitions, material.fields ?? {});
    if (name === 'connection.connect' && input.appId) {
      const app = await this.client.custody.api.json('/api/resources/' + Id.parse(input.appId), {}, Resource);
      if (app.kind !== 'app') throw new Error('Choose a connection application.');
      fields = { ...app.data.fields, ...fields };
    }
    const prepared = input.fields as Record<string, string> | undefined;
    const completed = suppliedConnectionFields(definitions, prepared ?? {}, fields);
    if (Object.entries(fields).some(([key, value]) => prepared?.[key] !== value)) {
      await this.client.configure(id, { fields: completed });
      return this.client.continue(id, material);
    }
    return null;
  }
  async authorize(plan: KeyholderPlan): Promise<ExecutionResultView> {
    const id = plan.id, { input } = plan.invocation;
    const permission = AuthorizeConnection.parse(input), previous = await this.client.custody.read(permission.connectionId);
    if (previous.version !== permission.version || previous.content.policy.ownerId !== permission.ownerId ||
      previous.content.policy.contentType !== ContentTypes.tokenSet) throw new Error('Review the current connection before changing its permissions.');
    const policy = await this.userPolicy(previous.content.policy, permission.users, permission.expiresAt);
    const current = await this.client.custody.api.json('/api/resources/' + permission.connectionId, {}, Resource);
    const resource = await this.client.custody.save(current.name, await this.client.custody.reveal(permission.connectionId), policy,
      { previous, metadata: previous.content.metadata,
        commit: async write => Resource.parse((await this.client.complete(id, plan.index, write as unknown as JsonValue)).results[plan.index]) });
    return { kind: 'saved', resource, executionId: id };
  }
  async saveApplication(plan: KeyholderPlan, material: PrivateOperationInput): Promise<ExecutionResultView> {
    const prepared = await this.prepareFields(plan, material); if (prepared) return prepared;
    const id = plan.id, { input } = plan.invocation;
    const destination = AppSave.parse(input);
    const previous = destination.resourceId ? await this.client.custody.latest(destination.resourceId) : undefined;
    if (previous && previous.version !== destination.version) throw new Error('This item changed. Reload it before saving.');
    const environments = await Promise.all((destination.environmentIds ?? []).map(id => this.client.custody.environment(id)));
    const type = ContentTypes.clientCredential;
    if (previous && (previous.content.policy.contentType !== type || previous.content.policy.ownerId !== destination.ownerId))
      throw new Error('Choose the item prepared by this operation.');
    const policy = previous && !previous.replaced && destination.environmentIds === undefined ? await this.client.custody.refreshRecipients(previous.content.policy)
      : await this.client.custody.policy(destination.ownerId, type, environments,
        previous?.replaced ? { replacing: previous.content.policy } : { previous: previous?.content.policy });
    let bytes: Uint8Array, metadata: Record<string, JsonValue> | undefined;
    const application = AppSave.parse(input);
    const old = previous && !previous.replaced
      ? AppMaterial.parse(JSON.parse(decode(await this.client.custody.reveal(previous.content.policy.id)))) : null;
    const method = await this.method(application.methodId);
    const fields = suppliedConnectionFields(method.kind === 'aws' ? [] : method.config.fields, application.fields ?? {}, material.fields ?? {});
    const same = old && old.methodId === application.methodId && old.clientId === application.clientId && canonical(old.fields) === canonical(fields);
    const app = AppMaterial.parse({ format: 1, methodId: application.methodId, clientId: application.clientId, fields,
      generation: same ? old.generation : crypto.randomUUID(),
      ...(material.clientSecret || old?.clientSecret ? { clientSecret: material.clientSecret || old?.clientSecret } : {}) });
    bytes = encode(canonical(app)); metadata = { methodId: app.methodId, clientId: app.clientId, generation: app.generation,
      fields: visibleConnectionFields(method.kind === 'aws' ? [] : method.config.fields, fields) };
    const resource = await this.client.custody.save(destination.name, bytes, policy, { previous, metadata,
      commit: async write => Resource.parse((await this.client.complete(id, plan.index, write as unknown as JsonValue)).results[plan.index]) });
    return { kind: 'saved' as const, resource, executionId: id };
  }
  async connect(plan: KeyholderPlan, material: PrivateOperationInput): Promise<ExecutionResultView> {
    const prepared = await this.prepareFields(plan, material); if (prepared) return prepared;
    const id = plan.id, { input } = plan.invocation;
    if (plan.continuation?.kind === 'connection') return this.client.connections.progress(plan.continuation.id);
    const connection = ConnectService.parse(input), method = await this.method(connection.methodId);
    if (!connection.name) {
      await this.client.configure(id, { name: this.connectionNames.get(connection.methodId) ?? method.name });
      return this.client.continue(id, material);
    }
    if (material.scopes && !connection.scopes && (method.kind === 'oauth' || method.kind === 'ovh')) {
      await this.client.configure(id, { scopes: material.scopes });
      return this.client.continue(id, material);
    }
    if (material.scopes && connection.scopes && (method.kind === 'oauth' || method.kind === 'ovh') &&
      canonical(selectScopes(method.config.scopes, material.scopes).sort()) !== canonical(selectScopes(method.config.scopes, connection.scopes).sort()))
      throw new Error('Use the service permissions prepared by this operation.');
    let appId = connection.appId;
    if (requiresApp(method) && !appId) {
      if (!connection.clientId) throw new Error('Enter the application client ID.');
      const app = AppMaterial.parse({ format: 1, methodId: connection.methodId, clientId: connection.clientId,
        generation: crypto.randomUUID(), fields: suppliedConnectionFields(method.kind === 'aws' ? [] : method.config.fields, connection.fields ?? {}, material.fields ?? {}),
        ...(material.clientSecret ? { clientSecret: material.clientSecret } : {}) });
      const policy = await this.client.custody.policy(connection.ownerId, ContentTypes.clientCredential, []);
      const saved = await this.client.custody.save((connection.name ?? method.name).slice(0, 185) + ' application', encode(canonical(app)), policy,
        { metadata: { methodId: app.methodId, clientId: app.clientId, generation: app.generation,
            fields: visibleConnectionFields(method.kind === 'aws' ? [] : method.config.fields, app.fields) },
          commit: async write => {
            const prepared = await this.client.custody.api.json('/api/executions/' + id + '/preparation', { method: 'POST',
              body: { index: plan.index, proof: write } }, Execution);
            return this.client.custody.api.json('/api/resources/' + prepared.operations[plan.index]!.input.appId, {}, Resource);
          } });
      appId = saved.id;
    }
    if (!connectionMethod(method).browserAuthorization) {
      if (await hash(method) !== connection.methodDigest) throw new Error('Review the current connection method.');
      const previous = connection.connectionId ? await this.client.custody.latest(connection.connectionId) : undefined;
      if (previous && (previous.content.policy.ownerId !== connection.ownerId || previous.content.policy.contentType !== ContentTypes.tokenSet))
        throw new Error('Choose a connection belonging to this owner.');
      const old = previous && !previous.replaced
        ? ConnectionMaterial.parse(JSON.parse(decode(await this.client.custody.reveal(connection.connectionId!)))) : undefined;
      const app = registrationApplication({ methodId: connection.methodId, method, appId,
        app: appId ? AppMaterial.parse(JSON.parse(decode(await this.client.custody.reveal(appId)))) : null });
      const state = registrationMaterial({ methodId: connection.methodId, method, appId: appId ?? null, app,
        fields: suppliedConnectionFields(connectionMethod(method).fields, connection.fields ?? {}, material.fields ?? {}),
        scopes: method.kind === 'oauth' ? selectScopes(method.config.scopes, connection.scopes) : [], aws: material.aws }, old);
      const policy = await connectionPolicy(this.client.custody, connection.ownerId, previous, connection.users);
      const resource = await this.client.custody.save(connection.name ?? method.name, encode(canonical(state)), policy,
        { previous, metadata: await connectionMetadata(state), labels: connectionLabels(state),
          commit: async write => {
            const completed = await this.client.complete(id, plan.index, write as unknown as JsonValue);
            const result = completed.results[plan.index] as { id: string };
            return this.client.custody.api.json('/api/resources/' + result.id, {}, Resource);
          } });
      return { kind: 'saved', resource, executionId: id };
    }
    return this.client.connections.start({ ownerId: connection.ownerId,
      name: connection.name ?? method.name, methodId: connection.methodId, method, appId,
      connectionId: connection.connectionId,
      fields: suppliedConnectionFields(method.kind === 'aws' ? [] : method.config.fields, connection.fields ?? {}, material.fields ?? {}),
      scopes: connection.scopes, users: connection.users, redirectUri: connection.redirectUri,
      execution: { id, index: plan.index } });
  }
}
export function connectionOperations(client: KeyholderClient) {
  const connections = new ConnectionOperations(client);
  return new Map<string, KeyholderOperation>([
    ['connection.authorize', { continue: plan => connections.authorize(plan) }],
    ['app.save', { continue: (plan, material) => connections.saveApplication(plan, material) }],
    ['connection.connect', { continue: (plan, material) => connections.connect(plan, material) }],
  ]);
}
