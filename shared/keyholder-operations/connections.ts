import { AppSave, AuthorizeConnection, ConnectService } from '../operations.js';
import { CatalogMethod, Id, Resource, listOf } from '../contracts.js';
import type { JsonValue } from '../contracts.js';
import { canonical } from '../authority.js';
import { ContentTypes } from '../custody.js';
import { AppMaterial, connectionLabels, connectionMetadata, requiresApp, sealedConnection } from '../connections.js';
import { suppliedConnectionFields, visibleConnectionFields } from '../connection-fields.js';
import { decode, encode } from '../encryption.js';
import { catalogDefinition, connectionMethod, methodDigest, selectScopes } from '../connection-methods.js';
import { connectionPolicy, withUsers } from '../connection-policy.js';
import { registrationMaterial, registrationApplication } from '../connection-registration.js';
import type { KeyholderPlan, OperationResultView, PrivateOperationInput } from '../operation-client.js';
import type { KeyholderClient, KeyholderOperation } from './types.js';

class ConnectionOperations {
  private readonly connectionNames = new Map<string, string>();
  constructor(readonly client: KeyholderClient) {}
  private async method(id: string) {
    const selected = (await this.client.custody.api.json('/api/connection-methods', {}, listOf(CatalogMethod))).items.find(item => item.id === id);
    if (!selected) throw new Error('Choose an available connection method.');
    this.connectionNames.set(id, selected.defaultName);
    return catalogDefinition(selected);
  }
  // The service settings the operation is made with, filled with those entered on this device.
  private async prepareFields(plan: KeyholderPlan, material: PrivateOperationInput): Promise<OperationResultView | null> {
    const { name, input } = plan;
    const method = await this.method(String(input.methodId)), definitions = method.kind === 'aws' ? [] : method.config.fields;
    let fields = visibleConnectionFields(definitions, material.fields ?? {});
    if (name === 'connection.connect' && input.appId) {
      const app = await this.client.custody.api.json('/api/resources/' + Id.parse(input.appId), {}, Resource);
      if (app.kind !== 'app') throw new Error('Choose a connection application.');
      fields = { ...app.data.fields, ...fields };
    }
    const prepared = input.fields as Record<string, string> | undefined;
    const completed = suppliedConnectionFields(definitions, prepared ?? {}, fields);
    if (Object.entries(fields).some(([key, value]) => prepared?.[key] !== value))
      return this.client.proceed(await this.client.configure(plan, { fields: completed }), material);
    return null;
  }
  async authorize(plan: KeyholderPlan): Promise<OperationResultView> {
    const id = plan.id, { input } = plan;
    const permission = AuthorizeConnection.parse(input), previous = await this.client.custody.read(permission.connectionId);
    if (previous.version !== permission.version || previous.content.policy.ownerId !== permission.ownerId ||
      previous.content.policy.contentType !== ContentTypes.tokenSet) throw new Error('Review the current connection before changing its permissions.');
    const policy = await withUsers(this.client.custody, { ...previous.content.policy, revision: previous.content.policy.revision + 1 },
      permission.users);
    const current = await this.client.custody.api.json('/api/resources/' + permission.connectionId, {}, Resource);
    const resource = await this.client.custody.save(current.name, await this.client.custody.reveal(permission.connectionId), policy,
      { previous, metadata: previous.content.metadata,
        commit: async write => Resource.parse((await this.client.commit(plan, write as unknown as JsonValue)).result) });
    return { kind: 'saved', resource, operationId: id };
  }
  async saveApplication(plan: KeyholderPlan, material: PrivateOperationInput): Promise<OperationResultView> {
    const prepared = await this.prepareFields(plan, material); if (prepared) return prepared;
    const id = plan.id, { input } = plan;
    const destination = AppSave.parse(input);
    const previous = destination.resourceId ? await this.client.custody.latest(destination.resourceId) : undefined;
    if (previous && previous.version !== destination.version) throw new Error('This item changed. Reload it before saving.');
    const type = ContentTypes.clientCredential;
    if (previous && (previous.content.policy.contentType !== type || previous.content.policy.ownerId !== destination.ownerId))
      throw new Error('Choose the item prepared by this operation.');
    const policy = previous && !previous.replaced ? await this.client.custody.refreshRecipients(previous.content.policy)
      : await this.client.custody.policy(destination.ownerId, type, previous ? { replacing: previous.content.policy } : {});
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
      commit: async write => Resource.parse((await this.client.commit(plan, write as unknown as JsonValue)).result) });
    return { kind: 'saved' as const, resource, operationId: id };
  }
  async connect(plan: KeyholderPlan, material: PrivateOperationInput): Promise<OperationResultView> {
    if (plan.continuation?.kind === 'connection') return this.client.connections.progress(plan.continuation.id);
    const prepared = await this.prepareFields(plan, material); if (prepared) return prepared;
    const id = plan.id, { input } = plan;
    const connection = ConnectService.parse(input), method = await this.method(connection.methodId);
    if (!connection.name)
      return this.client.proceed(await this.client.configure(plan, { name: this.connectionNames.get(connection.methodId) ?? method.name }), material);
    if (material.scopes && !connection.scopes && (method.kind === 'oauth' || method.kind === 'ovh'))
      return this.client.proceed(await this.client.configure(plan, { scopes: material.scopes }), material);
    if (material.scopes && connection.scopes && (method.kind === 'oauth' || method.kind === 'ovh') &&
      canonical(selectScopes(method.config.scopes, material.scopes).sort()) !== canonical(selectScopes(method.config.scopes, connection.scopes).sort()))
      throw new Error('Use the service permissions prepared by this operation.');
    // An application the connection needs is saved first, as an operation of its own.
    if (requiresApp(method) && !connection.appId) {
      if (!connection.clientId) throw new Error('Enter the application client ID.');
      const application = await this.saveApplication(await this.client.review({ name: 'app.save', input: { ownerId: connection.ownerId,
        name: (connection.name ?? method.name).slice(0, 185) + ' application', methodId: connection.methodId,
        clientId: connection.clientId, ...(connection.fields ? { fields: connection.fields } : {}) } }),
      { ...(material.clientSecret ? { clientSecret: material.clientSecret } : {}), ...(material.fields ? { fields: material.fields } : {}) });
      if (!('kind' in application) || application.kind !== 'saved') throw new Error('Save the application for this connection.');
      return this.client.proceed(await this.client.configure(plan, { appId: application.resource.id }), material);
    }
    const appId = connection.appId;
    if (!connectionMethod(method).browserAuthorization) {
      if (await methodDigest(method) !== connection.methodDigest) throw new Error('Review the current connection method.');
      const previous = connection.connectionId ? await this.client.custody.latest(connection.connectionId) : undefined;
      if (previous && (previous.content.policy.ownerId !== connection.ownerId || previous.content.policy.contentType !== ContentTypes.tokenSet))
        throw new Error('Choose a connection belonging to this owner.');
      const old = previous && !previous.replaced ? await this.client.custody.connection(connection.connectionId!) : undefined;
      const app = registrationApplication({ methodId: connection.methodId, method, appId,
        app: appId ? AppMaterial.parse(JSON.parse(decode(await this.client.custody.reveal(appId)))) : null });
      const state = registrationMaterial({ methodId: connection.methodId, method, appId: appId ?? null, app,
        fields: suppliedConnectionFields(connectionMethod(method).fields, connection.fields ?? {}, material.fields ?? {}),
        scopes: method.kind === 'oauth' ? selectScopes(method.config.scopes, connection.scopes) : [], aws: material.aws }, old);
      const policy = await connectionPolicy(this.client.custody, connection.ownerId, previous, connection.users);
      const resource = await this.client.custody.save(connection.name ?? method.name, sealedConnection(state), policy,
        { previous, metadata: await connectionMetadata(state), labels: connectionLabels(state),
          commit: async write => {
            const made = await this.client.commit(plan, write as unknown as JsonValue);
            return this.client.custody.api.json('/api/resources/' + Id.parse((made.result as { id?: unknown } | null)?.id), {}, Resource);
          } });
      return { kind: 'saved', resource, operationId: id };
    }
    return this.client.connections.start(plan, method,
      suppliedConnectionFields(method.kind === 'aws' ? [] : method.config.fields, connection.fields ?? {}, material.fields ?? {}));
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
