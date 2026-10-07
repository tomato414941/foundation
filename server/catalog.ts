import { randomUUID } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import {
  AuthKind,
  CatalogEntry,
  CatalogMethod,
  Id,
  InlineServiceDefinition,
  LegacyServiceDefinition,
  MethodDefinition,
  ServiceDefinition,
  ServiceInputDefinition,
} from '../shared/contracts.js';
import type {
  AuthKindName,
  CatalogConnectionMethod,
  CatalogService,
  LegacyServiceDescription,
  MethodDescription,
  ServiceDescription,
  ServiceDefinitionInput,
} from '../shared/contracts.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Actor } from './authorization.js';
import type { Configuration } from './config.js';
import type { Queryable } from './database.js';
import { fail } from './errors.js';

export const canonicalServiceId = (id: string) => (id === 'sakura-vps' ? 'sakura' : id);
const legacyKey = (serviceId: string, kind: AuthKindName) => serviceId + ':' + kind;
const uuid = (id: string) => Id.safeParse(id).success;
export function legacyMethod(service: LegacyServiceDescription, kind: AuthKindName): MethodDescription {
  const config = service.auth[kind];
  if (!config) fail(400, 'scheme_unavailable', 'Choose an available connection method.');
  return MethodDefinition.parse({
    name: (service.name + ' · ' + { oauth: 'OAuth', token: 'API key', role: 'IAM role' }[kind]).slice(0, 200),
    kind,
    config,
    ...(service.docs ? { docs: service.docs } : {}),
    ...(service.console ? { console: service.console } : {}),
  });
}
export function inlineService(value: ServiceDefinitionInput) {
  const input = ServiceInputDefinition.parse(value);
  if (!('auth' in input)) return input;
  const { auth, ...metadata } = input;
  return InlineServiceDefinition.parse({
    ...metadata,
    methods: Object.fromEntries(
      Object.keys(auth).map((kind) => [kind, legacyMethod(input, AuthKind.parse(kind))]),
    ),
  });
}

export class Catalog {
  readonly aliases = new Map<string, string>();
  private constructor(
    readonly definitions: Map<string, ServiceDescription>,
    readonly methods: Map<string, MethodDescription>,
    readonly resources: Resources,
    readonly config: Configuration,
  ) {}
  static async load(resources: Resources, config: Configuration) {
    const directory = new URL('./catalog/', import.meta.url),
      definitions = new Map<string, ServiceDescription>(),
      methods = new Map<string, MethodDescription>(),
      catalog = new Catalog(definitions, methods, resources, config);
    for (const filename of (await readdir(directory)).filter((name) => name.endsWith('.json')).sort()) {
      const { id: rawId, ...data } = JSON.parse(await readFile(new URL(filename, directory), 'utf8'));
      const id = canonicalServiceId(String(rawId)),
        input = inlineService(ServiceInputDefinition.parse(data)),
        references: Record<string, string> = {};
      for (const [rawKey, value] of Object.entries(input.methods)) {
        const key = id === 'sakura' && rawKey === 'token' ? 'vps-api-key' : rawKey;
        const methodId = typeof value === 'string' ? value : id + ':' + key;
        if (typeof value !== 'string') methods.set(methodId, MethodDefinition.parse(value));
        references[key] = methodId;
        if (AuthKind.safeParse(rawKey).success) {
          catalog.registerAlias(String(rawId), rawKey as AuthKindName, methodId);
          catalog.registerAlias(id, rawKey as AuthKindName, methodId);
        }
        if (id === 'sakura' && key === 'vps-api-key') {
          catalog.registerAlias('sakura-vps', 'token', methodId);
          catalog.registerAlias('sakura', 'token', methodId);
        }
      }
      definitions.set(
        id,
        ServiceDefinition.parse({
          ...input,
          ...(id === 'sakura' ? { name: 'さくら' } : {}),
          methods: references,
        }),
      );
    }
    for (const service of definitions.values())
      for (const methodId of Object.values(service.methods))
        if (!methods.has(methodId))
          throw new Error('A catalog service references an unknown connection method.');
    await catalog.migrateDefinitions();
    resources.connectionServices = (actor, methodId) => catalog.servicesForMethod(actor, methodId);
    return catalog;
  }
  private registerAlias(serviceId: string, kind: AuthKindName, methodId: string) {
    this.aliases.set(legacyKey(serviceId, kind), methodId);
  }
  async legacyMethodId(
    serviceId: string,
    kind: AuthKindName,
    connection: Queryable = this.resources.db.pool,
  ) {
    const known = this.aliases.get(legacyKey(serviceId, kind));
    if (known) return known;
    if (uuid(serviceId)) {
      const row = await this.resources.db.one<{ method_id: string }>(
        'SELECT method_id FROM connection_method_aliases WHERE service_id=$1 AND scheme=$2',
        [serviceId, kind],
        connection,
      );
      if (row) {
        this.registerAlias(serviceId, kind, row.method_id);
        return row.method_id;
      }
    }
    fail(400, 'method_required', 'Choose a connection method.');
  }
  private async methodName(ownerId: string, name: string, connection: Queryable) {
    const prefix = name.slice(0, 180);
    for (let index = 1; index <= 1000; index++) {
      const candidate = index === 1 ? prefix : prefix + ' (' + index + ')';
      const existing = await this.resources.db.one(
        "SELECT 1 FROM resources WHERE owner_id=$1 AND kind='method' AND name=$2",
        [ownerId, candidate],
        connection,
      );
      if (!existing) return candidate;
    }
    fail(409, 'name_taken', 'Choose another connection method name.');
  }
  private async migrateDefinitions() {
    await this.resources.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023747)');
      const existingAliases = await this.resources.db.all<{
        service_id: string;
        scheme: AuthKindName;
        method_id: string;
      }>('SELECT service_id,scheme,method_id FROM connection_method_aliases', [], connection);
      for (const row of existingAliases) this.registerAlias(row.service_id, row.scheme, row.method_id);
      const services = await this.resources.db.all<ResourceRow>(
        "SELECT * FROM resources WHERE kind='service' AND data ? 'auth' FOR UPDATE",
        [],
        connection,
      );
      for (const row of services) {
        const old = LegacyServiceDefinition.parse(row.data),
          { auth, ...metadata } = old,
          methods: Record<string, string> = {};
        for (const kind of Object.keys(auth).map((value) => AuthKind.parse(value))) {
          const definition = legacyMethod(old, kind),
            name = await this.methodName(row.owner_id, definition.name, connection),
            method = await this.resources.insert(row.owner_id, 'method', name, definition, {}, connection);
          methods[kind] = method.id;
          await connection.query(
            'INSERT INTO grants(resource_id,principal_id,actions) SELECT $1,principal_id,actions FROM grants WHERE resource_id=$2',
            [method.id, row.id],
          );
          await connection.query(
            'INSERT INTO connection_method_aliases(service_id,scheme,method_id) VALUES($1,$2,$3)',
            [row.id, kind, method.id],
          );
          this.registerAlias(row.id, kind, method.id);
        }
        await connection.query('UPDATE resources SET data=$2 WHERE id=$1', [
          row.id,
          JSON.stringify({ ...metadata, methods }),
        ]);
        await this.resources.references(row.id, Object.values(methods), connection);
      }
      const apps = await this.resources.db.all<ResourceRow>(
        "SELECT * FROM resources WHERE kind='app' AND NOT(data ? 'methodId') FOR UPDATE",
        [],
        connection,
      );
      for (const row of apps) {
        const { serviceId, ...data } = row.data,
          methodId = await this.legacyMethodId(String(serviceId), 'oauth', connection);
        await connection.query('UPDATE resources SET data=$2 WHERE id=$1', [
          row.id,
          JSON.stringify({ ...data, methodId }),
        ]);
        await this.resources.references(row.id, this.methods.has(methodId) ? [] : [methodId], connection);
      }
    });
  }
  async get(
    actor: Actor,
    id: string,
    connection: Queryable = this.resources.db.pool,
  ): Promise<ServiceDescription> {
    const builtin = this.definitions.get(canonicalServiceId(id));
    if (builtin) return builtin;
    if (!uuid(id)) fail(404, 'not_found', 'The service was not found.');
    const row = await this.resources.get(id, connection);
    if (row.kind !== 'service') fail(404, 'not_found', 'The service was not found.');
    await this.resources.authorization.requireResource(actor, row, 'use', connection);
    return ServiceDefinition.parse({ ...row.data, name: row.name });
  }
  async method(
    actor: Actor,
    id: string,
    connection: Queryable = this.resources.db.pool,
  ): Promise<MethodDescription> {
    const builtin = this.methods.get(id);
    if (builtin) return builtin;
    if (!uuid(id)) fail(404, 'not_found', 'The connection method was not found.');
    const row = await this.resources.get(id, connection);
    if (row.kind !== 'method') fail(404, 'not_found', 'The connection method was not found.');
    await this.resources.authorization.requireResource(actor, row, 'use', connection);
    return MethodDefinition.parse({ ...row.data, name: row.name });
  }
  async select(actor: Actor, input: { methodId?: string; serviceId?: string; scheme?: AuthKindName }) {
    const service = input.serviceId ? await this.get(actor, input.serviceId) : null;
    const id =
      input.methodId ??
      (input.serviceId && input.scheme
        ? await this.legacyMethodId(input.serviceId, input.scheme)
        : fail(400, 'method_required', 'Choose a connection method.'));
    if (service && !Object.values(service.methods).includes(id))
      fail(400, 'wrong_method', 'Choose a connection method offered by this service.');
    const definition = await this.method(actor, id);
    if (input.scheme && definition.kind !== input.scheme)
      fail(400, 'wrong_method', 'Choose a matching connection method.');
    return { id, definition };
  }
  async prepareDefinition(
    actor: Actor,
    ownerId: string,
    serviceId: string,
    value: ServiceDefinitionInput,
    connection: Queryable,
  ): Promise<ServiceDescription> {
    const input = inlineService(value),
      references: Record<string, string> = {};
    for (const [key, value] of Object.entries(input.methods)) {
      if (typeof value === 'string') {
        await this.method(actor, value, connection);
        references[key] = value;
      } else {
        if (!(await this.resources.authorization.canCreate(actor, ownerId, 'method', connection)))
          fail(403, 'forbidden', 'You cannot create connection methods for this principal.');
        const name = await this.methodName(ownerId, value.name, connection),
          row = await this.resources.insert(ownerId, 'method', name, value, {}, connection);
        references[key] = row.id;
      }
    }
    if ('auth' in value) {
      for (const kind of Object.keys(value.auth).map((key) => AuthKind.parse(key))) {
        await connection.query(
          'INSERT INTO connection_method_aliases(service_id,scheme,method_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',
          [serviceId, kind, references[kind]],
        );
      }
    }
    return ServiceDefinition.parse({ ...input, methods: references });
  }
  private async usable(actor: Actor, kind: 'service' | 'method') {
    const rows = await this.resources.db.all<ResourceRow>('SELECT * FROM resources WHERE kind=$1', [kind]);
    const permissions = await this.resources.authorization.actionsForResources(actor, rows);
    return rows.filter((row) => permissions.get(row.id)?.includes('use'));
  }
  methodView(id: string, value: MethodDescription): CatalogConnectionMethod {
    return CatalogMethod.parse({
      id,
      ...value,
      builtin: this.methods.has(id),
      availability:
        value.kind === 'oauth'
          ? value.config.adapter === 'openrouter'
            ? 'ready'
            : 'app-required'
          : 'ready',
    });
  }
  async listMethods(actor: Actor): Promise<CatalogConnectionMethod[]> {
    const custom = await this.usable(actor, 'method');
    return [
      ...[...this.methods].map(([id, data]) => this.methodView(id, data)),
      ...custom.map((row) =>
        this.methodView(row.id, MethodDefinition.parse({ ...row.data, name: row.name })),
      ),
    ].sort((a, b) => a.name.localeCompare(b.name));
  }
  private async services(actor: Actor) {
    const custom = await this.usable(actor, 'service');
    return [
      ...this.definitions.entries(),
      ...custom.map((row) => [row.id, ServiceDefinition.parse({ ...row.data, name: row.name })] as const),
    ];
  }
  async servicesForMethod(actor: Actor, methodId: string) {
    return (await this.services(actor))
      .filter(([, service]) => Object.values(service.methods).includes(methodId))
      .map(([id, service]) => ({ id, name: service.name }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }
  async list(actor: Actor): Promise<CatalogService[]> {
    const [services, methods] = await Promise.all([this.services(actor), this.listMethods(actor)]),
      byId = new Map(methods.map((method) => [method.id, method]));
    return services
      .map(([id, data]) =>
        CatalogEntry.parse({
          ...data,
          id,
          builtin: this.definitions.has(id),
          methods: Object.fromEntries(
            Object.entries(data.methods)
              .filter(([, methodId]) => byId.has(methodId))
              .map(([key, methodId]) => [key, byId.get(methodId)]),
          ),
        }),
      )
      .sort((a, b) => a.name.localeCompare(b.name));
  }
  async createService(actor: Actor, ownerId: string, name: string, value: ServiceDefinitionInput) {
    return this.resources.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023747)');
      const id = randomUUID(),
        data = await this.prepareDefinition(actor, ownerId, id, value, connection);
      return this.resources.insert(
        ownerId,
        'service',
        name,
        data,
        { id, references: Object.values(data.methods).filter((methodId) => !this.methods.has(methodId)) },
        connection,
      );
    });
  }
}
