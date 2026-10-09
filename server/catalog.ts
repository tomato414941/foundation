import { readdir, readFile } from 'node:fs/promises';
import {
  CatalogEntry,
  CatalogMethod,
  Id,
  MethodDefinition,
  ServiceDefinition,
  ServiceInputDefinition,
} from '../shared/contracts.js';
import type {
  CatalogConnectionMethod,
  CatalogService,
  MethodDescription,
  ServiceDescription,
  ServiceDefinitionInput,
} from '../shared/contracts.js';
import type { Resources, ResourceRow } from './resources.js';
import type { Actor } from './authorization.js';
import type { Configuration } from './config.js';
import type { Queryable } from './database.js';
import { fail } from './errors.js';

const uuid = (id: string) => Id.safeParse(id).success;

export class Catalog {
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
      const id = String(rawId),
        input = ServiceInputDefinition.parse(data),
        references: Record<string, string> = {};
      for (const [key, value] of Object.entries(input.methods)) {
        const methodId = typeof value === 'string' ? value : id + ':' + key;
        if (typeof value !== 'string') methods.set(methodId, MethodDefinition.parse(value));
        references[key] = methodId;
      }
      definitions.set(id, ServiceDefinition.parse({ ...input, methods: references }));
    }
    for (const service of definitions.values())
      for (const methodId of Object.values(service.methods))
        if (!methods.has(methodId))
          throw new Error('A catalog service references an unknown connection method.');
    resources.connectionServices = (actor, methodId) => catalog.servicesForMethod(actor, methodId);
    return catalog;
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
  async prepareDefinition(
    actor: Actor,
    ownerId: string,
    input: ServiceDefinitionInput,
    connection: Queryable,
  ): Promise<ServiceDescription> {
    const references: Record<string, string> = {};
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
    return ServiceDefinition.parse({ ...input, methods: references });
  }
  private async usable(actor: Actor, kind: 'service' | 'method') {
    const { authorization } = this.resources;
    await authorization.active(actor);
    if (actor.requestId) return [];
    return this.resources.db.all<ResourceRow>('SELECT * FROM resources WHERE id=ANY($1::uuid[]) ORDER BY created_at,id',
      [await authorization.find(actor.id, kind, 'use')]);
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
      const data = await this.prepareDefinition(actor, ownerId, value, connection);
      return this.resources.insert(
        ownerId,
        'service',
        name,
        data,
        { references: Object.values(data.methods).filter((methodId) => !this.methods.has(methodId)) },
        connection,
      );
    });
  }
}
