import assert from 'node:assert/strict';
import type { z } from 'zod';
import { delegatedFixture, MemoryJournal } from './delegation-support.js';
import { createContext } from '../server/context.js';
import { buildApp } from '../server/app.js';
import { DomainError } from '../server/errors.js';
import type { OutboundRequest, OutboundResponse, Transport } from '../server/transport.js';
import { CustodyClient } from '../shared/client.js';
import type { JsonApi } from '../shared/client.js';
import { ConnectionClient } from '../shared/connection-client.js';
import type { ConnectionFlow } from '../shared/connection-client.js';
import { CatalogMethod, Resource, listOf } from '../shared/contracts.js';
import { canonical } from '../shared/authority.js';
import { AppMaterial } from '../shared/connections.js';
import { ContentTypes } from '../shared/custody.js';
import { encode } from '../shared/encryption.js';
import { Task } from '../shared/execution.js';
import { Connections } from '../runtime/connections.js';
import { CommandProcess } from '../runtime/command.js';
import { Executor } from '../runtime/executor.js';
import { HttpBroker } from '../runtime/broker.js';
import { JournalTrust } from '../runtime/trust.js';
import type { RoleProvider } from '../runtime/roles.js';

export const jsonResponse = (value: unknown): OutboundResponse => ({ status: 200,
  headers: { 'content-type': 'application/json' }, body: encode(JSON.stringify(value)) });
export async function flowFixture(respond: (request: OutboundRequest) => OutboundResponse | Promise<OutboundResponse>
  = () => jsonResponse({ ok: true }), roles?: RoleProvider) {
  const f = await delegatedFixture();
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const app = await buildApp(context);
  const requests: OutboundRequest[] = [];
  const transport: Transport = { async send(request) { requests.push(request); return respond(request); } };
  const api = (token: string): JsonApi => ({ async json<T>(path: string,
    options: { method?: string; body?: unknown } = {}, schema?: z.ZodType<T>): Promise<T> {
    const result = await app.inject({ method: (options.method ?? 'GET') as 'GET', url: path,
      headers: { authorization: 'Bearer ' + token },
      ...(options.body !== undefined ? { payload: options.body as object } : {}) });
    const value = result.json();
    if (result.statusCode >= 400) throw new DomainError(result.statusCode, value.error.code, value.error.message);
    return schema ? schema.parse(value) : value as T;
  } });
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding);
  const client = new CustodyClient(api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys, trust);
  const flows = new Map<string, ConnectionFlow>();
  const connections = new ConnectionClient(client, { async get(id) { return structuredClone(flows.get(id) ?? null); },
    async put(flow) { flows.set(flow.id, structuredClone(flow)); } });
  const broker = new HttpBroker(api(f.executor.token)), journal = new MemoryJournal();
  const runtimeConnections = new Connections(f.executor.binding, f.executor.keys, broker.connections(), journal, transport, roles);
  const executor = new Executor(f.environment, f.executor.keys, broker, journal, transport,
    new CommandProcess({ isolation: 'process' }), runtimeConnections);
  const method = async (id: string) => {
    const catalog = await client.api.json('/api/connection-methods', {}, listOf(CatalogMethod));
    const selected = catalog.items.find(item => item.id === id)!;
    assert.ok(selected, id);
    const { id: _id, builtin: _builtin, availability: _availability, ...definition } = selected;
    return definition;
  };
  const saveApp = async (methodId: string, name = 'Application', fields = {}) => {
    const material = AppMaterial.parse({ format: 1, methodId, clientId: 'application-id',
      clientSecret: 'application-secret', generation: crypto.randomUUID(), fields });
    const policy = await client.policy(f.owner.actor.id, ContentTypes.clientCredential, [f.environment]);
    return client.save(name, encode(canonical(material)), policy, { metadata: {
      methodId, clientId: material.clientId, generation: material.generation,
    } });
  };
  async function start(input: { methodId: string; fields?: Record<string, string>; name?: string;
    connectionId?: string; appId?: string; role?: { arn: string; externalId: string; region: string } }) {
    return connections.start({ ...input, method: await method(input.methodId), name: input.name ?? 'Account',
      ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id });
  }
  async function tick(id: string) {
    await executor.tick();
    return connections.progress(id);
  }
  async function accept(id: string) {
    const accepted = await connections.accept(id);
    assert.equal(accepted.kind, 'pending');
    const connected = await tick(id);
    assert.equal(connected.kind, 'connected', JSON.stringify(connected));
    if (connected.kind !== 'connected') throw new Error('Expected a completed connection.');
    return client.api.json('/api/resources/' + connected.id, {}, Resource);
  }
  async function http(id: string, output: string, url = 'https://api.example.com/items') {
    const task = await client.submit(f.owner.actor.id, f.environment.manifest.id, { kind: 'http', request: {
      url, method: 'GET', headers: {}, bindings: [{ pointer: '/headers/authorization',
        parts: ['Bearer ', { id, output }] }],
    }, save: {} });
    await executor.tick();
    return client.result(await client.api.json('/api/executions/' + task.id, {}, Task));
  }
  return { ...f, context, app, api, client, connections, runtimeConnections, executor, journal, requests,
    method, saveApp, start, tick, accept, http,
    async close() { await app.close(); await f.close(); } };
}
