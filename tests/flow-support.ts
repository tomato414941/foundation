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
import { ExecutionClient } from '../shared/execution-client.js';
import { FunctionClient } from '../shared/function-client.js';
import { FunctionBroker, FunctionExecutor } from '../runtime/functions.js';
import type { ConnectionFlow } from '../shared/connection-client.js';
import { CatalogMethod, Resource, listOf } from '../shared/contracts.js';
import { canonical } from '../shared/authority.js';
import { AppMaterial } from '../shared/connections.js';
import { connectionMethod } from '../shared/connection-methods.js';
import { visibleConnectionFields } from '../shared/connection-fields.js';
import { ContentTypes } from '../shared/custody.js';
import { encode } from '../shared/encryption.js';
import { Task } from '../shared/runtime-protocol.js';
import { Connections } from '../runtime/connections.js';
import { CommandProcess } from '../runtime/command.js';
import { Executor } from '../runtime/executor.js';
import { HttpBroker } from '../runtime/broker.js';
import { JournalTrust } from '../runtime/trust.js';
import type { AwsConnectionProvider } from '../runtime/aws.js';
import type { AwsConnectionRequest } from '../shared/aws.js';

export const jsonResponse = (value: unknown): OutboundResponse => ({ status: 200,
  headers: { 'content-type': 'application/json' }, body: encode(JSON.stringify(value)) });
export async function flowFixture(respond: (request: OutboundRequest) => OutboundResponse | Promise<OutboundResponse>
  = () => jsonResponse({ ok: true }), aws?: AwsConnectionProvider) {
  const f = await delegatedFixture();
  const context = await createContext(f.config, { db: f.db, mailer: f.mailer });
  const app = await buildApp(context);
  const requests: OutboundRequest[] = [];
  const transport: Transport = { async send(request) { requests.push(request); return respond(request); } };
  const api = (token: string, remoteAddress?: string): JsonApi => ({ async json<T>(path: string,
    options: { method?: string; body?: unknown } = {}, schema?: z.ZodType<T>): Promise<T> {
    const result = await app.inject({ method: (options.method ?? 'GET') as 'GET', url: path,
      ...(remoteAddress ? { remoteAddress } : {}),
      headers: { authorization: 'Bearer ' + token },
      ...(options.body !== undefined ? { payload: options.body as object } : {}) });
    const value = result.statusCode === 204 ? null : result.json();
    if (result.statusCode >= 400) throw new DomainError(result.statusCode, value.error.code, value.error.message);
    return schema ? schema.parse(value) : value as T;
  } });
  const trust = new JournalTrust(new MemoryJournal());
  await trust.rememberBinding(f.executor.binding);
  const client = new CustodyClient(api(f.owner.token), f.config.origin, f.owner.binding, f.owner.keys, trust);
  const flows = new Map<string, ConnectionFlow>();
  const connections = new ConnectionClient(client, { async get(id) { return structuredClone(flows.get(id) ?? null); },
    async put(flow) { flows.set(flow.id, structuredClone(flow)); } }, transport, 'cli');
  const operations = new ExecutionClient(client, connections);
  const broker = new HttpBroker(api(f.executor.token)), journal = new MemoryJournal();
  const runtimeConnections = new Connections(f.executor.binding, f.executor.keys, broker.connections(), journal, transport, aws);
  const executor = new Executor(f.environment, f.executor.keys, broker, journal, transport,
    new CommandProcess({ isolation: 'process' }), runtimeConnections);
  const functions = new FunctionClient(api(f.owner.token), client);
  const functionExecutor = new FunctionExecutor(executor, new FunctionBroker(api(f.executor.token)), journal);
  const method = async (id: string) => {
    const catalog = await client.api.json('/api/connection-methods', {}, listOf(CatalogMethod));
    const selected = catalog.items.find(item => item.id === id)!;
    assert.ok(selected, id);
    const { id: _id, builtin: _builtin, availability: _availability, registration: _registration, defaultName: _defaultName, ...definition } = selected;
    return definition;
  };
  const saveApp = async (methodId: string, name = 'Application', fields = {}) => {
    const material = AppMaterial.parse({ format: 1, methodId, clientId: 'application-id',
      clientSecret: 'application-secret', generation: crypto.randomUUID(), fields });
    const policy = await client.policy(f.owner.actor.id, ContentTypes.clientCredential, [f.environment]);
    return client.save(name, encode(canonical(material)), policy, { metadata: {
      methodId, clientId: material.clientId, generation: material.generation,
      fields: visibleConnectionFields(connectionMethod(await method(methodId)).fields, fields),
    } });
  };
  async function start(input: { methodId: string; fields?: Record<string, string>; name?: string;
    scopes?: string[];
    connectionId?: string; appId?: string; aws?: AwsConnectionRequest }) {
    const { fields, scopes, aws, ...configuration } = input;
    const definition = await method(input.methodId);
    return operations.execute({ name: 'connection.connect', input: { ...configuration,
      name: input.name ?? 'Account', ownerId: f.owner.actor.id,
      ...(scopes ? { scopes } : {}) } }, { fields, scopes, aws });
  }
  async function saveConnection(input: Parameters<typeof start>[0]) {
    const result = await start(input);
    if (!('kind' in result) || result.kind !== 'saved') throw new Error('Expected saved credentials.');
    return result.resource;
  }
  async function authorize(input: Parameters<typeof start>[0]) {
    const result = await start(input);
    if (!('kind' in result) || result.kind !== 'authorize') throw new Error('Expected browser authorization.');
    return result;
  }
  async function saved(id: string) {
    const result = await connections.progress(id);
    if (result.kind !== 'connected') throw new Error('Expected saved credentials.');
    return client.api.json('/api/resources/' + result.id, {}, Resource);
  }
  async function tick(id: string) { return connections.progress(id); }
  async function http(id: string, output: string, url = 'https://api.example.com/items') {
    const task = await client.submit(f.owner.actor.id, f.environment.manifest.id, { kind: 'http', request: {
      url, method: 'GET', headers: {}, bindings: [{ pointer: '/headers/authorization',
        parts: ['Bearer ', { id, output }] }],
    }, save: {} });
    await executor.tick();
    return client.result(await client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  }
  return { ...f, executorIdentity: f.executor, context, app, api, client, connections, operations, functions, functionExecutor, runtimeConnections, executor, journal, requests,
    method, saveApp, start, authorize, saveConnection, tick, saved, http, transport, flows,
    async close() { await app.close(); await f.close(); } };
}
