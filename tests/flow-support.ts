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
  const api = (token: string): JsonApi => ({ async json<T>(path: string,
    options: { method?: string; body?: unknown } = {}, schema?: z.ZodType<T>): Promise<T> {
    const result = await app.inject({ method: (options.method ?? 'GET') as 'GET', url: path,
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
    async put(flow) { flows.set(flow.id, structuredClone(flow)); } });
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
    scopes?: string[];
    connectionId?: string; appId?: string; aws?: AwsConnectionRequest }) {
    const { fields, scopes, aws, ...configuration } = input;
    const definition = await method(input.methodId);
    if (definition.kind === 'token') {
      const execution = await operations.start({ name: 'connection.connect', input: { ...configuration,
        name: input.name ?? 'Account', ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id } });
      const progress = await connections.start({ ...configuration, name: input.name ?? 'Account',
        ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id, method: definition, fields, scopes,
        execution: { id: execution.id, index: execution.index } });
      if (progress.kind !== 'pending') throw new Error('Expected an executor connection step.');
      return progress;
    }
    const progress = await operations.execute({ name: 'connection.connect', input: { ...configuration,
      name: input.name ?? 'Account', ownerId: f.owner.actor.id, environmentId: f.environment.manifest.id } }, { fields, scopes, aws });
    if (!('kind' in progress) || progress.kind !== 'pending') throw new Error('Expected a pending connection.');
    return progress;
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
    return client.result(await client.api.json('/api/runtime/runs/' + task.id, {}, Task));
  }
  return { ...f, executorIdentity: f.executor, context, app, api, client, connections, operations, functions, functionExecutor, runtimeConnections, executor, journal, requests,
    method, saveApp, start, tick, accept, http,
    async close() { await app.close(); await f.close(); } };
}
