import { z } from 'zod';
import type { Actor } from './authorization.js';
import { DomainError, fail } from './errors.js';
import type { JsonValue, OperationTitle, RequestedOperation } from '../shared/contracts.js';
import { JsonObject } from '../shared/contracts.js';
import { Invocation } from '../shared/operations.js';
import type { OperationInvocation } from '../shared/operations.js';

type Title = readonly [string, string] | ((input: Record<string, JsonValue>) => readonly [string, string]);
export class OperationFailed extends DomainError {
  constructor(readonly result: JsonValue, readonly uncertain: boolean) {
    super(409, uncertain ? 'execution_uncertain' : 'execution_failed', uncertain
      ? 'Check the result before starting this operation again.' : 'The execution did not complete successfully.');
  }
}
export interface OperationDefinition {
  name: string;
  schema: z.ZodType;
  title: Title;
  execution: 'server' | 'keyholder';
  configure: readonly string[];
  secret(pointer: string): boolean;
  execute(actor: Actor, input: unknown): Promise<JsonValue>;
  complete?: (actor: Actor, input: unknown, proof: JsonValue, execution: { id: string; index: number }) => Promise<JsonValue>;
  resolve?: (actor: Actor, input: unknown) => Promise<Record<string, JsonValue>>;
}
export interface OperationEndpoint {
  name: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  schema: { params?: z.ZodType; body?: z.ZodType; querystring?: z.ZodType; response?: Record<number, z.ZodType> };
  input(params: Record<string, string>, body: unknown, query: unknown): unknown;
  status?: number | ((result: JsonValue) => number);
  bodyLimit?: number;
}

// Operations own their validation and implementation. HTTP routes are only transport adapters.
export class OperationRegistry {
  readonly definitions = new Map<string, OperationDefinition>();
  readonly endpoints: OperationEndpoint[] = [];
  define<T extends z.ZodType>(name: string, schema: T, title: Title,
    execute: (actor: Actor, input: z.output<T>) => Promise<unknown>,
    options: { execution?: 'server' | 'keyholder'; configure?: readonly string[]; secret?: (pointer: string) => boolean;
      complete?: (actor: Actor, input: z.output<T>, proof: JsonValue, execution: { id: string; index: number }) => Promise<unknown>;
      resolve?: (actor: Actor, input: z.output<T>) => Promise<unknown> } = {}) {
    Invocation.shape.name.parse(name);
    if (this.definitions.has(name)) throw new Error('Duplicate operation: ' + name);
    this.definitions.set(name, { name, schema, title, execution: options.execution ?? 'server',
      configure: options.configure ?? [], secret: options.secret ?? (() => false),
      execute: async (actor, input) => await execute(actor, schema.parse(input)) as JsonValue,
      ...(options.complete ? { complete: async (actor: Actor, input: unknown, proof: JsonValue, execution: { id: string; index: number }) =>
        await options.complete!(actor, schema.parse(input), proof, execution) as JsonValue } : {}),
      ...(options.resolve ? { resolve: async (actor: Actor, input: unknown) =>
        JsonObject.parse(await options.resolve!(actor, schema.parse(input))) } : {}) });
  }
  bind(endpoint: OperationEndpoint) {
    this.get(endpoint.name);
    this.endpoints.push(endpoint);
  }
  get(name: string) {
    const definition = this.definitions.get(name);
    if (!definition) fail(400, 'operation_unavailable', 'Choose an available operation.');
    return definition;
  }
  resolve(operation: RequestedOperation, validateTransport = false): OperationInvocation {
    if (!operation.path.startsWith('/api/') || /[\\\u0000-\u0020#]/.test(operation.path))
      fail(400, 'invalid_operation', 'Use a Foundation operation.');
    if (operation.method === 'CONNECT' && operation.path === '/api/connections')
      return { name: 'connection.connect', input: JsonObject.parse(operation.body) };
    const url = new URL(operation.path, 'https://foundation.invalid');
    if (url.origin !== 'https://foundation.invalid') fail(400, 'invalid_operation', 'Use a Foundation operation.');
    const named = /^\/api\/operations\/([a-z][a-z0-9.]*)$/.exec(url.pathname);
    if (named && operation.method === 'POST' && !url.search) {
      this.get(named[1]!);
      return Invocation.parse({ name: named[1], input: operation.body });
    }
    for (const endpoint of this.endpoints) {
      if (endpoint.method !== operation.method) continue;
      const keys: string[] = [];
      const pattern = endpoint.path.split('/').map(part => {
        if (part.startsWith(':')) { keys.push(part.slice(1)); return '([^/]+)'; }
        return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      }).join('/');
      const match = new RegExp('^' + pattern + '$').exec(url.pathname);
      if (!match) continue;
      let params: Record<string, string>;
      try { params = Object.fromEntries(keys.map((key, index) => [key, decodeURIComponent(match[index + 1]!)])); }
      catch { fail(400, 'invalid_operation', 'Use a valid Foundation operation path.'); }
      if ([...url.searchParams.keys()].some(key => url.searchParams.getAll(key).length > 1))
        fail(400, 'invalid_operation', 'Provide each operation parameter once.');
      const query = Object.fromEntries(url.searchParams);
      if (validateTransport) {
        endpoint.schema.params?.parse(params);
        endpoint.schema.body?.parse(operation.body);
        endpoint.schema.querystring?.parse(query);
      }
      return Invocation.parse({ name: endpoint.name, input: endpoint.input(params, operation.body, query) });
    }
    fail(400, 'operation_unavailable', 'Choose an available operation.');
  }
  allows(operation: RequestedOperation) {
    try { this.resolve(operation); return true; } catch { return false; }
  }
  describe(operation: RequestedOperation): OperationTitle {
    try {
      const invocation = this.resolve(operation), definition = this.get(invocation.name);
      const [ja, en] = typeof definition.title === 'function' ? definition.title(invocation.input) : definition.title;
      return { ja, en };
    } catch { return { ja: '依頼された操作', en: 'Requested operation' }; }
  }
  prepare(invocation: OperationInvocation) {
    const definition = this.get(invocation.name);
    return { definition, invocation: { name: invocation.name, input: JsonObject.parse(definition.schema.parse(invocation.input)) } };
  }
  async prepareFor(actor: Actor, invocation: OperationInvocation) {
    const prepared = this.prepare(invocation);
    if (prepared.definition.resolve) prepared.invocation.input = await prepared.definition.resolve(actor, prepared.invocation.input);
    return this.prepare(prepared.invocation);
  }
  configure(operation: RequestedOperation, values: Record<string, JsonValue>) {
    const invocation = this.resolve(operation), definition = this.get(invocation.name);
    for (const [key, value] of Object.entries(values)) {
      if (!definition.configure.includes(key) || (invocation.input[key] != null && invocation.input[key] !== '' &&
        JSON.stringify(invocation.input[key]) !== JSON.stringify(value)))
        fail(400, 'operation_changed', 'Use the operation prepared by the requester.');
      invocation.input[key] = value;
    }
    return { method: 'POST' as const, path: '/api/operations/' + invocation.name, body: invocation.input, inputs: [] };
  }
  async execute(actor: Actor, invocation: OperationInvocation) {
    const prepared = this.prepare(invocation);
    if (prepared.definition.execution !== 'server') fail(400, 'keyholder_required', 'Continue this operation with your encryption keys.');
    return prepared.definition.execute(actor, prepared.invocation.input);
  }
}
