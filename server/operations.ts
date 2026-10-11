import { z } from 'zod';
import type { Actor } from './authorization.js';
import { DomainError, fail } from './errors.js';
import type { JsonValue, OperationTitle } from '../shared/contracts.js';
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
  describe(invocation: OperationInvocation): OperationTitle {
    const definition = this.get(invocation.name);
    const [ja, en] = typeof definition.title === 'function' ? definition.title(invocation.input) : definition.title;
    return { ja, en };
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
  configure(input: OperationInvocation, values: Record<string, JsonValue>) {
    const invocation = structuredClone(input), definition = this.get(invocation.name);
    for (const [key, value] of Object.entries(values)) {
      if (!definition.configure.includes(key) || (invocation.input[key] != null && invocation.input[key] !== '' &&
        JSON.stringify(invocation.input[key]) !== JSON.stringify(value)))
        fail(400, 'operation_changed', 'Use the operation prepared by the requester.');
      invocation.input[key] = value;
    }
    return invocation;
  }
  async execute(actor: Actor, invocation: OperationInvocation) {
    const prepared = this.prepare(invocation);
    if (prepared.definition.execution !== 'server') fail(400, 'keyholder_required', 'Continue this operation with your encryption keys.');
    return prepared.definition.execute(actor, prepared.invocation.input);
  }
}
