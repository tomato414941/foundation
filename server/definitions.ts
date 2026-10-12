import { z } from 'zod';
import type { Actor } from './authorization.js';
import { DomainError, fail } from './errors.js';
import type { JsonValue, OperationTitle } from '../shared/contracts.js';
import { JsonObject } from '../shared/contracts.js';
import { Invocation } from '../shared/executions.js';
import type { DefinitionCall } from '../shared/executions.js';
import type { Queryable } from './database.js';

type Title = readonly [string, string] | ((input: Record<string, JsonValue>) => readonly [string, string]);
export class OperationFailed extends DomainError {
  constructor(readonly result: JsonValue, readonly uncertain: boolean) {
    super(409, uncertain ? 'execution_uncertain' : 'execution_failed', uncertain
      ? 'Check the result before starting this operation again.' : 'The execution did not complete successfully.');
  }
}
export interface ProcessingDefinition {
  name: string;
  schema: z.ZodType;
  title: Title;
  execution: 'server' | 'keyholder';
  configure: readonly string[];
  secret(pointer: string): boolean;
  execute(actor: Actor, input: unknown): Promise<JsonValue>;
  complete?: (actor: Actor, input: unknown, proof: JsonValue, execution: { id: string; index: number }) => Promise<JsonValue>;
  prepareInput?: (actor: Actor, input: unknown, proof: JsonValue, connection: Queryable) => Promise<Record<string, JsonValue>>;
  resolve?: (actor: Actor, input: unknown) => Promise<Record<string, JsonValue>>;
  review?: (actor: Actor, input: Record<string, JsonValue>) => Promise<Record<string, JsonValue>>;
  observe?: (actor: Actor, result: JsonValue) => Promise<{ state: 'pending' | 'succeeded' | 'failed' | 'cancelled' | 'uncertain'; result: JsonValue }>;
  cancel?: (actor: Actor, result: JsonValue) => Promise<unknown>;
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
export class DefinitionRegistry {
  readonly definitions = new Map<string, ProcessingDefinition>();
  readonly endpoints: OperationEndpoint[] = [];
  define<T extends z.ZodType>(name: string, schema: T, title: Title,
    execute: (actor: Actor, input: z.output<T>) => Promise<unknown>,
    options: { execution?: 'server' | 'keyholder'; configure?: readonly string[]; secret?: (pointer: string) => boolean;
      complete?: (actor: Actor, input: z.output<T>, proof: JsonValue, execution: { id: string; index: number }) => Promise<unknown>;
      prepareInput?: (actor: Actor, input: z.output<T>, proof: JsonValue, connection: Queryable) => Promise<unknown>;
      resolve?: (actor: Actor, input: z.output<T>) => Promise<unknown>;
      observe?: ProcessingDefinition['observe']; cancel?: ProcessingDefinition['cancel']; review?: ProcessingDefinition['review'] } = {}) {
    Invocation.shape.name.parse(name);
    if (this.definitions.has(name)) throw new Error('Duplicate operation: ' + name);
    this.definitions.set(name, { name, schema, title, execution: options.execution ?? 'server',
      configure: options.configure ?? [], secret: options.secret ?? (() => false),
      ...(options.observe ? { observe: options.observe } : {}), ...(options.cancel ? { cancel: options.cancel } : {}),
      ...(options.review ? { review: options.review } : {}),
      execute: async (actor, input) => await execute(actor, schema.parse(input)) as JsonValue,
      ...(options.complete ? { complete: async (actor: Actor, input: unknown, proof: JsonValue, execution: { id: string; index: number }) =>
        await options.complete!(actor, schema.parse(input), proof, execution) as JsonValue } : {}),
      ...(options.prepareInput ? { prepareInput: async (actor: Actor, input: unknown, proof: JsonValue, connection: Queryable) =>
        JsonObject.parse(await options.prepareInput!(actor, schema.parse(input), proof, connection)) } : {}),
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
  describe(invocation: DefinitionCall): OperationTitle {
    const definition = this.get(invocation.name);
    const [ja, en] = typeof definition.title === 'function' ? definition.title(invocation.input) : definition.title;
    return { ja, en };
  }
  prepare(invocation: DefinitionCall) {
    const definition = this.get(invocation.name);
    return { definition, invocation: { name: invocation.name, input: JsonObject.parse(definition.schema.parse(invocation.input)) } };
  }
  async prepareFor(actor: Actor, invocation: DefinitionCall) {
    const prepared = this.prepare(invocation);
    if (prepared.definition.resolve) prepared.invocation.input = await prepared.definition.resolve(actor, prepared.invocation.input);
    return this.prepare(prepared.invocation);
  }
  configure(input: DefinitionCall, values: Record<string, JsonValue>) {
    const invocation = structuredClone(input), definition = this.get(invocation.name);
    const fill = (previous: JsonValue | undefined, value: JsonValue): JsonValue => {
      if (previous == null || previous === '') return value;
      if (typeof previous === 'object' && !Array.isArray(previous) && value && typeof value === 'object' && !Array.isArray(value)) {
        const result = { ...previous };
        for (const [key, next] of Object.entries(value)) result[key] = fill(result[key], next);
        return result;
      }
      if (JSON.stringify(previous) !== JSON.stringify(value)) fail(400, 'operation_changed', 'Use the operation prepared by the requester.');
      return previous;
    };
    for (const [key, value] of Object.entries(values)) {
      if (!definition.configure.includes(key))
        fail(400, 'operation_changed', 'Use the operation prepared by the requester.');
      invocation.input[key] = fill(invocation.input[key], value);
    }
    return invocation;
  }
  async execute(actor: Actor, invocation: DefinitionCall) {
    const prepared = this.prepare(invocation);
    if (prepared.definition.execution !== 'server') fail(400, 'keyholder_required', 'Continue this operation with your encryption keys.');
    return prepared.definition.execute(actor, prepared.invocation.input);
  }
}
