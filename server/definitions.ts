import { z } from 'zod';
import type { Actor } from './authorization.js';
import { DomainError, fail } from './errors.js';
import type { JsonValue, OperationTitle } from '../shared/contracts.js';
import { JsonObject } from '../shared/contracts.js';
import { Invocation } from '../shared/operations.js';
import type { OperationCall } from '../shared/operations.js';

type Title = readonly [string, string] | ((input: Record<string, JsonValue>) => readonly [string, string]);
export class OperationFailed extends DomainError {
  constructor(readonly result: JsonValue, readonly uncertain: boolean) {
    super(409, uncertain ? 'operation_uncertain' : 'operation_failed', uncertain
      ? 'Check the result before making this operation again.' : 'The operation did not complete successfully.');
  }
}
export interface ProcessingDefinition {
  name: string;
  schema: z.ZodType;
  title: Title;
  // Whether the actor's device seals what the operation saves, and sends it to make the operation.
  keyholder: boolean;
  configure: readonly string[];
  secret(pointer: string): boolean;
  execute(actor: Actor, input: unknown): Promise<JsonValue>;
  // Makes an operation its actor's device sealed what it saves for, from what the device sent.
  complete?: (actor: Actor, input: unknown, proof: JsonValue) => Promise<JsonValue>;
  resolve?: (actor: Actor, input: unknown) => Promise<Record<string, JsonValue>>;
  review?: (actor: Actor, input: Record<string, JsonValue>) => Promise<Record<string, JsonValue>>;
  resultView?: (result: JsonValue) => JsonValue;
  continuation?: 'connection';
}
export interface OperationEndpoint {
  name: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  schema: { params?: z.ZodType; body?: z.ZodType; querystring?: z.ZodType; response?: Record<number, z.ZodType> };
  input(params: Record<string, string>, body: unknown, query: unknown): unknown;
  status?: number | ((result: JsonValue) => number);
  bodyLimit?: number;
  output?: (result: JsonValue) => JsonValue;
}

// Operations own their validation and implementation. HTTP routes are only transport adapters.
export class DefinitionRegistry {
  readonly definitions = new Map<string, ProcessingDefinition>();
  readonly endpoints: OperationEndpoint[] = [];
  define<T extends z.ZodType>(name: string, schema: T, title: Title,
    execute: (actor: Actor, input: z.output<T>) => Promise<unknown>,
    options: { keyholder?: boolean; configure?: readonly string[]; secret?: (pointer: string) => boolean;
      complete?: (actor: Actor, input: z.output<T>, proof: JsonValue) => Promise<unknown>;
      resolve?: (actor: Actor, input: z.output<T>) => Promise<unknown>;
      review?: ProcessingDefinition['review']; resultView?: ProcessingDefinition['resultView'];
      continuation?: ProcessingDefinition['continuation'] } = {}) {
    Invocation.shape.name.parse(name);
    if (this.definitions.has(name)) throw new Error('Duplicate operation: ' + name);
    this.definitions.set(name, { name, schema, title, keyholder: options.keyholder ?? false,
      configure: options.configure ?? [], secret: options.secret ?? (() => false),
      ...(options.review ? { review: options.review } : {}),
      ...(options.resultView ? { resultView: options.resultView } : {}),
      ...(options.continuation ? { continuation: options.continuation } : {}),
      execute: async (actor, input) => await execute(actor, schema.parse(input)) as JsonValue,
      ...(options.complete ? { complete: async (actor: Actor, input: unknown, proof: JsonValue) =>
        await options.complete!(actor, schema.parse(input), proof) as JsonValue } : {}),
      ...(options.resolve ? { resolve: async (actor: Actor, input: unknown) =>
        JsonObject.parse(await options.resolve!(actor, schema.parse(input))) } : {}) });
  }
  bind(endpoint: OperationEndpoint) {
    this.get(endpoint.name);
    this.endpoints.push(endpoint);
  }
  has(name: string) { return this.definitions.has(name); }
  get(name: string) {
    const definition = this.definitions.get(name);
    if (!definition) fail(400, 'operation_unavailable', 'Choose an available operation.');
    return definition;
  }
  describe(invocation: OperationCall): OperationTitle {
    const definition = this.get(invocation.name);
    const [ja, en] = typeof definition.title === 'function' ? definition.title(invocation.input) : definition.title;
    return { ja, en };
  }
  prepare(invocation: OperationCall) {
    const definition = this.get(invocation.name);
    return { definition, invocation: { name: invocation.name, input: JsonObject.parse(definition.schema.parse(invocation.input)) } };
  }
  async prepareFor(actor: Actor, invocation: OperationCall) {
    const prepared = this.prepare(invocation);
    if (prepared.definition.resolve) prepared.invocation.input = await prepared.definition.resolve(actor, prepared.invocation.input);
    return this.prepare(prepared.invocation);
  }
  configure(input: OperationCall, values: Record<string, JsonValue>) {
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
  async execute(actor: Actor, invocation: OperationCall) {
    const prepared = this.prepare(invocation);
    if (prepared.definition.keyholder) fail(400, 'keyholder_required', 'Make this operation with your encryption keys.');
    return prepared.definition.execute(actor, prepared.invocation.input);
  }
}
