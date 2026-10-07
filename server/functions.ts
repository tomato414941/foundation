import type { Actor } from './authorization.js';
import type { Resources } from './resources.js';
import { publicUrl } from './transport.js';
import { FunctionDefinition } from '../shared/contracts.js';
import type { FunctionSpec, HttpRequestInput, JsonValue } from '../shared/contracts.js';
import { pointerParts } from '../shared/values.js';
import { fail } from './errors.js';
import { functionRequest } from '../shared/function-request.js';

export class Functions {
  constructor(
    readonly resources: Resources,
    readonly origin: string,
  ) {}
  references(spec: HttpRequestInput): string[] {
    return spec.bindings.flatMap((binding) =>
      binding.parts.flatMap((part) => (typeof part === 'string' ? [] : [part.id])),
    );
  }
  async validate(actor: Actor, spec: HttpRequestInput) {
    publicUrl(spec.url, this.origin);
    if ([spec.body, spec.json, spec.form].filter((value) => value !== undefined).length > 1)
      fail(400, 'multiple_bodies', 'Choose one request body format.');
    for (const binding of spec.bindings) {
      let parts: string[];
      try {
        parts = pointerParts(binding.pointer);
      } catch {
        fail(400, 'invalid_binding', 'Choose a field in the headers or body.');
      }
      if (
        !parts.length ||
        !['headers', 'body', 'json', 'form'].includes(parts[0]!) ||
        (parts[0] === 'body' && parts.length !== 1) ||
        (['headers', 'form'].includes(parts[0]!) && parts.length !== 2)
      )
        fail(400, 'invalid_binding', 'Choose a field in the headers or body.');
      for (const part of binding.parts)
        if (typeof part !== 'string') {
          const row = await this.resources.get(part.id);
          if (row.kind !== part.kind) fail(400, 'wrong_kind', 'Choose a secret or connection.');
          await this.resources.authorization.requireResource(actor, row, 'use');
        }
    }
  }
  async validateFunction(actor: Actor, definition: FunctionSpec) {
    const spec = FunctionDefinition.parse(definition),
      names = new Set<string>();
    for (const parameter of spec.parameters) {
      if (names.has(parameter.name)) fail(400, 'duplicate_parameter', 'Use unique parameter names.');
      names.add(parameter.name);
    }
    const url = new URL(spec.request.url.replace(/\{[^}]+\}/g, 'placeholder'));
    if (url.host.includes('placeholder'))
      fail(400, 'variable_origin', 'The function must have a fixed destination host.');
    const filled = this.arguments(
      spec,
      Object.fromEntries(spec.parameters.map((parameter) => [parameter.name, 'example'])),
    );
    await this.validate(actor, filled);
    return spec;
  }
  async create(actor: Actor, ownerId: string, name: string, definition: FunctionSpec) {
    if (!(await this.resources.authorization.canCreate(actor, ownerId, 'function')))
      fail(403, 'forbidden', 'You cannot create functions for this principal.');
    const spec = await this.validateFunction(actor, {
      ...definition, ...(Object.keys(definition.save).length ? { outputOwnerId: ownerId } : {}),
    });
    // The owner provides the authority each invocation uses. Validate its sources before publishing.
    await this.validate(
      { id: ownerId },
      this.arguments(
        spec,
        Object.fromEntries(spec.parameters.map((parameter) => [parameter.name, 'example'])),
      ),
    );
    return this.resources.db.transaction((connection) =>
      this.resources.insert(
        ownerId,
        'function',
        name,
        spec as unknown as Record<string, JsonValue>,
        { references: this.references(spec.request) },
        connection,
      ),
    );
  }
  arguments(spec: FunctionSpec, args: Record<string, string>): HttpRequestInput {
    return functionRequest(spec, args);
  }
}
