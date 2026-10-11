import { Template } from '@fedify/uri-template';
import { Command, HttpRequest } from './contracts.js';
import type { FunctionSpec, JsonValue, SourceReference } from './contracts.js';

export function functionArguments(spec: FunctionSpec, args: Record<string, JsonValue>) {
  const values: Record<string, JsonValue> = {};
  if (Object.keys(args).some(name => !spec.parameters.some(parameter => parameter.name === name)))
    throw new Error('Use the parameters this function declares.');
  for (const parameter of spec.parameters) {
    const value = Object.hasOwn(args, parameter.name) ? args[parameter.name] : parameter.default;
    if (value === undefined) {
      if (parameter.required) throw new Error('Complete the required function parameters.');
      continue;
    }
    if ((parameter.type !== 'json' && typeof value !== parameter.type) || (parameter.type === 'number' && !Number.isFinite(value)))
      throw new Error('Use the argument types this function declares.');
    if (parameter.required && parameter.type === 'string' && value === '') throw new Error('Complete the required function parameters.');
    if (JSON.stringify(value).length > 8192) throw new Error('The function argument is too long.');
    values[parameter.name] = value;
  }
  return values;
}

export function functionProgram(spec: FunctionSpec, args: Record<string, JsonValue>) {
  const values = functionArguments(spec, args);
  if (spec.program.kind === 'command') {
    const { kind, ...command } = spec.program;
    return { kind, ...Command.parse({ ...command, stdin: JSON.stringify(values) }) };
  }
  const request = spec.program.request;
  const text = (value: JsonValue) => typeof value === 'string' ? value : JSON.stringify(value);
  const substitute = (value: JsonValue, structured = false): JsonValue => {
    if (structured && typeof value === 'string') {
      const parameter = /^\{\{([A-Za-z][A-Za-z0-9_]*)\}\}$/.exec(value)?.[1];
      if (parameter) {
        if (!spec.parameters.some(item => item.name === parameter)) throw new Error('Declare every function parameter.');
        return Object.hasOwn(values, parameter) ? values[parameter]! : null;
      }
    }
    if (typeof value === 'string') return value.replace(/\{\{([A-Za-z][A-Za-z0-9_]*)\}\}/g, (_match, name: string) => {
      if (!spec.parameters.some(parameter => parameter.name === name)) throw new Error('Declare every function parameter.');
      return Object.hasOwn(values, name) ? text(values[name]!) : '';
    });
    if (Array.isArray(value)) return value.map(child => substitute(child, structured));
    if (value && typeof value === 'object')
      return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, substitute(child, structured)]));
    return value;
  };
  const url = new Template(request.url).expand(Object.fromEntries(Object.entries(values).map(([name, value]) => [name, text(value)])));
  const filled = HttpRequest.parse({
    ...(substitute(request as unknown as JsonValue) as Record<string, JsonValue>),
    url, bindings: request.bindings,
    ...(request.json === undefined ? {} : { json: substitute(request.json, true) }),
  });
  const fixed = new URL(request.url.replace(/\{[^}]+\}/g, 'placeholder'));
  if (new URL(url).origin !== fixed.origin) throw new Error('The function must have a fixed destination host.');
  return { kind: 'http' as const, request: filled };
}

export function functionSources(spec: FunctionSpec): SourceReference[] {
  return spec.program.kind === 'command' ? spec.program.inputs.map(input => input.source)
    : spec.program.request.bindings.flatMap(binding => binding.parts.filter((part): part is SourceReference => typeof part !== 'string'));
}
