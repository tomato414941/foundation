import { Template } from '@fedify/uri-template';
import type { FunctionSpec, HttpRequestInput, JsonValue } from './contracts.js';
import { HttpRequest } from './contracts.js';

export function functionRequest(spec: FunctionSpec, args: Record<string, string>): HttpRequestInput {
  const values: Record<string, string> = {};
  if (Object.keys(args).some(name => !spec.parameters.some(parameter => parameter.name === name)))
    throw new Error('Use the parameters this function declares.');
  for (const parameter of spec.parameters) {
    const value = args[parameter.name] ?? parameter.default ?? '';
    if (parameter.required && !value) throw new Error('Complete the required function parameters.');
    if (value.length > 8192) throw new Error('The function argument is too long.');
    values[parameter.name] = value;
  }
  const substitute = (value: JsonValue): JsonValue => {
    if (typeof value === 'string') return value.replace(/\{\{([A-Za-z][A-Za-z0-9_]*)\}\}/g, (_match, name: string) => {
      if (!Object.hasOwn(values, name)) throw new Error('Declare every function parameter.');
      return values[name]!;
    });
    if (Array.isArray(value)) return value.map(substitute);
    if (value && typeof value === 'object')
      return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, substitute(child)]));
    return value;
  };
  const url = new Template(spec.request.url).expand(values);
  const result = HttpRequest.parse({
    ...(substitute(spec.request as unknown as JsonValue) as Record<string, JsonValue>), url,
    bindings: spec.request.bindings,
  });
  const fixed = new URL(spec.request.url.replace(/\{[^}]+\}/g, 'placeholder'));
  if (new URL(url).origin !== fixed.origin) throw new Error('The function must have a fixed destination host.');
  return result;
}
