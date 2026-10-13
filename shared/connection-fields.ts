import safeRegex from 'safe-regex2';
import { Template } from '@fedify/uri-template';
import type { ConnectionField } from './connection-methods.js';
import type { MethodDescription } from './contracts.js';

export class ConnectionFieldError extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}

export function activeConnectionField(field: ConnectionField, values: Record<string, string>) {
  return !field.when || values[field.when.field] === undefined || field.when.values.includes(values[field.when.field]!);
}

export function connectionFields(definitions: ConnectionField[], input: Record<string, string>, defaults = {}) {
  const reject = (code: string, message: string): never => { throw new ConnectionFieldError(code, message); };
  const values: Record<string, string> = { ...defaults, ...input };
  for (const field of definitions) if (values[field.name] === undefined && field.defaultValue !== undefined)
    values[field.name] = field.defaultValue;
  for (const field of definitions) {
    if (!activeConnectionField(field, values)) { delete values[field.name]; continue; }
    if (field.required !== false && !values[field.name]) reject('missing_field', 'Complete the required service fields.');
    if (values[field.name]?.includes('\0')) reject('invalid_field', 'Check the service fields.');
    if (field.choices && values[field.name] && !field.choices.some(choice => choice.value === values[field.name]))
      reject('invalid_field', 'Choose an available service setting.');
    if (field.pattern && (field.pattern.length > 200 || !safeRegex(field.pattern)))
      reject('invalid_pattern', 'Use a simple field validation pattern.');
    if (field.pattern && values[field.name] && !new RegExp(field.pattern, 'u').test(values[field.name]!.slice(0, 1000)))
      reject('invalid_field', 'Check the service fields.');
  }
  if (Object.keys(input).some(key => !definitions.some(field => field.name === key)))
    reject('invalid_field', 'Remove unrecognized service fields.');
  return values;
}

export function connectionValues(definitions: ConnectionField[], input: Record<string, string>, defaults = {}) {
  const values = connectionFields(definitions, input, defaults);
  const derived: Record<string, string> = {};
  for (const field of definitions) {
    const choice = field.choices?.find(choice => choice.value === values[field.name]);
    for (const [key, value] of Object.entries(choice?.values ?? {})) {
      if (definitions.some(definition => definition.name === key) || key in derived && derived[key] !== value)
        throw new ConnectionFieldError('invalid_field', 'Use distinct values for each service setting.');
      derived[key] = value;
    }
  }
  return { ...values, ...derived };
}

export function publicConnectionFields(definitions: ConnectionField[], input: Record<string, string>) {
  for (const [key, value] of Object.entries(input)) {
    const field = definitions.find(field => field.name === key);
    if (!field) throw new ConnectionFieldError('invalid_field', 'Use the fields declared by the connection method.');
    if (field.secret !== false && value !== '')
      throw new ConnectionFieldError('encrypted_input_required', 'Supply private material directly with your encryption keys.');
  }
  return connectionFields(definitions.map(field => ({ ...field, required: false, defaultValue: undefined })), input);
}

export function visibleConnectionFields(definitions: ConnectionField[], input: Record<string, string>) {
  return publicConnectionFields(definitions, Object.fromEntries(definitions
    .filter(field => field.secret === false && input[field.name])
    .map(field => [field.name, input[field.name]!])));
}

export function suppliedConnectionFields(definitions: ConnectionField[], prepared: Record<string, string>, supplied: Record<string, string>) {
  publicConnectionFields(definitions, prepared);
  for (const [key, value] of Object.entries(prepared)) if (value && supplied[key] !== undefined && supplied[key] !== value)
    throw new ConnectionFieldError('operation_changed', 'Use the service settings prepared by this operation.');
  return { ...prepared, ...supplied };
}

export function connectionConsole(method: MethodDescription, fields: Record<string, string> = {}) {
  const template = method.kind === 'token' ? method.config.console ?? method.console : method.console;
  if (!template) return undefined;
  try {
    if (!template.includes('{')) {
      const url = new URL(template);
      return ['https:', 'http:'].includes(url.protocol) ? url.href : undefined;
    }
    const definitions = method.kind === 'aws' ? [] : method.config.fields;
    const defaults = method.kind === 'oauth' ? method.config.defaults : {};
    const values = connectionValues(definitions.map(field => ({ ...field, required: false })), visibleConnectionFields(definitions, fields), defaults);
    if ([...template.matchAll(/\{[+#./;?&]?([^}]+)\}/g)].some(match => match[1]!.split(',').some(key => !values[key]))) return undefined;
    const url = new URL(new Template(template).expand(values));
    return ['https:', 'http:'].includes(url.protocol) ? url.href : undefined;
  } catch { return undefined; }
}
