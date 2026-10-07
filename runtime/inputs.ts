import type { InjectionInput, SourceReference } from '../shared/contracts.js';
import { atPointer, textValue } from '../shared/values.js';
import { encode } from '../shared/encryption.js';

export function utf8(value: Uint8Array) {
  return new TextDecoder('utf-8', { fatal: true }).decode(value);
}
export async function processInputs(
  inputs: InjectionInput[], resolve: (source: SourceReference) => Promise<Uint8Array>,
) {
  const environment: Record<string, string> = {}, files: Record<string, string> = {}, sensitive: string[] = [];
  const names = new Set<string>();
  for (const input of inputs) {
    if (names.has(input.name) ||
      /^(FOUNDATION_|LD_|DYLD_)|^(NODE_OPTIONS|BASH_ENV|ENV|PYTHONSTARTUP|GIT_CONFIG_COUNT|GIT_CONFIG_SYSTEM)$/u.test(input.name))
      throw new Error('Use distinct, unreserved environment variable names.');
    names.add(input.name);
    let value = await resolve(input.source);
    if (input.format === 'json') value = encode(textValue(atPointer(JSON.parse(utf8(value)), input.pointer ?? '')));
    if (input.format === 'file') files[input.name] = Buffer.from(value).toString('base64');
    else {
      const text = utf8(value);
      if (text.includes('\0')) throw new Error('Use a file to pass binary content.');
      environment[input.name] = text;
    }
    sensitive.push(Buffer.from(value).toString('utf8'), Buffer.from(value).toString('base64'),
      Buffer.from(value).toString('base64url'));
  }
  return { environment, files, sensitive };
}
