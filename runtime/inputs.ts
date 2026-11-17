import { hash } from '../shared/authority.js';
import type { CustodyClient } from '../shared/client.js';
import type { InjectionInput, SourceReference } from '../shared/contracts.js';
import { validInputName } from '../shared/contracts.js';
import { ContentTypes, Operations, useContent } from '../shared/custody.js';
import type { ExecutionIntent } from '../shared/custody.js';
import { atPointer, textValue } from '../shared/values.js';
import { encode } from '../shared/encryption.js';
import type { Connections } from './connections.js';
import type { ConnectionOutputs } from './connection-provider.js';

export function utf8(value: Uint8Array) {
  return new TextDecoder('utf-8', { fatal: true }).decode(value);
}
// A resolved source says whether its connection method delivers it as a file when the input names no format.
export interface ResolvedSource { value: Uint8Array; file?: boolean }
export async function processInputs(
  inputs: InjectionInput[], resolve: (source: SourceReference) => Promise<ResolvedSource>,
) {
  const environment: Record<string, string> = {}, files: Record<string, string> = {}, sensitive: string[] = [];
  const names = new Set<string>();
  for (const input of inputs) {
    if (names.has(input.name) || !validInputName(input.name))
      throw new Error('Use distinct, unreserved environment variable names.');
    names.add(input.name);
    const resolved = await resolve(input.source), format = input.format ?? (resolved.file ? 'file' : 'text');
    let value = resolved.value;
    if (format === 'json') value = encode(textValue(atPointer(JSON.parse(utf8(value)), input.pointer ?? '')));
    if (format === 'file') files[input.name] = Buffer.from(value).toString('base64');
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

// Opens each input on this machine with the user's own keys; a connection renews its tokens here when they expire.
export async function openInputs(custody: CustodyClient, connections: Connections, inputs: InjectionInput[]) {
  const { binding, keys } = connections;
  const sources = await custody.sourceContents(inputs.map(input => input.source.id));
  const intent: ExecutionIntent = {
    format: 2, id: crypto.randomUUID(), origin: custody.origin, ownerId: binding.principalId,
    actor: binding, executor: binding, environmentId: binding.id, environmentDigest: await hash(binding),
    operation: Operations.command, functionDigest: null, operationDigest: await hash(inputs),
    sources: await Promise.all(sources.map(async content => ({ id: content.policy.id,
      policyDigest: await hash(content.policy), materialRevision: content.materialRevision,
      ...(content.policy.contentType === ContentTypes.tokenSet ? { authorizationDigest: String(content.metadata.authorizationDigest) } : {}),
    }))), resultRecipients: [binding], createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
  };
  const outputs = new Map<string, Promise<ConnectionOutputs>>();
  return processInputs(inputs, async source => {
    const content = sources.find(content => content.policy.id === source.id)!;
    if (content.policy.contentType === ContentTypes.value) return { value: await useContent(content, intent, keys) };
    if (!outputs.has(source.id)) outputs.set(source.id, connections.outputs(content, intent, sources, new AbortController().signal));
    const { values, files } = await outputs.get(source.id)!;
    if (!source.output || !Object.hasOwn(values, source.output)) throw new Error('Choose an available connection output.');
    return { value: encode(values[source.output]!), file: files.includes(source.output) };
  });
}
