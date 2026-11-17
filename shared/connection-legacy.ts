import { z } from 'zod';
import { MethodDefinition } from './contracts.js';
import { ConnectionMaterial } from './connections.js';
import { decode } from './encryption.js';

// Connections were once sealed with the method they were made with, and with the display name of their account. This
// reads one as connections are used now, so that its owner's device can seal it again without them, naming in the signed
// metadata the rules it was approved with, or change it before then. It lives in its own file so that it can be removed
// once production holds none.
const Named = z.object({ accountName: z.string().optional() }).passthrough();
// The method it was made with, without the HTTP settings that methods no longer have.
const EarlierMethod = z.preprocess(value => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  const { http: _http, ...method } = value as Record<string, unknown>;
  return method;
}, MethodDefinition);
const Earlier = z.object({ format: z.literal(2), methodId: z.string().min(1), method: EarlierMethod,
  oauth: Named.optional(), facts: Named.optional() }).passthrough();
const unnamed = (value?: z.infer<typeof Named>) => {
  if (!value) return {};
  const { accountName: _accountName, ...rest } = value;
  return rest;
};
export function earlierConnection(bytes: Uint8Array) {
  const { format: _format, oauth, facts, ...earlier } = Earlier.parse(JSON.parse(decode(bytes)));
  return ConnectionMaterial.parse({ ...earlier, format: 3, ...(oauth ? { oauth: unnamed(oauth) } : {}),
    ...(facts ? { facts: unnamed(facts) } : {}) });
}
