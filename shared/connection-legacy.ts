import { z } from 'zod';
import { MethodDefinition } from './contracts.js';
import { ConnectionMaterial } from './connections.js';
import { decode } from './encryption.js';

// Connections were once sealed with the method they were made with. This reads one as connections are used now, so that
// its owner's device can seal it again without the method, naming in the signed metadata the rules it was approved with.
// It lives in its own file so that it can be removed once production holds none.
const Earlier = z.object({ format: z.literal(2), methodId: z.string().min(1), method: MethodDefinition }).passthrough();
export function earlierConnection(bytes: Uint8Array) {
  const { format: _format, ...earlier } = Earlier.parse(JSON.parse(decode(bytes)));
  return ConnectionMaterial.parse({ ...earlier, format: 3 });
}
