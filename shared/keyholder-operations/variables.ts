import { ValueSave } from '../operations.js';
import { Resource } from '../contracts.js';
import type { JsonValue } from '../contracts.js';
import { encode } from '../encryption.js';
import type { KeyholderClient, KeyholderOperation } from './types.js';

export function variableOperation(client: KeyholderClient): KeyholderOperation {
  return { continue: async (plan, material) => {
    const destination = ValueSave.parse(plan.input);
    const previous = destination.resourceId ? await client.custody.latest(destination.resourceId) : undefined;
    if (previous && previous.version !== destination.version) throw new Error('This item changed. Reload it before saving.');
    if (material.value === undefined) throw new Error('Enter the value to save.');
    const bytes = typeof material.value === 'string' ? encode(material.value) : material.value;
    const resource = await client.custody.save({ id: destination.resourceId ?? crypto.randomUUID(), ownerId: destination.ownerId,
      kind: 'variable' }, destination.name, bytes, { previous,
      commit: async write => Resource.parse((await client.commit(plan, write as unknown as JsonValue)).result) });
    return { kind: 'saved' as const, resource, operationId: plan.id };
  } };
}
