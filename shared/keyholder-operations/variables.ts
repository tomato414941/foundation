import { ValueSave } from '../executions.js';
import { Resource } from '../contracts.js';
import type { JsonValue } from '../contracts.js';
import { ContentTypes } from '../custody.js';
import { encode } from '../encryption.js';
import type { KeyholderClient, KeyholderOperation } from './types.js';

export function variableOperation(client: KeyholderClient): KeyholderOperation {
  return { continue: async (plan, material) => {
    const id = plan.id, { input } = plan.invocation;

    const destination = ValueSave.parse(input);
    const previous = destination.resourceId ? await client.custody.read(destination.resourceId) : undefined;
    if (previous && previous.version !== destination.version) throw new Error('This item changed. Reload it before saving.');
    const environments = await Promise.all((destination.environmentIds ?? []).map(id => client.custody.environment(id)));
    const type = ContentTypes.value;
    if (previous && (previous.content.policy.contentType !== type || previous.content.policy.ownerId !== destination.ownerId))
      throw new Error('Choose the item prepared by this operation.');
    const policy = previous && destination.environmentIds === undefined ? previous.content.policy
      : await client.custody.policy(destination.ownerId, type, environments, { previous: previous?.content.policy });

    if (material.value === undefined) throw new Error('Enter the value to save.');
    const bytes = typeof material.value === 'string' ? encode(material.value) : material.value;
    const resource = await client.custody.save(destination.name, bytes, policy, { previous,
      commit: async write => Resource.parse((await client.complete(id, plan.index, write as unknown as JsonValue)).results[plan.index]) });
    return { kind: 'saved' as const, resource, executionId: id };
  } };
}
