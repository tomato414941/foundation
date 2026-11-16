import { Resource } from '../../../shared/contracts';
import type { JsonValue } from '../../../shared/contracts';
import { RunOperation } from '../../../shared/executions';
import type { DefinitionCall } from '../../../shared/executions';
import { api, ApiFailure, formText } from '../api';
import { defineForm } from './types';
import { EnvironmentFields, loadOwner, OwnerFields } from './common';
import type { OwnedForm } from './common';
import { reviewer, ReviewRows } from '../operation-review';
import type { ReviewRow, ReviewValue } from '../operation-review';

// Where a run keeps the values of its result, by their JSON pointers: in a new variable by the name it is given, or in
// a variable its owner has, whose current value it replaces.
async function destinations(input: DefinitionCall['input']): Promise<ReviewRow[]> {
  const save = RunOperation.shape.save.parse(input.save), names = RunOperation.shape.names.parse(input.names);
  const rows = await Promise.all(Object.entries(save).map(async ([pointer, id]): Promise<ReviewRow> => {
    if (Object.hasOwn(names, pointer)) return { field: pointer, literal: true, value: { kind: 'newVariable', name: names[pointer]! } };
    const resource = await api('/resources/' + id, {}, Resource).catch(error => {
      if (error instanceof ApiFailure && [403, 404].includes(error.status)) return null;
      throw error;
    });
    const value: ReviewValue = !resource ? { kind: 'unknown', id }
      : resource.kind === 'variable' && resource.ownerId === input.ownerId ? { kind: 'replacedValue', resource } : { kind: 'resource', resource };
    return { field: pointer, literal: true, value };
  }));
  return rows.length ? [{ field: 'save', value: { kind: 'group', rows } }] : [];
}

type RunData = OwnedForm & { review: ReviewRow[] };
async function load(invocation: DefinitionCall): Promise<RunData> {
  const { name, input } = invocation;
  const rows = reviewer({ approver: null, principals: [], inspect: true, signal: new AbortController().signal });
  const [owned, review, kept] = await Promise.all([loadOwner(invocation, undefined, true),
    rows(name === 'connection.revoke' ? { connectionId: input.connectionId ?? null } : input.operation as Record<string, JsonValue>),
    name === 'run.execute' ? destinations(input) : []]);
  return { ...owned, review: [...review, ...kept] };
}
export const runForm = defineForm({ load,
  submit: (data: RunData, form: FormData) => ({ input: { ...data.invocation.input,
    environmentId: data.invocation.input.environmentId ?? formText(form, 'environmentId') }, material: {} }),
  Fields: ({ data }: { data: RunData }) => <><OwnerFields data={data} />
    <ReviewRows rows={data.review} />
    <EnvironmentFields data={data} />
  </>,
});
