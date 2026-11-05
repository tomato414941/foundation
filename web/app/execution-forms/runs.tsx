import type { JsonValue } from '../../../shared/contracts';
import type { DefinitionCall } from '../../../shared/executions';
import { formText } from '../api';
import { defineForm } from './types';
import { EnvironmentFields, loadOwner, OwnerFields } from './common';
import type { OwnedForm } from './common';
import { reviewer, ReviewRows } from '../operation-review';
import type { ReviewRow } from '../operation-review';

type RunData = OwnedForm & { review: ReviewRow[] };
async function load(invocation: DefinitionCall): Promise<RunData> {
  const { name, input } = invocation;
  const rows = reviewer({ approver: null, principals: [], inspect: true, signal: new AbortController().signal });
  const [owned, review] = await Promise.all([loadOwner(invocation, undefined, true),
    rows(name === 'connection.revoke' ? { connectionId: input.connectionId ?? null } : input.operation as Record<string, JsonValue>)]);
  return { ...owned, review };
}
export const runForm = defineForm({ load,
  submit: (data: RunData, form: FormData) => ({ input: { ...data.invocation.input,
    environmentId: data.invocation.input.environmentId ?? formText(form, 'environmentId') }, material: {} }),
  Fields: ({ data }: { data: RunData }) => <><OwnerFields data={data} />
    <ReviewRows rows={data.review} />
    <EnvironmentFields data={data} />
  </>,
});
