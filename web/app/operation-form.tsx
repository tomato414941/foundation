import type { OperationCall } from '../../shared/operations';
import { ApiFailure } from './api';
import { operationForms } from './operation-forms';

function formFor(invocation: OperationCall) {
  const form = operationForms.get(invocation.name);
  if (!form) throw new ApiFailure('operation_unavailable');
  return form;
}
export async function loadOperationForm(invocation: OperationCall) {
  return { invocation, fields: await formFor(invocation).load(invocation) };
}
export type OperationFormData = Awaited<ReturnType<typeof loadOperationForm>>;
export function operationSubmission(data: OperationFormData, form: FormData) {
  return formFor(data.invocation).submit(data.fields, form);
}
export function OperationInputFields({ data, requestPrincipalId }: { data: OperationFormData; requestPrincipalId?: string }) {
  const Fields = formFor(data.invocation).Fields;
  return <div className="flex min-w-0 flex-col gap-6"><Fields data={data.fields} requestPrincipalId={requestPrincipalId} /></div>;
}
