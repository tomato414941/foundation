import type { DefinitionCall } from '../../shared/executions';
import { ApiFailure } from './api';
import { executionForms } from './execution-forms';

function formFor(invocation: DefinitionCall) {
  const form = executionForms.get(invocation.name);
  if (!form) throw new ApiFailure('operation_unavailable');
  return form;
}
export async function loadExecutionForm(invocation: DefinitionCall) {
  return { invocation, fields: await formFor(invocation).load(invocation) };
}
export type ExecutionFormData = Awaited<ReturnType<typeof loadExecutionForm>>;
export function executionSubmission(data: ExecutionFormData, form: FormData) {
  return formFor(data.invocation).submit(data.fields, form);
}
export function ExecutionInputFields({ data, requestPrincipalId }: { data: ExecutionFormData; requestPrincipalId?: string }) {
  const Fields = formFor(data.invocation).Fields;
  return <div className="flex min-w-0 flex-col gap-6"><Fields data={data.fields} requestPrincipalId={requestPrincipalId} /></div>;
}
