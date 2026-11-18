import type { ReactNode } from 'react';
import type { OperationCall } from '../../../shared/operations';
import type { PrivateOperationInput } from '../../../shared/operation-client';

export interface Submission { input: OperationCall['input']; material: PrivateOperationInput; }
interface OperationForm<T> {
  load(invocation: OperationCall): Promise<T>;
  submit(data: T, form: FormData): Submission;
  Fields(props: { data: T; requestPrincipalId?: string }): ReactNode;
}
export interface RegisteredForm {
  load(invocation: OperationCall): Promise<unknown>;
  submit(data: unknown, form: FormData): Submission;
  Fields(props: { data: unknown; requestPrincipalId?: string }): ReactNode;
}
export function defineForm<T>(form: OperationForm<T>): RegisteredForm {
  return { load: form.load, submit: (data, values) => form.submit(data as T, values),
    Fields: ({ data, requestPrincipalId }) => <form.Fields data={data as T} requestPrincipalId={requestPrincipalId} /> };
}
