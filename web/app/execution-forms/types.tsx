import type { ReactNode } from 'react';
import type { DefinitionCall } from '../../../shared/executions';
import type { PrivateOperationInput } from '../../../shared/execution-client';

export interface Submission { input: DefinitionCall['input']; material: PrivateOperationInput; }
interface OperationForm<T> {
  load(invocation: DefinitionCall): Promise<T>;
  submit(data: T, form: FormData): Submission;
  Fields(props: { data: T }): ReactNode;
}
export interface RegisteredForm {
  load(invocation: DefinitionCall): Promise<unknown>;
  submit(data: unknown, form: FormData): Submission;
  Fields(props: { data: unknown }): ReactNode;
}
export function defineForm<T>(form: OperationForm<T>): RegisteredForm {
  return { load: form.load, submit: (data, values) => form.submit(data as T, values),
    Fields: ({ data }) => <form.Fields data={data as T} /> };
}
