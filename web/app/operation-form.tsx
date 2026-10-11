import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CatalogMethod, Principal, Resource, listOf } from '../../shared/contracts';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import type { OperationInvocation } from '../../shared/operations';
import type { PrivateOperationInput } from '../../shared/operation-client';
import type { ConnectionState } from '../../shared/connections';
import { api, formText, ApiFailure } from './api';
import { availableEnvironments, EnvironmentChoice } from './environments';
import { ConnectionFields, ConnectionMethodHelp, ConnectionPreparation, connectionSettings, connectionFields } from './connection-form';
import { InputField, TextareaField } from './form-fields';
import { Detail, JsonView } from './components';
import { connectionMethodName } from './connection-method-labels';

export async function loadOperationForm(invocation: OperationInvocation) {
  const ownerId = String(invocation.input.ownerId);
  const usesMethod = invocation.name === 'connection.connect' || invocation.name === 'app.save';
  const [environments, methods, owned, shared, owner] = await Promise.all([
    invocation.name === 'function.save' ? [] : availableEnvironments(ownerId),
    usesMethod ? api('/connection-methods', {}, listOf(CatalogMethod)) : { items: [] },
    invocation.name === 'connection.connect' ? api('/principals/' + ownerId + '/resources?kind=app&limit=200', {}, listOf(Resource))
      .catch(error => { if (error instanceof ApiFailure && error.status === 403) return { items: [] }; throw error; }) : { items: [] },
    invocation.name === 'connection.connect' ? api('/resources/shared', {}, listOf(Resource)) : { items: [] },
    api('/principals/' + ownerId, {}, Principal).catch(error => {
      if (error instanceof ApiFailure && error.status === 403) return { name: ownerId };
      throw error;
    }),
  ]);
  const method = methods.items.find(item => item.id === invocation.input.methodId);
  const apps = [...new Map([...owned.items, ...shared.items].filter(item => item.kind === 'app' &&
    item.data.methodId === invocation.input.methodId && item.permissions.includes('use')).map(item => [item.id, item])).values()];
  return { invocation, environments, method, apps, owner };
}
export type OperationFormData = Awaited<ReturnType<typeof loadOperationForm>>;

export function connectionSubmission(input: OperationInvocation['input'], form: FormData, method: CatalogConnectionMethod, previous?: ConnectionState) {
  const settings = connectionSettings(method, form, previous);
  const appId = formText(form, 'appId');
  return { input: { ...input, name: input.name ?? (formText(form, 'name') || method.name),
    environmentId: input.environmentId ?? formText(form, 'environmentId'),
    ...(input.appId || (appId && appId !== 'new') ? { appId: input.appId ?? appId } : {}),
    ...(input.clientId || formText(form, 'clientId') ? { clientId: input.clientId ?? formText(form, 'clientId') } : {}) },
    material: { ...settings, clientSecret: formText(form, 'clientSecret') || undefined } };
}
export function operationSubmission(data: OperationFormData, form: FormData): { input: OperationInvocation['input']; material: PrivateOperationInput } {
  const { name, input } = data.invocation;
  if (name === 'connection.connect') {
    if (!data.method) throw new ApiFailure('invalid_input');
    return connectionSubmission(input, form, data.method);
  }
  if (name === 'variable.save' || name === 'app.save') {
    return { input: { ...input, name: input.name ?? formText(form, 'name'),
      environmentIds: input.environmentIds ?? form.getAll('environments').map(String),
      ...(name === 'app.save' ? { clientId: input.clientId || formText(form, 'clientId') } : {}) },
      material: { value: formText(form, 'value'), clientSecret: formText(form, 'clientSecret') || undefined,
        fields: connectionFields(form) } };
  }
  if (name === 'function.save') return { input, material: {} };
  return { input: { ...input, environmentId: input.environmentId ?? formText(form, 'environmentId') }, material: {} };
}

export function OperationInputFields({ data }: { data: OperationFormData }) {
  const { t } = useTranslation(), { name, input } = data.invocation;
  const [environmentId, setEnvironmentId] = useState(String(input.environmentId ?? ''));
  const executor = data.environments.find(item => item.id === environmentId);
  const fixedEnvironment = typeof input.environmentId === 'string' && input.environmentId;
  const existing: ResourceView | null = null;
  return <div className="flex min-w-0 flex-col gap-6">
    <Detail label={t('owner')}>{data.owner.name}</Detail>
    {input.name ? <Detail label={t('name')}>{String(input.name)}</Detail> : name !== 'run.execute' &&
      <InputField name="name" label={t('name')} defaultValue={data.method?.name ?? ''} required />}
    {data.method && <Detail label={t('method')}>{connectionMethodName(data.method.name, t)}</Detail>}
    {name === 'run.execute' && <JsonView value={input.operation} />}
    {name === 'function.save' && <JsonView value={input.definition} />}
    {name === 'variable.save' && <TextareaField name="value" label={t('value')} autoComplete="off" rows={5} required />}
    {(name === 'connection.connect' || name === 'app.save') && <>
      <ConnectionMethodHelp method={data.method} />
      <ConnectionFields purpose={name === 'app.save' ? 'app' : 'connection'} method={data.method}
        existing={existing} appMaterial={null} apps={data.apps} selectedAppId={typeof input.appId === 'string' ? input.appId : undefined}
        clientId={typeof input.clientId === 'string' && input.clientId ? input.clientId : undefined} />
    </>}
    {name === 'function.save' ? null : Array.isArray(input.environmentIds) ? <Detail label={t('approvedExecutors')}>
      {input.environmentIds.map(id => data.environments.find(item => item.id === id)?.name ?? String(id)).join(', ') || '—'}
    </Detail> : fixedEnvironment ? <Detail label={t('executionDestination')}>
      {data.environments.find(item => item.id === fixedEnvironment)?.name ?? fixedEnvironment}
      <input type="hidden" name="environmentId" value={fixedEnvironment} />
    </Detail> : <EnvironmentChoice items={data.environments} multiple={name === 'variable.save' || name === 'app.save'}
      selected={Array.isArray(input.environmentIds) ? input.environmentIds.map(String) : []} onChange={setEnvironmentId} />}
    <ConnectionPreparation method={name === 'connection.connect' ? data.method : undefined} newConnection={!input.connectionId} executor={executor} />
  </div>;
}
