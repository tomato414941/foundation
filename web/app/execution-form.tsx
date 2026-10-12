import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CatalogMethod, Principal, Resource, listOf } from '../../shared/contracts';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import type { DefinitionCall } from '../../shared/executions';
import type { PrivateOperationInput } from '../../shared/execution-client';
import type { ConnectionState } from '../../shared/connections';
import { api, formText, ApiFailure } from './api';
import { availableEnvironments, EnvironmentChoice } from './environments';
import { ConnectionFields, ConnectionMethodHelp, ConnectionPreparation, connectionSettings, connectionFields } from './connection-form';
import { InputField, TextareaField } from './form-fields';
import { Detail, JsonView } from './components';
import { connectionMethodName } from './connection-method-labels';
import { connectionMethod } from '../../shared/connection-methods';
import { visibleConnectionFields } from '../../shared/connection-fields';

export async function loadExecutionForm(invocation: DefinitionCall) {
  const ownerId = String(invocation.input.ownerId);
  const usesMethod = invocation.name === 'connection.connect' || invocation.name === 'app.save';
  const authorizing = invocation.name === 'connection.authorize';
  const [methods, owned, shared, owner, connection, users] = await Promise.all([
    usesMethod ? api('/connection-methods', {}, listOf(CatalogMethod)) : { items: [] },
    invocation.name === 'connection.connect' ? api('/principals/' + ownerId + '/resources?kind=app&limit=200', {}, listOf(Resource))
      .catch(error => { if (error instanceof ApiFailure && error.status === 403) return { items: [] }; throw error; }) : { items: [] },
    invocation.name === 'connection.connect' ? api('/resources/shared', {}, listOf(Resource)) : { items: [] },
    api('/principals/' + ownerId, {}, Principal).catch(error => {
      if (error instanceof ApiFailure && error.status === 403) return { name: ownerId };
      throw error;
    }),
    authorizing ? api('/resources/' + invocation.input.connectionId, {}, Resource) : null,
    authorizing ? Promise.all((Array.isArray(invocation.input.users) ? invocation.input.users : []).map(id =>
      api('/identities/' + String(id), {}, Principal.pick({ id: true, name: true, publicKey: true })))) : [],
  ]);
  const method = methods.items.find(item => item.id === invocation.input.methodId);
  const environments = method && !connectionMethod(method).requiresEnvironment || invocation.name === 'connection.authorize' ? [] : await availableEnvironments(ownerId);
  const preparedFields = invocation.input.fields as Record<string, string> | undefined;
  const apps = [...new Map([...owned.items, ...shared.items].filter(item => item.kind === 'app' &&
    item.data.methodId === invocation.input.methodId && item.permissions.includes('use') &&
    Object.entries(preparedFields ?? {}).every(([name, value]) => !value || item.data.fields[name] === value))
    .map(item => [item.id, item])).values()];
  return { invocation, environments, method, apps, owner, connection, users };
}
export type ExecutionFormData = Awaited<ReturnType<typeof loadExecutionForm>>;

export function connectionSubmission(input: DefinitionCall['input'], form: FormData, method: CatalogConnectionMethod, previous?: ConnectionState) {
  const settings = connectionSettings(method, form, previous);
  const appId = formText(form, 'appId');
  return { input: { ...input, name: input.name ?? (formText(form, 'name') || method.name),
    fields: { ...(input.fields as Record<string, string> | undefined), ...visibleConnectionFields(connectionMethod(method).fields, settings.fields) },
    ...(connectionMethod(method).requiresEnvironment ? { environmentId: input.environmentId ?? formText(form, 'environmentId') } : {}),
    ...(input.appId || (appId && appId !== 'new') ? { appId: input.appId ?? appId } : {}),
    ...(input.clientId || formText(form, 'clientId') ? { clientId: input.clientId ?? formText(form, 'clientId') } : {}) },
    material: { ...settings, clientSecret: formText(form, 'clientSecret') || undefined } };
}
export function executionSubmission(data: ExecutionFormData, form: FormData): { input: DefinitionCall['input']; material: PrivateOperationInput } {
  const { name, input } = data.invocation;
  if (name === 'connection.connect') {
    if (!data.method) throw new ApiFailure('invalid_input');
    return connectionSubmission(input, form, data.method);
  }
  if (name === 'variable.save' || name === 'app.save') {
    return { input: { ...input, name: input.name ?? formText(form, 'name'),
      environmentIds: input.environmentIds ?? form.getAll('environments').map(String),
      ...(name === 'app.save' ? { clientId: input.clientId || formText(form, 'clientId'),
        fields: { ...(input.fields as Record<string, string> | undefined), ...visibleConnectionFields(data.method ? connectionMethod(data.method).fields : [], connectionFields(form)) } } : {}) },
      material: { value: formText(form, 'value'), clientSecret: formText(form, 'clientSecret') || undefined,
        fields: connectionFields(form) } };
  }
  if (name === 'function.save' || name === 'connection.authorize') return { input, material: {} };
  return { input: { ...input, environmentId: input.environmentId ?? formText(form, 'environmentId') }, material: {} };
}

export function ExecutionInputFields({ data }: { data: ExecutionFormData }) {
  const { t } = useTranslation(), { name, input } = data.invocation;
  const definition = name === 'function.save' ? input.definition as { environmentId: string } : null;
  const [environmentId, setEnvironmentId] = useState(String(input.environmentId ?? definition?.environmentId ?? ''));
  const executor = data.environments.find(item => item.id === environmentId);
  const fixedEnvironment = typeof input.environmentId === 'string' && input.environmentId || definition?.environmentId;
  const usesEnvironment = ['run.execute', 'function.save', 'variable.save', 'app.save', 'connection.revoke'].includes(name) ||
    name === 'connection.connect' && !!data.method && connectionMethod(data.method).requiresEnvironment;
  const existing: ResourceView | null = null;
  return <div className="flex min-w-0 flex-col gap-6">
    <Detail label={t('owner')}>{data.owner.name}</Detail>
    {name === 'connection.authorize' && <>
      <Detail label={t('connectionName')}>{data.connection?.name}</Detail>
      <Detail label={t('authorizedUsers')}>{data.users.map(user => user.name).join(', ') || '—'}</Detail>
    </>}
    {input.name ? <Detail label={t('name')}>{String(input.name)}</Detail> : ['variable.save', 'app.save', 'function.save', 'connection.connect'].includes(name) &&
      <InputField name="name" label={t('name')} defaultValue={data.method?.name ?? ''} required />}
    {data.method && <Detail label={t('method')}>{connectionMethodName(data.method.name, t)}</Detail>}
    {name === 'connection.revoke' && <Detail label={t('connectionTarget')}>{String(input.connectionId)}</Detail>}
    {name === 'function.save' && <JsonView value={input.definition} />}
    {name === 'run.execute' && <JsonView value={input.operation} />}
    {name === 'variable.save' && <TextareaField name="value" label={t('value')} autoComplete="off" rows={5} required />}
    {(name === 'connection.connect' || name === 'app.save') && <>
      <ConnectionMethodHelp method={data.method} />
      <ConnectionFields purpose={name === 'app.save' ? 'app' : 'connection'} method={data.method}
        existing={existing} appMaterial={null} apps={data.apps} selectedAppId={typeof input.appId === 'string' ? input.appId : undefined}
        preparedFields={input.fields as Record<string, string> | undefined}
        preparedScopes={input.scopes as string[] | undefined}
        clientId={typeof input.clientId === 'string' && input.clientId ? input.clientId : undefined} />
    </>}
    {usesEnvironment && (Array.isArray(input.environmentIds) ? <Detail label={t('approvedExecutors')}>
      {input.environmentIds.map(id => data.environments.find(item => item.id === id)?.name ?? String(id)).join(', ') || '—'}
    </Detail> : fixedEnvironment ? <Detail label={t('executionDestination')}>
      {data.environments.find(item => item.id === fixedEnvironment)?.name ?? fixedEnvironment}
      <input type="hidden" name="environmentId" value={fixedEnvironment} />
    </Detail> : <EnvironmentChoice items={data.environments} multiple={name === 'variable.save' || name === 'app.save'}
      selected={Array.isArray(input.environmentIds) ? input.environmentIds.map(String) : []} onChange={setEnvironmentId} />)}
    <ConnectionPreparation method={name === 'connection.connect' ? data.method : undefined} newConnection={!input.connectionId} executor={executor} />
  </div>;
}
