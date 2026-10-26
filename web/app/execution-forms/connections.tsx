import { useTranslation } from 'react-i18next';
import { CatalogMethod, Principal, Resource, listOf } from '../../../shared/contracts';
import type { CatalogConnectionMethod } from '../../../shared/contracts';
import type { DefinitionCall } from '../../../shared/executions';
import type { ConnectionState } from '../../../shared/connections';
import { api, formText, ApiFailure } from '../api';
import { ConnectionFields, ConnectionMethodHelp, ConnectionPreparation, connectionSettings, connectionFields } from '../connection-form';
import { Detail } from '../components';
import { ConnectionUsers } from '../connection-users';
import { connectionMethodName } from '../connection-method-labels';
import { connectionMethod } from '../../../shared/connection-methods';
import { visibleConnectionFields } from '../../../shared/connection-fields';
import { ConnectionMaterial } from '../../../shared/connections';
import { decode } from '../../../shared/encryption';
import { custodyClient } from '../custody';
import { connectionInitialValues } from '../connection-form';
import { defineForm } from './types';
import { EnvironmentFields, loadOwner, OwnerFields } from './common';

async function load(invocation: DefinitionCall) {
  const connecting = invocation.name === 'connection.connect', authorizing = invocation.name === 'connection.authorize';
  const base = await loadOwner(invocation, undefined, Array.isArray(invocation.input.environmentIds) && invocation.input.environmentIds.length > 0);
  const ownerId = String(invocation.input.ownerId);
  const [methods, owned, shared, connection, users] = await Promise.all([
    authorizing ? { items: [] } : api('/connection-methods', {}, listOf(CatalogMethod)),
    connecting ? api('/principals/' + ownerId + '/resources?kind=app&limit=200', {}, listOf(Resource))
      .catch(error => { if (error instanceof ApiFailure && error.status === 403) return { items: [] }; throw error; }) : { items: [] },
    connecting ? api('/resources/shared', {}, listOf(Resource)) : { items: [] },
    authorizing || connecting && invocation.input.connectionId ? api('/resources/' + invocation.input.connectionId, {}, Resource) : null,
    authorizing ? Promise.all((Array.isArray(invocation.input.users) ? invocation.input.users : []).map(id =>
      api('/identities/' + String(id), {}, Principal.pick({ id: true, name: true, publicKey: true })))) : [],
  ]);
  const method = methods.items.find(item => item.id === invocation.input.methodId);
  const preparedFields = invocation.input.fields as Record<string, string> | undefined;
  const apps = [...new Map([...owned.items, ...shared.items].filter(item => item.kind === 'app' &&
    item.data.methodId === invocation.input.methodId && item.permissions.includes('use') &&
    Object.entries(preparedFields ?? {}).every(([name, value]) => !value || item.data.fields[name] === value))
    .map(item => [item.id, item])).values()];
  const initial = connecting && connection ? connectionInitialValues(ConnectionMaterial.parse(JSON.parse(decode(await (await custodyClient()).reveal(connection.id))))) : undefined;
  return { ...base, method, apps, connection, users, initial };
}
type Data = Awaited<ReturnType<typeof load>>;
export function connectionSubmission(input: DefinitionCall['input'], form: FormData, method: CatalogConnectionMethod, previous?: ConnectionState) {
  const settings = connectionSettings(method, form, previous);
  const appId = formText(form, 'appId');
  return { input: { ...input, name: input.name ?? (formText(form, 'name') || method.defaultName),
    fields: { ...(input.fields as Record<string, string> | undefined), ...visibleConnectionFields(connectionMethod(method).fields, settings.fields) },
    ...(settings.scopes ? { scopes: input.scopes ?? settings.scopes } : {}),
    ...(input.appId || (appId && appId !== 'new') ? { appId: input.appId ?? appId } : {}),
    ...(input.clientId || formText(form, 'clientId') ? { clientId: input.clientId ?? formText(form, 'clientId') } : {}) },
    material: { ...settings, clientSecret: formText(form, 'clientSecret') || undefined } };
}

export const connectionForm = defineForm({ load,
  submit: (data: Data, form: FormData) => {
    const { name, input } = data.invocation;
    if (name === 'connection.authorize') return { input, material: {} };
    if (name === 'connection.connect') {
      if (!data.method) throw new ApiFailure('invalid_input');
      return connectionSubmission(input, form, data.method);
    }
    return { input: { ...input, name: input.name ?? formText(form, 'name'),
      environmentIds: input.environmentIds ?? form.getAll('environments').map(String),
      clientId: input.clientId || formText(form, 'clientId'),
      fields: { ...(input.fields as Record<string, string> | undefined), ...visibleConnectionFields(data.method ? connectionMethod(data.method).fields : [], connectionFields(form)) } },
      material: { clientSecret: formText(form, 'clientSecret') || undefined, fields: connectionFields(form) } };
  },
  Fields: ({ data, requestPrincipalId }: { data: Data; requestPrincipalId?: string }) => {
    const { t } = useTranslation(), { name, input } = data.invocation;
    const compact = !!requestPrincipalId && name === 'connection.connect';
    return <>
      {compact ? input.ownerId !== requestPrincipalId && <Detail label={t('owner')}>{data.owner.name}</Detail>
        : <OwnerFields data={data} name={name !== 'connection.authorize'} defaultName={data.method?.defaultName} />}
      {name === 'connection.authorize' ? <>
        <Detail label={t('connectionName')}>{data.connection?.name}</Detail>
        {requestPrincipalId ? <ConnectionUsers users={data.users} expiresAt={typeof input.expiresAt === 'string' ? input.expiresAt : undefined} />
          : <Detail label={t('authorizedUsers')}>{data.users.map(user => user.name).join(', ') || '—'}</Detail>}
      </> : <>
        {!compact && data.method && <Detail label={t('method')}>{connectionMethodName(data.method.name, t)}</Detail>}
        {(!compact || data.method?.registration.device === 'cli') && <ConnectionMethodHelp method={data.method} connecting={name === 'connection.connect'} />}
        <ConnectionFields purpose={name === 'app.save' ? 'app' : 'connection'} method={data.method}
          compact={compact}
          existing={data.connection} appMaterial={null} apps={data.apps}
          selectedAppId={typeof input.appId === 'string' ? input.appId : undefined}
          preparedFields={input.fields as Record<string, string> | undefined} preparedScopes={input.scopes as string[] | undefined}
          reusableFields={data.initial?.reusableFields}
          clientId={typeof input.clientId === 'string' && input.clientId ? input.clientId : undefined} />
        {Array.isArray(input.environmentIds) && input.environmentIds.length > 0 && <EnvironmentFields data={data} />}
        {name === 'connection.connect' && <ConnectionPreparation method={data.method} newConnection={!input.connectionId} initial={data.initial} />}
      </>}
    </>;
  },
});
