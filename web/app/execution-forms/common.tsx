import { useTranslation } from 'react-i18next';
import { Principal } from '../../../shared/contracts';
import type { ResourceView } from '../../../shared/contracts';
import type { DefinitionCall } from '../../../shared/executions';
import { api, ApiFailure } from '../api';
import { availableEnvironments, EnvironmentChoice } from '../environments';
import { Detail } from '../components';
import { InputField } from '../form-fields';

export async function loadOwner(invocation: DefinitionCall, ownerId = String(invocation.input.ownerId), environments = false) {
  const [owner, choices] = await Promise.all([
    api('/principals/' + ownerId, {}, Principal).catch(error => {
      if (error instanceof ApiFailure && error.status === 403) return { name: ownerId };
      throw error;
    }), environments ? availableEnvironments(ownerId) : [],
  ]);
  return { invocation, owner, environments: choices };
}
export type OwnedForm = Awaited<ReturnType<typeof loadOwner>>;
export function OwnerFields({ data, name = false, defaultName = '' }: { data: OwnedForm; name?: boolean; defaultName?: string }) {
  const { t } = useTranslation(), input = data.invocation.input;
  return <>
    <Detail label={t('owner')}>{data.owner.name}</Detail>
    {input.name ? <Detail label={t('name')}>{String(input.name)}</Detail> : name &&
      <InputField name="name" label={t('name')} defaultValue={defaultName} required />}
  </>;
}
export function EnvironmentFields({ data }: { data: OwnedForm }) {
  const { t } = useTranslation(), input = data.invocation.input;
  if (Array.isArray(input.environmentIds)) return <Detail label={t('approvedExecutors')}>
    {input.environmentIds.map(id => data.environments.find(item => item.id === id)?.name ?? String(id)).join(', ') || '—'}
  </Detail>;
  if (typeof input.environmentId === 'string' && input.environmentId) return <Detail label={t('executionDestination')}>
    {data.environments.find((item: ResourceView) => item.id === input.environmentId)?.name ?? input.environmentId}
    <input type="hidden" name="environmentId" value={input.environmentId} />
  </Detail>;
  return <EnvironmentChoice items={data.environments} />;
}
