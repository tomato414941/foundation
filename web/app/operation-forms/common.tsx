import { useTranslation } from 'react-i18next';
import { Principal } from '../../../shared/contracts';
import type { OperationCall } from '../../../shared/operations';
import { api, ApiFailure } from '../api';
import { Detail } from '../components';
import { InputField } from '../form-fields';

export async function loadOwner(invocation: OperationCall, ownerId = String(invocation.input.ownerId)) {
  const owner = await api('/principals/' + ownerId, {}, Principal).catch(error => {
    if (error instanceof ApiFailure && error.status === 403) return { name: ownerId };
    throw error;
  });
  return { invocation, owner };
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
