import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Resource, listOf } from '../../shared/contracts';
import type { ResourceView } from '../../shared/contracts';
import { api, ApiFailure } from './api';
import { CheckboxField, SelectField } from './form-fields';
import { SelectItem } from './components/ui/select';
import { Notice, Panel } from './components';

export async function availableEnvironments(owner: string) {
  const [owned, shared] = await Promise.all([
    api('/principals/' + owner + '/resources?kind=environment&limit=200', {}, listOf(Resource)).catch(error => {
      if (error instanceof ApiFailure && error.status === 403) return { items: [] };
      throw error;
    }),
    api('/resources/shared', {}, listOf(Resource)),
  ]);
  return [...new Map([...owned.items, ...shared.items].filter(item => item.kind === 'environment' &&
    item.data.executorId && item.data.state === 'running' && item.permissions.includes('execute')).map(item => [item.id, item])).values()];
}
export function EnvironmentChoice({ items, selected, multiple = false }: {
  items: ResourceView[]; selected?: string[]; multiple?: boolean;
}) {
  const { t } = useTranslation();
  return <Panel title={t(multiple ? 'approvedExecutors' : 'executionDestination')}>
    <p className="text-sm leading-relaxed text-muted-foreground">{t(multiple ? 'executorDisclosure' : 'executorChoiceHelp')}</p>
    {!items.length && <Notice tone="info">{t('noExecutors')}</Notice>}
    {multiple ? items.map(item => <CheckboxField key={item.id} name="environments" value={item.id}
      label={item.name} defaultChecked={selected?.includes(item.id)} />) :
      <SelectField name="environmentId" label={t('singular.environment')} defaultValue={selected?.[0] ?? ''} required>
        {items.map(item => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}
      </SelectField>}
    <Link className="text-sm underline underline-offset-4" to="/account/trust">{t('trustIdentity')}</Link>
  </Panel>;
}
