import { useTranslation } from 'react-i18next';
import type { CatalogConnectionMethod } from '../../shared/contracts';
import { selectScopes } from '../../shared/connection-methods';
import { ExternalLink, Notice } from './components';
import { TextareaField } from './form-fields';
import { ApplicationConnectionFields } from './application-connection-fields';
import { ServiceFields } from './connection-fields';
import type { ConnectionFieldsProps } from './connection-fields';

export function OvhConnectionHelp({ method }: { method?: CatalogConnectionMethod }) {
  const { t } = useTranslation();
  if (method?.kind !== 'ovh') return null;
  return <Notice tone="info">
    <p>{t('ovhApiRegionHelp')}</p>
    <p className="mt-2">{t(method.config.authorization === 'consumer_key' ? 'ovhBrowserHelp' : 'ovhApiKeysHelp')}</p>
    {method.docs && <ExternalLink href={method.docs}>{t('docs')}</ExternalLink>}
  </Notice>;
}
export function OvhConnectionFields(props: ConnectionFieldsProps) {
  const { t } = useTranslation(), { method, existing } = props;
  if (method?.kind !== 'ovh') return null;
  if (method.config.authorization === 'api_key') return props.purpose === 'connection'
    ? <ServiceFields {...props} method={method} fields={method.config.fields} /> : null;
  const scopes = selectScopes(method.config.scopes, props.preparedScopes ?? (existing?.kind === 'connection'
    ? existing.data.scopes : undefined));
  return <ApplicationConnectionFields {...props} identifierLabel="ovhApplicationKey" secretLabel="ovhApplicationSecret" secretRequired>
    <TextareaField name="scopes" label={t('ovhApiPermissions')} defaultValue={scopes.join('\n')} rows={5} readOnly={!!props.preparedScopes}
      hint={t('ovhApiPermissionsHelp')} />
  </ApplicationConnectionFields>;
}
