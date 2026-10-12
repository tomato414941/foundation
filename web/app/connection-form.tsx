import { useTranslation } from 'react-i18next';
import { useState } from 'react';
import type { CatalogConnectionMethod } from '../../shared/contracts';
import type { ConnectionState } from '../../shared/connections';
import { ExternalLink, Notice } from './components';
import { connectionForm } from './connection-forms';
import { OAuthConnectionFields } from './oauth-connection-form';
import type { ConnectionFieldsProps } from './connection-fields';
import { connectionConsole } from '../../shared/connection-fields';
export { ConnectionPreparation, connectionInitialValues, connectionNeedsMaterial } from './connection-forms';

export function connectionFields(form: FormData): Record<string, string> {
  return Object.fromEntries([...form.entries()].filter(([key]) => key.startsWith('field.'))
    .map(([key, value]) => [key.slice(6), String(value)]));
}
export function connectionSettings(method: CatalogConnectionMethod, form: FormData, previous?: ConnectionState) {
  return { fields: connectionFields(form), ...connectionForm(method).settings?.(form, previous) };
}
export function ConnectionMethodHelp({ method, connecting = true }: { method?: CatalogConnectionMethod; connecting?: boolean }) {
  const { t } = useTranslation();
  const Help = method ? connectionForm(method).Help : undefined;
  return <>
    {Help && <Help method={method} />}
    {connecting && method?.registration.device === 'cli' && <Notice tone="info">
      <p>{t('connectionCliHelp')}</p>
      {method.registration.tokenAlternatives.length > 0 && <p className="mt-2">{t('connectionTokenAlternative')}</p>}
    </Notice>}
  </>;
}
export function ConnectionFields(props: ConnectionFieldsProps) {
  const { t } = useTranslation();
  const form = props.method ? connectionForm(props.method) : undefined;
  const Fields = form?.Fields ?? (props.purpose === 'app' && !props.method ? OAuthConnectionFields : undefined);
  const appId = props.selectedAppId ?? (props.existing?.kind === 'connection' ? props.existing.data.appId : props.apps[0]?.id);
  const app = props.apps.find(item => item.id === appId);
  const [fields, setFields] = useState<Record<string, string>>({
    ...(props.method?.kind === 'oauth' ? props.method.config.defaults : {}),
    ...props.appMaterial?.fields,
    ...(app?.kind === 'app' ? app.data.fields : {}),
    ...(props.existing?.kind === 'connection' ? props.existing.data.fields : {}),
    ...props.preparedFields,
  });
  const console = props.method ? connectionConsole(props.method, fields) : undefined;
  return <div className="flex min-w-0 flex-col gap-6">
    {Fields && <Fields {...props} fieldValues={fields} onFieldsChange={values => setFields(previous => ({ ...previous, ...values }))} />}
    {console && <ExternalLink href={console}>{t('serviceConsole')}</ExternalLink>}
  </div>;
}
