import { useTranslation } from 'react-i18next';
import type { CatalogConnectionMethod } from '../../shared/contracts';
import type { ConnectionState } from '../../shared/connections';
import { ExternalLink } from './components';
import { connectionForm } from './connection-forms';
import { OAuthConnectionFields } from './oauth-connection-form';
import type { ConnectionFieldsProps } from './connection-fields';
export { ConnectionPreparation, connectionInitialValues, connectionNeedsMaterial } from './connection-forms';

export function connectionFields(form: FormData): Record<string, string> {
  return Object.fromEntries([...form.entries()].filter(([key]) => key.startsWith('field.'))
    .map(([key, value]) => [key.slice(6), String(value)]));
}
export function connectionSettings(method: CatalogConnectionMethod, form: FormData, previous?: ConnectionState) {
  return { fields: connectionFields(form), ...connectionForm(method).settings?.(form, previous) };
}
export function ConnectionMethodHelp({ method }: { method?: CatalogConnectionMethod }) {
  const Help = method ? connectionForm(method).Help : undefined;
  return Help ? <Help method={method} /> : null;
}
export function ConnectionFields(props: ConnectionFieldsProps) {
  const { t } = useTranslation();
  const form = props.method ? connectionForm(props.method) : undefined;
  const Fields = form?.Fields ?? (props.purpose === 'app' && !props.method ? OAuthConnectionFields : undefined);
  const console = props.method ? form?.console(props.method) : undefined;
  return <div className="flex min-w-0 flex-col gap-6">
    {Fields && <Fields {...props} />}
    {console && <ExternalLink href={console}>{t('serviceConsole')}</ExternalLink>}
  </div>;
}
