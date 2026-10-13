import type { ComponentType } from 'react';
import type { CatalogConnectionMethod } from '../../shared/contracts';
import type { ConnectionState } from '../../shared/connections';
import type { ConnectionFamily } from '../../shared/connection-methods';
import { connectionMethod } from '../../shared/connection-methods';
import { AwsConnectionForm, awsConnectionSettings, awsFormValues } from './aws-connection-form';
import { OAuthConnectionFields, OAuthConnectionHelp } from './oauth-connection-form';
import { OvhConnectionFields, OvhConnectionHelp } from './ovh-connection-form';
import { ServiceFields } from './connection-fields';
import type { ConnectionFieldsProps } from './connection-fields';
import { formText } from './api';
import { Notice } from './components';
import { useTranslation } from 'react-i18next';

export interface ConnectionPreparationProps {
  method?: CatalogConnectionMethod;
  initial?: { aws: ReturnType<typeof awsFormValues> };
  newConnection: boolean;
}
interface ConnectionForm {
  Fields?: ComponentType<ConnectionFieldsProps>;
  Help?: ComponentType<{ method?: CatalogConnectionMethod; connecting?: boolean }>;
  Preparation?: ComponentType<ConnectionPreparationProps & { active: boolean }>;
  settings?(form: FormData, previous?: ConnectionState): { scopes?: string[]; aws?: ReturnType<typeof awsConnectionSettings> };
  needsMaterial?(form: FormData): boolean;
}
const forms: Record<ConnectionFamily, ConnectionForm> = {
  approval: { Help: () => {
    const { t } = useTranslation();
    return <Notice tone="info">{t('runpodApprovalHelp')}</Notice>;
  } },
  oauth: { Fields: OAuthConnectionFields, Help: OAuthConnectionHelp,
    settings: form => form.has('scopes') ? { scopes: formText(form, 'scopes').split(/\s+/).filter(Boolean) } : {} },
  token: { Fields: props => props.purpose === 'connection' && props.method?.kind === 'token'
    ? <ServiceFields {...props} method={props.method} fields={props.method.config.fields} /> : null },
  ovh: { Fields: OvhConnectionFields, Help: OvhConnectionHelp,
    settings: form => form.has('scopes') ? { scopes: formText(form, 'scopes').split(/\r?\n/).map(scope => scope.trim()).filter(Boolean) } : {} },
  aws: {
    Preparation: ({ active, initial, newConnection }) => <AwsConnectionForm active={active}
      initial={initial?.aws} newConnection={newConnection} />,
    settings: (form, previous) => ({ aws: awsConnectionSettings(form, previous?.aws) }),
    needsMaterial: form => formText(form, 'awsAuthentication') !== 'environment' &&
      (!formText(form, 'awsSecretAccessKey') || (formText(form, 'awsAuthentication') === 'session' && !formText(form, 'awsSessionToken'))),
  },
};

export function connectionForm(method: CatalogConnectionMethod) { return forms[connectionMethod(method).family]; }
export function connectionNeedsMaterial(method: CatalogConnectionMethod, form: FormData) {
  return connectionForm(method).needsMaterial?.(form) ?? false;
}
export function connectionInitialValues(state: ConnectionState) { return { aws: awsFormValues(state),
  reusableFields: Object.entries(state.fields ?? {}).filter(([, value]) => value).map(([name]) => name) }; }
export function ConnectionPreparation(props: ConnectionPreparationProps) {
  const family = props.method ? connectionMethod(props.method).family : undefined;
  return Object.entries(forms).map(([key, form]) => form.Preparation
    ? <form.Preparation key={key} {...props} active={family === key} /> : null);
}
