import type { ComponentType } from 'react';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import type { ConnectionState } from '../../shared/connections';
import type { ConnectionFamily } from '../../shared/connection-methods';
import { connectionMethod } from '../../shared/connection-methods';
import { AwsConnectionForm, awsConnectionSettings, awsFormValues } from './aws-connection-form';
import { OAuthConnectionFields, OAuthConnectionHelp } from './oauth-connection-form';
import { ServiceFields } from './connection-fields';
import type { ConnectionFieldsProps } from './connection-fields';
import { formText } from './api';

export interface ConnectionPreparationProps {
  method?: CatalogConnectionMethod;
  initial?: { aws: ReturnType<typeof awsFormValues> };
  newConnection: boolean;
  executor?: ResourceView;
}
interface ConnectionForm {
  Fields?: ComponentType<ConnectionFieldsProps>;
  Help?: ComponentType<{ method?: CatalogConnectionMethod }>;
  Preparation?: ComponentType<ConnectionPreparationProps & { active: boolean }>;
  settings?(form: FormData, previous?: ConnectionState): { scopes?: string[]; aws?: ReturnType<typeof awsConnectionSettings> };
  needsMaterial?(form: FormData): boolean;
  console(method: CatalogConnectionMethod): string | undefined;
}
const forms: Record<ConnectionFamily, ConnectionForm> = {
  oauth: { Fields: OAuthConnectionFields, Help: OAuthConnectionHelp, console: method => method.console,
    settings: form => form.has('scopes') ? { scopes: formText(form, 'scopes').split(/\s+/).filter(Boolean) } : {} },
  token: { Fields: ({ purpose, method, existing, appMaterial }) => purpose === 'connection' && method?.kind === 'token'
    ? <ServiceFields method={method} fields={method.config.fields} existing={existing} appMaterial={appMaterial} /> : null,
    console: method => method.kind === 'token' ? method.config.console ?? method.console : method.console },
  aws: { console: method => method.console,
    Preparation: ({ active, initial, newConnection, executor }) => <AwsConnectionForm active={active}
      initial={initial?.aws} newConnection={newConnection} executor={executor} />,
    settings: (form, previous) => ({ aws: awsConnectionSettings(form, previous?.aws) }),
    needsMaterial: form => formText(form, 'awsAuthentication') !== 'environment' &&
      (!formText(form, 'awsSecretAccessKey') || (formText(form, 'awsAuthentication') === 'session' && !formText(form, 'awsSessionToken'))),
  },
};

export function connectionForm(method: CatalogConnectionMethod) { return forms[connectionMethod(method).family]; }
export function connectionNeedsMaterial(method: CatalogConnectionMethod, form: FormData) {
  return connectionForm(method).needsMaterial?.(form) ?? false;
}
export function connectionInitialValues(state: ConnectionState) { return { aws: awsFormValues(state) }; }
export function ConnectionPreparation(props: ConnectionPreparationProps) {
  const family = props.method ? connectionMethod(props.method).family : undefined;
  return Object.entries(forms).map(([key, form]) => form.Preparation
    ? <form.Preparation key={key} {...props} active={family === key} /> : null);
}
