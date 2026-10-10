import { useTranslation } from 'react-i18next';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import type { AppState, ConnectionState } from '../../shared/connections';
import { connectionMethod } from '../../shared/connection-methods';
import { formText } from './api';
import { AwsRoleForm, awsRoleSettings } from './aws-role-form';
import { ExternalLink, Notice } from './components';
import { SelectItem } from './components/ui/select';
import { InputField, SelectField } from './form-fields';
import { serviceLabels } from './service-labels';

interface OAuthPreparation {
  instructions: string[];
  scopes: boolean;
  docs?: boolean;
}
const oauthPreparations: Array<{ matches(method: CatalogConnectionMethod): boolean; preparation: OAuthPreparation }> = [
  { matches: method => method.id === 'shopify:client_credentials',
    preparation: { instructions: ['shopifyClientCredentialsHelp'], scopes: false } },
  { matches: method => method.id.startsWith('ovh:'),
    preparation: { instructions: ['ovhApiRegionHelp', 'ovhClientCredentialsHelp'], scopes: true, docs: true } },
];
function preparation(method: CatalogConnectionMethod): OAuthPreparation {
  if (method.kind === 'oauth' && !connectionMethod(method).browserAuthorization) {
    const selected = oauthPreparations.find(item => item.matches(method));
    if (selected) return selected.preparation;
  }
  return { instructions: [], scopes: true };
}

export function connectionFields(form: FormData): Record<string, string> {
  return Object.fromEntries([...form.entries()].filter(([key]) => key.startsWith('field.'))
    .map(([key, value]) => [key.slice(6), String(value)]));
}
export function connectionSettings(method: CatalogConnectionMethod, form: FormData): {
  fields: Record<string, string>; scopes?: string[]; role?: ConnectionState['role'];
} {
  return {
    fields: connectionFields(form),
    ...(method.kind === 'role' ? { role: awsRoleSettings(form) } : {}),
    ...(form.has('scopes') ? { scopes: formText(form, 'scopes').split(/\s+/).filter(Boolean) } : {}),
  };
}

export function ConnectionMethodHelp({ method }: { method?: CatalogConnectionMethod }) {
  const { t } = useTranslation();
  if (method?.kind !== 'oauth') return null;
  const direct = !connectionMethod(method).browserAuthorization;
  const setup = preparation(method);
  return <>
    <p className="text-sm text-muted-foreground">
      OAuth 2.0 / {direct ? 'Client Credentials' : 'Authorization Code'}
    </p>
    {direct && <Notice tone="info">
      <p>{t('clientCredentialsHelp')}</p>
      {setup.instructions.map(instruction => <p key={instruction} className="mt-2">{t(instruction)}</p>)}
      {setup.docs && method.docs && <ExternalLink href={method.docs}>{t('docs')}</ExternalLink>}
    </Notice>}
  </>;
}

export function ConnectionFields({ purpose, method, existing, appMaterial, apps }: {
  purpose: 'connection' | 'app';
  method?: CatalogConnectionMethod;
  existing: ResourceView | null;
  appMaterial: AppState | null;
  apps: ResourceView[];
}) {
  const { t, i18n } = useTranslation();
  const behavior = method ? connectionMethod(method) : undefined;
  const fields = (purpose === 'app' && method?.kind === 'oauth') ||
    (purpose === 'connection' && method?.kind === 'token') ? behavior?.fields ?? [] : [];
  const service = method?.id.split(':')[0];
  const consoleUrl = method?.kind === 'token' ? method.config.console ?? method.console : method?.console;
  return <div className="flex min-w-0 flex-col gap-6">
    {purpose === 'connection' && method?.kind === 'oauth' && <>
      {behavior?.requiresApp && <SelectField name="appId" label={t('app')}
        defaultValue={existing?.kind === 'connection' ? existing.data.appId ?? '' : apps[0]?.id ?? ''}>
        {apps.map(item => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}
      </SelectField>}
      {preparation(method).scopes && <InputField name="scopes" label={t('scopes')}
        defaultValue={existing?.kind === 'connection' ? existing.data.scopes.join(' ') : method.config.scopes.default.join(' ')}
        hint={t('scopesHelp')} />}
      {method.config.scopes.docs && <ExternalLink href={method.config.scopes.docs}>{t('docs')}</ExternalLink>}
    </>}
    {purpose === 'app' && <>
      <InputField name="clientId" required label={t('clientId')}
        defaultValue={existing?.kind === 'app' ? existing.data.clientId : ''} />
      <InputField name="clientSecret" type="password" autoComplete="new-password"
        required={!existing && method?.kind === 'oauth' && !behavior?.browserAuthorization && method.config.clientAuth !== 'none'}
        label={t('clientSecret')} hint={existing ? t('unchangedSecret') : undefined} />
      {(!method || behavior?.browserAuthorization) && <InputField label={t('callbackUrl')}
        value={typeof window !== 'undefined' ? window.location.origin + '/oauth/callback' : ''} readOnly />}
    </>}
    {fields.map(field => <InputField key={field.name} name={'field.' + field.name}
      label={i18n.language === 'ja' ? serviceLabels[`${service}.${method?.kind}.${field.name}.label`] ?? field.label : field.label}
      type={field.secret ? 'password' : 'text'} required={field.required ?? true}
      defaultValue={existing?.kind === 'app' ? appMaterial?.fields[field.name] ?? ''
        : purpose === 'app' && method?.kind === 'oauth' ? method.config.defaults[field.name] ?? '' : ''}
      placeholder={field.placeholder} autoComplete="off"
      hint={i18n.language === 'ja' ? serviceLabels[`${service}.${method?.kind}.${field.name}.note`] ?? field.note : field.note} />)}
    {consoleUrl && <ExternalLink href={consoleUrl}>{t('serviceConsole')}</ExternalLink>}
  </div>;
}

export function ConnectionPreparation({ method, initialRole, newConnection, executor }: {
  method?: CatalogConnectionMethod;
  initialRole?: ConnectionState['role'];
  newConnection: boolean;
  executor?: ResourceView;
}) {
  return <AwsRoleForm active={method?.kind === 'role'} initialRole={initialRole}
    newConnection={newConnection} executor={executor} />;
}
