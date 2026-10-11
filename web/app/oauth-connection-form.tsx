import { useTranslation } from 'react-i18next';
import { useState } from 'react';
import type { CatalogConnectionMethod } from '../../shared/contracts';
import { connectionMethod, selectScopes } from '../../shared/connection-methods';
import { ExternalLink, Notice } from './components';
import { SelectItem } from './components/ui/select';
import { InputField, SelectField } from './form-fields';
import { ServiceFields } from './connection-fields';
import type { ConnectionFieldsProps } from './connection-fields';
import { servicePreparation } from './service-preparations';

export function OAuthConnectionHelp({ method }: { method?: CatalogConnectionMethod }) {
  const { t } = useTranslation();
  if (method?.kind !== 'oauth') return null;
  const direct = !connectionMethod(method).browserAuthorization, setup = servicePreparation(method);
  return <>
    <p className="text-sm text-muted-foreground">OAuth 2.0 / {direct ? 'Client Credentials' : 'Authorization Code'}</p>
    {direct && <Notice tone="info">
      <p>{t('clientCredentialsHelp')}</p>
      {setup.instructions.map(instruction => <p key={instruction} className="mt-2">{t(instruction)}</p>)}
      {setup.docs && method.docs && <ExternalLink href={method.docs}>{t('docs')}</ExternalLink>}
    </Notice>}
  </>;
}
export function OAuthConnectionFields({ purpose, method, existing, appMaterial, apps, selectedAppId, clientId }: ConnectionFieldsProps) {
  const { t } = useTranslation();
  const spec = method?.kind === 'oauth' ? method.config : undefined;
  const behavior = method ? connectionMethod(method) : undefined;
  const requiredScopes = spec?.scopes.required ?? [];
  const [appId, setAppId] = useState(selectedAppId ?? (existing?.kind === 'connection' ? existing.data.appId ?? 'new' : apps[0]?.id ?? 'new'));
  const inline = purpose === 'connection' && behavior?.requiresApp && appId === 'new';
  return <>
    {purpose === 'connection' && method && spec && <>
      {behavior?.requiresApp && <SelectField name="appId" label={t('app')}
        value={appId} onValueChange={setAppId} disabled={!!selectedAppId}>
        {apps.map(item => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}
        <SelectItem value="new">{t('newApplication')}</SelectItem>
      </SelectField>}
      {servicePreparation(method).scopes && <InputField name="scopes" label={t('scopes')}
        defaultValue={selectScopes(spec.scopes, existing?.kind === 'connection' ? existing.data.scopes : undefined).join(' ')}
        hint={requiredScopes.length ? t('scopesHelp') + ' ' + t('requiredScopesHelp', { scopes: requiredScopes.join(', ') }) : t('scopesHelp')} />}
      {spec.scopes.docs && <ExternalLink href={spec.scopes.docs}>{t('docs')}</ExternalLink>}
    </>}
    {(purpose === 'app' || inline) && <>
      <InputField name="clientId" required label={t('clientId')}
        defaultValue={clientId ?? (existing?.kind === 'app' ? existing.data.clientId : '')} readOnly={!!clientId} />
      <InputField name="clientSecret" type="password" autoComplete="new-password"
        required={(inline || !existing) && !!spec && !behavior?.browserAuthorization && spec.clientAuth !== 'none'}
        label={t('clientSecret')} hint={existing ? t('unchangedSecret') : undefined} />
      {(!method || behavior?.browserAuthorization) && <InputField label={t('callbackUrl')}
        value={typeof window !== 'undefined' ? window.location.origin + '/oauth/callback' : ''} readOnly />}
      {method && spec && <ServiceFields method={method} fields={spec.fields} defaults={spec.defaults}
        existing={existing} appMaterial={appMaterial} />}
    </>}
  </>;
}
