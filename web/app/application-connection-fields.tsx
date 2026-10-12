import { useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { connectionMethod } from '../../shared/connection-methods';
import { InputField, SelectField } from './form-fields';
import { SelectItem } from './components/ui/select';
import { ServiceFields } from './connection-fields';
import type { ConnectionFieldsProps } from './connection-fields';

export function ApplicationConnectionFields({ purpose, method, existing, appMaterial, apps, selectedAppId, clientId,
  preparedFields, fieldValues, onFieldsChange, identifierLabel = 'clientId', secretLabel = 'clientSecret',
  callback = false, secretRequired = false, children }: ConnectionFieldsProps & {
    identifierLabel?: string; secretLabel?: string; callback?: boolean; secretRequired?: boolean; children?: ReactNode;
  }) {
  const { t } = useTranslation(), behavior = method ? connectionMethod(method) : undefined;
  const defaults = method?.kind === 'oauth' ? method.config.defaults : {};
  const [appId, setAppId] = useState(selectedAppId ?? (existing?.kind === 'connection' ? existing.data.appId ?? 'new' : apps[0]?.id ?? 'new'));
  const inline = purpose === 'connection' && behavior?.requiresApp && appId === 'new';
  const selected = apps.find(item => item.id === appId);
  const applicationFields = selected?.kind === 'app' ? selected.data.fields : {};
  return <>
    {purpose === 'connection' && <>
      {behavior?.requiresApp && <SelectField name="appId" label={t('app')} value={appId} onValueChange={value => {
        setAppId(value);
        const app = apps.find(item => item.id === value);
        if (app?.kind === 'app') onFieldsChange?.(app.data.fields);
      }} disabled={!!selectedAppId}>
        {apps.map(item => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}
        <SelectItem value="new">{t('newApplication')}</SelectItem>
      </SelectField>}
      {children}
    </>}
    {(purpose === 'app' || inline) && <>
      <InputField name="clientId" required label={t(identifierLabel)}
        defaultValue={clientId ?? (existing?.kind === 'app' ? existing.data.clientId : '')} readOnly={!!clientId} />
      <InputField name="clientSecret" type="password" autoComplete="new-password" required={(inline || !existing) && secretRequired}
        label={t(secretLabel)} hint={existing ? t('unchangedSecret') : undefined} />
      {callback && <InputField label={t('callbackUrl')}
        value={typeof window !== 'undefined' ? window.location.origin + '/oauth/callback' : ''} readOnly />}
      {method && <ServiceFields method={method} fields={behavior!.fields} defaults={defaults} existing={existing}
        appMaterial={appMaterial} preparedFields={preparedFields} fieldValues={fieldValues} onFieldsChange={onFieldsChange} />}
    </>}
    {purpose === 'connection' && !inline && method && <ServiceFields method={method}
      fields={behavior!.fields.filter(field => field.secret === false)} defaults={defaults} existing={existing} appMaterial={null}
      preparedFields={{ ...applicationFields, ...preparedFields }} fieldValues={fieldValues} onFieldsChange={onFieldsChange} />}
  </>;
}
