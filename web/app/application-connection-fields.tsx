import { useState } from 'react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Notice } from './components';
import { useTranslation } from 'react-i18next';
import { connectionMethod } from '../../shared/connection-methods';
import { InputField, SelectField } from './form-fields';
import { SelectItem } from './components/ui/select';
import { ServiceFields } from './connection-fields';
import type { ConnectionFieldsProps } from './connection-fields';

export function ApplicationConnectionFields({ purpose, method, existing, appMaterial, apps, selectedAppId, clientId,
  preparedFields, fieldValues, onFieldsChange, appSetupUrl, identifierLabel = 'clientId', secretLabel = 'clientSecret',
  callback = false, secretRequired = false, children }: ConnectionFieldsProps & {
    identifierLabel?: string; secretLabel?: string; callback?: boolean; secretRequired?: boolean; children?: ReactNode;
  }) {
  const { t } = useTranslation(), behavior = method ? connectionMethod(method) : undefined;
  const defaults = method?.kind === 'oauth' ? method.config.defaults : {};
  const [appId, setAppId] = useState(selectedAppId ?? (existing?.kind === 'connection' ? existing.data.appId ?? '' : apps[0]?.id ?? ''));
  const selected = apps.find(item => item.id === appId);
  const applicationFields = selected?.kind === 'app' ? selected.data.fields : {};
  return <>
    {purpose === 'connection' && <>
      {behavior?.requiresApp && apps.length > 0 && <SelectField name="appId" label={t('app')} value={appId} onValueChange={value => {
        setAppId(value);
        const app = apps.find(item => item.id === value);
        if (app?.kind === 'app') onFieldsChange?.(app.data.fields);
      }} disabled={!!selectedAppId}>
        {apps.map(item => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}
      </SelectField>}
      {behavior?.requiresApp && !apps.length && <Notice tone="info">
        <p>{t('appRequired')}</p>
        {appSetupUrl && <Link className="mt-2 inline-block underline underline-offset-4" to={appSetupUrl}>{t('prepareConnectionApp')}</Link>}
      </Notice>}
      {children}
    </>}
    {purpose === 'app' && <>
      <InputField name="clientId" required label={t(identifierLabel)}
        defaultValue={clientId ?? (existing?.kind === 'app' ? existing.data.clientId : '')} readOnly={!!clientId} />
      <InputField name="clientSecret" type="password" autoComplete="new-password" required={!existing && secretRequired}
        label={t(secretLabel)} hint={existing ? t('unchangedSecret') : undefined} />
      {callback && <InputField label={t('callbackUrl')}
        value={typeof window !== 'undefined' ? window.location.origin + '/oauth/callback' : ''} readOnly />}
      {method && <ServiceFields method={method} fields={behavior!.fields} defaults={defaults} existing={existing}
        appMaterial={appMaterial} preparedFields={preparedFields} fieldValues={fieldValues} onFieldsChange={onFieldsChange} />}
    </>}
    {purpose === 'connection' && method && <ServiceFields method={method}
      fields={behavior!.fields.filter(field => field.secret === false && field.visibility !== 'application')} defaults={defaults} existing={existing} appMaterial={null}
      preparedFields={{ ...applicationFields, ...preparedFields }} fieldValues={fieldValues} onFieldsChange={onFieldsChange} />}
    {purpose === 'connection' && behavior?.fields.filter(field => field.secret === false && field.visibility === 'application')
      .map(field => <input key={field.name} type="hidden" name={'field.' + field.name}
        value={preparedFields?.[field.name] ?? applicationFields[field.name] ?? ''} />)}
  </>;
}
