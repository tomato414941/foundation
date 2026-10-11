import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import { AwsConnectionInput } from '../../shared/aws';
import type { AwsConnectionRequest, AwsConnectionState } from '../../shared/aws';
import { AwsRoleSetup, awsRoleCreateUrl } from '../../shared/aws-setup';
import type { AwsRolePermissionName } from '../../shared/aws-setup';
import type { ConnectionState } from '../../shared/connections';
import type { ResourceView } from '../../shared/contracts';
import { api, formText } from './api';
import { ExternalLink, Notice, Panel } from './components';
import { SelectItem } from './components/ui/select';
import { CheckboxField, InputField, SelectField } from './form-fields';
import { Button } from './components/ui/button';
import { awsRoleSetupKey, consumeAwsRoleSetup, rememberAwsRoleSetup } from './aws-role-setup';

export type AwsFormValues = {
  authentication: AwsConnectionRequest['authentication']['kind'];
  accessKeyId?: string;
  expiresAt?: number;
  region: string;
  role?: AwsConnectionRequest['role'];
};
export function awsFormValues(state: ConnectionState): AwsFormValues | undefined {
  const input = state.aws;
  if (!input) return;
  return { authentication: input.authentication.kind, region: input.region,
    ...(input.role ? { role: input.role } : {}),
    ...(input.authentication.kind !== 'environment' ? { accessKeyId: input.authentication.accessKeyId } : {}),
    ...(input.authentication.kind === 'session' ? { expiresAt: input.authentication.expiresAt } : {}),
  };
}
export function awsConnectionSettings(form: FormData, previous?: AwsConnectionState): AwsConnectionRequest {
  const kind = formText(form, 'awsAuthentication'), accessKeyId = formText(form, 'awsAccessKeyId');
  const saved = previous?.authentication.kind === kind && previous.authentication.kind !== 'environment' &&
    previous.authentication.accessKeyId === accessKeyId ? previous.authentication : undefined;
  return AwsConnectionInput.parse({
    authentication: kind === 'environment' ? { kind } : {
      kind, accessKeyId, secretAccessKey: formText(form, 'awsSecretAccessKey') || saved?.secretAccessKey,
      ...(kind === 'session' ? {
        sessionToken: formText(form, 'awsSessionToken') || (saved?.kind === 'session' ? saved.sessionToken : undefined),
        expiresAt: new Date(formText(form, 'awsExpiresAt')).getTime(),
      } : {}),
    },
    region: formText(form, 'region'),
    ...(form.has('awsAssumeRole') ? { role: { arn: formText(form, 'arn'),
      ...(formText(form, 'externalId') ? { externalId: formText(form, 'externalId') } : {}) } } : {}),
  });
}
const localDate = (value?: number) => {
  if (!value) return '';
  const date = new Date(value);
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 16);
};

export function AwsConnectionForm({ active, initial, newConnection, executor }: {
  active: boolean; initial?: AwsFormValues; newConnection: boolean; executor?: ResourceView;
}) {
  const { t } = useTranslation();
  const [authentication, setAuthentication] = useState(initial?.authentication ?? 'access_key');
  const [useRole, setUseRole] = useState(Boolean(initial?.role));
  const [accessKeyId, setAccessKeyId] = useState(initial?.accessKeyId ?? '');
  const [externalId, setExternalId] = useState(initial?.role?.externalId ?? '');
  const [arn, setArn] = useState(initial?.role?.arn ?? '');
  const [region, setRegion] = useState(initial?.region ?? 'ap-northeast-1');
  const [permission, setPermission] = useState<AwsRolePermissionName>('ReadOnlyAccess');
  const [setupId, setSetupId] = useState(() => crypto.randomUUID());
  const [roleFilled, setRoleFilled] = useState(false);
  const [setupError, setSetupError] = useState(false);
  const [templateUrl, setTemplateUrl] = useState('');
  const awsPrincipal = executor?.kind === 'environment' ? executor.data.awsPrincipal : undefined;
  const environmentId = executor?.id;
  const sameCredentials = !newConnection && authentication === initial?.authentication && accessKeyId === initial?.accessKeyId;
  const setup = useMemo(() => {
    if (!active || authentication !== 'environment' || !useRole || !awsPrincipal || !environmentId || typeof window === 'undefined') return null;
    const result = AwsRoleSetup.safeParse({ id: setupId, environmentId, principalArn: awsPrincipal,
      externalId, region, permission, returnUrl: window.location.origin + '/connections/aws/complete' });
    return result.success ? result.data : null;
  }, [active, authentication, useRole, awsPrincipal, environmentId, setupId, externalId, region, permission]);
  useEffect(() => {
    if (!active || authentication !== 'environment' || !useRole || !awsPrincipal || templateUrl || setupError) return;
    const controller = new AbortController();
    api('/aws/role-template', { signal: controller.signal }, z.object({ url: z.string() }))
      .then(result => setTemplateUrl(result.url)).catch(() => { if (!controller.signal.aborted) setSetupError(true); });
    return () => controller.abort();
  }, [active, authentication, useRole, awsPrincipal, templateUrl, setupError]);
  useEffect(() => {
    if (!setup) return;
    const receive = () => {
      const returnedArn = consumeAwsRoleSetup(setup);
      if (!returnedArn) return;
      setArn(returnedArn); setRoleFilled(true); setSetupId(crypto.randomUUID());
    };
    const changed = (event: StorageEvent) => { if (event.key === awsRoleSetupKey(setup.id)) receive(); };
    receive();
    window.addEventListener('storage', changed);
    return () => {
      window.removeEventListener('storage', changed);
      try { localStorage.removeItem(awsRoleSetupKey(setup.id)); } catch { /* Storage may be unavailable. */ }
    };
  }, [setup]);
  if (!active) return null;
  const createRoleUrl = setup && templateUrl ? awsRoleCreateUrl(templateUrl, setup) : '';
  return <Panel title={t('awsAuthentication')}>
    <SelectField name="awsAuthentication" label={t('awsAuthenticationMethod')} value={authentication}
      onValueChange={value => {
        setAuthentication(value as AwsFormValues['authentication']);
        if (value === 'environment' && useRole && newConnection && !externalId)
          setExternalId(crypto.randomUUID().replaceAll('-', ''));
      }}>
      {(['access_key', 'session', 'environment'] as const).map(kind =>
        <SelectItem key={kind} value={kind}>{t('awsAuth.' + kind)}</SelectItem>)}
    </SelectField>
    <p className="text-sm leading-relaxed text-muted-foreground">{t('awsAuthHelp.' + authentication)}</p>
    {authentication !== 'environment' && <>
      <InputField name="awsAccessKeyId" label={t('awsAccessKeyId')} value={accessKeyId}
        onChange={event => setAccessKeyId(event.target.value)} required autoComplete="off" />
      <InputField name="awsSecretAccessKey" label={t('awsSecretAccessKey')} type="password"
        required={!sameCredentials} autoComplete="new-password" hint={sameCredentials ? t('unchangedSecret') : undefined} />
      {authentication === 'session' && <>
        <InputField name="awsSessionToken" label={t('awsSessionToken')} type="password"
          required={!sameCredentials} autoComplete="new-password" hint={sameCredentials ? t('unchangedSecret') : undefined} />
        <InputField name="awsExpiresAt" label={t('awsExpiresAt')} type="datetime-local"
          defaultValue={localDate(initial?.expiresAt)} required />
      </>}
    </>}
    <InputField name="region" label={t('region')} value={region}
      onChange={event => setRegion(event.target.value)} required />
    <CheckboxField name="awsAssumeRole" label={t('awsAssumeRole')} checked={useRole}
      onCheckedChange={checked => {
        setUseRole(checked === true);
        if (checked && authentication === 'environment' && newConnection && !externalId)
          setExternalId(crypto.randomUUID().replaceAll('-', ''));
      }} hint={t('awsAssumeRoleHelp')} />
    {useRole && <div className="flex min-w-0 flex-col gap-6 border-t pt-6">
      {authentication === 'environment' && executor && !awsPrincipal &&
        <Notice tone="warning">{t('executorAwsUnconfirmed')}</Notice>}
      {authentication === 'environment' && awsPrincipal && <>
        <SelectField label={t('awsRolePermission')} value={permission}
          onValueChange={value => setPermission(value as AwsRolePermissionName)}>
          {(['ReadOnlyAccess', 'AdministratorAccess'] as const).map(value =>
            <SelectItem key={value} value={value}>{t('awsRolePermission.' + value)}</SelectItem>)}
        </SelectField>
        {permission === 'AdministratorAccess' && <Notice tone="warning">{t('awsRoleAdminHelp')}</Notice>}
        {!templateUrl && !setupError && <p className="text-sm text-muted-foreground" role="status">{t('awsSetupLoading')}</p>}
      </>}
      {setupError && <Notice tone="error" action={<Button type="button" variant="outline" onClick={() => setSetupError(false)}>{t('awsSetupRetry')}</Button>}>
        {t('awsSetupFailed')}
      </Notice>}
      {createRoleUrl && <>
        <p className="text-sm leading-relaxed text-muted-foreground">{t('createRoleHelp')}</p>
        <ExternalLink href={createRoleUrl} onClick={event => {
          event.preventDefault();
          try {
            const attempt = { ...setup!, id: crypto.randomUUID() };
            rememberAwsRoleSetup(attempt); setSetupId(attempt.id); setRoleFilled(false);
            window.open(awsRoleCreateUrl(templateUrl, attempt), '_blank', 'noopener,noreferrer');
          } catch { setSetupError(true); }
        }}>{t('createRole')}</ExternalLink>
      </>}
      {roleFilled && <Notice tone="success">{t('awsRoleFilled')}</Notice>}
      <InputField name="arn" label={t('roleArn')} value={arn} onChange={event => { setArn(event.target.value); setRoleFilled(false); }}
        required hint={t('awsRoleArnHelp')} />
      <InputField name="externalId" label="External ID" value={externalId}
        onChange={event => setExternalId(event.target.value)} minLength={2} hint={t('awsExternalIdHelp')} />
    </div>}
  </Panel>;
}
