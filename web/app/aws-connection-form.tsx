import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import { AwsConnectionInput } from '../../shared/aws';
import type { AwsConnectionRequest, AwsConnectionState } from '../../shared/aws';
import type { ConnectionState } from '../../shared/connections';
import type { ResourceView } from '../../shared/contracts';
import { api, formText } from './api';
import { ExternalLink, Notice, Panel } from './components';
import { SelectItem } from './components/ui/select';
import { CheckboxField, InputField, SelectField } from './form-fields';

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
  const [region, setRegion] = useState(initial?.region ?? 'ap-northeast-1');
  const [templateUrl, setTemplateUrl] = useState('');
  const awsPrincipal = executor?.kind === 'environment' ? executor.data.awsPrincipal : undefined;
  const sameCredentials = !newConnection && authentication === initial?.authentication && accessKeyId === initial?.accessKeyId;
  useEffect(() => {
    if (!active || authentication !== 'environment' || !useRole || !awsPrincipal || templateUrl) return;
    const controller = new AbortController();
    api('/aws/role-template', { signal: controller.signal }, z.object({ url: z.string() }))
      .then(result => setTemplateUrl(result.url)).catch(() => {});
    return () => controller.abort();
  }, [active, authentication, useRole, awsPrincipal, templateUrl]);
  if (!active) return null;
  const createRoleUrl = authentication === 'environment' && awsPrincipal && templateUrl && externalId.length >= 16
    ? 'https://console.aws.amazon.com/cloudformation/home?' + new URLSearchParams({ region }) +
      '#/stacks/create/review?' + new URLSearchParams({ templateURL: templateUrl,
        stackName: 'foundation-' + externalId.slice(0, 12), param_PrincipalArn: awsPrincipal, param_ExternalId: externalId,
      }) : '';
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
      {createRoleUrl && <>
        <p className="text-sm leading-relaxed text-muted-foreground">{t('createRoleHelp')}</p>
        <ExternalLink href={createRoleUrl}>{t('createRole')}</ExternalLink>
      </>}
      <InputField name="arn" label={t('roleArn')} defaultValue={initial?.role?.arn ?? ''}
        required hint={t('awsRoleArnHelp')} />
      <InputField name="externalId" label="External ID" value={externalId}
        onChange={event => setExternalId(event.target.value)} minLength={2} hint={t('awsExternalIdHelp')} />
    </div>}
  </Panel>;
}
