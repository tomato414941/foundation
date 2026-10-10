import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import type { ConnectionState } from '../../shared/connections';
import type { ResourceView } from '../../shared/contracts';
import { api, formText } from './api';
import { ExternalLink, Notice, Panel } from './components';
import { InputField } from './form-fields';

export function awsRoleSettings(form: FormData): NonNullable<ConnectionState['role']> {
  return {
    arn: formText(form, 'arn'),
    region: formText(form, 'region'),
    externalId: formText(form, 'externalId'),
  };
}

export function AwsRoleForm({ active, initialRole, newConnection, executor }: {
  active: boolean;
  initialRole?: ConnectionState['role'];
  newConnection: boolean;
  executor?: ResourceView;
}) {
  const { t } = useTranslation();
  const awsPrincipal = executor?.kind === 'environment' ? executor.data.awsPrincipal : undefined;
  const [externalId, setExternalId] = useState(() => initialRole?.externalId ??
    (newConnection ? crypto.randomUUID().replaceAll('-', '') : ''));
  const [region, setRegion] = useState(initialRole?.region ?? 'ap-northeast-1');
  const [templateUrl, setTemplateUrl] = useState('');
  useEffect(() => {
    if (!active || !awsPrincipal || templateUrl) return;
    const controller = new AbortController();
    api('/aws/role-template', { signal: controller.signal }, z.object({ url: z.string() }))
      .then((result) => setTemplateUrl(result.url))
      .catch(() => {});
    return () => controller.abort();
  }, [active, awsPrincipal, templateUrl]);

  // Keep state while another connection method is selected.
  if (!active) return null;
  const consoleUrl = awsPrincipal && templateUrl
    ? 'https://console.aws.amazon.com/cloudformation/home?' + new URLSearchParams({ region }) +
      '#/stacks/create/review?' + new URLSearchParams({
        templateURL: templateUrl,
        stackName: 'foundation-' + externalId.slice(0, 12),
        param_PrincipalArn: awsPrincipal,
        param_ExternalId: externalId,
      })
    : '';

  return <Panel title={t('role')}>
    {executor && (awsPrincipal
      ? <>
          <p className="text-sm leading-relaxed text-muted-foreground">{t('createRoleHelp')}</p>
          {consoleUrl && <ExternalLink href={consoleUrl}>{t('createRole')}</ExternalLink>}
        </>
      : <Notice tone="warning">{t('executorAwsUnconfirmed')}</Notice>)}
    <InputField name="arn" label={t('roleArn')} required hint={t('roleArnHelp')}
      defaultValue={initialRole?.arn ?? ''} />
    <InputField name="region" label={t('region')} value={region}
      onChange={event => setRegion(event.target.value)} required />
    <InputField name="externalId" label="External ID" required minLength={16} value={externalId}
      onChange={event => setExternalId(event.target.value)} hint={t('externalIdHelp')} />
  </Panel>;
}
