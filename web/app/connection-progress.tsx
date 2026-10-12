import { useTranslation } from 'react-i18next';
import type { FlowProgress } from '../../shared/connection-client';
import { AwsConnectionInfo } from '../../shared/aws';
import { AwsConnectionFacts } from './aws-connection-facts';
import { OvhConnectionInfo } from '../../shared/ovh';
import { OvhConnectionFacts } from './ovh-connection-facts';
import { ConnectionSettings } from './connection-settings';
import { Button } from './components/ui/button';
import { Detail, ErrorNotice, ExternalLink, Notice, Panel, State } from './components';

export function ConnectionProgress({ progress, acceptIntent = 'accept', cancelIntent = 'cancel' }: {
  progress: FlowProgress; acceptIntent?: string; cancelIntent?: string;
}) {
  const { t } = useTranslation();
  const aws = AwsConnectionInfo.safeParse(progress.kind === 'review' ? progress.metadata.aws : undefined);
  const ovh = OvhConnectionInfo.safeParse(progress.kind === 'review' ? progress.metadata.ovh : undefined);
  return <div className="flex min-w-0 flex-col gap-6">
    {progress.kind === 'pending' && <Notice tone="info">{t('connectionPending')}</Notice>}
    {progress.kind === 'authorize' && <ExternalLink href={progress.url}>{t('authorizeService')}</ExternalLink>}
    {progress.kind === 'review' && <Panel title={t('connectionApprove')}>
      <ConnectionSettings methodId={String(progress.metadata.methodId ?? '')} settings={progress.metadata.settings} />
      <Detail label={t('accountName')}>{String(progress.metadata.account ?? t('accountUnverified'))}</Detail>
      {!progress.metadata.accountVerified && <Notice tone="warning">{t('accountUnverified')}</Notice>}
      {aws.success ? <AwsConnectionFacts value={aws.data} /> : ovh.success ? <OvhConnectionFacts value={ovh.data} /> :
        <Detail label={t('scopes')}>{Array.isArray(progress.metadata.scopes) && progress.metadata.scopes.length
          ? progress.metadata.scopes.join(', ') : t('scopesUnknown')}</Detail>}
      <Button type="submit" name="intent" value={acceptIntent}>{t('save')}</Button>
    </Panel>}
    {progress.kind === 'failed' && <><State value={progress.task.state} />
      <ErrorNotice error={progress.error && typeof progress.error === 'object' && !Array.isArray(progress.error) &&
        typeof progress.error.code === 'string' ? progress.error.code : 'failure'} />
    </>}
    {progress.kind === 'cancelled' && <State value="cancelled" />}
    {!['cancelled', 'connected'].includes(progress.kind) && <Button variant="ghost" type="submit" name="intent" value={cancelIntent} formNoValidate>{t('cancel')}</Button>}
  </div>;
}
