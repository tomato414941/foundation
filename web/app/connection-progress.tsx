import { useTranslation } from 'react-i18next';
import type { FlowProgress } from '../../shared/connection-client';
import { Button } from './components/ui/button';
import { ArrowUpRight } from 'lucide-react';
import { connectionRequestAction } from './connection-request-review';
import { Copy, ErrorNotice, ExternalLink, Notice } from './components';

export function ConnectionProgress({ progress, cancelIntent = 'cancel', authorization, review = false }: {
  progress: FlowProgress; cancelIntent?: string; authorization?: { label: string; newWindow: boolean }; review?: boolean;
}) {
  const { t } = useTranslation();
  return <div className="flex min-w-0 flex-col gap-6">
    {progress.kind === 'pending' && <Notice tone="info">{t('connectionPending')}</Notice>}
    {progress.kind === 'authorize' && progress.device && <div className="flex flex-col gap-3">
      <p className="text-sm">{t('deviceAuthorizeHelp')}</p>
      <div className="flex min-w-0 flex-wrap items-center gap-3">
        <code className="break-all text-2xl font-semibold tracking-widest">{progress.device.userCode}</code>
        <Copy value={progress.device.userCode} />
      </div>
      <p role="status" className="text-sm text-muted-foreground">{t('deviceAuthorizeWaiting')}</p>
    </div>}
    {progress.kind === 'authorize' && (authorization ? <Button asChild className={review ? 'w-fit ' + connectionRequestAction : 'w-fit'}>
      <a href={progress.url} target={authorization.newWindow ? '_blank' : undefined} rel={authorization.newWindow ? 'noopener noreferrer' : undefined}>{authorization.label}{review && <ArrowUpRight aria-hidden="true" />}</a>
    </Button> : <ExternalLink href={progress.url}>{t('authorizeService')}</ExternalLink>)}
    {progress.kind === 'cli' && <Notice tone="info">
      <p>{t(progress.flow.error ? 'browserExchangeRestart' : 'connectionCliHelp')}</p>
      <div className="mt-3 flex min-w-0 items-center gap-2"><code className="min-w-0 break-all text-sm">{progress.command}</code><Copy value={progress.command} /></div>
      <p className="mt-3">{t('connectionCliLoginHelp')}</p>
    </Notice>}
    {progress.kind === 'failed' && <ErrorNotice error={progress.error} />}
    {!['cancelled', 'connected'].includes(progress.kind) && <Button className={review ? 'min-h-12 w-fit px-4 text-muted-foreground' : undefined} variant="ghost" type="submit" name="intent" value={cancelIntent} formNoValidate>{t('cancel')}</Button>}
  </div>;
}
