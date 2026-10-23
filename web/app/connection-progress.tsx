import { useTranslation } from 'react-i18next';
import type { FlowProgress } from '../../shared/connection-client';
import { Button } from './components/ui/button';
import { Copy, ErrorNotice, ExternalLink, Notice } from './components';

export function ConnectionProgress({ progress, cancelIntent = 'cancel', authorization }: {
  progress: FlowProgress; cancelIntent?: string; authorization?: { label: string; newWindow: boolean };
}) {
  const { t } = useTranslation();
  return <div className="flex min-w-0 flex-col gap-6">
    {progress.kind === 'pending' && <Notice tone="info">{t('connectionPending')}</Notice>}
    {progress.kind === 'authorize' && (authorization ? <Button asChild className="w-fit">
      <a href={progress.url} target={authorization.newWindow ? '_blank' : undefined} rel={authorization.newWindow ? 'noopener noreferrer' : undefined}>{authorization.label}</a>
    </Button> : <ExternalLink href={progress.url}>{t('authorizeService')}</ExternalLink>)}
    {progress.kind === 'cli' && <Notice tone="info">
      <p>{t(progress.flow.error ? 'browserExchangeRestart' : 'connectionCliHelp')}</p>
      <div className="mt-3 flex min-w-0 items-center gap-2"><code className="min-w-0 break-all text-sm">{progress.command}</code><Copy value={progress.command} /></div>
      <p className="mt-3">{t('connectionCliLoginHelp')}</p>
    </Notice>}
    {progress.kind === 'failed' && <ErrorNotice error={progress.error} />}
    {!['cancelled', 'connected'].includes(progress.kind) && <Button variant="ghost" type="submit" name="intent" value={cancelIntent} formNoValidate>{t('cancel')}</Button>}
  </div>;
}
