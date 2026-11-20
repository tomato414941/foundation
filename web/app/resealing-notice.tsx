import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CircleCheck, LoaderCircle, TriangleAlert } from 'lucide-react';
import { errorCode } from './api';
import { requireKeys, resealNow, useResealing } from './keys';
import { Alert, AlertDescription, AlertTitle } from './components/ui/alert';
import { Button } from './components/ui/button';
import { Progress } from './components/ui/progress';

export function ResealingNotice({ principalId, requestId }: { principalId?: string; requestId?: string }) {
  const { t } = useTranslation(), state = useResealing(principalId);
  const [retrying, setRetrying] = useState(false), [retryError, setRetryError] = useState<string | null>(null);
  const outcome = !requestId || state?.requestId === requestId ? state : null;
  if (!outcome || !requestId && !outcome.failed.length && !outcome.error && !(outcome.running && outcome.total)) return null;
  const incomplete = !!outcome.error || outcome.failed.length > 0;
  const Icon = outcome.running ? LoaderCircle : incomplete ? TriangleAlert : CircleCheck;
  async function retry() {
    if (!principalId) return;
    setRetrying(true);
    setRetryError(null);
    try {
      await requireKeys(principalId);
      await resealNow(principalId, requestId);
    } catch (error) { setRetryError(errorCode(error)); }
    finally { setRetrying(false); }
  }
  const reason = (code: string) => t('resealingReasons.' + code,
    { defaultValue: t('errors.' + code, { defaultValue: t('failure') }) });
  return <Alert role="region" aria-label={t('resealingTitle')} className={outcome.running ? undefined : incomplete
    ? 'border-amber-500/20 bg-amber-500/5 text-amber-300' : 'border-emerald-500/20 bg-emerald-500/5 text-emerald-300'}>
    <Icon aria-hidden="true" className={outcome.running ? 'size-4 animate-spin' : 'size-4'} />
    <AlertTitle>{t(requestId ? 'resealingApproved' : 'resealingTitle')}</AlertTitle>
    <AlertDescription className="space-y-3 text-inherit [&_p:not(:last-child)]:mb-0">
      <div aria-live="polite" aria-atomic="true">
        {outcome.running ? <>
          <p>{t('resealingWorking')}</p>
          <p className="mt-2 text-sm tabular-nums">{outcome.total === null ? t('resealingChecking') :
            t('resealingCount', { completed: outcome.completed, total: outcome.total })}</p>
        </> : incomplete ? <>
          {outcome.done > 0 && <p>{t('resealingUpdated', { count: outcome.done })}</p>}
          <p>{outcome.error ? t('resealingError') : t('resealingPending', { count: outcome.failed.length })}</p>
        </> : <p>{outcome.done > 0 ? t('resealingComplete', { count: outcome.done }) : t('resealingUnneeded')}</p>}
      </div>
      {outcome.running ? <>
        <Progress value={outcome.total ? outcome.completed / outcome.total * 100 : null}
          aria-label={t('resealingTitle')} getValueLabel={() => t('resealingCount', { completed: outcome.completed, total: outcome.total ?? 0 })} />
        <p className="text-xs text-muted-foreground">{t('resealingWait')}</p>
      </> : incomplete && <>
        {outcome.error && <p>{reason(outcome.error)}</p>}
        {outcome.failed.length > 0 && <ul className="list-disc space-y-2 pl-5">
          {outcome.failed.map(item => <li key={item.id} className="wrap-anywhere">
            {t('resealingItem', { name: item.name ?? t('resealingUnnamed'), reason: reason(item.code) })}
          </li>)}
        </ul>}
        {requestId && <p>{t('resealingNoApprovalNeeded')}</p>}
        {retryError && <p role="alert">{reason(retryError)}</p>}
        <Button variant="outline" onClick={() => void retry()} loading={retrying} disabled={retrying}>{t('resealingRetry')}</Button>
      </>}
    </AlertDescription>
  </Alert>;
}
