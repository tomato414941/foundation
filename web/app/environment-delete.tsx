import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useRevalidator } from 'react-router';
import { useTranslation } from 'react-i18next';
import { EnvironmentDeletion } from '../../shared/contracts';
import type { EnvironmentView } from '../../shared/contracts';
import { api, errorCode } from './api';
import { ErrorNotice, Notice } from './components';
import { Button } from './components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from './components/ui/dialog';

export function EnvironmentDelete({ item }: { item: EnvironmentView }) {
  const { t } = useTranslation();
  const navigate = useNavigate(), revalidator = useRevalidator();
  const [deletion, setDeletion] = useState(item.data.deletion);
  const [open, setOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checkFailed, setCheckFailed] = useState(false);
  const inFlight = useRef(false);
  const pending = deletion?.state === 'pending';
  const failed = deletion?.state === 'failed';
  const list = `/p/${item.ownerId}/environments`;
  useEffect(() => {
    if (item.data.deletion) setDeletion(item.data.deletion);
  }, [item.data.deletion?.state, item.data.deletion?.error]);
  useEffect(() => {
    if (!pending) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next = await api(`/resources/${item.id}/deletion`, { signal: controller.signal }, EnvironmentDeletion);
        if (controller.signal.aborted) return;
        setCheckFailed(false);
        setDeletion(next);
        if (next.state === 'complete') { void navigate(list + '?deleted=1', { replace: true }); return; }
        if (next.state === 'failed') { void revalidator.revalidate(); return; }
      } catch {
        if (controller.signal.aborted) return;
        setCheckFailed(true);
      }
      timer = setTimeout(poll, 1500);
    };
    timer = setTimeout(poll, 1000);
    return () => { controller.abort(); clearTimeout(timer); };
  }, [pending, item.id, list, navigate, revalidator]);
  const remove = async () => {
    if (inFlight.current || pending) return;
    inFlight.current = true;
    setSubmitting(true);
    setError(null);
    try {
      setDeletion(await api(`/resources/${item.id}`, { method: 'DELETE' }, EnvironmentDeletion));
      void revalidator.revalidate();
    } catch (cause) { setError(errorCode(cause)); void revalidator.revalidate(); }
    finally { inFlight.current = false; setSubmitting(false); }
  };
  const progress = <>
    {pending && <Notice><span role="status">{t('environmentDeletingHelp')}</span></Notice>}
    {checkFailed && pending && <Notice tone="warning">{t('environmentDeletionCheckFailed')}</Notice>}
    <ErrorNotice error={error ?? deletion?.error} />
  </>;
  return <Dialog open={open} onOpenChange={value => { if (!submitting) setOpen(value); }}>
    <div className="flex min-w-0 flex-col items-start gap-3">
      {!open && progress}
      <DialogTrigger asChild><Button variant="ghost" className="text-destructive hover:text-destructive" loading={pending || submitting}
        onClick={() => setError(null)}>
        {pending || submitting ? t('deleting') : failed ? t('retryDeletion') : t('delete')}
      </Button></DialogTrigger>
      <DialogContent showCloseButton={false}>
        <form className="space-y-5" onSubmit={event => { event.preventDefault(); void remove(); }}>
          <DialogHeader>
            <DialogTitle>{pending || submitting ? t('deleting') : failed ? t('deleteFailed') : t('deleteTitle', { name: item.name })}</DialogTitle>
            <DialogDescription>{t(item.data.driver === 'attached' ? 'attachedEnvironmentDeleteBody' : 'environmentDeleteBody')}</DialogDescription>
          </DialogHeader>
          {progress}
          <DialogFooter>
            {pending ? <Button asChild variant="outline"><Link to={list}>{t('backToEnvironments')}</Link></Button>
              : <Button variant="outline" autoFocus disabled={submitting} onClick={() => setOpen(false)}>{t(failed ? 'close' : 'cancel')}</Button>}
            <Button type="submit" variant="destructive" loading={submitting || pending}>
              {pending || submitting ? t('deleting') : failed ? t('retryDeletion') : t('delete')}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </div>
  </Dialog>;
}
