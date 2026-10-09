import { useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import { Link, Form, useNavigation, useRevalidator } from 'react-router';
import {
  Check,
  ChevronLeft,
  ChevronRight,
  Copy as CopyIcon,
  ExternalLink as ExternalLinkIcon,
  Info,
  LoaderCircle,
  CircleCheck,
  TriangleAlert,
} from 'lucide-react';
import { cn } from 'cn';
import { useTranslation } from 'react-i18next';
import { errorCode } from './api';
import type { ApprovalView } from '../../shared/contracts';
import { Button } from './components/ui/button';
import { Badge } from './components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from './components/ui/card';
import { Alert, AlertDescription } from './components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from './components/ui/dialog';
import { Tooltip, TooltipContent, TooltipTrigger } from './components/ui/tooltip';
import { TextareaField } from './form-fields';

export function Page({
  title,
  children,
  actions,
  narrow = false,
  back,
}: {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
  narrow?: boolean;
  back?: { to: string; label: string };
}) {
  return (
    <section className={cn('mx-auto flex w-full flex-col gap-6', narrow ? 'max-w-2xl' : 'max-w-6xl')}>
      {back && <Link to={back.to} className="flex w-fit items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft className="size-4" aria-hidden="true" />{back.label}
      </Link>}
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <h1 className="min-w-0 text-2xl font-semibold tracking-tight wrap-anywhere">{title}</h1>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

export function Panel({ title, children }: { title?: string; children: ReactNode }) {
  return (
    <Card className="gap-5 py-5 shadow-none sm:py-6">
      {title && (
        <CardHeader className="px-5 sm:px-6">
          <CardTitle className="text-sm font-semibold wrap-anywhere">
            <h2>{title}</h2>
          </CardTitle>
        </CardHeader>
      )}
      <CardContent className="flex min-w-0 flex-col gap-4 px-5 sm:px-6">{children}</CardContent>
    </Card>
  );
}

export function Notice({
  tone = 'info',
  children,
  action,
}: {
  tone?: 'info' | 'success' | 'warning' | 'error';
  children: ReactNode;
  action?: ReactNode;
}) {
  const Icon =
    tone === 'success' ? CircleCheck : tone === 'warning' || tone === 'error' ? TriangleAlert : Info;
  return (
    <Alert
      variant={tone === 'error' ? 'destructive' : 'default'}
      className={cn(
        'rounded-lg',
        tone === 'success' && 'border-emerald-500/20 bg-emerald-500/5 text-emerald-300',
        tone === 'warning' && 'border-amber-500/20 bg-amber-500/5 text-amber-300',
      )}
    >
      <Icon className="size-4" aria-hidden="true" />
      <AlertDescription className="flex flex-wrap items-center justify-between gap-3 text-inherit">
        <span className="min-w-0 leading-relaxed">{children}</span>
        {action}
      </AlertDescription>
    </Alert>
  );
}

export function ErrorNotice({ error }: { error?: string | null }) {
  const { t } = useTranslation();
  return error ? (
    <Notice tone="error">{t('errors.' + error, { defaultValue: t('failure') })}</Notice>
  ) : null;
}

export function Busy() {
  const { t } = useTranslation();
  return (
    <div className="flex justify-center p-12" role="status">
      <LoaderCircle className="size-5 animate-spin text-muted-foreground" aria-hidden="true" />
      <span className="sr-only">{t('loading')}</span>
    </div>
  );
}

export function Empty({ search = false }: { search?: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="rounded-xl border border-dashed py-16 text-center text-muted-foreground">
      {t(search ? 'noResults' : 'empty')}
    </div>
  );
}

// What a proposed change does, in one sentence: the line it draws, or who becomes the owner.
export function ProposalText({ proposal }: { proposal: NonNullable<ApprovalView['proposal']> }) {
  const { t } = useTranslation();
  return proposal.kind === 'line'
    ? t('line', { subject: proposal.subject.name, relation: t(proposal.relation), object: proposal.object.name })
    : t('transferLine', { item: proposal.item.name, to: proposal.to.name });
}
export function State({ value, label }: { value: string; label?: string }) {
  const { t } = useTranslation();
  return (
    <Badge
      variant="outline"
      className={cn(
        'gap-1.5 font-normal',
        ['ready', 'succeeded', 'approved', 'running'].includes(value) &&
          'border-emerald-500/20 bg-emerald-500/5 text-emerald-300',
        ['failed', 'deleteFailed', 'reconnect', 'reconnect_required'].includes(value) &&
          'border-amber-500/20 bg-amber-500/5 text-amber-300',
      )}
    >
      <span className="size-1.5 rounded-full bg-current" aria-hidden="true" />
      {label ?? t('state.' + value, { defaultValue: value })}
    </Badge>
  );
}

export function DateText({ value }: { value: string | null }) {
  const { i18n } = useTranslation();
  return (
    <>
      {value
        ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }).format(
            new Date(value),
          )
        : '—'}
    </>
  );
}

export function Bytes({ value }: { value: number }) {
  const { i18n } = useTranslation();
  const power = value < 1024 ? 0 : Math.min(3, Math.floor(Math.log(value) / Math.log(1024)));
  return (
    <>
      {new Intl.NumberFormat(i18n.language, { maximumFractionDigits: power ? 1 : 0 }).format(
        value / 1024 ** power,
      )}{' '}
      {['B', 'KB', 'MB', 'GB'][power]}
    </>
  );
}

export function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <dl className="grid min-w-0 gap-1.5 sm:grid-cols-[160px_minmax(0,1fr)] sm:items-baseline sm:gap-4">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 leading-relaxed wrap-anywhere">{children}</dd>
    </dl>
  );
}

export function JsonView({ value }: { value: unknown }) {
  return (
    <pre className="m-0 max-h-[480px] overflow-auto rounded-lg border bg-background/60 p-4 font-mono text-xs leading-relaxed whitespace-pre-wrap wrap-anywhere">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export function JsonField({
  name,
  label,
  value = {},
  rows = 6,
  helperText,
}: {
  name: string;
  label: string;
  value?: unknown;
  rows?: number;
  helperText?: string;
}) {
  const { t } = useTranslation();
  return (
    <TextareaField
      name={name}
      label={label}
      defaultValue={JSON.stringify(value, null, 2)}
      rows={rows}
      hint={helperText ?? t('jsonHelp')}
      spellCheck={false}
      className="font-mono text-xs"
    />
  );
}

export function Copy({ value }: { value: string }) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const task = useTask();
  useEffect(() => {
    if (copied) {
      const timer = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(timer);
    }
  }, [copied]);
  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon-sm"
            className="ml-1 align-middle text-muted-foreground"
            aria-label={t(copied ? 'copied' : 'copy')}
            onClick={() =>
              task.run(async () => {
                await navigator.clipboard.writeText(value);
                setCopied(true);
              })
            }
          >
            {copied ? (
              <Check className="size-3.5 text-emerald-400" />
            ) : (
              <CopyIcon className="size-3.5" />
            )}
          </Button>
        </TooltipTrigger>
        <TooltipContent>{t(copied ? 'copied' : 'copy')}</TooltipContent>
      </Tooltip>
      <ErrorNotice error={task.error} />
    </>
  );
}

export function SaveBar({
  back,
  label = 'save',
  busy = false,
  fixedOnMobile = false,
}: {
  back: string;
  label?: string;
  busy?: boolean;
  fixedOnMobile?: boolean;
}) {
  const { t } = useTranslation();
  const navigation = useNavigation();
  return (
    <div className={cn('flex flex-wrap items-center gap-2 pt-2', fixedOnMobile &&
      'fixed inset-x-0 bottom-0 z-30 border-t bg-background px-4 pt-3 pb-[calc(0.75rem+env(safe-area-inset-bottom))] sm:static sm:z-auto sm:border-0 sm:bg-transparent sm:px-0 sm:pt-2 sm:pb-0')}>
      <Button type="submit" className={fixedOnMobile ? 'h-11 flex-1 sm:h-9 sm:flex-none' : undefined}
        loading={busy || navigation.state === 'submitting'}>
        {t(label)}
      </Button>
      <Button asChild variant="ghost">
        <Link to={back}>{t('cancel')}</Link>
      </Button>
    </div>
  );
}

export function Confirm({
  label,
  name,
  body,
  children,
  danger = true,
}: {
  label: string;
  name: string;
  body?: string;
  children?: ReactNode;
  danger?: boolean;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const navigation = useNavigation();
  useEffect(() => {
    if (navigation.state === 'loading') setOpen(false);
  }, [navigation.state]);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button
          variant="ghost"
          className={danger ? 'text-destructive hover:text-destructive' : undefined}
        >
          {label}
        </Button>
      </DialogTrigger>
      <DialogContent showCloseButton={false}>
        <Form method="post" className="space-y-5">
          <DialogHeader>
            <DialogTitle>{danger ? t('deleteTitle', { name }) : label}</DialogTitle>
            <DialogDescription>{body ?? t('deleteBody')}</DialogDescription>
          </DialogHeader>
          {children}
          <DialogFooter>
            <Button variant="outline" autoFocus onClick={() => setOpen(false)}>
              {t('cancel')}
            </Button>
            <Button
              type="submit"
              variant={danger ? 'destructive' : 'default'}
              loading={navigation.state === 'submitting'}
            >
              {label}
            </Button>
          </DialogFooter>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

export function useTask() {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return {
    error,
    busy,
    clear: () => setError(null),
    run: async <T,>(operation: () => Promise<T>): Promise<T | undefined> => {
      setBusy(true);
      setError(null);
      try {
        return await operation();
      } catch (error) {
        setError(errorCode(error));
        return undefined;
      } finally {
        setBusy(false);
      }
    },
  };
}

export function usePolling(active: boolean, milliseconds = 2500) {
  const revalidator = useRevalidator();
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible' && revalidator.state === 'idle')
        void revalidator.revalidate();
    }, milliseconds);
    return () => clearInterval(timer);
  }, [active, milliseconds, revalidator]);
}

// Moves through one list of a page: param names where the list's position is kept, for a page with more than one.
export function Paging({ next, search, param = 'after' }: { next: string | null; search: URLSearchParams; param?: string }) {
  const { t } = useTranslation();
  const more = new URLSearchParams(search);
  if (next) more.set(param, next);
  const first = new URLSearchParams(search);
  first.delete(param);
  return next || search.has(param) ? (
    <nav aria-label={t('pagination')} className="flex items-center justify-end gap-2">
      {search.has(param) && (
        <Button asChild variant="outline">
          <Link to={'?' + first}>
            <ChevronLeft className="size-4" />
            {t('firstPage')}
          </Link>
        </Button>
      )}
      {next && (
        <Button asChild variant="outline">
          <Link to={'?' + more}>
            {t('more')}
            <ChevronRight className="size-4" />
          </Link>
        </Button>
      )}
    </nav>
  ) : null;
}

export function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex w-fit items-center gap-1.5 text-sm underline-offset-4 hover:underline"
    >
      {children}
      <ExternalLinkIcon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
    </a>
  );
}
