import { useState } from 'react';
import type { ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Resource, listOf } from '../../shared/contracts';
import type { EnvironmentOptions, Payment, Usage } from '../../shared/contracts';
import type { z } from 'zod';
import { api } from './api';
import { Notice, Panel, SaveBar } from './components';
import { InputField } from './form-fields';
import { Button } from './components/ui/button';
import { SSHKeyInput } from './ssh-key-input';
import type { SSHKeyEntry } from './ssh-key-input';

const computeWeights = { small: 1, medium: 2, large: 4 };

function Setting({ title, summary, children }: { title: string; summary?: string; children: ReactNode }) {
  return <details className="group border-t border-border pt-1" onInvalidCapture={event => { event.currentTarget.open = true; }}>
    <summary className="flex min-h-14 cursor-pointer list-none items-center justify-between gap-3 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring [&::-webkit-details-marker]:hidden">
      <span className="grid min-w-0 gap-1">
        <span className="text-sm font-medium">{title}</span>
        {summary && <span className="text-xs text-muted-foreground">{summary}</span>}
      </span>
      <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden="true" />
    </summary>
    <div className="pt-3">{children}</div>
  </details>;
}

export async function environmentReservations(ownerId: string, signal: AbortSignal) {
  let reserved = 0, after: string | null = null;
  do {
    const query = new URLSearchParams({ kind: 'environment', limit: '200' });
    if (after) query.set('after', after);
    const page = await api(`/principals/${ownerId}/resources?${query}`, { signal }, listOf(Resource));
    for (const item of page.items) if (item.kind === 'environment' && item.data.driver !== 'attached' &&
      ['starting', 'running', 'stopping'].includes(item.data.state)) {
      reserved += item.data.lifetime.maxSeconds * computeWeights[item.data.size];
    }
    after = page.next;
  } while (after);
  return reserved;
}

export function EnvironmentForm({ owner, usage, reservedSeconds, payment, canManageBilling, canManagePayment,
  ssh, available, back, busy }: {
  owner: { id: string };
  usage: z.infer<typeof Usage> | null;
  reservedSeconds: number;
  payment: z.infer<typeof Payment> | null;
  canManageBilling: boolean;
  canManagePayment: boolean;
  ssh: boolean;
  available: boolean;
  back: string;
  busy: boolean;
}) {
  const { t, i18n } = useTranslation();
  const [size, setSize] = useState<EnvironmentOptions['size']>('small');
  const [image, setImage] = useState('');
  const [idle, setIdle] = useState('60');
  const [maximum, setMaximum] = useState('60');
  const [keys, setKeys] = useState<SSHKeyEntry[]>([]);
  const [readingKeys, setReadingKeys] = useState(false);
  const idleMinutes = Number(idle), maximumMinutes = Number(maximum);
  const validMinutes = (value: number) => Number.isInteger(value) && value >= 1 && value <= 1440;
  const invalidRange = !validMinutes(idleMinutes) || !validMinutes(maximumMinutes);
  const idleTooLong = !invalidRange && idleMinutes > maximumMinutes;
  const required = validMinutes(maximumMinutes) ? maximumMinutes * 60 * computeWeights[size] : null;
  const remaining = usage ? Math.max(0, usage.computeLimit - usage.computeSeconds - reservedSeconds) : null;
  const shortfall = required === null || remaining === null ? 0 : Math.max(0, required - remaining);
  const insufficient = shortfall > 0;
  const paymentRequired = Boolean(payment?.required && !payment.active);
  const minutes = (seconds: number) => new Intl.NumberFormat(i18n.language).format(Math.floor(seconds / 60));
  const authorizedKeys = keys.map(key => key.value.trim()).filter(Boolean);
  const keyCount = new Set(authorizedKeys).size;
  const billingPath = `/p/${owner.id}/settings/billing`;
  return <>
    <Panel>
      <InputField name="name" label={t('name')} maxLength={200} />
      <fieldset className="grid min-w-0 gap-2">
        <legend className="mb-2 text-sm font-medium">{t('size')}</legend>
        <div className="grid grid-cols-3 gap-2">
          {(['small', 'medium', 'large'] as const).map(value => {
            const [name, capacity] = t(value).split(' — ');
            return <label key={value} className={'cursor-pointer rounded-lg border p-3 transition-colors ' +
              (size === value ? 'border-foreground/60 bg-muted/50' : 'border-border hover:border-foreground/30')}>
              <span className="flex items-center justify-between gap-1">
                <span className="text-sm font-medium">{name}</span>
                <input type="radio" name="size" value={value} aria-label={t(value)} checked={size === value}
                  onChange={() => setSize(value)} className="size-3.5 shrink-0 accent-current" />
              </span>
              <span className="mt-2 block text-xs leading-relaxed text-muted-foreground">{capacity}</span>
            </label>;
          })}
        </div>
      </fieldset>
      <Setting title={t('environmentCommandImage')} summary={t(image.trim() ? 'environmentCustomImage' : 'defaultImage')}>
        <InputField name="image" label={t('image')} placeholder={t('defaultImage')}
          value={image} onChange={event => setImage(event.target.value.trim())} maxLength={300}
          pattern={'[a-zA-Z0-9.\\/:_\\-]+@sha256:[a-f0-9]{64}'}
          hint={t('environmentImageHelp')} spellCheck={false} autoCapitalize="off" autoCorrect="off" />
      </Setting>
      <Setting title={t('environmentLifetime')} summary={invalidRange ? t('environmentLifetimeRange') :
        t('environmentLifetimeSummary', { idle, maximum })}>
        <div className="grid gap-4 sm:grid-cols-2">
          <InputField type="number" name="idle" label={t('idle')} value={idle}
            onChange={event => setIdle(event.target.value)} required min={1} max={1440}
            aria-invalid={idleTooLong || undefined} />
          <InputField type="number" name="maximum" label={t('maximum')} value={maximum}
            onChange={event => setMaximum(event.target.value)} required min={1} max={1440} />
        </div>
      </Setting>
      {(invalidRange || idleTooLong) && <p role="alert" className="text-sm text-destructive">
        {t(invalidRange ? 'environmentLifetimeRange' : 'environmentIdleTooLong')}
      </p>}
      {ssh && <Setting title={t('environmentSSH')}
        summary={keyCount ? t('environmentSSHKeyCount', { count: keyCount }) : undefined}>
        <SSHKeyInput value={keys} onChange={setKeys} reading={readingKeys} onReadingChange={setReadingKeys} />
      </Setting>}
    </Panel>
    <SaveBar back={back} label="create" busy={busy} fixedOnMobile
      disabled={!available || paymentRequired || insufficient || invalidRange || idleTooLong || readingKeys}
      summary={<div className="grid gap-2">
        <div aria-live="polite" className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 text-sm">
          <span className="font-medium">{t('environmentRequiredQuota', { minutes: required === null ? '—' : minutes(required) })}</span>
          {remaining !== null && <span className="text-muted-foreground">{t('environmentRemainingQuota', { minutes: minutes(remaining) })}</span>}
        </div>
        {insufficient && <p role="alert" className="text-xs leading-relaxed text-destructive">
          {t('environmentQuotaInsufficient', { minutes: new Intl.NumberFormat(i18n.language).format(Math.ceil(shortfall / 60)) })}
        </p>}
        {paymentRequired && <Notice action={canManagePayment && payment?.payer ?
          <Button asChild variant="ghost"><Link to={`/p/${payment.payer.id}/settings/billing`}>{t('addPayment')}</Link></Button> : undefined}>
          {t('paymentRequired')}
        </Notice>}
        {canManageBilling && <Link to={billingPath} className="inline-flex min-h-8 w-fit items-center text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground">
          {t('environmentQuotaSettings')}
        </Link>}
      </div>} />
  </>;
}
