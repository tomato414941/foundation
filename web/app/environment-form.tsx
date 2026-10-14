import { useState } from 'react';
import type { ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { EnvironmentOptions, Payment, Usage } from '../../shared/contracts';
import type { z } from 'zod';
import { Notice, Panel, SaveBar } from './components';
import { CheckboxField, InputField } from './form-fields';
import { Button } from './components/ui/button';
import { SSHKeyInput } from './ssh-key-input';
import type { SSHKeyEntry } from './ssh-key-input';

function Setting({ title, summary, inline = false, children }: { title: string; summary?: string; inline?: boolean; children: ReactNode }) {
  return <details className="group border-t border-border pt-1" onInvalidCapture={event => { event.currentTarget.open = true; }}>
    <summary className="flex min-h-14 cursor-pointer list-none items-center justify-between gap-3 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring [&::-webkit-details-marker]:hidden">
      <span className={inline ? 'flex min-w-0 flex-1 flex-wrap items-baseline justify-between gap-x-4 gap-y-1' : 'grid min-w-0 gap-1'}>
        <span className="text-sm font-medium">{title}</span>
        {summary && <span className="text-xs text-muted-foreground">{summary}</span>}
      </span>
      <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden="true" />
    </summary>
    <div className="pt-3">{children}</div>
  </details>;
}

export function EnvironmentForm({ owner, usage, payment, canManageBilling, canManagePayment,
  ssh, available, back, busy }: {
  owner: { id: string };
  usage: z.infer<typeof Usage> | null;
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
  const [idleEnabled, setIdleEnabled] = useState(false);
  const [maximumEnabled, setMaximumEnabled] = useState(false);
  const [keys, setKeys] = useState<SSHKeyEntry[]>([]);
  const [readingKeys, setReadingKeys] = useState(false);
  const idleMinutes = Number(idle), maximumMinutes = Number(maximum);
  const validMinutes = (value: number) => Number.isInteger(value) && value >= 1 && value * 60 <= 2147483647;
  const invalidRange = idleEnabled && !validMinutes(idleMinutes) || maximumEnabled && !validMinutes(maximumMinutes);
  const remaining = usage ? Math.max(0, usage.computeLimit - usage.computeSeconds) : null;
  const insufficient = remaining !== null && remaining < { small: 1, medium: 2, large: 4 }[size];
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
      <Setting title={t('environmentLifetime')} inline summary={[
        maximumEnabled ? t('environmentMaximumSummary', { minutes: maximum }) : '',
        idleEnabled ? t('environmentIdleSummary', { minutes: idle }) : '',
      ].filter(Boolean).join(' / ') || t('none')}>
        <div className="grid gap-5 sm:grid-cols-2">
          <div className="grid content-start gap-3">
            <CheckboxField label={t('environmentMaximumEnabled')} checked={maximumEnabled}
              onCheckedChange={value => setMaximumEnabled(value === true)} />
            {maximumEnabled && <InputField type="number" name="maximum" label={t('maximum')} value={maximum}
              onChange={event => setMaximum(event.target.value)} required min={1} max={Math.floor(2147483647 / 60)} />}
          </div>
          <div className="grid content-start gap-3">
            <CheckboxField label={t('environmentIdleEnabled')} checked={idleEnabled}
              onCheckedChange={value => setIdleEnabled(value === true)} />
            {idleEnabled && <InputField type="number" name="idle" label={t('idle')} value={idle}
              onChange={event => setIdle(event.target.value)} required min={1} max={Math.floor(2147483647 / 60)} />}
          </div>
        </div>
      </Setting>
      {invalidRange && <p role="alert" className="text-sm text-destructive">
        {t('environmentLifetimeRange')}
      </p>}
      {ssh && <Setting title={t('environmentSSH')}
        summary={keyCount ? t('environmentSSHKeyCount', { count: keyCount }) : undefined}>
        <SSHKeyInput value={keys} onChange={setKeys} reading={readingKeys} onReadingChange={setReadingKeys} />
      </Setting>}
    </Panel>
    <SaveBar back={back} label="create" busy={busy} fixedOnMobile
      disabled={!available || paymentRequired || insufficient || invalidRange || readingKeys}
      summary={<div className="grid gap-2">
        <div aria-live="polite" className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 text-sm">
          {remaining !== null && <span className="text-muted-foreground">{t('environmentRemainingQuota', { minutes: minutes(remaining) })}</span>}
        </div>
        {insufficient && <p role="alert" className="text-xs leading-relaxed text-destructive">
          {t('environmentQuotaExhausted')}
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
