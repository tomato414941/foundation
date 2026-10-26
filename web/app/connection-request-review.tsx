import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

export const connectionRequestAction = 'min-h-12 gap-5 rounded-lg px-5 text-sm sm:text-base';

export function ConnectionRequestReview({ title, from, name, message, children }: {
  title: string; from?: string; name?: string; message?: string; children: ReactNode;
}) {
  const { t } = useTranslation();
  return <section className="mx-auto flex w-full max-w-[536px] flex-col gap-8 pb-12 pt-8 sm:pt-12">
    <header>
      {from && <p className="mb-4 text-xs leading-relaxed text-muted-foreground sm:text-sm">{t('requestFrom', { name: from })}</p>}
      <h1 className="text-[28px] font-semibold leading-snug tracking-tight wrap-anywhere sm:text-[32px]">{title}</h1>
      {name && <p className="mt-2 text-sm leading-relaxed text-muted-foreground wrap-anywhere sm:text-base">{name}</p>}
      {message && <blockquote className="mt-6 border-l-2 border-border pl-3 text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground wrap-anywhere">{message}</blockquote>}
    </header>
    <div className="flex min-w-0 flex-col gap-6">{children}</div>
  </section>;
}
