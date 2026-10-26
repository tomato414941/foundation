import { useTranslation } from 'react-i18next';
import { DateText, Detail } from './components';

export function ConnectionUsers({ users, expiresAt, review = false }: { users: { name: string }[]; expiresAt?: string; review?: boolean }) {
  const { t } = useTranslation();
  if (review) return <section className="flex flex-col gap-4 border-t border-border pt-6">
    <h2 className="text-xs font-medium leading-relaxed text-muted-foreground">{t('requestConnectionPrincipals')}</h2>
    {users.length ? <>
      <div className="flex items-start justify-between gap-4">
        <p className="min-w-0 text-sm font-medium leading-relaxed wrap-anywhere sm:text-base">{users.map(user => user.name).join(', ')}</p>
        {!expiresAt && <span className="shrink-0 rounded-md border border-border bg-muted px-2 py-0.5 text-xs leading-relaxed">{t('requestConnectionDuration')}</span>}
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground sm:text-sm">{t('requestConnectionAccess')}</p>
      {expiresAt && <Detail label={t('expires')}><DateText value={expiresAt} /></Detail>}
    </> : <p className="text-sm leading-relaxed">{t('requestConnectionNoUsers')}</p>}
  </section>;
  if (!users.length) return <p className="text-sm leading-relaxed">{t('requestConnectionNoUsers')}</p>;
  return <div className="flex flex-col gap-2">
    <Detail label={t('requestConnectionUsers')}>{users.map(user => user.name).join(', ')}</Detail>
    <p className="text-sm leading-relaxed text-muted-foreground">{t(expiresAt ? 'requestConnectionPermissionsHelp' : 'requestConnectionUsersHelp')}</p>
    {expiresAt && <Detail label={t('expires')}><DateText value={expiresAt} /></Detail>}
  </div>;
}
