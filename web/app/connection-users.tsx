import { useTranslation } from 'react-i18next';
import { Detail } from './components';

export function ConnectionUsers({ users, review = false }: { users: { name: string }[]; review?: boolean }) {
  const { t } = useTranslation();
  if (review) return <section className="flex flex-col gap-4 border-t border-border pt-6">
    <h2 className="text-xs font-medium leading-relaxed text-muted-foreground">{t('requestConnectionPrincipals')}</h2>
    {users.length ? <>
      <p className="min-w-0 text-sm font-medium leading-relaxed wrap-anywhere sm:text-base">{users.map(user => user.name).join(', ')}</p>
      <p className="text-xs leading-relaxed text-muted-foreground sm:text-sm">{t('requestConnectionAccess')}</p>
    </> : <p className="text-sm leading-relaxed">{t('requestConnectionNoUsers')}</p>}
  </section>;
  if (!users.length) return <p className="text-sm leading-relaxed">{t('requestConnectionNoUsers')}</p>;
  return <div className="flex flex-col gap-2">
    <Detail label={t('requestConnectionUsers')}>{users.map(user => user.name).join(', ')}</Detail>
    <p className="text-sm leading-relaxed text-muted-foreground">{t('requestConnectionUsersHelp')}</p>
  </div>;
}
