import { useTranslation } from 'react-i18next';

export function ConnectionUsers({ users }: { users: { name: string }[] }) {
  const { t } = useTranslation();
  return <section className="flex flex-col gap-4 border-t border-border pt-6">
    <h2 className="text-xs font-medium leading-relaxed text-muted-foreground">{t('requestConnectionPrincipals')}</h2>
    {users.length ? <>
      <p className="min-w-0 text-sm font-medium leading-relaxed wrap-anywhere sm:text-base">{users.map(user => user.name).join(', ')}</p>
      <p className="text-xs leading-relaxed text-muted-foreground sm:text-sm">{t('requestConnectionAccess')}</p>
    </> : <p className="text-sm leading-relaxed">{t('requestConnectionNoUsers')}</p>}
  </section>;
}
