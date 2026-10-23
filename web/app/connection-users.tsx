import { useTranslation } from 'react-i18next';
import { DateText, Detail } from './components';

export function ConnectionUsers({ users, expiresAt }: { users: { name: string }[]; expiresAt?: string }) {
  const { t } = useTranslation();
  if (!users.length) return <p className="text-sm leading-relaxed">{t('requestConnectionNoUsers')}</p>;
  return <div className="flex flex-col gap-2">
    <Detail label={t('requestConnectionUsers')}>{users.map(user => user.name).join(', ')}</Detail>
    <p className="text-sm leading-relaxed text-muted-foreground">{t(expiresAt ? 'requestConnectionPermissionsHelp' : 'requestConnectionUsersHelp')}</p>
    {expiresAt && <Detail label={t('expires')}><DateText value={expiresAt} /></Detail>}
  </div>;
}
