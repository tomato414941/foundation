import { useTranslation } from 'react-i18next';
import type { OvhInfo } from '../../shared/ovh';
import { Detail } from './components';

export function OvhConnectionFacts({ value }: { value: OvhInfo }) {
  const { t, i18n } = useTranslation();
  return <>
    <Detail label={t('ovhApiPermissions')}>
      {value.rules.map(rule => rule.method + ' ' + rule.path).join(', ') || t('scopesEmpty')}
      <p className="mt-1 text-sm text-muted-foreground">{t('ovhIamPermissionsHelp')}</p>
    </Detail>
    {value.expiresAt !== null && <Detail label={t('ovhKeyExpiresAt')}>
      {new Date(value.expiresAt).toLocaleString(i18n.language === 'ja' ? 'ja-JP' : 'en-US')}
    </Detail>}
    {!!value.allowedIPs?.length && <Detail label={t('ovhAllowedIPs')}>{value.allowedIPs.join(', ')}</Detail>}
  </>;
}
