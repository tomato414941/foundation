import { Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { ConnectionView } from '../../shared/contracts';
import { Detail } from './components';

export type ConnectionFactsValue = Pick<
  ConnectionView['data'],
  'account' | 'accountId' | 'accountVerified' | 'scopes' | 'scopesStatus'
>;

export function ConnectionFacts({ value }: { value: ConnectionFactsValue }) {
  const { t } = useTranslation();
  return (
    <>
      <Detail label={t('accountName')}>
        {value.account || t('accountUnverified')}
        {value.account && !value.accountVerified && (
          <Typography variant="body2" color="text.secondary">
            {t('accountUnverified')}
          </Typography>
        )}
      </Detail>
      {value.accountId && value.accountId !== value.account && (
        <Detail label={t('externalAccountId')}>{value.accountId}</Detail>
      )}
      <Detail label={t('scopes')}>
        {value.scopesStatus === 'unknown' ? (
          t('scopesUnknown')
        ) : (
          <>
            {value.scopes.join(', ') || t('scopesEmpty')}
            <Typography variant="body2" color="text.secondary">
              {t('scopes.' + value.scopesStatus)}
            </Typography>
          </>
        )}
      </Detail>
    </>
  );
}
