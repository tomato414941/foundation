import { useTranslation } from 'react-i18next';
import type { ConnectionView } from '../../shared/contracts';
import { Detail } from './components';
import { AwsConnectionFacts } from './aws-connection-facts';
export type ConnectionFactsValue = Pick<
  ConnectionView['data'],
  'account' | 'accountId' | 'accountVerified' | 'scopes' | 'scopesStatus' | 'aws'
>;
export function ConnectionFacts({ value }: { value: ConnectionFactsValue }) {
  const { t } = useTranslation();
  return (
    <>
      <Detail label={t('accountName')}>
        {value.account || t('accountUnverified')}
        {value.account && !value.accountVerified && (
          <p className="leading-relaxed text-muted-foreground text-sm">{t('accountUnverified')}</p>
        )}
      </Detail>
      {value.accountId && value.accountId !== value.account && (
        <Detail label={t('externalAccountId')}>{value.accountId}</Detail>
      )}
      {value.aws ? <AwsConnectionFacts value={value.aws} /> : <Detail label={t('scopes')}>
        {value.scopesStatus === 'unknown' ? (
          t('scopesUnknown')
        ) : (
          <>
            {value.scopes.join(', ') || t('scopesEmpty')}
            <p className="leading-relaxed text-muted-foreground text-sm">
              {t('scopes.' + value.scopesStatus)}
            </p>
          </>
        )}
      </Detail>}
    </>
  );
}
