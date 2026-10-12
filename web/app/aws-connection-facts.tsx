import { useTranslation } from 'react-i18next';
import type { z } from 'zod';
import type { AwsConnectionInfo } from '../../shared/aws';
import { Detail } from './components';

export function AwsConnectionFacts({ value }: { value: z.infer<typeof AwsConnectionInfo> }) {
  const { t, i18n } = useTranslation();
  return <>
    <Detail label={t('awsAuthenticationMethod')}>{t('awsAuth.' + value.authentication)}</Detail>
    {value.roleArn && <Detail label={t('roleArn')}>{value.roleArn}</Detail>}
    <Detail label={t('region')}>{value.region}</Detail>
    {value.expiresAt && <Detail label={t('awsExpiresAt')}>
      {new Date(value.expiresAt).toLocaleString(i18n.language === 'ja' ? 'ja-JP' : 'en-US')}
    </Detail>}
  </>;
}
