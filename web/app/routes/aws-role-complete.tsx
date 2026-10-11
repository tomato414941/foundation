import { useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Notice, Page } from '../components';
import { completeAwsRoleSetup } from '../aws-role-setup';

export function clientLoader() { return completeAwsRoleSetup(new URL(window.location.href)); }
export default function AwsRoleComplete() {
  const result = useLoaderData<typeof clientLoader>(), { t } = useTranslation();
  return <Page title={t('awsAuthentication')} narrow>
    <Notice tone={result ? 'success' : 'error'}>{t(result ? 'awsRoleReturned' : 'awsRoleReturnInvalid')}</Notice>
  </Page>;
}
