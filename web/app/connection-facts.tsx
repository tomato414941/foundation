import type { ConnectionView } from '../../shared/contracts';
import { ConnectionSettings } from './connection-settings';
import { AwsConnectionFacts } from './aws-connection-facts';
import { Detail } from './components';
import { useTranslation } from 'react-i18next';
export type ConnectionFactsValue = Pick<ConnectionView['data'], 'methodId' | 'settings' | 'aws' | 'scopes' | 'scopesStatus'>;
export function ConnectionFacts({ value }: { value: ConnectionFactsValue }) {
  const { t } = useTranslation();
  return <>
    <ConnectionSettings methodId={value.methodId} settings={value.settings} />
    {value.aws && <AwsConnectionFacts value={value.aws} />}
    {value.scopesStatus === 'requested' && value.scopes.length > 0 && <Detail label={t('requestedPermissions')}>{value.scopes.join(', ')}</Detail>}
  </>;
}
