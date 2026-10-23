import { useTranslation } from 'react-i18next';
import type { CatalogConnectionMethod } from '../../shared/contracts';
import { connectionMethod, selectScopes } from '../../shared/connection-methods';
import { ExternalLink, Notice } from './components';
import { InputField } from './form-fields';
import { ApplicationConnectionFields } from './application-connection-fields';
import type { ConnectionFieldsProps } from './connection-fields';
import { servicePreparation } from './service-preparations';
import { PreparedConnectionScopes } from './connection-scopes';

export function OAuthConnectionHelp({ method, connecting = true }: { method?: CatalogConnectionMethod; connecting?: boolean }) {
  const { t, i18n } = useTranslation();
  if (method?.kind !== 'oauth') return null;
  const direct = !connectionMethod(method).browserAuthorization, setup = servicePreparation(method);
  return <>
    {(direct || !connecting && setup.instructions.length > 0) && <Notice tone="info">
      {direct && <p>{t('clientCredentialsHelp')}</p>}
      {setup.instructions.map((instruction, index) => <p key={index} className="mt-2">
        {typeof instruction === 'string' ? instruction : instruction[i18n.resolvedLanguage === 'ja' ? 'ja' : 'en']}
      </p>)}
      {setup.docs && method.docs && <ExternalLink href={method.docs}>{t('docs')}</ExternalLink>}
    </Notice>}
  </>;
}
export function OAuthConnectionFields(props: ConnectionFieldsProps) {
  const { method, existing } = props;
  const { t } = useTranslation();
  const spec = method?.kind === 'oauth' ? method.config : undefined;
  const behavior = method ? connectionMethod(method) : undefined;
  const requiredScopes = spec?.scopes.required ?? [];
  return <ApplicationConnectionFields {...props} callback={!method || behavior?.browserAuthorization}
    secretRequired={spec ? spec.clientAuth !== 'none' : false}>
    {method && spec && <>
      {props.compact && props.preparedScopes ? <PreparedConnectionScopes method={method} scopes={props.preparedScopes} existing={existing} reviewAccess={props.reviewAccess} />
        : servicePreparation(method).scopes && <InputField name="scopes" label={t('scopes')}
        defaultValue={selectScopes(spec.scopes, props.preparedScopes ?? (existing?.kind === 'connection' ? existing.data.scopes : undefined)).join(' ')}
        readOnly={!!props.preparedScopes} required={servicePreparation(method).scopesRequired} hint={requiredScopes.length ? t('scopesHelp') + ' ' + t('requiredScopesHelp', { scopes: requiredScopes.join(', ') }) : t('scopesHelp')} />}
      {!props.compact && spec.scopes.docs && <ExternalLink href={spec.scopes.docs}>{t('docs')}</ExternalLink>}
    </>}
  </ApplicationConnectionFields>;
}
