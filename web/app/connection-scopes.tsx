import { useTranslation } from 'react-i18next';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import { selectScopes } from '../../shared/connection-methods';
import { serviceLabels } from './service-labels';

export function PreparedConnectionScopes({ method, scopes, existing, reviewAccess = false }: {
  method: CatalogConnectionMethod; scopes: string[]; existing: ResourceView | null; reviewAccess?: boolean;
}) {
  const { t, i18n } = useTranslation();
  if (method.kind !== 'oauth' && method.kind !== 'ovh') return null;
  const definition = method.config.scopes, selected = selectScopes(definition, scopes);
  const previous = existing?.kind === 'connection' ? existing.data.scopes : null;
  const unchanged = previous && JSON.stringify([...previous].sort()) === JSON.stringify([...selected].sort());
  return <>
    <input type="hidden" name="scopes" value={selected.join(definition.separator)} />
    {(!unchanged || reviewAccess) && selected.length > 0 && <div className="flex flex-col gap-2">
      <p className="text-sm font-medium">{t('connectionPermissions')}</p>
      <ul className="list-disc space-y-1 pl-5 text-sm leading-relaxed wrap-anywhere">
        {selected.map(scope => {
          const name = definition.values?.find(value => value.id === scope)?.name ?? scope;
          return <li key={scope}>{i18n.language === 'ja'
            ? serviceLabels[`${method.id}.scope.${scope}`] ?? name : name}</li>;
        })}
      </ul>
    </div>}
  </>;
}
