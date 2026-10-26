import { useTranslation } from 'react-i18next';
import { Check } from 'lucide-react';
import type { CatalogConnectionMethod } from '../../shared/contracts';
import { selectScopes } from '../../shared/connection-methods';
import { serviceLabels } from './service-labels';

export function PreparedConnectionScopes({ method, scopes }: {
  method: CatalogConnectionMethod; scopes: string[];
}) {
  const { t, i18n } = useTranslation();
  if (method.kind !== 'oauth' && method.kind !== 'ovh') return null;
  const definition = method.config.scopes, selected = selectScopes(definition, scopes);
  return <>
    <input type="hidden" name="scopes" value={selected.join(definition.separator)} />
    {selected.length > 0 && <section className="flex flex-col gap-4 border-t border-border pt-6">
      <h2 className="text-xs font-medium leading-relaxed text-muted-foreground">{t('connectionPermissions')}</h2>
      <ul className="flex flex-col gap-3 text-sm leading-relaxed wrap-anywhere sm:text-base">
        {selected.map(scope => {
          const name = definition.values?.find(value => value.id === scope)?.name ?? scope;
          return <li key={scope} className="flex items-start gap-3">
            <Check className="mt-1 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            <span>{i18n.language === 'ja' ? serviceLabels[`${method.id}.scope.${scope}`] ?? name : name}</span>
          </li>;
        })}
      </ul>
    </section>}
  </>;
}
