import { useTranslation } from 'react-i18next';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import type { AppState } from '../../shared/connections';
import type { ConnectionField } from '../../shared/connection-methods';
import { InputField } from './form-fields';
import { serviceLabels } from './service-labels';

export interface ConnectionFieldsProps {
  purpose: 'connection' | 'app';
  method?: CatalogConnectionMethod;
  existing: ResourceView | null;
  appMaterial: AppState | null;
  apps: ResourceView[];
}
export function ServiceFields({ method, fields, defaults = {}, existing, appMaterial }: {
  method: CatalogConnectionMethod; fields: ConnectionField[]; defaults?: Record<string, string>;
  existing: ResourceView | null; appMaterial: AppState | null;
}) {
  const { i18n } = useTranslation(), service = method.id.split(':')[0];
  return fields.map(field => <InputField key={field.name} name={'field.' + field.name}
    label={i18n.language === 'ja' ? serviceLabels[`${service}.${method.kind}.${field.name}.label`] ?? field.label : field.label}
    type={field.secret ? 'password' : 'text'} required={field.required ?? true}
    defaultValue={existing?.kind === 'app' ? appMaterial?.fields[field.name] ?? '' : defaults[field.name] ?? ''}
    placeholder={field.placeholder} autoComplete="off"
    hint={i18n.language === 'ja' ? serviceLabels[`${service}.${method.kind}.${field.name}.note`] ?? field.note : field.note} />);
}
