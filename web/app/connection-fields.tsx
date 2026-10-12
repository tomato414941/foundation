import { useTranslation } from 'react-i18next';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import type { AppState } from '../../shared/connections';
import type { ConnectionField } from '../../shared/connection-methods';
import { InputField, SelectField } from './form-fields';
import { SelectItem } from './components/ui/select';
import { Detail } from './components';
import { serviceLabels } from './service-labels';

export interface ConnectionFieldsProps {
  purpose: 'connection' | 'app';
  method?: CatalogConnectionMethod;
  existing: ResourceView | null;
  appMaterial: AppState | null;
  apps: ResourceView[];
  selectedAppId?: string;
  clientId?: string;
  preparedFields?: Record<string, string>;
  fieldValues?: Record<string, string>;
  onFieldsChange?: (values: Record<string, string>) => void;
}
export function ServiceFields({ method, fields, defaults = {}, existing, appMaterial, preparedFields = {}, fieldValues = {}, onFieldsChange }: {
  method: CatalogConnectionMethod; fields: ConnectionField[]; defaults?: Record<string, string>;
  existing: ResourceView | null; appMaterial: AppState | null;
  preparedFields?: Record<string, string>; fieldValues?: Record<string, string>;
  onFieldsChange?: (values: Record<string, string>) => void;
}) {
  const { i18n } = useTranslation(), service = method.id.split(':')[0];
  return fields.map(field => {
    const label = i18n.language === 'ja' ? serviceLabels[`${service}.${method.kind}.${field.name}.label`] ?? field.label : field.label;
    const value = preparedFields[field.name] || fieldValues[field.name] || (existing?.kind === 'app' ? appMaterial?.fields[field.name] : '') || defaults[field.name] || '';
    if (preparedFields[field.name]) return <div key={field.name}>
      <Detail label={label}>{field.choices?.find(choice => choice.value === value)?.label ?? value}</Detail>
      <input type="hidden" name={'field.' + field.name} value={value} />
    </div>;
    if (field.choices) return <SelectField key={field.name} name={'field.' + field.name} label={label}
      value={value} required={field.required ?? true} onValueChange={value => onFieldsChange?.({ [field.name]: value })}>
      {field.choices.map(choice => <SelectItem key={choice.value} value={choice.value}>{choice.label}</SelectItem>)}
    </SelectField>;
    return <InputField key={field.name} name={'field.' + field.name} label={label}
      type={field.secret !== false ? 'password' : 'text'} required={field.required ?? true} defaultValue={value}
      onChange={field.secret !== false ? undefined : event => onFieldsChange?.({ [field.name]: event.target.value })}
      placeholder={field.placeholder} autoComplete="off"
      hint={i18n.language === 'ja' ? serviceLabels[`${service}.${method.kind}.${field.name}.note`] ?? field.note : field.note} />;
  });
}
