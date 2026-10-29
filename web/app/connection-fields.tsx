import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import type { AppState } from '../../shared/connections';
import type { ConnectionField } from '../../shared/connection-methods';
import { InputField, SelectField } from './form-fields';
import { SelectItem } from './components/ui/select';
import { Detail } from './components';
import { serviceLabels } from './service-labels';
import { activeConnectionField } from '../../shared/connection-fields';

export interface ConnectionFieldsProps {
  purpose: 'connection' | 'app';
  compact?: boolean;
  method?: CatalogConnectionMethod;
  existing: ResourceView | null;
  appMaterial: AppState | null;
  apps: ResourceView[];
  selectedAppId?: string;
  clientId?: string;
  preparedFields?: Record<string, string>;
  preparedScopes?: string[];
  fieldValues?: Record<string, string>;
  onFieldsChange?: (values: Record<string, string>) => void;
  reusableFields?: string[];
  appSetupUrl?: string;
}
// The chosen file's text is submitted as the field's value; the file itself is not.
function FileTextField({ name, label, required, hint }: { name: string; label: string; required: boolean; hint?: string }) {
  const { t } = useTranslation(), [text, setText] = useState('');
  return <>
    <InputField type="file" label={label} required={required} hint={hint} onChange={event => {
      const input = event.currentTarget, file = input.files?.[0];
      setText('');
      input.setCustomValidity(file && file.size > 16384 ? t('fileTooLarge') : '');
      if (file && file.size <= 16384) void file.text().then(setText, () => input.setCustomValidity(t('fileUnreadable')));
    }} />
    <input type="hidden" name={name} value={text} />
  </>;
}
export function ServiceFields({ method, fields, defaults = {}, existing, appMaterial, preparedFields = {}, fieldValues = {}, onFieldsChange, reusableFields = [] }: {
  method: CatalogConnectionMethod; fields: ConnectionField[]; defaults?: Record<string, string>;
  existing: ResourceView | null; appMaterial: AppState | null;
  preparedFields?: Record<string, string>; fieldValues?: Record<string, string>;
  onFieldsChange?: (values: Record<string, string>) => void;
  reusableFields?: string[];
}) {
  const { i18n, t } = useTranslation(), service = method.id.split(':')[0];
  const values = Object.fromEntries(fields.map(field => [field.name,
    preparedFields[field.name] ?? fieldValues[field.name] ?? defaults[field.name] ?? field.defaultValue ?? '']));
  return fields.filter(field => activeConnectionField(field, values)).map(field => {
    const label = i18n.language === 'ja' ? serviceLabels[`${service}.${method.kind}.${field.name}.label`] ?? field.label : field.label;
    const value = preparedFields[field.name] || fieldValues[field.name] || (existing?.kind === 'app' ? appMaterial?.fields[field.name] : '') || defaults[field.name] || field.defaultValue || '';
    const choiceLabel = (choice: NonNullable<ConnectionField['choices']>[number]) => i18n.language === 'ja'
      ? serviceLabels[`${service}.${method.kind}.${field.name}.${choice.value}.label`] ?? choice.label : choice.label;
    if (preparedFields[field.name]) return <div key={field.name}>
      <Detail label={label}>{field.choices?.find(choice => choice.value === value) ? choiceLabel(field.choices.find(choice => choice.value === value)!) : value}</Detail>
      <input type="hidden" name={'field.' + field.name} value={value} />
    </div>;
    if (field.choices) return <SelectField key={field.name} name={'field.' + field.name} label={label}
      value={value} required={field.required ?? true} onValueChange={value => onFieldsChange?.({ [field.name]: value })}>
      {field.choices.map(choice => <SelectItem key={choice.value} value={choice.value}>{choiceLabel(choice)}</SelectItem>)}
    </SelectField>;
    const reusable = field.secret !== false && reusableFields.includes(field.name);
    if (field.inputType === 'file') return <FileTextField key={field.name} name={'field.' + field.name} label={label}
      required={!reusable && (field.required ?? true)}
      hint={reusable ? t('unchangedSecret') : i18n.language === 'ja' ? serviceLabels[`${service}.${method.kind}.${field.name}.note`] ?? field.note : field.note} />;
    return <InputField key={field.name} name={'field.' + field.name} label={label}
      type={field.inputType ?? (field.secret !== false ? 'password' : 'text')} required={!reusable && (field.required ?? true)} defaultValue={value}
      onChange={field.secret !== false ? undefined : event => onFieldsChange?.({ [field.name]: event.target.value })}
      placeholder={field.placeholder} autoComplete="off"
      hint={reusable ? t('unchangedSecret') : i18n.language === 'ja' ? serviceLabels[`${service}.${method.kind}.${field.name}.note`] ?? field.note : field.note} />;
  });
}
