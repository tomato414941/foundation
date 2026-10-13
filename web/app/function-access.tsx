import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { InputField, SelectField } from './form-fields';
import { SelectItem } from './components/ui/select';
import { ApiFailure, formText } from './api';

function localDate(value?: string | null) {
  if (!value) return '';
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function inputAccessFromForm(form: FormData) {
  if (formText(form, 'inputAccessKind') !== 'expires') return { expiresAt: null };
  const date = new Date(formText(form, 'inputExpiresAt'));
  if (!Number.isFinite(date.getTime()) || date.getTime() <= Date.now()) throw new ApiFailure('invalid_input');
  return { expiresAt: date.toISOString() };
}

export function FunctionAccessFields({ access }: { access?: { expiresAt: string | null } }) {
  const { t } = useTranslation();
  const [kind, setKind] = useState(access?.expiresAt ? 'expires' : 'continuous');
  return <div className="grid gap-4">
    <SelectField name="inputAccessKind" label={t('functionInputAccess')} value={kind} onValueChange={setKind}>
      <SelectItem value="continuous">{t('functionInputContinuous')}</SelectItem>
      <SelectItem value="expires">{t('functionInputExpiring')}</SelectItem>
    </SelectField>
    {kind === 'expires' && <InputField name="inputExpiresAt" label={t('functionInputExpires')} type="datetime-local"
      required defaultValue={localDate(access?.expiresAt)} min={localDate(new Date().toISOString())} />}
    <p className="text-sm text-muted-foreground">{t('functionInputAccessHelp')}</p>
  </div>;
}
