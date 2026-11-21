import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { PrincipalView } from '../../shared/contracts';
import { SelectItem } from './components/ui/select';
import { InputField, SelectField } from './form-fields';

export function PrincipalField({ name, label, idLabel, principals }: {
  name: string;
  label: string;
  idLabel: string;
  principals: Pick<PrincipalView, 'id' | 'name'>[];
}) {
  const { t } = useTranslation();
  const [choice, setChoice] = useState('');
  const enterId = principals.length === 0 || choice === 'id';
  return <>
    {principals.length > 0 && <SelectField
      name={enterId ? undefined : name}
      label={label}
      placeholder={t('selectPrincipal')}
      value={choice}
      onValueChange={setChoice}
      required
    >
      {principals.map(principal => <SelectItem key={principal.id} value={principal.id}>{principal.name}</SelectItem>)}
      <SelectItem value="id">{t('enterPrincipalId')}</SelectItem>
    </SelectField>}
    {enterId && <InputField name={name} label={idLabel} autoComplete="off" required />}
  </>;
}
