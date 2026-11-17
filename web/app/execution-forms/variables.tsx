import { useTranslation } from 'react-i18next';
import type { DefinitionCall } from '../../../shared/executions';
import { formText } from '../api';
import { TextareaField } from '../form-fields';
import { defineForm } from './types';
import { loadOwner, OwnerFields } from './common';
import type { OwnedForm } from './common';

export const variableForm = defineForm({
  load: (invocation: DefinitionCall) => loadOwner(invocation),
  submit: (data: OwnedForm, form: FormData) => ({ input: { ...data.invocation.input,
    name: data.invocation.input.name ?? formText(form, 'name') },
    material: { value: formText(form, 'value') } }),
  Fields: ({ data }: { data: OwnedForm }) => {
    const { t } = useTranslation();
    return <><OwnerFields data={data} name /><TextareaField name="value" label={t('value')} autoComplete="off" rows={5} required /></>;
  },
});
