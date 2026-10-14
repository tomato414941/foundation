import { useTranslation } from 'react-i18next';
import type { DefinitionCall } from '../../../shared/executions';
import { formText } from '../api';
import { TextareaField } from '../form-fields';
import { defineForm } from './types';
import { EnvironmentFields, loadOwner, OwnerFields } from './common';
import type { OwnedForm } from './common';

export const variableForm = defineForm({
  load: (invocation: DefinitionCall) => loadOwner(invocation, undefined, Array.isArray(invocation.input.environmentIds) && invocation.input.environmentIds.length > 0),
  submit: (data: OwnedForm, form: FormData) => ({ input: { ...data.invocation.input,
    name: data.invocation.input.name ?? formText(form, 'name'),
    environmentIds: data.invocation.input.environmentIds ?? form.getAll('environments').map(String) },
    material: { value: formText(form, 'value') } }),
  Fields: ({ data }: { data: OwnedForm }) => {
    const { t } = useTranslation(), input = data.invocation.input;
    return <><OwnerFields data={data} name /><TextareaField name="value" label={t('value')} autoComplete="off" rows={5} required />
      {Array.isArray(input.environmentIds) && input.environmentIds.length > 0 && <EnvironmentFields data={data} />}</>;
  },
});
