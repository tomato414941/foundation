import { useTranslation } from 'react-i18next';
import type { DefinitionCall } from '../../../shared/executions';
import { formText } from '../api';
import { Detail, JsonView } from '../components';
import { defineForm } from './types';
import { EnvironmentFields, loadOwner, OwnerFields } from './common';
import type { OwnedForm } from './common';

export const runForm = defineForm({ load: (invocation: DefinitionCall) => loadOwner(invocation, undefined, true),
  submit: (data: OwnedForm, form: FormData) => ({ input: { ...data.invocation.input,
    environmentId: data.invocation.input.environmentId ?? formText(form, 'environmentId') }, material: {} }),
  Fields: ({ data }: { data: OwnedForm }) => {
    const { t } = useTranslation(), { name, input } = data.invocation;
    return <><OwnerFields data={data} />
      {name === 'connection.revoke' ? <Detail label={t('connectionTarget')}>{String(input.connectionId)}</Detail> : <JsonView value={input.operation} />}
      <EnvironmentFields data={data} />
    </>;
  },
});
