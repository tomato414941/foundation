import { useTranslation } from 'react-i18next';
import { Resource } from '../../../shared/contracts';
import type { DefinitionCall } from '../../../shared/executions';
import { api } from '../api';
import { Detail, JsonView } from '../components';
import { defineForm } from './types';
import { EnvironmentFields, loadOwner, OwnerFields } from './common';

async function load(invocation: DefinitionCall) {
  const fn = invocation.name === 'function.configure' ? await api('/functions/' + invocation.input.functionId, {}, Resource) : null;
  return { ...await loadOwner(invocation, fn?.ownerId, !!invocation.input.environmentId), fn };
}
type Data = Awaited<ReturnType<typeof load>>;
export const functionForm = defineForm({ load, submit: (data: Data) => ({ input: data.invocation.input, material: {} }),
  Fields: ({ data }: { data: Data }) => {
    const { t } = useTranslation(), { name, input } = data.invocation;
    return <><OwnerFields data={data} name={name === 'function.save'} />
      {name === 'function.save' ? <JsonView value={input.definition} /> : <>
        <Detail label={t('singular.function')}>{data.fn?.name}</Detail>
        {input.environmentId ? <EnvironmentFields data={data} /> : <Detail label={t('executionDestination')}>{t('none')}</Detail>}
        <JsonView value={input.inputAccess} />
      </>}
    </>;
  },
});
