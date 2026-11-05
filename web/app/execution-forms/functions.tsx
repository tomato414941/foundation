import { useTranslation } from 'react-i18next';
import { Resource } from '../../../shared/contracts';
import type { JsonValue } from '../../../shared/contracts';
import type { DefinitionCall } from '../../../shared/executions';
import { api } from '../api';
import { Detail } from '../components';
import { defineForm } from './types';
import { EnvironmentFields, loadOwner, OwnerFields } from './common';
import { reviewer, ReviewRows } from '../operation-review';

async function load(invocation: DefinitionCall) {
  const fn = invocation.name === 'function.configure' ? await api('/functions/' + invocation.input.functionId, {}, Resource) : null;
  const rows = reviewer({ approver: null, principals: [], inspect: true, signal: new AbortController().signal });
  const [owned, review] = await Promise.all([loadOwner(invocation, fn?.ownerId, !!invocation.input.environmentId),
    rows((invocation.name === 'function.save' ? invocation.input.definition : invocation.input.inputAccess) as Record<string, JsonValue>)]);
  return { ...owned, fn, review };
}
type Data = Awaited<ReturnType<typeof load>>;
export const functionForm = defineForm({ load, submit: (data: Data) => ({ input: data.invocation.input, material: {} }),
  Fields: ({ data }: { data: Data }) => {
    const { t } = useTranslation(), { name, input } = data.invocation;
    return <><OwnerFields data={data} name={name === 'function.save'} />
      {name === 'function.save' ? <ReviewRows rows={data.review} /> : <>
        <Detail label={t('singular.function')}>{data.fn?.name}</Detail>
        {input.environmentId ? <EnvironmentFields data={data} /> : <Detail label={t('executionDestination')}>{t('none')}</Detail>}
        <ReviewRows rows={data.review} />
      </>}
    </>;
  },
});
