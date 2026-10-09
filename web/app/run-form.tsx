import { InputField } from './form-fields';
import { Form, redirect, useActionData, useLoaderData } from 'react-router';
import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Principal, Resource } from '../../shared/contracts';
import type { ExecutionOperation } from '../../shared/execution';
import { actionResult, api, ApiFailure, formText, jsonField } from './api';
import { ErrorNotice, JsonField, Page, Panel, SaveBar } from './components';
import { RequestFields } from './resource-form';
import { resourcePath } from './navigation';
import { custodyClient } from './custody';
import { availableEnvironments, EnvironmentChoice } from './environments';
async function runResource(params: LoaderFunctionArgs['params']) {
  if (!params.id) return null;
  const resource = await api('/resources/' + params.id, {}, Resource);
  if (resource.kind !== 'function' || resource.ownerId !== params.owner)
    throw new Response('Not found', { status: 404 });
  return resource;
}
export async function runLoader({ params }: LoaderFunctionArgs) {
  const [resource, environments] = await Promise.all([
    runResource(params),
    availableEnvironments(params.owner!),
  ]);
  return { resource, environments };
}
export async function runAction({ params, request }: ActionFunctionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const resource = await runResource(params);
    let input: ExecutionOperation;
    if (resource?.kind === 'function')
      input = {
        kind: 'function',
        definition: resource.data,
        outputs: {},
        arguments: Object.fromEntries(
          [...form.entries()]
            .filter(([key]) => key.startsWith('argument.'))
            .map(([key, value]) => [key.slice(9), String(value)]),
        ),
      };
    else
      input = {
        kind: 'http',
        request: {
          url: formText(form, 'url'),
          method: formText(form, 'httpMethod') as 'GET',
          headers: jsonField(form, 'headers', {}),
          ...(formText(form, 'body') ? { body: String(form.get('body')) } : {}),
          bindings: jsonField(form, 'bindings', []),
        },
        save: {},
      };
    const client = await custodyClient();
    let ownerId = params.owner!;
    try {
      const owner = await api('/principals/' + ownerId, {}, Principal);
      if (!owner.permissions.includes('execute')) ownerId = client.binding.principalId;
    } catch (error) {
      if (!(error instanceof ApiFailure) || error.status !== 403) throw error;
      ownerId = client.binding.principalId;
    }
    const result = await client.submit(ownerId, formText(form, 'environmentId'), input,
      { save: jsonField(form, 'save', {}) });
    return redirect('/runs/' + result.id);
  });
}
export default function RunForm() {
  const { resource, environments } = useLoaderData<typeof runLoader>();
  const result = useActionData<typeof runAction>();
  const { t } = useTranslation();
  return (
    <Page title={resource ? t('execute') + ' — ' + resource.name : t('http')} narrow>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Form method="post">
        <div className="flex min-w-0 flex-col gap-6">
          <EnvironmentChoice items={environments} />
          {resource?.kind === 'function' ? (
            resource.data.parameters.map((parameter) => (
              <InputField
                key={parameter.name}
                name={'argument.' + parameter.name}
                label={parameter.label || parameter.name}
                required={parameter.required}
                defaultValue={parameter.default ?? ''}
              />
            ))
          ) : (
            <>
              <Panel>
                <RequestFields />
              </Panel>
              <JsonField name="save" label={t('saveOutputs')} value={{}} />
            </>
          )}
          <SaveBar back={resource ? resourcePath(resource) : '..'} label="execute" />
        </div>
      </Form>
    </Page>
  );
}
