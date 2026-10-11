import { CheckboxField, InputField, TextareaField } from './form-fields';
import { Form, redirect, useActionData, useLoaderData } from 'react-router';
import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Principal, Resource } from '../../shared/contracts';
import type { JsonValue } from '../../shared/contracts';
import { actionResult, api, ApiFailure, formText, jsonField } from './api';
import { ErrorNotice, JsonField, Page, Panel, SaveBar } from './components';
import { RequestFields } from './resource-form';
import { resourcePath } from './navigation';
import { executionClient, functionClient } from './custody';
import { availableEnvironments, EnvironmentChoice } from './environments';
async function runResource(params: LoaderFunctionArgs['params']) {
  if (!params.id) return null;
  const resource = await api('/functions/' + params.id, {}, Resource);
  if (resource.kind !== 'function' || resource.ownerId !== params.owner)
    throw new Response('Not found', { status: 404 });
  return resource;
}
export async function runLoader({ params }: LoaderFunctionArgs) {
  const resource = await runResource(params);
  const environments = resource ? [] : await availableEnvironments(params.owner!);
  return { resource, environments };
}
export async function runAction({ params, request }: ActionFunctionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const resource = await runResource(params);
    let input: Record<string, JsonValue>;
    if (resource?.kind === 'function') {
      const args: Record<string, JsonValue> = {};
      for (const parameter of resource.data.parameters) {
        const name = 'argument.' + parameter.name, text = String(form.get(name) ?? '');
        if (parameter.type === 'boolean') args[parameter.name] = form.has(name);
        else if (parameter.type === 'json') {
          if (text.trim()) args[parameter.name] = jsonField(form, name, null);
        } else if (parameter.type === 'number') {
          if (text.trim()) {
            const value = Number(text);
            if (!Number.isFinite(value)) throw new ApiFailure('invalid_input');
            args[parameter.name] = value;
          }
        } else if (text || parameter.required) args[parameter.name] = text;
      }
      const save = jsonField<Record<string, string>>(form, 'save', {});
      const result = await (await functionClient(Object.keys(save).length > 0)).invoke(resource.id, args, { save });
      return redirect('/executions/' + result.id);
    } else
      input = {
        kind: 'http',
        request: {
          url: formText(form, 'url'),
          method: formText(form, 'httpMethod') as 'GET',
          headers: jsonField(form, 'headers', {}),
          ...(formText(form, 'body') ? { body: String(form.get('body')) } : {}),
          bindings: jsonField(form, 'bindings', []),
        },
      };
    const client = await executionClient();
    let ownerId = params.owner!;
    try {
      const owner = await api('/principals/' + ownerId, {}, Principal);
      if (!owner.permissions.includes('execute')) ownerId = client.custody.binding.principalId;
    } catch (error) {
      if (!(error instanceof ApiFailure) || error.status !== 403) throw error;
      ownerId = client.custody.binding.principalId;
    }
    const result = await client.execute({ name: 'run.execute', input: { ownerId,
      environmentId: formText(form, 'environmentId'),
      operation: input, save: jsonField(form, 'save', {}) } });
    if (!('kind' in result) || result.kind !== 'run') throw new ApiFailure('invalid_input');
    return redirect('/executions/' + result.task.intent.operationContext!.id);
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
          {!resource && <EnvironmentChoice items={environments} />}
          {resource?.kind === 'function' ? (
            resource.data.parameters.map((parameter) => {
              const props = { name: 'argument.' + parameter.name, label: parameter.label || parameter.name };
              return parameter.type === 'boolean' ? <CheckboxField key={parameter.name} {...props} defaultChecked={parameter.default === true} />
                : parameter.type === 'json' ? <TextareaField key={parameter.name} {...props} required={parameter.required}
                    defaultValue={parameter.default === undefined ? '' : JSON.stringify(parameter.default, null, 2)} />
                : <InputField key={parameter.name} {...props} required={parameter.required}
                    type={parameter.type === 'number' ? 'number' : 'text'} step={parameter.type === 'number' ? 'any' : undefined}
                    defaultValue={typeof parameter.default === 'string' || typeof parameter.default === 'number' ? parameter.default : ''} />;
            })
          ) : (
            <>
              <Panel>
                <RequestFields />
              </Panel>
            </>
          )}
          <JsonField name="save" label={t('saveOutputs')} value={{}} />
          <SaveBar back={resource ? resourcePath(resource) : '..'} label="execute" />
        </div>
      </Form>
    </Page>
  );
}
