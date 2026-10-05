import { Form, redirect, useActionData, useLoaderData } from 'react-router';
import type { ActionFunctionArgs, LoaderFunctionArgs } from 'react-router';
import { Stack, TextField } from '@mui/material';
import { useTranslation } from 'react-i18next';
import { Resource, Run } from '../../shared/contracts';
import type { NewRun } from '../../shared/contracts';
import { actionResult, api, formText, jsonField } from './api';
import { ErrorNotice, JsonField, Page, Panel, SaveBar } from './components';
import { RequestFields } from './resource-form';
import { resourcePath } from './navigation';
export async function runLoader({ params }: LoaderFunctionArgs) { return params.id ? api('/resources/' + params.id, {}, Resource) : null; }
export async function runAction({ params, request }: ActionFunctionArgs) { return actionResult(async () => { const form = await request.formData(); const resource = params.id ? await api('/resources/' + params.id, {}, Resource) : null; let input: NewRun;
  if (resource?.kind === 'function') input = { kind: 'function', functionId: resource.id, arguments: Object.fromEntries([...form.entries()].filter(([key]) => key.startsWith('argument.')).map(([key, value]) => [key.slice(9), String(value)])) };
  else if (resource?.kind === 'environment') input = { kind: 'command', environmentId: resource.id, command: jsonField(form, 'command', []), stdin: String(form.get('stdin') ?? ''), timeoutSeconds: Number(formText(form, 'timeout')), inputs: jsonField(form, 'inputs', []) };
  else input = { kind: 'http', request: { url: formText(form, 'url'), method: formText(form, 'httpMethod') as 'GET', headers: jsonField(form, 'headers', {}), ...(formText(form, 'body') ? { body: String(form.get('body')) } : {}), bindings: jsonField(form, 'bindings', []) }, save: jsonField(form, 'save', {}) };
  const result = await api('/principals/' + params.owner + '/runs', { method: 'POST', body: input }, Run); return redirect('/runs/' + result.id);
}); }
export default function RunForm() { const resource = useLoaderData<typeof runLoader>(); const result = useActionData<typeof runAction>(); const { t } = useTranslation(); return <Page title={resource ? t('execute') + ' — ' + resource.name : t('http')} narrow><ErrorNotice error={result && 'error' in result ? result.error : null} /><Form method="post"><Stack spacing={3}>{resource?.kind === 'function' ? resource.data.parameters.map(parameter => <TextField key={parameter.name} name={'argument.' + parameter.name} label={parameter.label || parameter.name} required={parameter.required} defaultValue={parameter.default ?? ''} />) : resource?.kind === 'environment' ? <><JsonField name="command" label={t('command')} value={['node', '--version']} rows={3} helperText={t('commandHelp')} /><TextField name="stdin" label={t('stdin')} multiline minRows={3} /><TextField type="number" name="timeout" label={t('timeout')} defaultValue={60} required slotProps={{ htmlInput: { min: 1, max: 3600 } }} /><JsonField name="inputs" label={t('inputs')} value={[]} /></> : <><Panel><RequestFields /></Panel><JsonField name="save" label={t('saveOutputs')} value={{}} /></>}<SaveBar back={resource ? resourcePath(resource) : '..'} label="execute" /></Stack></Form></Page>; }
