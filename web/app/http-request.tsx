import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { HttpRequest, Resource, listOf } from '../../shared/contracts';
import type { HttpRequestInput, ResourceView } from '../../shared/contracts';
import { api, ApiFailure, formText, jsonField } from './api';
import { InputField, SelectField, TextareaField } from './form-fields';
import { SelectItem } from './components/ui/select';
import { JsonField } from './components';

export async function httpConnections(ownerId: string, signal?: AbortSignal) {
  const owned = api(`/principals/${ownerId}/resources?kind=connection&limit=200`, { signal }, listOf(Resource))
    .catch(error => {
      if (error instanceof ApiFailure && error.status === 403) return { items: [] };
      throw error;
    });
  const [own, shared] = await Promise.all([owned, api('/resources/shared', { signal }, listOf(Resource))]);
  return [...new Map([...own.items, ...shared.items].map(item => [item.id, item])).values()]
    .filter(item => item.kind === 'connection' && item.data.http && item.data.state === 'ready' && item.permissions.includes('use'));
}

export function httpRequestFromForm(form: FormData) {
  const connectionId = formText(form, 'httpConnectionId');
  const body = formText(form, 'body'), format = formText(form, 'requestBodyFormat');
  return HttpRequest.parse({
    ...(connectionId && connectionId !== 'none' ? { connectionId } : {}),
    ...(formText(form, 'url') ? { url: formText(form, 'url') } : {}),
    method: formText(form, 'httpMethod'), headers: jsonField(form, 'headers', {}),
    ...(body ? format === 'json' ? { json: jsonField(form, 'body', null) }
      : format === 'form' ? { form: jsonField(form, 'body', {}) } : { body: String(form.get('body')) } : {}),
    bindings: jsonField(form, 'bindings', []),
  });
}

export function RequestFields({ value, connections = [] }: { value?: HttpRequestInput; connections?: ResourceView[] }) {
  const { t } = useTranslation();
  const [connectionId, setConnectionId] = useState(value?.connectionId ?? 'none');
  const [bodyFormat, setBodyFormat] = useState(value?.json !== undefined ? 'json' : value?.form !== undefined ? 'form' : 'text');
  const connection = connections.find(item => item.id === connectionId);
  const storedUrl = connection?.kind === 'connection' && Boolean(connection.data.http?.urlField);
  return <>
    <SelectField name="httpConnectionId" label={t('connection')} value={connectionId} onValueChange={setConnectionId}>
      <SelectItem value="none">{t('noConnection')}</SelectItem>
      {connections.map(item => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}
    </SelectField>
    <InputField name="url" label={t('url')} defaultValue={value?.url ?? ''} required={!storedUrl}
      placeholder={storedUrl ? t('storedConnectionUrl') : 'https://api.example.com/items'}
      hint={storedUrl ? t('connectionUrlHint') : undefined} />
    <SelectField name="httpMethod" label={t('httpMethod')} defaultValue={value?.method ?? 'GET'}>
      {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map(method => <SelectItem key={method} value={method}>{method}</SelectItem>)}
    </SelectField>
    <SelectField name="requestBodyFormat" label={t('requestBodyFormat')} value={bodyFormat} onValueChange={setBodyFormat}>
      <SelectItem value="text">{t('functionText')}</SelectItem>
      <SelectItem value="json">JSON</SelectItem>
      <SelectItem value="form">{t('formBody')}</SelectItem>
    </SelectField>
    <TextareaField name="body" label={t('body')} hint={bodyFormat === 'text' ? undefined : t('jsonHelp')}
      defaultValue={value?.body ?? (value?.json !== undefined ? JSON.stringify(value.json, null, 2)
        : value?.form !== undefined ? JSON.stringify(value.form, null, 2) : '')} rows={3} />
    <details className="rounded-md border p-4" open={Boolean(value?.bindings.length || Object.keys(value?.headers ?? {}).length)}>
      <summary className="cursor-pointer text-sm">{t('advancedHttpSettings')}</summary>
      <div className="mt-4 flex flex-col gap-4">
        <JsonField name="headers" label={t('headers')} value={value?.headers ?? {}} rows={3} />
        <JsonField name="bindings" label={t('bindings')} value={value?.bindings ?? []} rows={3} />
      </div>
    </details>
  </>;
}
