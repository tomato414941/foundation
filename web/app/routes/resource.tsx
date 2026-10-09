import { Button } from '../components/ui/button';
import { InputField, TextareaField, CheckboxField } from '../form-fields';
import { Notice } from '../components';
import { useState } from 'react';
import { Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource';
import { Resource, EnvironmentDeletion } from '../../../shared/contracts';
import { decode } from '../../../shared/encryption';
import { api, ApiFailure, actionResult, formText } from '../api';
import { authenticate, decryptVariable } from '../keys';
import {
  Bytes,
  Confirm,
  Copy,
  DateText,
  Detail,
  ErrorNotice,
  JsonView,
  Page,
  Panel,
  State,
  usePolling,
  useTask,
} from '../components';
import { resourceKind, sectionFor } from '../navigation';
import { useWorkspace } from './workspace';
import { ConnectionFacts } from '../connection-facts';
import { connectionMethodName } from '../connection-method-labels';
import { custodyClient } from '../custody';
import { availableEnvironments, EnvironmentChoice } from '../environments';
import { EnvironmentDelete } from '../environment-delete';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const resource = await api('/resources/' + params.id, { signal: request.signal }, Resource).catch(async error => {
    if (params.section === 'environments' && error instanceof ApiFailure && error.status === 404) {
      const deletion = await api('/resources/' + params.id + '/deletion', { signal: request.signal }, EnvironmentDeletion)
        .catch(() => null);
      if (deletion?.state === 'complete') throw redirect(`/p/${params.owner}/environments?deleted=1`);
    }
    throw error;
  });
  if (resource.ownerId !== params.owner || resource.kind !== resourceKind(params.section))
    throw new Response('Not found', { status: 404 });
  return { resource, environments: resource.kind === 'connection' ? await availableEnvironments(resource.ownerId) : [] };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    if (formText(form, 'intent') === 'stop') {
      await api(`/resources/${params.id}/stop`, { method: 'POST', body: {} });
      return { ok: true };
    }
    if (form.has('revoke')) {
      const client = await custodyClient();
      const task = await client.submit(params.owner, formText(form, 'environmentId'),
        { kind: 'revoke', input: { action: 'revoke', id: params.id } }, { sourceIds: [params.id] });
      return redirect('/runs/' + task.id);
    }
    await api(`/resources/${params.id}`, { method: 'DELETE' });
    return redirect(`/p/${params.owner}/${params.section}`);
  });
}
function downloadBytes(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)]));
  const element = document.createElement('a');
  element.href = url;
  element.download = name;
  element.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export default function ResourceDetail() {
  const { resource: item, environments } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { session } = useWorkspace();
  const { t } = useTranslation();
  const task = useTask();
  const [content, setContent] = useState<Uint8Array | null>(null);
  const [link, setLink] = useState<{
    url: string;
    expiresAt: string;
  } | null>(null);
  const [minutes, setMinutes] = useState(15);
  const [revoke, setRevoke] = useState(true);
  const can = (action: (typeof item.permissions)[number]) => item.permissions.includes(action);
  const environment = item.kind === 'environment' ? item : null;
  const environmentState = environment?.data.deletion
    ? environment.data.deletion.state === 'failed' ? 'deleteFailed' : 'deleting'
    : environment?.data.state;
  usePolling(
    item.kind === 'environment' && !item.data.deletion && ['starting', 'running', 'stopping'].includes(item.data.state),
    item.kind === 'environment' && item.data.state === 'running' ? 15000 : 2500,
  );
  const reveal = async () => {
    try {
      return await decryptVariable(item.id, session.principal!.id);
    } catch {
      const result = await authenticate(session.principal!.id);
      if (!result.encrypted) throw new Error('key unavailable');
      return decryptVariable(item.id, session.principal!.id);
    }
  };
  return (
    <Page
      title={item.name}
      back={{ to: `/p/${item.ownerId}/${sectionFor(item.kind)}`, label: t(item.kind === 'environment' ? 'backToEnvironments' : 'backToList') }}
      actions={
        <>
          {environmentState && <State value={environmentState}
            label={environmentState === 'running' ? t('state.environmentRunning') : undefined} />}
          {environment && !environment.data.deletion && ['starting', 'running'].includes(environment.data.state) && can('delete') && (
            <Confirm label={t('stop')} name={item.name} body={t('stopBody')} danger={false}>
              <input type="hidden" name="intent" value="stop" />
            </Confirm>
          )}
          {can('update') && !['environment', 'connection'].includes(item.kind) && (
            <Button variant="outline" asChild>
              <Link to="edit">{t('edit')}</Link>
            </Button>
          )}
          {can('share') && (
            <Button variant="ghost" asChild>
              <Link to="share">{t('share')}</Link>
            </Button>
          )}
          {can('transfer') && item.kind !== 'environment' && (
            <Button variant="ghost" asChild>
              <Link to="transfer">{t('transfer')}</Link>
            </Button>
          )}
        </>
      }
    >
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      {!environment && <Panel><BoxDetails item={item} /></Panel>}
      {item.kind === 'variable' && can('reveal') && (
        <Panel>
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Button
              loading={task.busy}
              onClick={() => task.run(async () => setContent(content ? null : await reveal()))}
              variant="default"
            >
              {t(content ? 'hide' : 'reveal')}
            </Button>
            <Button
              loading={task.busy}
              onClick={() => task.run(async () => downloadBytes(await reveal(), item.name))}
              variant="ghost"
            >
              {t('download')}
            </Button>
          </div>
          {content && (
            <>
              <TextareaField
                label={t('value')}
                value={decode(content)}
                rows={3}
                readOnly={true}
                spellCheck={false}
              />
              <Copy value={decode(content)} />
            </>
          )}
        </Panel>
      )}
      {item.kind === 'connection' && (
        <Panel title={t('outputs')}>
          {item.data.state !== 'ready' && (
            <Notice tone={'warning'}>{t('state.' + item.data.state)}</Notice>
          )}
          <JsonView value={item.data.outputs} />
          <p className="leading-relaxed text-muted-foreground text-sm">{t('connectionUseHelp')}</p>
          {can('update') && (
            <Button variant="outline" asChild>
              <Link to={`../new?connection=${item.id}`} relative="path">
                {t('reconnect')}
              </Link>
            </Button>
          )}
        </Panel>
      )}
      {item.kind === 'object' && (
        <Panel>
          <div className="flex min-w-0 flex-wrap items-center gap-4">
            <Button variant="default" asChild>
              <a href={`/api/resources/${item.id}/content`}>{t('download')}</a>
            </Button>
            {can('update') && (
              <Button variant="ghost" asChild>
                <Link to="edit">{t('replaceFile')}</Link>
              </Button>
            )}
          </div>
          <p className="leading-relaxed text-muted-foreground text-sm">{t('linkHelp')}</p>
          <div className="flex min-w-0 flex-col sm:flex-row sm:items-center gap-4">
            <InputField
              type="number"
              label={t('expires') + ' (' + t('minutes') + ')'}
              value={minutes}
              onChange={(event) => setMinutes(Number(event.target.value))}
              min={1}
              max={1440}
            />
            <Button
              loading={task.busy}
              onClick={() =>
                task.run(async () =>
                  setLink(
                    await api(`/resources/${item.id}/link`, { method: 'POST', body: { minutes } }),
                  ),
                )
              }
              variant="ghost"
            >
              {t('createLink')}
            </Button>
          </div>
          {link && (
            <>
              <InputField label={t('link')} value={link.url} readOnly={true} />
              <Copy value={link.url} />
              <p className="leading-relaxed text-sm">
                <DateText value={link.expiresAt} />
              </p>
            </>
          )}
        </Panel>
      )}
      {item.kind === 'environment' && (
        <>
          {item.data.error && <Notice tone={'error'}>{t('failure')}</Notice>}
          {!item.data.deletion && ['stopped', 'failed'].includes(item.data.state) && (
            <p className="leading-relaxed text-muted-foreground">{t('stoppedHelp')}</p>
          )}
          {item.data.driver !== 'attached' && <Panel title={t('settings')}>
            <Detail label={t('image')}>{item.data.image ?? t('defaultImage')}</Detail>
            <Detail label={t('size')}>{t(item.data.size)}</Detail>
            <Detail label={t('maximum')}>{item.data.lifetime.maxSeconds / 60}</Detail>
            <Detail label={t('idle')}>{item.data.lifetime.idleSeconds / 60}</Detail>
          </Panel>}
          <Panel>
            <BoxDetails item={item} />
            {item.data.executorId && <Link to={'/account/trust?principal=' + item.data.executorId}
              className="inline-flex min-h-11 w-fit items-center text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground">
              {t('verifyEnvironment')}
            </Link>}
          </Panel>
        </>
      )}
      {item.kind === 'function' && (
        <Panel>
          <p className="leading-relaxed">{item.data.description}</p>
          <JsonView value={item.data} />
          {can('execute') && (
            <Button variant="default" asChild>
              <Link to="run">{t('execute')}</Link>
            </Button>
          )}
        </Panel>
      )}
      {(item.kind === 'service' || item.kind === 'app' || item.kind === 'method') && (
        <Panel>
          <JsonView value={item.data} />
          {item.kind === 'method' && can('use') && (
            <Button variant="ghost" asChild>
              <Link to={`/p/${item.ownerId}/services/new?method=${item.id}`}>{t('connect')}</Link>
            </Button>
          )}
        </Panel>
      )}
      {item.kind === 'environment' && can('delete') && <EnvironmentDelete item={item} />}
      {item.kind !== 'environment' && can('delete') && (
        <div className="flex min-w-0 flex-wrap items-center">
          <Confirm label={t(item.kind === 'connection' ? 'disconnect' : 'delete')} name={item.name}>
            {item.kind === 'connection' && item.data.methodKind === 'oauth' && (
              <><CheckboxField name="revoke" checked={revoke} onCheckedChange={value => setRevoke(value === true)} label={t('revokeProvider')} />
                {revoke && <EnvironmentChoice items={environments} />}</>
            )}
            {item.kind === 'connection' && (
              <p className="leading-relaxed text-sm">{t('disconnectHelp')}</p>
            )}
          </Confirm>
        </div>
      )}
    </Page>
  );
}
function BoxDetails({ item }: { item: Awaited<ReturnType<typeof clientLoader>>['resource'] }) {
  const { t } = useTranslation();
  return (
    <>
      <Detail label={t('id')}>
        {item.id}
        <Copy value={item.id} />
      </Detail>
      <Detail label={t('created')}>
        <DateText value={item.createdAt} />
      </Detail>
      <Detail label={t('updated')}>
        <DateText value={item.updatedAt} />
      </Detail>
      {item.kind !== 'environment' && 'state' in item.data && (
        <Detail label={t('status')}>
          <State value={item.data.state} />
        </Detail>
      )}
      {item.kind === 'connection' && (
        <>
          <Detail label={t('service')}>
            {item.data.services.map((service) => service.name).join(', ') || '—'}
          </Detail>
          <Detail label={t('method')}>{connectionMethodName(item.data.methodName, t)}</Detail>
          <ConnectionFacts value={item.data} />
        </>
      )}
      {item.kind === 'variable' && (
        <Detail label={t('size')}>
          <Bytes value={item.data.bytes} />
        </Detail>
      )}
      {item.kind === 'object' && (
        <Detail label={t('size')}>
          <Bytes value={item.data.size} />
        </Detail>
      )}
    </>
  );
}
