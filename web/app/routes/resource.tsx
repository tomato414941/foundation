import { Button } from '../components/ui/button';
import { InputField, TextareaField } from '../form-fields';
import { Notice } from '../components';
import { useState } from 'react';
import { Form, Link, redirect, useActionData, useLoaderData, useNavigation } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource';
import { Resource, EnvironmentDeletion, FunctionExecutionSettings } from '../../../shared/contracts';
import { decode } from '../../../shared/encryption';
import { api, ApiFailure, actionResult, formText } from '../api';
import { decryptVariable, requireKeys, useExcludedRecipients } from '../keys';
import { RecipientVerificationLinks } from '../recipient-verification';
import {
  Bytes,
  Confirm,
  Copy,
  DateText,
  Detail,
  ErrorNotice,
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
import { executionClient, functionClient } from '../custody';
import { FunctionSettings } from '../function-settings';
import { inputAccessFromForm } from '../function-access';
import { availableEnvironments, EnvironmentChoice, environmentState } from '../environments';
import { EnvironmentDelete } from '../environment-delete';
import { EnvironmentSSH } from '../environment-ssh';
import { sshSettings } from '../ssh';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const resource = await api((params.section === 'functions' ? '/functions/' : '/resources/') + params.id,
    { signal: request.signal }, Resource).catch(async error => {
    if (params.section === 'environments' && error instanceof ApiFailure && error.status === 404) {
      const deletion = await api('/resources/' + params.id + '/deletion', { signal: request.signal }, EnvironmentDeletion)
        .catch(() => null);
      if (deletion?.state === 'complete') throw redirect(`/p/${params.owner}/environments?deleted=1`);
    }
    throw error;
  });
  if (resource.ownerId !== params.owner || resource.kind !== resourceKind(params.section))
    throw new Response('Not found', { status: 404 });
  const functionSettings = resource.kind === 'function' && resource.permissions.includes('read')
    ? await api('/functions/' + resource.id + '/execution-settings', { signal: request.signal }, FunctionExecutionSettings) : null;
  return { resource, functionSettings, environments: resource.kind === 'connection' && resource.data.revocable ||
    resource.kind === 'function' && resource.permissions.includes('update') ? await availableEnvironments(resource.ownerId) : [] };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    if (formText(form, 'intent') === 'ssh') {
      const settings = sshSettings(form);
      await api(`/environments/${params.id}/ssh`, { method: 'PUT',
        body: { ...settings, revision: Number(formText(form, 'sshRevision')) } });
      return { sshSaved: true };
    }
    const intent = formText(form, 'intent');
    if (intent === 'functionConfigure' || intent === 'functionUnconfigure') {
      await (await functionClient(true)).configure(params.id!, {
        environmentId: intent === 'functionConfigure' ? formText(form, 'environmentId') : null,
        inputAccess: intent === 'functionConfigure' ? inputAccessFromForm(form) : { expiresAt: null },
      }, { functionVersion: Number(formText(form, 'functionVersion')), version: Number(formText(form, 'settingsVersion')) });
      return { functionConfigured: true };
    }
    if (intent === 'stop' || intent === 'start') {
      await api(`/resources/${params.id}/${intent}`, { method: 'POST', body: {} });
      return { ok: true };
    }
    if (formText(form, 'intent') === 'disconnect') {
      await requireKeys();
      const result = await (await executionClient()).execute({ name: 'connection.revoke',
        input: { ownerId: params.owner, environmentId: formText(form, 'environmentId'), connectionId: params.id } });
      if (!('kind' in result) || result.kind !== 'run') throw new ApiFailure('execution_required');
      return redirect('/executions/' + result.task.intent.operationContext!.id);
    }
    await api(`${params.section === 'functions' ? '/functions' : '/resources'}/${params.id}`, { method: 'DELETE' });
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
  const { resource: item, environments, functionSettings } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { session } = useWorkspace();
  const excluded = useExcludedRecipients(session.principal?.id, item.id);
  const { t } = useTranslation();
  const task = useTask();
  const navigation = useNavigation();
  const [content, setContent] = useState<Uint8Array | null>(null);
  const [link, setLink] = useState<{
    url: string;
    expiresAt: string;
  } | null>(null);
  const [minutes, setMinutes] = useState(15);
  const can = (action: (typeof item.permissions)[number]) => item.permissions.includes(action);
  const environment = item.kind === 'environment' ? item : null;
  const status = environment ? environmentState(environment) : null;
  usePolling(
    item.kind === 'environment' && !item.data.deletion && ['starting', 'running', 'stopping'].includes(item.data.state),
    item.kind === 'environment' && item.data.state === 'running' ? 15000 : 2500,
  );
  const reveal = async () => {
    await requireKeys(session.principal!.id);
    return decryptVariable(item.id, session.principal!.id);
  };
  return (
    <Page
      title={item.name}
      back={{ to: `/p/${item.ownerId}/${sectionFor(item.kind)}`, label: t(item.kind === 'environment' ? 'backToEnvironments' : 'backToList') }}
      actions={
        <>
          {status && <State value={status} />}
          {environment?.data.driver === 'managed' && !environment.data.deletion &&
            ['stopped', 'failed'].includes(environment.data.state) && can('update') && <Form method="post">
              <Button type="submit" name="intent" value="start" loading={navigation.state !== 'idle'}>
                {t(navigation.state !== 'idle' ? 'state.starting' : 'start')}
              </Button>
            </Form>}
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
          {can('update') && item.kind === 'connection' && <Button variant="outline" asChild>
            <Link to="access">{t('authorizeConnection')}</Link>
          </Button>}
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
      {!!excluded?.length && <Notice tone="warning">
        <p>{t('recipientExclusionsSaved')}</p>
        <RecipientVerificationLinks recipients={excluded} />
      </Notice>}
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
        <Panel>
          {item.data.state !== 'ready' && (
            <Notice tone={'warning'}>{t('state.' + item.data.state)}</Notice>
          )}
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
                <Link to="edit">{t('replaceObject')}</Link>
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
          {!item.data.deletion && item.data.stopReason && item.data.stopReason !== 'manual' &&
            <Notice tone="info">{t('environmentStop.' + item.data.stopReason)}</Notice>}
          {item.data.driver !== 'attached' && <Panel title={t('settings')}>
            <Detail label={t('size')}>{t(item.data.size)}</Detail>
            <Detail label={t('environmentLifetime')}>{[
              item.data.lifetime.maxSeconds === null ? '' : t('environmentMaximumSummary', { minutes: item.data.lifetime.maxSeconds / 60 }),
              item.data.lifetime.idleSeconds === null ? '' : t('environmentIdleSummary', { minutes: item.data.lifetime.idleSeconds / 60 }),
            ].filter(Boolean).join(' / ') || t('none')}</Detail>
          </Panel>}
          <EnvironmentSSH item={item} canUpdate={can('update')} busy={navigation.state !== 'idle'}
            saved={Boolean(result && 'sshSaved' in result && result.sshSaved)} />
          <Panel>
            <BoxDetails item={item} />
            {item.data.executorId && <Link to={'/account/trust?principal=' + item.data.executorId}
              className="inline-flex min-h-11 w-fit items-center text-sm text-muted-foreground underline underline-offset-4 hover:text-foreground">
              {t('verifyEnvironment')}
            </Link>}
          </Panel>
        </>
      )}
      {item.kind === 'function' && (item.data.description || can('execute')) && (
        <Panel>
          {item.data.description && <p className="leading-relaxed">{item.data.description}</p>}
          {can('execute') && (
            <Button variant="default" asChild>
              <Link to="run">{t('execute')}</Link>
            </Button>
          )}
        </Panel>
      )}
      {item.kind === 'function' && functionSettings && <FunctionSettings settings={functionSettings}
        environments={environments} functionVersion={item.version} canUpdate={can('update')} busy={navigation.state !== 'idle'} />}
      {item.kind === 'method' && can('use') && (
        <Button variant="ghost" asChild>
          <Link to={`/p/${item.ownerId}/services/new?method=${item.id}`}>{t('connect')}</Link>
        </Button>
      )}
      {item.kind === 'environment' && can('delete') && <EnvironmentDelete item={item} />}
      {item.kind !== 'environment' && can('delete') && (
        <div className="flex min-w-0 flex-wrap items-center">
          <Confirm label={t(item.kind === 'connection' ? 'disconnect' : 'delete')} name={item.name}>
            {item.kind === 'connection' && environments.length > 0 && (
              <><input type="hidden" name="intent" value="disconnect" />
                <EnvironmentChoice items={environments} /></>
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
