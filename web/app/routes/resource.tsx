import { Button } from '../components/ui/button';
import { InputField, TextareaField } from '../form-fields';
import { Notice } from '../components';
import { useState } from 'react';
import { Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource';
import { CatalogMethod, Resource } from '../../../shared/contracts';
import { catalogDefinition } from '../../../shared/connection-methods';
import { connectionConsole } from '../../../shared/connection-fields';
import { decode } from '../../../shared/encryption';
import { api, actionResult } from '../api';
import { decryptVariable, requireKeys } from '../keys';
import { RecipientAccessNotice } from '../recipient-verification';
import {
  Bytes,
  Confirm,
  Copy,
  DateText,
  Detail,
  ErrorNotice,
  ExternalLink,
  Operation,
  Page,
  Panel,
  State,
  useTask,
} from '../components';
import { resourceKind, sectionFor } from '../navigation';
import { useWorkspace } from './workspace';
import { ConnectionFacts } from '../connection-facts';
import { connectionMethodName } from '../connection-method-labels';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const resource = await api('/resources/' + params.id, { signal: request.signal }, Resource);
  if (resource.ownerId !== params.owner || resource.kind !== resourceKind(params.section))
    throw new Response('Not found', { status: 404 });
  // Removing a connection leaves its credentials valid at the service, whose console is where they are disabled.
  const method = resource.kind === 'connection' && resource.permissions.includes('delete')
    ? catalogDefinition(await api('/connections/' + resource.id + '/method', { signal: request.signal }, CatalogMethod)) : null;
  return { resource,
    serviceConsole: method && resource.kind === 'connection' ? connectionConsole(method, resource.data.fields) ?? null : null };
}
export async function clientAction({ params }: Route.ClientActionArgs) {
  return actionResult(async () => {
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
  const { resource: item, serviceConsole } = useLoaderData<typeof clientLoader>();
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
  const can = (action: (typeof item.permissions)[number]) => item.permissions.includes(action);
  const connection = item.kind === 'connection' ? item : null;
  const reveal = async () => {
    await requireKeys(session.principal!.id);
    return decryptVariable(item.id, session.principal!.id);
  };
  return (
    <Page
      title={item.name}
      narrow={!!connection}
      back={{ to: `/p/${item.ownerId}/${sectionFor(item.kind)}`, label: t('backToList') }}
      actions={
        <>
          {can('update') && !connection && (
            <Button variant="outline" asChild>
              <Link to="edit">{t('edit')}</Link>
            </Button>
          )}
          {can('update') && connection && <Button asChild>
            <Link to={`../new?connection=${item.id}`} relative="path">{t('reconnect')}</Link>
          </Button>}
          {can('share') && !connection && (
            <Button variant="ghost" asChild>
              <Link to="share">{t('share')}</Link>
            </Button>
          )}
          {can('transfer') && !connection && (
            <Button variant="ghost" asChild>
              <Link to="transfer">{t('transfer')}</Link>
            </Button>
          )}
        </>
      }
    >
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      <RecipientAccessNotice principalId={session.principal?.id} id={item.id} />
      {connection && connection.data.state !== 'ready' && (
        <Notice tone={'warning'}>{t('state.' + connection.data.state)}</Notice>
      )}
      <Panel><BoxDetails item={item} /></Panel>
      {connection && (can('update') || can('share') || can('transfer') || can('delete')) && (
        <Panel title={t('rarelyUsed')}>
          <div className="divide-y divide-border">
            {can('update') && (
              <Operation title={t('authorizeConnection')} help={t('connectionPermissionHelp')}>
                <Button variant="outline" asChild>
                  <Link to="access">{t('authorizeConnection')}</Link>
                </Button>
              </Operation>
            )}
            {can('share') && (
              <Operation title={t('share')} help={t('connectionUseHelp')}>
                <Button variant="outline" asChild>
                  <Link to="share">{t('share')}</Link>
                </Button>
              </Operation>
            )}
            {can('transfer') && (
              <Operation title={t('transfer')} help={t('transferHelp')}>
                <Button variant="outline" asChild>
                  <Link to="transfer">{t('transfer')}</Link>
                </Button>
              </Operation>
            )}
            {can('delete') && (
              <Operation title={t('disconnect')} help={t('disconnectHelp')}>
                <div className="flex flex-wrap items-center gap-3">
                  {serviceConsole && <ExternalLink href={serviceConsole}>{t('serviceConsole')}</ExternalLink>}
                  <Confirm label={t('disconnect')} name={item.name} />
                </div>
              </Operation>
            )}
          </div>
        </Panel>
      )}
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
      {item.kind === 'method' && can('use') && (
        <Button variant="ghost" asChild>
          <Link to={`/p/${item.ownerId}/services/new?method=${item.id}`}>{t('connect')}</Link>
        </Button>
      )}
      {!connection && can('delete') && (
        <div className="flex min-w-0 flex-wrap items-center">
          <Confirm label={t('delete')} name={item.name} />
        </div>
      )}
    </Page>
  );
}
function BoxDetails({ item }: { item: Awaited<ReturnType<typeof clientLoader>>['resource'] }) {
  const { t } = useTranslation();
  if (item.kind === 'connection') return <>
    <Detail label={t('status')}><State value={item.data.state} /></Detail>
    <Detail label={t('service')}>{item.data.services.map((service) => service.name).join(', ') || '—'}</Detail>
    <Detail label={t('method')}>{connectionMethodName(item.data.methodName, t)}</Detail>
    <ConnectionFacts value={item.data} />
    <Detail label={t('updated')}><DateText value={item.updatedAt} /></Detail>
    <Detail label={t('id')}>{item.id}<Copy value={item.id} /></Detail>
  </>;
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
