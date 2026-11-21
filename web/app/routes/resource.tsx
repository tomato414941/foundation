import { Button } from '../components/ui/button';
import { InputField, TextareaField } from '../form-fields';
import { useId, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { cn } from 'cn';
import { Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource';
import { CatalogMethod, Resource } from '../../../shared/contracts';
import type { ConnectionView } from '../../../shared/contracts';
import { catalogDefinition } from '../../../shared/connection-methods';
import { connectionConsole } from '../../../shared/connection-fields';
import { decode } from '../../../shared/encryption';
import { api, actionResult, ApiFailure } from '../api';
import { decryptVariable, requireKeys } from '../keys';
import {
  Bytes,
  Confirm,
  Copy,
  DateText,
  Detail,
  ErrorNotice,
  ExternalLink,
  Page,
  Panel,
  State,
  useTask,
} from '../components';
import { resourceKind, sectionFor } from '../navigation';
import { useWorkspace } from './workspace';
import { ConnectionFacts } from '../connection-facts';
import { connectionKeyLabel, connectionMethodName } from '../connection-method-labels';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const resource = await api('/resources/' + params.id, { signal: request.signal }, Resource);
  if (resource.ownerId !== params.owner || resource.kind !== resourceKind(params.section))
    throw new Response('Not found', { status: 404 });
  let serviceConsole: string | undefined;
  if (resource.kind === 'connection') {
    const method = await api('/connections/' + resource.id + '/method', { signal: request.signal }, CatalogMethod)
      .catch(error => {
        if (error instanceof ApiFailure && error.status === 404) return null;
        throw error;
      });
    if (method) serviceConsole = connectionConsole(catalogDefinition(method), resource.data.fields);
  }
  return { resource, serviceConsole };
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
  if (item.kind === 'connection')
    return <ConnectionDetail key={item.id} item={item} serviceConsole={serviceConsole} />;
  const reveal = async () => {
    await requireKeys(session.principal!.id);
    return decryptVariable(item.id, session.principal!.id);
  };
  return (
    <Page
      title={item.name}
      back={{ to: `/p/${item.ownerId}/${sectionFor(item.kind)}`, label: t('backToList') }}
      actions={
        <>
          {can('update') && (
            <Button variant="outline" asChild>
              <Link to="edit">{t('edit')}</Link>
            </Button>
          )}
          {can('share') && (
            <Button variant="ghost" asChild>
              <Link to="share">{t('share')}</Link>
            </Button>
          )}
          {can('transfer') && (
            <Button variant="ghost" asChild>
              <Link to="transfer">{t('transfer')}</Link>
            </Button>
          )}
        </>
      }
    >
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      <Panel><BoxDetails item={item} /></Panel>
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
      {can('delete') && (
        <div className="flex min-w-0 flex-wrap items-center">
          <Confirm label={t('delete')} name={item.name} />
        </div>
      )}
    </Page>
  );
}
function ConnectionDetail({ item, serviceConsole }: { item: ConnectionView; serviceConsole?: string }) {
  const { t } = useTranslation();
  const { principal } = useWorkspace();
  const result = useActionData<typeof clientAction>();
  const infoId = useId();
  const [infoOpen, setInfoOpen] = useState(false);
  const keyLabel = item.data.methodKind === 'token' ? connectionKeyLabel(item.data.methodName) : undefined;
  const service = item.data.services.length === 1 ? item.data.services[0]?.name : undefined;

  return (
    <Page
      title={item.name}
      status={<State value={item.data.state} />}
      back={{ to: `/p/${item.ownerId}/services`, label: t('backToList') }}
      actions={item.permissions.includes('share') && <Button variant="outline" asChild><Link to="share">{t('share')}</Link></Button>}
    >
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <div className="grid items-start border-t lg:grid-cols-[minmax(0,1fr)_minmax(17rem,35%)] lg:grid-rows-[auto_auto_1fr] lg:gap-x-8">
        <div className="grid min-w-0 gap-4 py-5 lg:col-start-1 lg:row-start-1">
          <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
            <dl className="min-w-0 space-y-1">
              <dt className="text-sm text-muted-foreground">{t('method')}</dt>
              <dd className="font-medium wrap-anywhere">{keyLabel ? t(keyLabel) : connectionMethodName(item.data.methodName, t, service)}</dd>
            </dl>
            {item.permissions.includes('update') && (
              <Button variant={item.data.state === 'reconnect' ? 'default' : 'ghost'} className="min-h-10 lg:min-h-8" asChild>
                <Link to="edit">
                  {keyLabel ? t('changeConnectionKey', { keyName: t(keyLabel) }) : t('reconnect')}
                </Link>
              </Button>
            )}
          </div>
          <div className="space-y-4 empty:hidden"><ConnectionFacts value={item.data} /></div>
        </div>

        <aside aria-label={t('connectionInfo')} className="min-w-0 border-t lg:col-start-2 lg:row-span-3 lg:row-start-1 lg:border-t-0 lg:border-l lg:py-5 lg:pl-6">
          <h2 className="hidden text-sm font-semibold lg:block">{t('connectionInfo')}</h2>
          <button type="button" aria-controls={infoId} aria-expanded={infoOpen} onClick={() => setInfoOpen(!infoOpen)}
            className="flex min-h-11 w-full items-center gap-2 rounded-sm text-left text-sm font-semibold lg:hidden">
            <ChevronRight className={cn('size-4 text-muted-foreground', infoOpen && 'rotate-90')} aria-hidden="true" />
            {t('connectionInfo')}
          </button>
          <div id={infoId} className={cn('space-y-4 pb-4 lg:block lg:pt-4 lg:pb-0', !infoOpen && 'hidden')}>
            <div className="space-y-4 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                <dl className="min-w-0 space-y-1">
                  <dt className="text-muted-foreground">{t('owner')}</dt>
                  <dd className="wrap-anywhere">{principal.name}</dd>
                </dl>
                {item.permissions.includes('transfer') && <Button variant="ghost" size="sm" className="min-h-10 lg:min-h-7" asChild>
                  <Link to="transfer">{t('transfer')}</Link>
                </Button>}
              </div>
              <dl className="space-y-1">
                <dt className="text-muted-foreground">{t('updated')}</dt>
                <dd><DateText value={item.updatedAt} /></dd>
              </dl>
              <div className="flex flex-wrap items-end justify-between gap-x-3 gap-y-1">
                {item.data.services.length > 0 && <dl className="min-w-0 space-y-1">
                  <dt className="text-muted-foreground">{t('service')}</dt>
                  <dd className="wrap-anywhere">{item.data.services.map(entry => entry.name).join(', ')}</dd>
                </dl>}
                {serviceConsole && <ExternalLink href={serviceConsole}>{t('serviceConsole')}</ExternalLink>}
              </div>
            </div>
            <details className="group border-t">
              <summary className="flex min-h-10 cursor-pointer list-none items-center gap-2 rounded-sm text-sm text-muted-foreground [&::-webkit-details-marker]:hidden">
                <ChevronRight className="size-4 group-open:rotate-90" aria-hidden="true" />{t('id')}
              </summary>
              <div className="flex flex-wrap items-center gap-x-1">
                <code className="text-xs text-muted-foreground wrap-anywhere">{item.id}</code><Copy value={item.id} />
              </div>
            </details>
          </div>
        </aside>

        {item.permissions.includes('delete') && <div className="border-t py-2 lg:col-start-1 lg:row-start-2">
          <Confirm label={t('disconnect')} name={item.name} title={t('disconnectTitle', { name: item.name })} body={t('disconnectHelp')}>
            {serviceConsole && <ExternalLink href={serviceConsole}>{t('serviceConsole')}</ExternalLink>}
          </Confirm>
        </div>}
      </div>
    </Page>
  );
}

function BoxDetails({ item }: { item: Exclude<Awaited<ReturnType<typeof clientLoader>>['resource'], ConnectionView> }) {
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
