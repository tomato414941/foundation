import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs';
import { Button } from '../components/ui/button';
import { Progress } from '../components/ui/progress';
import { InputField } from '../form-fields';
import { Notice } from '../components';
import {
  Form,
  Link,
  redirect,
  useActionData,
  useLoaderData,
  useSearchParams,
  useNavigate,
} from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/settings';
import {
  AuditEntry,
  Credential,
  Payment,
  Principal,
  Settings,
  Usage,
  listOf,
} from '../../../shared/contracts';
import { Changed, actionResult, api, formText, signedIn } from '../api';
import { Bytes, Confirm, Copy, DateText, Detail, ErrorNotice, Operation, Page, Paging, Panel } from '../components';
import { useWorkspace } from './workspace';
import { rekeySharing } from '../keys';
import { CredentialsPanel } from '../credentials-panel';
import { z } from 'zod';

// Limits are entered in the same binary megabytes the usage figures are shown in.
const MB = 1024 * 1024;
const DefinitionTitle = z.object({ name: z.string(), title: z.object({ ja: z.string(), en: z.string() }) });
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  if (!['general', 'credentials', 'billing', 'integrations', 'audit'].includes(params.tab))
    throw new Response('Not found', { status: 404 });
  const prefix = '/principals/' + params.owner;
  if (params.tab === 'credentials' && (await signedIn(request)).principal?.id === params.owner) throw redirect('/account');
  const [principal, credentials, payment, usage, settings, audit] = await Promise.all([
    api(prefix, { signal: request.signal }, Principal),
    params.tab === 'credentials'
      ? api(prefix + '/credentials', { signal: request.signal }, listOf(Credential))
      : null,
    params.tab === 'billing' ? api(prefix + '/payment', { signal: request.signal }, Payment) : null,
    params.tab === 'billing' ? api(prefix + '/usage', { signal: request.signal }, Usage) : null,
    params.tab === 'integrations'
      ? api(prefix + '/settings', { signal: request.signal }, Settings)
      : null,
    params.tab === 'audit'
      ? api(
          prefix + '/audit?' + new URL(request.url).searchParams,
          { signal: request.signal },
          listOf(AuditEntry),
        )
      : null,
  ]);
  const titles: Record<string, z.infer<typeof DefinitionTitle>['title']> = audit ? await api('/definitions', { signal: request.signal }, listOf(DefinitionTitle))
    .then(list => Object.fromEntries(list.items.map(item => [item.name, item.title])), () => ({})) : {};
  return { principal, tab: params.tab, credentials, payment, usage, settings, audit, titles };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const prefix = '/principals/' + params.owner;
    const intent = formText(form, 'intent');
    if (intent === 'rename')
      await api(prefix, { method: 'PATCH', body: { name: formText(form, 'name') } });
    else if (intent === 'delete') {
      await api(prefix, { method: 'DELETE' });
      return redirect('/');
    } else if (intent === 'transfer') {
      const to = formText(form, 'to');
      const contents = await rekeySharing(prefix + '/transfer-recipients?' + new URLSearchParams({ to }));
      const changed = await api(prefix + '/transfer', { method: 'POST', body: { to, contents } }, Changed);
      return redirect('id' in changed ? '/executions/' + changed.id : '/');
    } else if (intent === 'credential')
      await api(prefix + '/credentials/' + formText(form, 'credentialId'), { method: 'DELETE' });
    else if (intent === 'limits')
      await api(prefix + '/limits', {
        method: 'PUT',
        body: {
          storageBytes: Math.round(Number(formText(form, 'storage')) * MB),
          computeSeconds: Math.round(Number(formText(form, 'compute')) * 60),
        },
      });
    else if (intent === 'checkout' || intent === 'portal')
      return redirect(
        (
          await api<{
            url: string;
          }>(prefix + '/payment/' + intent, { method: 'POST', body: {} })
        ).url,
      );
    else if (intent === 'settings') {
      await api(prefix + '/settings', {
        method: 'PUT',
        body: Object.fromEntries(
          ['returnUrl', 'refreshUrl']
            .map((key) => [key, formText(form, key)])
            .filter(([, value]) => value),
        ),
      });
    }
    return { ok: true };
  });
}
export default function SettingsPage() {
  const { t, i18n } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { session } = useWorkspace();
  const [search] = useSearchParams();
  const navigate = useNavigate();
  const can = (action: (typeof data.principal.permissions)[number]) =>
    data.principal.permissions.includes(action);
  const prefix = '/p/' + data.principal.id + '/settings/';
  const self = data.principal.id === session.principal?.id;
  const transfer = can('transfer') && !self;
  const actionLabel = (action: string) => {
    const title = data.titles[action];
    return title ? (i18n.language === 'en' ? title.en : title.ja) : action;
  };
  return (
    <Page title={t('settings')}>
      <Tabs value={data.tab} onValueChange={(tab) => void navigate(prefix + tab)} className="gap-6">
        <TabsList aria-label={t('settings')} className="max-w-full justify-start overflow-x-auto overflow-y-hidden">
          {(['general', 'credentials', 'billing', 'integrations', 'audit'] as const)
            .filter((tab) =>
              tab === 'credentials'
                ? can('manage_credentials') && !self
                : tab === 'billing'
                  ? can('manage_billing')
                  : tab === 'integrations'
                    ? can('share')
                    : true,
            )
            .map((tab) => (
              <TabsTrigger key={tab} value={tab}>
                {t(tab)}
              </TabsTrigger>
            ))}
        </TabsList>
        <TabsContent value={data.tab} className="flex min-w-0 max-w-3xl flex-col gap-6">
          <ErrorNotice error={result && 'error' in result ? result.error : null} />
          {result && 'ok' in result && <Notice tone={'success'}>{t('saved')}</Notice>}
          {data.tab === 'general' && (
            <>
              <Panel title={t('general')}>
                <Form method="post" className="flex min-w-0 flex-wrap items-end gap-2">
                  <div className="min-w-0 flex-1 basis-64">
                    <InputField
                      name="name"
                      label={t('name')}
                      defaultValue={data.principal.name}
                      key={data.principal.name}
                      required
                      disabled={!can('update')}
                    />
                  </div>
                  {can('update') && (
                    <Button type="submit" name="intent" value="rename" variant="outline" size="lg">
                      {t('save')}
                    </Button>
                  )}
                </Form>
                <Detail label={t('id')}>
                  {data.principal.id}
                  <Copy value={data.principal.id} />
                </Detail>
                {can('share') && (
                  <div>
                    <Button variant="outline" asChild>
                      <Link to={prefix + 'general/share'}>{t('share')}</Link>
                    </Button>
                  </div>
                )}
              </Panel>
              {(can('export') || transfer || can('delete')) && (
                <Panel title={t('rarelyUsed')}>
                  <div className="divide-y divide-border">
                    {can('export') && (
                      <Operation title={t('export')} help={t('exportHelp')}>
                        <Button variant="outline" asChild>
                          <a href={`/api/principals/${data.principal.id}/export`}>{t('download')}</a>
                        </Button>
                      </Operation>
                    )}
                    {transfer && (
                      <Operation title={t('transfer')} help={t('transferHelp')}>
                        <Form method="post" className="flex w-full min-w-0 flex-wrap items-end gap-2">
                          <div className="min-w-0 flex-1 basis-64">
                            <InputField name="to" label={t('transferTo')} required />
                          </div>
                          <Button name="intent" value="transfer" type="submit" variant="outline" size="lg">
                            {t('transfer')}
                          </Button>
                        </Form>
                      </Operation>
                    )}
                    {can('delete') && (
                      <Operation
                        title={t(self ? 'deleteAccount' : 'deletePrincipal')}
                        help={t(self ? 'deleteAccountHelp' : 'deletePrincipalHelp')}
                      >
                        <Confirm label={t(self ? 'deleteAccount' : 'deletePrincipal')} name={data.principal.name}>
                          <input type="hidden" name="intent" value="delete" />
                        </Confirm>
                      </Operation>
                    )}
                  </div>
                </Panel>
              )}
            </>
          )}
          {data.credentials && (
            <CredentialsPanel principal={data.principal} items={data.credentials.items} currentId={session.credentialId} />
          )}
          {data.payment && data.usage && (
            <>
              <Panel title={t('billing')}>
                <Detail label={t('status')}>
                  {t(
                    data.payment.required
                      ? data.payment.active
                        ? 'active'
                        : 'inactive'
                      : 'paymentNotRequired',
                  )}
                </Detail>
                <Detail label={t('payer')}>{data.payment.payer?.name ?? '—'}</Detail>
                {data.payment.available ? (
                  <Form method="post">
                    <Button
                      type="submit"
                      name="intent"
                      value={data.payment.active ? 'portal' : 'checkout'}
                      variant="outline"
                    >
                      {t(data.payment.active ? 'managePayment' : 'addPayment')}
                    </Button>
                  </Form>
                ) : (
                  <Notice tone={'info'}>
                    {t(data.payment.required ? 'featureUnavailable' : 'paymentIncluded')}
                  </Notice>
                )}
              </Panel>
              <Panel title={t('usage') + ' — ' + data.usage.month}>
                {([
                  ['storage', data.usage.storageBytes, data.usage.storageLimit,
                    <><Bytes value={data.usage.storageBytes} /> / <Bytes value={data.usage.storageLimit} /></>],
                  ['compute', data.usage.computeSeconds, data.usage.computeLimit,
                    <>{Math.ceil(data.usage.computeSeconds / 60)} / {Math.floor(data.usage.computeLimit / 60)} {t('minutes')}</>],
                ] as const).map(([key, used, limit, text]) => (
                  <div key={key} className="grid gap-2">
                    <div className="flex flex-wrap items-baseline justify-between gap-2">
                      <span className="text-muted-foreground">{t(key)}</span>
                      <span>{text}</span>
                    </div>
                    <Progress value={Math.min(100, (used / limit) * 100)} aria-label={t(key)} />
                  </div>
                ))}
                <details className="group">
                  <summary className="w-fit cursor-pointer text-sm text-muted-foreground hover:text-foreground">
                    {t('changeLimits')}
                  </summary>
                  <Form method="post" className="mt-4 grid gap-4">
                    <p className="text-xs leading-relaxed text-muted-foreground">{t('limitsHelp')}</p>
                    <div className="grid gap-4 sm:grid-cols-2">
                      <InputField
                        type="number"
                        name="storage"
                        label={t('storageLimit')}
                        defaultValue={data.usage.storageLimit / MB}
                        required
                        min={0.000001}
                        max={1000000}
                        step={'any'}
                      />
                      <InputField
                        type="number"
                        name="compute"
                        label={t('computeLimit')}
                        defaultValue={data.usage.computeLimit / 60}
                        required
                        min={1}
                        max={166666}
                        step={'any'}
                      />
                    </div>
                    <div>
                      <Button name="intent" value="limits" type="submit" variant="outline">
                        {t('save')}
                      </Button>
                    </div>
                  </Form>
                </details>
              </Panel>
            </>
          )}
          {data.settings && (
            <Panel title={t('integrations')}>
              <p className="leading-relaxed text-muted-foreground">{t('integrationsHelp')}</p>
              <Form method="post" className="grid gap-4">
                {['returnUrl', 'refreshUrl'].map((key) => (
                  <InputField
                    key={key}
                    type="url"
                    name={key}
                    label={t(key)}
                    defaultValue={data.settings?.[key as keyof typeof data.settings] ?? ''}
                  />
                ))}
                <div>
                  <Button name="intent" value="settings" type="submit" variant="outline">
                    {t('save')}
                  </Button>
                </div>
              </Form>
            </Panel>
          )}
          {data.audit && (
            <Panel title={t('audit')}>
              <ul className="divide-y divide-border">
                {data.audit.items.map((entry) => (
                  <li key={entry.id} className="flex flex-wrap items-center gap-3 py-3 first:pt-0 last:pb-0">
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="font-medium wrap-anywhere">{actionLabel(entry.action)}</div>
                      <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
                        <DateText value={entry.createdAt} /> ·{' '}
                        {entry.actorId === null
                          ? 'Foundation'
                          : entry.actorId === data.principal.id
                            ? data.principal.name
                            : entry.actorId === session.principal?.id
                              ? session.principal.name
                              : entry.actorId}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
              {!data.audit.items.length && (
                <p className="leading-relaxed text-muted-foreground">{t('empty')}</p>
              )}
              <Paging next={data.audit.next} search={search} />
            </Panel>
          )}
        </TabsContent>
      </Tabs>
    </Page>
  );
}
