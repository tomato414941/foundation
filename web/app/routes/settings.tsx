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
import { actionResult, api, formText } from '../api';
import { Bytes, Confirm, Copy, DateText, Detail, ErrorNotice, Page, Paging, Panel } from '../components';
import { useWorkspace } from './workspace';
import { rekeySharing } from '../keys';
import { CredentialsPanel } from '../credentials-panel';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  if (!['general', 'credentials', 'billing', 'integrations', 'audit'].includes(params.tab))
    throw new Response('Not found', { status: 404 });
  const prefix = '/principals/' + params.owner;
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
  return { principal, tab: params.tab, credentials, payment, usage, settings, audit };
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
      const secrets = await rekeySharing(prefix + '/transfer-recipients?' + new URLSearchParams({ to }));
      await api(prefix + '/transfer', { method: 'POST', body: { to, secrets } });
      return redirect('/');
    } else if (intent === 'credential')
      await api(prefix + '/credentials/' + formText(form, 'credentialId'), { method: 'DELETE' });
    else if (intent === 'limits')
      await api(prefix + '/limits', {
        method: 'PUT',
        body: {
          storageBytes: Math.round(Number(formText(form, 'storage')) * 1000000),
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
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { session } = useWorkspace();
  const [search] = useSearchParams();
  const navigate = useNavigate();
  const can = (action: (typeof data.principal.permissions)[number]) =>
    data.principal.permissions.includes(action);
  const prefix = '/p/' + data.principal.id + '/settings/';
  return (
    <Page title={t('settings')}>
      <Tabs value={data.tab} onValueChange={(tab) => void navigate(prefix + tab)} className="gap-6">
        <TabsList aria-label={t('settings')} className="max-w-full justify-start overflow-x-auto overflow-y-hidden">
          {(['general', 'credentials', 'billing', 'integrations', 'audit'] as const)
            .filter((tab) =>
              tab === 'credentials'
                ? can('credentials')
                : tab === 'billing'
                  ? can('billing')
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
        <TabsContent value={data.tab} className="flex min-w-0 flex-col gap-6">
          <ErrorNotice error={result && 'error' in result ? result.error : null} />
          {result && 'ok' in result && <Notice tone={'success'}>{t('saved')}</Notice>}
          {data.tab === 'general' && (
            <>
              <Panel title={t('general')}>
                <Detail label={t('id')}>
                  {data.principal.id}
                  <Copy value={data.principal.id} />
                </Detail>
                <Form method="post">
                  <div className="flex min-w-0 flex-col gap-4">
                    <InputField
                      name="name"
                      label={t('name')}
                      defaultValue={data.principal.name}
                      key={data.principal.name}
                      required
                      disabled={!can('update')}
                    />
                    {can('update') && (
                      <Button type="submit" name="intent" value="rename" variant="default">
                        {t('save')}
                      </Button>
                    )}
                  </div>
                </Form>
                {can('share') && (
                  <Button variant="ghost" asChild>
                    <Link to={prefix + 'general/share'}>{t('share')}</Link>
                  </Button>
                )}
              </Panel>
              {can('export') && (
                <Panel title={t('export')}>
                  <p className="leading-relaxed text-muted-foreground">{t('exportHelp')}</p>
                  <Button variant="outline" asChild>
                    <a href={`/api/principals/${data.principal.id}/export`}>{t('download')}</a>
                  </Button>
                </Panel>
              )}
              {can('transfer') && data.principal.id !== session.principal?.id && (
                <Panel title={t('transfer')}>
                  <p className="leading-relaxed text-muted-foreground">{t('transferHelp')}</p>
                  <Form method="post">
                    <div className="flex min-w-0 flex-col gap-4">
                      <InputField name="to" label={t('transferTo')} required />
                      <Button name="intent" value="transfer" type="submit" variant="ghost">
                        {t('transfer')}
                      </Button>
                    </div>
                  </Form>
                </Panel>
              )}
              {can('delete') && (
                <div className="flex min-w-0 flex-wrap items-center">
                  <Confirm label={t('deletePrincipal')} name={data.principal.name}>
                    <input type="hidden" name="intent" value="delete" />
                  </Confirm>
                </div>
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
                      variant="default"
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
                <Detail label={t('storage')}>
                  <Bytes value={data.usage.storageBytes} /> / <Bytes value={data.usage.storageLimit} />
                </Detail>
                <Progress
                  value={Math.min(100, (data.usage.storageBytes / data.usage.storageLimit) * 100)}
                  aria-label={t('storage')}
                />
                <Detail label={t('compute')}>
                  {Math.ceil(data.usage.computeSeconds / 60)} /{' '}
                  {Math.floor(data.usage.computeLimit / 60)} {t('minutes')}
                </Detail>
                <Progress
                  value={Math.min(100, (data.usage.computeSeconds / data.usage.computeLimit) * 100)}
                  aria-label={t('compute')}
                />
              </Panel>
              <Panel>
                <p className="leading-relaxed text-muted-foreground">{t('limitsHelp')}</p>
                <Form method="post">
                  <div className="flex min-w-0 flex-col gap-6">
                    <InputField
                      type="number"
                      name="storage"
                      label={t('storageLimit')}
                      defaultValue={data.usage.storageLimit / 1000000}
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
                    <Button name="intent" value="limits" type="submit" variant="default">
                      {t('save')}
                    </Button>
                  </div>
                </Form>
              </Panel>
            </>
          )}
          {data.settings && (
            <>
              <Panel title={t('integrations')}>
                <Form method="post">
                  <div className="flex min-w-0 flex-col gap-6">
                    {['returnUrl', 'refreshUrl'].map((key) => (
                      <InputField
                        key={key}
                        type="url"
                        name={key}
                        label={t(key)}
                        defaultValue={data.settings?.[key as keyof typeof data.settings] ?? ''}
                      />
                    ))}
                    <Button name="intent" value="settings" type="submit" variant="default">
                      {t('save')}
                    </Button>
                  </div>
                </Form>
              </Panel>
            </>
          )}
          {data.audit && (
            <Panel title={t('audit')}>
              <ul className="divide-y divide-border">
                {data.audit.items.map((entry) => (
                  <li
                    key={entry.id}
                    className="flex flex-wrap items-center gap-3 py-4 first:pt-0 last:pb-0"
                  >
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="font-medium wrap-anywhere">{entry.action}</div>
                      <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
                        {
                          <>
                            <DateText value={entry.createdAt} /> · {entry.actorId ?? 'Foundation'}
                          </>
                        }
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
