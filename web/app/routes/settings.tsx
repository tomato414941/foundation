import { Form, Link, redirect, useActionData, useLoaderData, useSearchParams } from 'react-router';
import {
  Alert,
  Button,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  Stack,
  Tab,
  Tabs,
  TextField,
  Typography,
} from '@mui/material';
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
    params.tab === 'integrations' ? api(prefix + '/settings', { signal: request.signal }, Settings) : null,
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
    if (intent === 'rename') await api(prefix, { method: 'PATCH', body: { name: formText(form, 'name') } });
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
          storageBytes: Math.round(Number(formText(form, 'storage')) * 1_000_000),
          computeSeconds: Math.round(Number(formText(form, 'compute')) * 60),
        },
      });
    else if (intent === 'checkout' || intent === 'portal')
      return redirect(
        (await api<{ url: string }>(prefix + '/payment/' + intent, { method: 'POST', body: {} })).url,
      );
    else if (intent === 'settings')
      return api<{ webhookSecret?: string }>(prefix + '/settings', {
        method: 'PUT',
        body: Object.fromEntries(
          ['returnUrl', 'refreshUrl', 'webhookUrl']
            .map((key) => [key, formText(form, key)])
            .filter(([, value]) => value),
        ),
      });
    else if (intent === 'rotate')
      return api<{ webhookSecret: string }>(prefix + '/settings/rotate', { method: 'POST', body: {} });
    return { ok: true };
  });
}
export default function SettingsPage() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { session } = useWorkspace();
  const [search] = useSearchParams();
  const can = (action: (typeof data.principal.permissions)[number]) =>
    data.principal.permissions.includes(action);
  const prefix = '/p/' + data.principal.id + '/settings/';
  return (
    <Page title={t('settings')}>
      <Tabs value={data.tab} variant="scrollable" scrollButtons="auto" aria-label={t('settings')}>
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
            <Tab key={tab} value={tab} label={t(tab)} component={Link} to={prefix + tab} />
          ))}
      </Tabs>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      {result && 'ok' in result && <Alert severity="success">{t('saved')}</Alert>}
      {data.tab === 'general' && (
        <>
          <Panel title={t('general')}>
            <Detail label={t('id')}>
              {data.principal.id}
              <Copy value={data.principal.id} />
            </Detail>
            <Form method="post">
              <Stack spacing={2}>
                <TextField
                  name="name"
                  label={t('name')}
                  defaultValue={data.principal.name}
                  key={data.principal.name}
                  required
                  fullWidth
                  disabled={!can('update')}
                />
                {can('update') && (
                  <Button type="submit" name="intent" value="rename" variant="contained">
                    {t('save')}
                  </Button>
                )}
              </Stack>
            </Form>
            {can('share') && (
              <Button component={Link} to={prefix + 'general/share'}>
                {t('share')}
              </Button>
            )}
          </Panel>
          {can('export') && (
            <Panel title={t('export')}>
              <Typography color="text.secondary">{t('exportHelp')}</Typography>
              <Button href={`/api/principals/${data.principal.id}/export`} variant="outlined">
                {t('download')}
              </Button>
            </Panel>
          )}
          {can('transfer') && data.principal.id !== session.principal?.id && (
            <Panel title={t('transfer')}>
              <Typography color="text.secondary">{t('transferHelp')}</Typography>
              <Form method="post">
                <Stack spacing={2}>
                  <TextField name="to" label={t('transferTo')} required fullWidth />
                  <Button name="intent" value="transfer" type="submit">
                    {t('transfer')}
                  </Button>
                </Stack>
              </Form>
            </Panel>
          )}
          {can('delete') && (
            <Stack direction="row">
              <Confirm label={t('deletePrincipal')} name={data.principal.name}>
                <input type="hidden" name="intent" value="delete" />
              </Confirm>
            </Stack>
          )}
        </>
      )}
      {data.credentials && (
        <Panel title={t('credentials')}>
          <Button component={Link} to="new" variant="contained">
            {t('add')}
          </Button>
          <List>
            {data.credentials.items.map((credential) => (
              <ListItem key={credential.id} disableGutters sx={{ flexWrap: 'wrap' }}>
                <ListItemText
                  primary={credential.name}
                  secondary={
                    <>
                      {t(
                        credential.kind === 'key'
                          ? 'apiKey'
                          : credential.kind === 'email'
                            ? 'email'
                            : 'passkeySignin',
                      )}{' '}
                      · <DateText value={credential.lastUsedAt ?? credential.createdAt} />
                      {credential.expiresAt && (
                        <>
                          {' '}
                          · {t('expires')}: <DateText value={credential.expiresAt} />
                        </>
                      )}
                    </>
                  }
                />
                <Confirm label={t('delete')} name={credential.name}>
                  <input type="hidden" name="intent" value="credential" />
                  <input type="hidden" name="credentialId" value={credential.id} />
                </Confirm>
              </ListItem>
            ))}
          </List>
        </Panel>
      )}
      {data.payment && data.usage && (
        <>
          <Panel title={t('billing')}>
            <Detail label={t('status')}>
              {t(data.payment.required ? (data.payment.active ? 'active' : 'inactive') : 'paymentNotRequired')}
            </Detail>
            <Detail label={t('payer')}>{data.payment.payer?.name ?? '—'}</Detail>
            {data.payment.available ? (
              <Form method="post">
                <Button
                  type="submit"
                  name="intent"
                  value={data.payment.active ? 'portal' : 'checkout'}
                  variant="contained"
                >
                  {t(data.payment.active ? 'managePayment' : 'addPayment')}
                </Button>
              </Form>
            ) : (
              <Alert severity="info">
                {t(data.payment.required ? 'featureUnavailable' : 'paymentIncluded')}
              </Alert>
            )}
          </Panel>
          <Panel title={t('usage') + ' — ' + data.usage.month}>
            <Detail label={t('storage')}>
              <Bytes value={data.usage.storageBytes} /> / <Bytes value={data.usage.storageLimit} />
            </Detail>
            <LinearProgress
              variant="determinate"
              value={Math.min(100, (data.usage.storageBytes / data.usage.storageLimit) * 100)}
              aria-label={t('storage')}
            />
            <Detail label={t('compute')}>
              {Math.ceil(data.usage.computeSeconds / 60)} / {Math.floor(data.usage.computeLimit / 60)}{' '}
              {t('minutes')}
            </Detail>
            <LinearProgress
              variant="determinate"
              value={Math.min(100, (data.usage.computeSeconds / data.usage.computeLimit) * 100)}
              aria-label={t('compute')}
            />
          </Panel>
          <Panel>
            <Typography color="text.secondary">{t('limitsHelp')}</Typography>
            <Form method="post">
              <Stack spacing={3}>
                <TextField
                  type="number"
                  name="storage"
                  label={t('storageLimit')}
                  defaultValue={data.usage.storageLimit / 1_000_000}
                  required
                  slotProps={{ htmlInput: { min: 0.000001, max: 1_000_000, step: 'any' } }}
                />
                <TextField
                  type="number"
                  name="compute"
                  label={t('computeLimit')}
                  defaultValue={data.usage.computeLimit / 60}
                  required
                  slotProps={{ htmlInput: { min: 1, max: 166666, step: 'any' } }}
                />
                <Button name="intent" value="limits" type="submit" variant="contained">
                  {t('save')}
                </Button>
              </Stack>
            </Form>
          </Panel>
        </>
      )}
      {data.settings && (
        <>
          <Panel title={t('integrations')}>
            <Form method="post">
              <Stack spacing={3}>
                {['returnUrl', 'refreshUrl', 'webhookUrl'].map((key) => (
                  <TextField
                    key={key}
                    type="url"
                    name={key}
                    label={t(key)}
                    defaultValue={data.settings?.[key as keyof typeof data.settings] ?? ''}
                    fullWidth
                  />
                ))}
                <Button name="intent" value="settings" type="submit" variant="contained">
                  {t('save')}
                </Button>
              </Stack>
            </Form>
          </Panel>
          {result && 'webhookSecret' in result && result.webhookSecret && (
            <Panel title={t('webhookSecret')}>
              <TextField
                value={result.webhookSecret}
                label={t('webhookSecret')}
                slotProps={{ input: { readOnly: true } }}
              />
              <Copy value={result.webhookSecret} />
            </Panel>
          )}
          {data.settings.webhookUrl && (
            <Confirm label={t('rotate')} name={t('webhookSecret')} body={t('rotateHelp')} danger={false}>
              <input type="hidden" name="intent" value="rotate" />
            </Confirm>
          )}
        </>
      )}
      {data.audit && (
        <Panel title={t('audit')}>
          <List>
            {data.audit.items.map((entry) => (
              <ListItem key={entry.id} disableGutters>
                <ListItemText
                  primary={entry.action}
                  secondary={
                    <>
                      <DateText value={entry.createdAt} /> · {entry.actorId ?? 'Foundation'}
                    </>
                  }
                />
              </ListItem>
            ))}
          </List>
          {!data.audit.items.length && <Typography color="text.secondary">{t('empty')}</Typography>}
          <Paging next={data.audit.next} search={search} />
        </Panel>
      )}
    </Page>
  );
}
