import { useEffect, useState } from 'react';
import { Form, Link, useActionData, useLoaderData, useRevalidator, useRouteLoaderData } from 'react-router';
import { Button, Stack, TextField, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/request';
import type { clientLoader as rootLoader } from '../root';
import { ApprovalRequest } from '../../../shared/contracts';
import { actionResult, api, formText, session } from '../api';
import {
  Copy,
  DateText,
  Detail,
  ErrorNotice,
  ExternalLink,
  JsonView,
  Page,
  Panel,
  State,
  usePolling,
  useTask,
} from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const token = fragment.get('token');
  if (token) {
    await api(`/requests/${params.id}/redeem`, { method: 'POST', body: { token } });
    history.replaceState(null, '', window.location.pathname);
  }
  const [item, account] = await Promise.all([
    api('/requests/' + params.id, { signal: request.signal }, ApprovalRequest),
    session(request),
  ]);
  if (['pending', 'running'].includes(item.state) && item.from.id === account.principal?.id)
    item.code = sessionStorage.getItem('foundation.request.' + item.id) ?? undefined;
  else sessionStorage.removeItem('foundation.request.' + item.id);
  return { item, account };
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const intent = formText(form, 'intent');
    if (intent === 'role') {
      await api(`/connections/${formText(form, 'roleId')}/role`, {
        method: 'POST',
        body: { arn: formText(form, 'arn'), region: formText(form, 'region') },
      });
      return api('/requests/' + params.id, {}, ApprovalRequest);
    }
    const item = await api('/requests/' + params.id, {}, ApprovalRequest);
    const values = item.operations.map((operation, index) =>
      Object.fromEntries(
        operation.inputs.map((input, inputIndex) => [
          input.pointer,
          String(form.get(`input.${index}.${inputIndex}`) ?? ''),
        ]),
      ),
    );
    return api(
      '/requests/' + params.id + '/' + intent,
      {
        method: 'POST',
        body: intent === 'approve' ? { values, code: formText(form, 'code') || undefined } : {},
      },
      ApprovalRequest,
    );
  });
}
export default function RequestPage() {
  const { t } = useTranslation();
  const { item, account } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const task = useTask();
  const [link, setLink] = useState('');
  const pending = ['pending', 'running'].includes(item.state);
  const requester = item.from.id === account.principal?.id;
  const root = useRouteLoaderData<typeof rootLoader>('root');
  const revalidator = useRevalidator();
  useEffect(() => {
    if (account.requestId && root?.requestId !== account.requestId && revalidator.state === 'idle')
      void revalidator.revalidate();
  }, [account.requestId, root?.requestId, revalidator]);
  const role = item.results.find(
    (value) =>
      value && typeof value === 'object' && !Array.isArray(value) && value.kind === 'role' && value.pending,
  ) as { id: string; principalArn: string; externalId: string } | undefined;
  usePolling(pending, 5000);
  return (
    <Page title={t('requests')} narrow>
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      <Panel>
        <Detail label={t('status')}>
          <State value={item.state} />
        </Detail>
        <Detail label={t('requestedBy')}>
          {item.from.name}
          <Copy value={item.from.id} />
        </Detail>
        <Detail label={t('requestedTo')}>{item.to?.name ?? '—'}</Detail>
        <Detail label={t('expires')}>
          <DateText value={item.expiresAt} />
        </Detail>
        <Typography sx={{ whiteSpace: 'pre-wrap' }}>{item.message || t('noMessage')}</Typography>
        {item.code && (
          <Detail label={t('code')}>
            {item.code}
            <Copy value={item.code} />
          </Detail>
        )}
        {requester && (
          <Detail label={t('url')}>
            {item.url}
            <Copy value={item.url} />
          </Detail>
        )}
      </Panel>
      <Form method="post">
        <Stack spacing={3}>
          {item.operations.map((operation, index) => (
            <Panel key={index} title={`${index + 1}. ${operation.method} ${operation.path}`}>
              <JsonView value={operation.body ?? {}} />
              {operation.inputs.map((input, inputIndex) => (
                <Stack key={input.pointer} spacing={1}>
                  <TextField
                    name={`input.${index}.${inputIndex}`}
                    label={input.label}
                    type={input.secret && !input.multiline ? 'password' : 'text'}
                    multiline={input.multiline}
                    minRows={input.multiline ? 3 : undefined}
                    autoComplete="off"
                    fullWidth
                    disabled={!item.canRespond || !pending}
                    required={item.canRespond && pending}
                    helperText={input.pointer}
                  />
                  {input.site && <ExternalLink href={input.site}>{t('serviceConsole')}</ExternalLink>}
                </Stack>
              ))}
            </Panel>
          ))}
          {pending && item.canRespond && !item.to && (
            <TextField name="code" label={t('code')} required helperText={t('codeHelp')} autoComplete="off" />
          )}
          {item.continueUrl && item.canRespond && (
            <Button variant="contained" href={item.continueUrl}>
              {t('finishConnection')}
            </Button>
          )}
          {pending && item.canRespond && !item.continueUrl && !role && (
            <Stack direction="row" spacing={2}>
              <Button
                type="submit"
                name="intent"
                value="approve"
                variant="contained"
                disabled={item.state === 'running'}
              >
                {t('approve')}
              </Button>
              <Button type="submit" name="intent" value="decline" formNoValidate>
                {t('decline')}
              </Button>
            </Stack>
          )}
          {pending && requester && (
            <Button type="submit" name="intent" value="cancel" color="error" formNoValidate>
              {t('cancelRequest')}
            </Button>
          )}
        </Stack>
      </Form>
      {pending && item.canRespond && role && (
        <Panel title={t('role')}>
          <Typography>{t('roleHelp')}</Typography>
          <JsonView
            value={{
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Principal: { AWS: role.principalArn },
                  Action: 'sts:AssumeRole',
                  Condition: { StringEquals: { 'sts:ExternalId': role.externalId } },
                },
              ],
            }}
          />
          <Form method="post">
            <Stack spacing={2}>
              <input type="hidden" name="roleId" value={role.id} />
              <TextField name="arn" label={t('roleArn')} required fullWidth />
              <TextField name="region" label={t('region')} defaultValue="ap-northeast-1" required />
              <Button type="submit" name="intent" value="role" variant="contained">
                {t('connect')}
              </Button>
            </Stack>
          </Form>
        </Panel>
      )}
      {!account.principal && pending && (
        <Button
          component={Link}
          to={'/signin?returnTo=' + encodeURIComponent('/requests/' + item.id)}
          variant="contained"
        >
          {t('signinToApprove')}
        </Button>
      )}
      {item.results.some((value) => value !== null) && (
        <Panel title={t('result')}>
          <JsonView value={item.results} />
        </Panel>
      )}
      {!pending && item.returnUrl && (
        <Button href={item.returnUrl} variant="contained">
          {t('returnToService', { name: item.from.name })}
        </Button>
      )}
      {['expired', 'cancelled'].includes(item.state) && item.refreshUrl && (
        <Button href={item.refreshUrl}>{t('retry')}</Button>
      )}
      {pending && item.canRespond && !account.requestId && item.to && (
        <Panel>
          <Typography variant="body2" color="text.secondary">
            {t('requestLinkHelp')}
          </Typography>
          <Button
            loading={task.busy}
            onClick={() =>
              task.run(async () =>
                setLink(
                  (await api<{ url: string }>(`/requests/${item.id}/links`, { method: 'POST', body: {} }))
                    .url,
                ),
              )
            }
          >
            {t('requestLink')}
          </Button>
          {link && (
            <>
              <TextField label={t('url')} value={link} slotProps={{ input: { readOnly: true } }} />
              <Copy value={link} />
            </>
          )}
        </Panel>
      )}
    </Page>
  );
}
