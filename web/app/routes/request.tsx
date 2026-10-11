import { Button } from '../components/ui/button';
import { InputField, TextareaField } from '../form-fields';
import { useEffect } from 'react';
import {
  Form,
  Link,
  useActionData,
  useLoaderData,
  useRevalidator,
  useRouteLoaderData,
} from 'react-router';
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
  ProposalText,
  State,
  usePolling,
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
  const { t, i18n } = useTranslation();
  const { item, account } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const pending = ['pending', 'running'].includes(item.state);
  const requester = item.from.id === account.principal?.id;
  const root = useRouteLoaderData<typeof rootLoader>('root');
  const revalidator = useRevalidator();
  useEffect(() => {
    if (account.requestId && root?.requestId !== account.requestId && revalidator.state === 'idle')
      void revalidator.revalidate();
  }, [account.requestId, root?.requestId, revalidator]);
  usePolling(pending, 5000);
  return (
    <Page title={t('requests')} narrow>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
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
        {item.proposal ? (
          <p className="font-medium leading-relaxed wrap-anywhere">
            <ProposalText proposal={item.proposal} />
          </p>
        ) : (
          <p className="leading-relaxed whitespace-pre-wrap">{item.message || t('noMessage')}</p>
        )}
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
        <div className="flex min-w-0 flex-col gap-6">
          {!item.proposal && item.operations.map((operation, index) => (
            <Panel key={index} title={`${index + 1}. ${i18n.language === 'ja' ? operation.title.ja : operation.title.en}`}>
              {operation.body != null && (typeof operation.body !== 'object' || Object.keys(operation.body).length > 0) && (
                <JsonView value={operation.body} />
              )}
              {operation.inputs.map((input, inputIndex) => (
                <div key={input.pointer} className="flex min-w-0 flex-col gap-2">
                  {input.multiline ? (
                    <TextareaField
                      name={`input.${index}.${inputIndex}`}
                      label={input.label}
                      autoComplete="off"
                      disabled={!item.canRespond || !pending}
                      required={item.canRespond && pending}
                      rows={3}
                    />
                  ) : (
                    <InputField
                      name={`input.${index}.${inputIndex}`}
                      label={input.label}
                      type={input.secret ? 'password' : 'text'}
                      autoComplete="off"
                      disabled={!item.canRespond || !pending}
                      required={item.canRespond && pending}
                    />
                  )}
                  {input.site && <ExternalLink href={input.site}>{t('serviceConsole')}</ExternalLink>}
                </div>
              ))}
            </Panel>
          ))}
          {pending && item.canRespond && !item.to && (
            <InputField name="code" label={t('code')} required autoComplete="off" hint={t('codeHelp')} />
          )}
          {item.continueUrl && item.canRespond && (
            <Button variant="default" asChild>
              <a href={item.continueUrl}>{t('finishConnection')}</a>
            </Button>
          )}
          {pending && item.canRespond && !item.continueUrl && (
            <div className="flex min-w-0 flex-wrap items-center gap-4">
              <Button
                type="submit"
                name="intent"
                value="approve"
                disabled={item.state === 'running'}
                variant="default"
              >
                {t('approve')}
              </Button>
              <Button type="submit" name="intent" value="decline" formNoValidate variant="ghost">
                {t('decline')}
              </Button>
            </div>
          )}
          {pending && requester && (
            <Button type="submit" name="intent" value="cancel" formNoValidate variant="destructive">
              {t('cancelRequest')}
            </Button>
          )}
        </div>
      </Form>
      {!account.principal && pending && (
        <Button variant="default" asChild>
          <Link to={'/signin?returnTo=' + encodeURIComponent('/requests/' + item.id)}>
            {t('signinToApprove')}
          </Link>
        </Button>
      )}
      {!pending && item.returnUrl && (
        <Button variant="default" asChild>
          <a href={item.returnUrl}>{t('returnToService', { name: item.from.name })}</a>
        </Button>
      )}
      {['expired', 'cancelled'].includes(item.state) && item.refreshUrl && (
        <Button variant="ghost" asChild>
          <a href={item.refreshUrl}>{t('retry')}</a>
        </Button>
      )}
    </Page>
  );
}
