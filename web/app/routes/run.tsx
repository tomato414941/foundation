import { Button } from '../components/ui/button';
import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/run';
import { Task } from '../../../shared/execution';
import { actionResult, api, ApiFailure, errorCode, formText, signedIn } from '../api';
import { Resource } from '../../../shared/contracts';
import { custodyClient } from '../custody';
import { DateText, Detail, ErrorNotice, Notice, Page, Panel, State, usePolling } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  const task = await api('/executions/' + params.id, { signal: request.signal }, Task);
  try { return { task, decrypted: task.receipt ? await (await custodyClient()).result(task) : null, decryptError: null }; }
  catch (error) { return { task, decrypted: null, decryptError: errorCode(error) }; }
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    if (formText(await request.formData(), 'intent') === 'removeConnection') {
      const task = await api('/executions/' + params.id, {}, Task);
      const result = await (await custodyClient()).result(task);
      const id = revokedConnection(task.kind, result?.ok === true ? result.result : null);
      if (!id) throw new ApiFailure('invalid_input');
      const resource = await api('/resources/' + id, {}, Resource);
      if (resource.kind !== 'connection') throw new ApiFailure('invalid_input');
      await api('/resources/' + id, { method: 'DELETE' });
      return redirect('/p/' + resource.ownerId + '/services');
    }
    return api('/executions/' + params.id + '/cancel', { method: 'POST', body: {} }, Task);
  });
}
function revokedConnection(kind: string, result: unknown) {
  return kind === 'revoke' && result && typeof result === 'object' && 'kind' in result &&
    result.kind === 'revoked' && 'id' in result && typeof result.id === 'string' ? result.id : null;
}
export default function RunPage() {
  const { t } = useTranslation();
  const { task: data, decrypted, decryptError } = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  usePolling(['queued', 'running'].includes(data.state));
  return (
    <Page
      title={t('result')}
      actions={
        ['queued', 'running'].includes(data.state) && (
          <Form method="post">
            <Button type="submit" variant="destructive">
              {t('cancel')}
            </Button>
          </Form>
        )
      }
    >
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Panel>
        <Detail label={t('id')}>{data.id}</Detail>
        <Detail label={t('status')}>
          <State value={data.state} />
        </Detail>
        <Detail label={t('created')}>
          <DateText value={data.createdAt} />
        </Detail>
      </Panel>
      {data.error && <ErrorNotice error={data.error} />}
      {decryptError && <Notice tone="info"><ErrorNotice error={decryptError} /><Link to="/account">{t('unlock')}</Link></Notice>}
      {decrypted?.error && <ErrorNotice error={decrypted.error.code} />}
      {decrypted?.ok && revokedConnection(data.kind, decrypted.result) && <Form method="post">
        <input type="hidden" name="intent" value="removeConnection" />
        <Button type="submit" variant="destructive">{t('removeRevokedConnection')}</Button>
      </Form>}
    </Page>
  );
}
