import { InputField } from '../form-fields';
import { PrincipalField } from '../principal-field';
import { Notice } from '../components';
import { Form, redirect, useLoaderData, useActionData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource-transfer';
import { Resource } from '../../../shared/contracts';
import { transferResource } from '../../../shared/client';
import { actionResult, api, formText } from '../api';
import { custodyClient } from '../custody';
import { requireKeys } from '../keys';
import { ErrorNotice, Page, SaveBar } from '../components';
import { resourcePath } from '../navigation';
import { useWorkspace } from './workspace';
export async function clientLoader({ params }: Route.ClientLoaderArgs) {
  return api('/resources/' + params.id, {}, Resource);
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const to = formText(form, 'to');
    const changed = await transferResource({ json: (path, options, schema) => api(path.slice(4), options, schema) },
      params.id, to, async () => { await requireKeys(); return custodyClient(); });
    if ('url' in changed) return redirect(changed.url);
    return redirect(`/p/${params.owner}/${params.section}`);
  });
}
export default function Transfer() {
  const item = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { t } = useTranslation();
  const { session } = useWorkspace();
  if (item.kind === 'connection') return <Page title={t('transfer')} narrow
    back={{ to: resourcePath(item), label: item.name }}>
    <ErrorNotice error={result && 'error' in result ? result.error : null} />
    <Form method="post" className="grid gap-4">
      <PrincipalField name="to" label={t('transferRecipient')} idLabel={t('transferTo')}
        principals={session.principals.filter(principal => principal.id !== item.ownerId)} />
      <p className="text-sm text-muted-foreground">{t('connectionTransferHelp')}</p>
      <SaveBar back={resourcePath(item)} label="transfer" />
    </Form>
  </Page>;
  return (
    <Page title={t('transfer') + ' — ' + item.name} narrow>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Notice tone={'info'}>{t('transferHelp')}</Notice>
      <Form method="post">
        <div className="flex min-w-0 flex-col gap-6">
          <InputField name="to" label={t('transferTo')} required />
          <SaveBar back={resourcePath(item)} label="transfer" />
        </div>
      </Form>
    </Page>
  );
}
