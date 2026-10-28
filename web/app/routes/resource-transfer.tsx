import { InputField } from '../form-fields';
import { Notice } from '../components';
import { Form, redirect, useLoaderData, useActionData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource-transfer';
import { Resource } from '../../../shared/contracts';
import { IdentityVerificationRequired, transferResource } from '../../../shared/client';
import { actionResult, api, formText } from '../api';
import { custodyClient } from '../custody';
import { requireKeys } from '../keys';
import { ErrorNotice, Page, SaveBar } from '../components';
import { resourcePath } from '../navigation';
import { RecipientVerificationLinks } from '../recipient-verification';
export async function clientLoader({ params }: Route.ClientLoaderArgs) {
  return api('/resources/' + params.id, {}, Resource);
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const to = formText(form, 'to');
    try {
      const changed = await transferResource({ json: (path, options, schema) => api(path.slice(4), options, schema) },
        params.id, to, async () => { await requireKeys(); return custodyClient(); });
      if ('url' in changed) return redirect(changed.url);
    } catch (error) {
      if (error instanceof IdentityVerificationRequired) return { error: error.code, verification: [error.recipient] };
      throw error;
    }
    return redirect(`/p/${params.owner}/${params.section}`);
  });
}
export default function Transfer() {
  const item = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const verification = result && 'verification' in result ? result.verification : [];
  const { t } = useTranslation();
  return (
    <Page title={t('transfer') + ' — ' + item.name} narrow>
      {verification.length ? <Notice tone="warning"><RecipientVerificationLinks recipients={verification} /></Notice>
        : <ErrorNotice error={result && 'error' in result ? result.error : null} />}
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
