import { InputField } from '../form-fields';
import { Notice } from '../components';
import { Form, redirect, useLoaderData, useActionData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource-transfer';
import { Recipient, Resource, listOf } from '../../../shared/contracts';
import { seal } from '../../../shared/encryption';
import { actionResult, api, formText, session } from '../api';
import { decryptSecret } from '../keys';
import { ErrorNotice, Page, SaveBar } from '../components';
import { resourcePath } from '../navigation';
export async function clientLoader({ params }: Route.ClientLoaderArgs) {
  return api('/resources/' + params.id, {}, Resource);
}
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const to = formText(form, 'to');
    const resource = await api('/resources/' + params.id, {}, Resource);
    let sealed;
    if (resource.kind === 'secret') {
      const data = await session();
      const content = await decryptSecret(resource.id, data.principal!.id);
      const recipients = await api(
        `/resources/${resource.id}/transfer-recipients?to=${encodeURIComponent(to)}`,
        {},
        listOf(Recipient),
      );
      if (resource.data.allowUse) recipients.items.push(data.server);
      sealed = await seal(content, recipients.items, 'resource:' + resource.id);
    }
    await api('/resources/' + resource.id + '/transfer', {
      method: 'POST',
      body: { to, ...(sealed ? { sealed } : {}) },
    });
    return redirect(`/p/${params.owner}/${params.section}`);
  });
}
export default function Transfer() {
  const item = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  const { t } = useTranslation();
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
