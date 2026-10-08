import { InputField } from '../form-fields';
import { Notice } from '../components';
import { Form, redirect, useLoaderData, useActionData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource-transfer';
import { Resource, listOf } from '../../../shared/contracts';
import { BoundRecipient } from '../../../shared/protocol';
import { verifyBinding } from '../../../shared/authority';
import { isProtected } from '../../../shared/protected';
import { actionResult, api, formText } from '../api';
import { custodyClient } from '../custody';
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
    if (isProtected(resource.kind)) {
      const client = await custodyClient(), previous = await client.read(resource.id);
      const recipients = await api(
        `/resources/${resource.id}/transfer-recipients?to=${encodeURIComponent(to)}`,
        {},
        listOf(BoundRecipient),
      );
      for (const { name: _name, ...item } of recipients.items) { await verifyBinding(item); await client.trusted(item.binding); }
      const readers = recipients.items.map(item => item.binding);
      const policy = { ...previous.content.policy, ownerId: to, revision: previous.content.policy.revision + 1,
        readers, authorities: readers, grants: [], observers: [], producers: [] };
      await client.save(resource.name, await client.reveal(resource.id), policy, { previous, metadata: previous.content.metadata });
    } else await api('/resources/' + resource.id + '/transfer', {
      method: 'POST',
      body: { to },
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
