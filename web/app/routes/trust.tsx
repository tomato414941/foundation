import { Form, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/trust';
import { hash } from '../../../shared/authority';
import { actionResult, formText, signedIn } from '../api';
import { custodyClient } from '../custody';
import { InputField } from '../form-fields';
import { Copy, Detail, ErrorNotice, Notice, Page, Panel, SaveBar } from '../components';

export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  const client = await custodyClient();
  return { id: client.binding.principalId, fingerprint: await hash(client.binding) };
}
export async function clientAction({ request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData(), client = await custodyClient();
    await client.trustIdentity(formText(form, 'principalId'), formText(form, 'fingerprint'));
    return { ok: true };
  });
}
export default function Trust() {
  const { t } = useTranslation(), data = useLoaderData<typeof clientLoader>(), result = useActionData<typeof clientAction>();
  return <Page title={t('trustIdentity')} narrow>
    <ErrorNotice error={result && 'error' in result ? result.error : null} />
    {result && 'ok' in result && <Notice tone="success">{t('saved')}</Notice>}
    <Panel title={t('myIdentity')}>
      <Detail label={t('id')}>{data.id}<Copy value={data.id} /></Detail>
      <Detail label={t('fingerprint')}><span className="break-all font-mono">{data.fingerprint}</span><Copy value={data.fingerprint} /></Detail>
    </Panel>
    <Form method="post"><div className="flex flex-col gap-6">
      <p className="text-sm leading-relaxed text-muted-foreground">{t('trustIdentityHelp')}</p>
      <InputField name="principalId" label={t('recipient')} required />
      <InputField name="fingerprint" label={t('fingerprint')} required autoComplete="off" minLength={43} maxLength={43} />
      <SaveBar back="/account" label="trustIdentity" />
    </div></Form>
  </Page>;
}
