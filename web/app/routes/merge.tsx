import { Button } from '../components/ui/button';
import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/merge';
import type { PublicEncryptionKey, ResourceView } from '../../../shared/contracts';
import { protect, reveal } from '../../../shared/custody';
import type { CustodyContent } from '../../../shared/custody';
import type { BoundKeys } from '../../../shared/authority';
import { actionResult, api, signedIn } from '../api';
import { custodyClient } from '../custody';
import { ErrorNotice, Page, Panel } from '../components';
import { ResourceTable } from '../resource-table';
type MergePlan = {
  from: {
    id: string;
    name: string;
    publicKey: PublicEncryptionKey | null;
  };
  resources: ResourceView[];
  protectedItems: Array<{ id: string; version: number; content: CustodyContent }>;
  recipients: Array<{ binding: BoundKeys; signature: string; name: string }>;
};
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return api<MergePlan>('/account/merge/' + params.id);
}
export async function clientAction({ params }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const plan = await api<MergePlan>('/account/merge/' + params.id);
    const client = await custodyClient(), previous = await custodyClient(plan.from.id);
    await previous.trust.rememberBinding(client.binding);
    await client.trust.rememberBinding(previous.binding);
    const contents: Record<string, { version: number; content: CustodyContent }> = {};
    for (const item of plan.protectedItems) {
      await previous.observe(item.content, item.id);
      for (const recipient of plan.recipients) await client.trusted(recipient.binding);
      const keep = (binding: BoundKeys) => binding.principalId !== plan.from.id;
      const unique = (values: BoundKeys[]) => [...new Map(values.map(binding => [binding.id, binding])).values()];
      const recipients = plan.recipients.map(item => item.binding);
      const policy = { ...item.content.policy, ownerId: client.binding.principalId, revision: item.content.policy.revision + 1,
        readers: unique([...item.content.policy.readers.filter(keep), ...recipients]),
        authorities: unique([...item.content.policy.authorities.filter(keep), ...recipients]),
        grants: item.content.policy.grants.filter(grant => keep(grant.executor)).map(grant => ({
          ...grant, actor: keep(grant.actor) ? grant.actor : client.binding })),
        observers: (item.content.policy.observers ?? []).filter(id => id !== plan.from.id), producers: [],
      };
      contents[item.id] = { version: item.version, content: await protect(
        await reveal(item.content, previous.binding, previous.keys.encryption), policy, item.content.materialRevision + 1,
        previous.binding, previous.keys, item.content.metadata, item.content) };
    }
    await api('/account/merge/' + params.id, { method: 'POST', body: { contents } });
    return redirect('/account');
  });
}
export default function Merge() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const result = useActionData<typeof clientAction>();
  return (
    <Page title={t('mergeReview')}>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Panel>
        <p className="leading-relaxed">
          {t('mergeFrom')}: {data.from.name}
        </p>
        <p className="leading-relaxed">{t('mergeCount', { count: data.resources.length })}</p>
      </Panel>
      <ResourceTable items={data.resources} kinds />
      <Form method="post">
        <div className="flex min-w-0 flex-wrap items-center gap-4">
          <Button type="submit" variant="default">
            {t('mergeConfirm')}
          </Button>
          <Button variant="ghost" asChild>
            <Link to="/account">{t('cancel')}</Link>
          </Button>
        </div>
      </Form>
    </Page>
  );
}
