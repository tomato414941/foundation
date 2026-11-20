import { Button } from '../components/ui/button';
import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/merge';
import type { PublicEncryptionKey, ResourceView } from '../../../shared/contracts';
import { sealItem } from '../../../shared/custody';
import type { SealedItemValue } from '../../../shared/custody';
import { actionResult, api, signedIn } from '../api';
import { custodyClient } from '../custody';
import { requireKeys } from '../keys';
import { ErrorNotice, Page, Panel } from '../components';
import { ResourceTable } from '../resource-table';
type MergePlan = {
  from: {
    id: string;
    name: string;
    publicKey: PublicEncryptionKey | null;
  };
  resources: ResourceView[];
  protectedItems: Array<{ id: string; version: number; content: SealedItemValue }>;
  recipients: Array<{ id: string; name: string; publicKey: PublicEncryptionKey }>;
};
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return api<MergePlan>('/account/merge/' + params.id);
}
// What the other account holds is opened with its key, which its passkey opened here, and sealed for whoever uses what
// this account holds.
export async function clientAction({ params }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const plan = await api<MergePlan>('/account/merge/' + params.id);
    await requireKeys();
    const previous = await custodyClient(plan.from.id);
    const contents: Record<string, { version: number; content: SealedItemValue }> = {};
    for (const item of plan.protectedItems)
      contents[item.id] = { version: item.version, content: await sealItem(await previous.open(item.content), plan.recipients,
        item.content.revision + 1, item.content.metadata) };
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
