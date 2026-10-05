import { Form, Link, redirect, useActionData, useLoaderData } from 'react-router';
import { Button, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/merge';
import type { PublicEncryptionKey, ResourceView, SealedContent } from '../../../shared/contracts';
import { open, seal } from '../../../shared/encryption';
import { actionResult, api, session, signedIn } from '../api';
import { getKey } from '../keys';
import { ErrorNotice, Page, Panel } from '../components';
import { ResourceTable } from '../resource-table';
type MergePlan = {
  from: { id: string; name: string; publicKey: PublicEncryptionKey | null };
  resources: ResourceView[];
  secrets: Array<{ id: string; sealed: SealedContent }>;
  recipients: Array<{ id: string; publicKey: PublicEncryptionKey }>;
};
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return api<MergePlan>('/account/merge/' + params.id);
}
export async function clientAction({ params }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const plan = await api<MergePlan>('/account/merge/' + params.id);
    const current = await session();
    const key = await getKey(plan.from.id);
    const secrets: Record<string, SealedContent> = {};
    if (key)
      for (const item of plan.secrets) {
        try {
          const value = await open(item.sealed, key, plan.from.id, 'resource:' + item.id);
          const recipients = [...plan.recipients];
          if (item.sealed.recipients.some((recipient) => recipient.header.kid === current.server.id))
            recipients.push(current.server);
          secrets[item.id] = await seal(value, recipients, 'resource:' + item.id);
        } catch {
          /* Server can rewrap a secret only when Foundation has its use permission. */
        }
      }
    await api('/account/merge/' + params.id, { method: 'POST', body: { secrets } });
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
        <Typography>
          {t('mergeFrom')}: {data.from.name}
        </Typography>
        <Typography>{t('mergeCount', { count: data.resources.length })}</Typography>
      </Panel>
      <ResourceTable items={data.resources} kinds />
      <Form method="post">
        <Stack direction="row" spacing={2}>
          <Button variant="contained" type="submit">
            {t('mergeConfirm')}
          </Button>
          <Button component={Link} to="/account">
            {t('cancel')}
          </Button>
        </Stack>
      </Form>
    </Page>
  );
}
