import { Form, redirect, useActionData } from 'react-router';
import { Stack, TextField } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/request-new';
import { ApprovalRequest } from '../../../shared/contracts';
import { actionResult, api, formText, jsonField, signedIn } from '../api';
import { ErrorNotice, JsonField, Page, SaveBar } from '../components';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return null;
}
export async function clientAction({ request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const result = await api(
      '/requests',
      {
        method: 'POST',
        body: {
          to: formText(form, 'to') || undefined,
          message: formText(form, 'message'),
          operations: jsonField(form, 'operations', []),
          expiresInMinutes: Number(formText(form, 'expires')),
        },
      },
      ApprovalRequest,
    );
    if (result.code) sessionStorage.setItem('foundation.request.' + result.id, result.code);
    return redirect('/requests/' + result.id);
  });
}
export default function RequestNew() {
  const { t } = useTranslation();
  const result = useActionData<typeof clientAction>();
  return (
    <Page title={t('newRequest')} narrow>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Form method="post">
        <Stack spacing={3}>
          <TextField name="to" label={t('requestTo')} />
          <TextField name="message" label={t('message')} multiline minRows={3} />
          <JsonField
            name="operations"
            label={t('requestOperations')}
            value={[
              {
                method: 'POST',
                path: '/api/relations',
                body: { subjectId: '$requester', relation: 'agent', principalId: '$approver' },
              },
            ]}
            rows={10}
          />
          <TextField
            name="expires"
            label={t('expires') + ' (' + t('minutes') + ')'}
            type="number"
            defaultValue={30}
            required
            slotProps={{ htmlInput: { min: 1, max: 1440 } }}
          />
          <SaveBar back="/requests" label="create" />
        </Stack>
      </Form>
    </Page>
  );
}
