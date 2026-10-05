import { Form, redirect, useActionData } from 'react-router';
import { Stack, TextField, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/principal-new';
import { Principal } from '../../../shared/contracts';
import { actionResult, api, formText } from '../api';
import { ErrorNotice, Page, SaveBar } from '../components';
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const principal = await api(
      '/principals',
      { method: 'POST', body: { name: formText(form, 'name'), ownerId: params.owner } },
      Principal,
    );
    return redirect('/p/' + principal.id);
  });
}
export default function PrincipalNew() {
  const { t } = useTranslation();
  const result = useActionData<typeof clientAction>();
  return (
    <Page title={t('createPrincipal')} narrow>
      <Typography color="text.secondary">{t('principalHelp')}</Typography>
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      <Form method="post">
        <Stack spacing={3}>
          <TextField label={t('name')} name="name" required fullWidth autoFocus />
          <SaveBar back=".." label="create" />
        </Stack>
      </Form>
    </Page>
  );
}
