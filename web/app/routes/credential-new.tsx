import { useState } from 'react';
import { Form, Link, useActionData, useNavigate, useRevalidator } from 'react-router';
import { Alert, Button, MenuItem, Stack, TextField } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/credential-new';
import { actionResult, api, formText } from '../api';
import { registerPasskey } from '../keys';
import { Copy, ErrorNotice, Page, Panel, SaveBar, useTask } from '../components';
import { useWorkspace } from './workspace';
import i18n from '../i18n';
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    if (formText(form, 'kind') === 'email')
      return api<{ email: string }>('/auth/email', {
        method: 'POST',
        body: {
          email: formText(form, 'email'),
          principalId: params.owner,
          returnTo: `/p/${params.owner}/settings/credentials`,
          locale: i18n.language === 'en' ? 'en' : 'ja',
        },
      });
    return api<{ token: string }>('/principals/' + params.owner + '/credentials', {
      method: 'POST',
      body: {
        name: formText(form, 'name'),
        expiresAt: formText(form, 'expiresAt') ? new Date(formText(form, 'expiresAt')).toISOString() : null,
      },
    });
  });
}
export default function CredentialNew() {
  const { t } = useTranslation();
  const { principal, session } = useWorkspace();
  const result = useActionData<typeof clientAction>();
  const [kind, setKind] = useState('passkey');
  const [name, setName] = useState('');
  const task = useTask();
  const navigate = useNavigate();
  const revalidator = useRevalidator();
  const back = `/p/${principal.id}/settings/credentials`;
  return (
    <Page title={t('add')} narrow>
      <ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} />
      {result && 'token' in result ? (
        <Panel title={t('apiKey')}>
          <Alert severity="info">{t('keyOnce')}</Alert>
          <TextField
            label={t('apiKey')}
            value={result.token}
            multiline
            slotProps={{ input: { readOnly: true } }}
          />
          <Copy value={result.token} />
          <Button component={Link} to={back}>
            {t('close')}
          </Button>
        </Panel>
      ) : (
        <Form
          method="post"
          onSubmit={(event) => {
            if (kind === 'passkey') {
              event.preventDefault();
              void task.run(async () => {
                await registerPasskey(name, principal);
                await revalidator.revalidate();
                await navigate(back);
              });
            }
          }}
        >
          <Stack spacing={3}>
            <TextField
              select
              name="kind"
              label={t('kind')}
              value={kind}
              onChange={(event) => setKind(event.target.value)}
            >
              <MenuItem value="passkey">{t('addPasskey')}</MenuItem>
              {session.features.email && <MenuItem value="email">{t('email')}</MenuItem>}
              <MenuItem value="key">{t('apiKey')}</MenuItem>
            </TextField>
            {kind === 'email' ? (
              <TextField name="email" type="email" label={t('email')} required autoComplete="email" />
            ) : (
              <TextField
                name="name"
                label={t('name')}
                value={name}
                onChange={(event) => setName(event.target.value)}
                required
              />
            )}
            {kind === 'key' && (
              <TextField
                name="expiresAt"
                type="datetime-local"
                label={t('expires')}
                helperText={t('noExpiry')}
                slotProps={{ inputLabel: { shrink: true } }}
              />
            )}
            {result && 'email' in result && (
              <Alert severity="success">{t('emailSent', { email: result.email })}</Alert>
            )}
            <SaveBar back={back} label={kind === 'email' ? 'sendLink' : 'add'} busy={task.busy} />
          </Stack>
        </Form>
      )}
    </Page>
  );
}
