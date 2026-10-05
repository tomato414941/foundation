import { useState } from 'react';
import { Form, useActionData, useLoaderData, useSearchParams } from 'react-router';
import { Alert, Button, Divider, Stack, TextField, Typography } from '@mui/material';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/signin';
import { actionResult, api, formText, safeReturn, session } from '../api';
import { authenticate, registerPasskey } from '../keys';
import { ErrorNotice, Page, Panel, useTask } from '../components';
import i18n from '../i18n';
export async function clientLoader() { return session(); }
export async function clientAction({ request }: Route.ClientActionArgs) { return actionResult(async () => { const form = await request.formData(); return api<{ email: string }>('/auth/email', { method: 'POST', body: { email: formText(form, 'email'), locale: i18n.language === 'en' ? 'en' : 'ja', returnTo: safeReturn(formText(form, 'returnTo')) } }); }); }
export default function Signin() {
  const { t } = useTranslation(); const data = useLoaderData<typeof clientLoader>(); const result = useActionData<typeof clientAction>(); const [search] = useSearchParams(); const [create, setCreate] = useState(false); const [name, setName] = useState(''); const task = useTask(); const back = safeReturn(search.get('returnTo'));
  return <Page title={t(create ? 'signup' : 'signinTitle')} narrow><Typography color="text.secondary">{t('signinDescription')}</Typography><ErrorNotice error={task.error ?? (result && 'error' in result ? result.error : null)} /><Panel><Stack spacing={3}>{create && <TextField required label={t('name')} value={name} onChange={event => setName(event.target.value)} autoComplete="name" slotProps={{ htmlInput: { maxLength: 200 } }} />}<Button variant="contained" size="large" startIcon={<FingerprintIcon />} loading={task.busy} disabled={create && !name.trim()} onClick={() => task.run(async () => { const auth = create ? await registerPasskey(name) : await authenticate(); window.location.assign(back === '/' && !auth.encrypted ? '/account?encryption=unavailable' : back); })}>{t(create ? 'passkeyCreate' : 'passkeySignin')}</Button><Button onClick={() => setCreate(!create)}>{t(create ? 'signin' : 'signup')}</Button>{data.features.email && <><Divider>{t('or')}</Divider><Form method="post"><Stack spacing={2}><input type="hidden" name="returnTo" value={back} /><TextField required type="email" name="email" label={t('email')} autoComplete="email" fullWidth />{result && 'email' in result && <Alert severity="success">{t('emailSent', { email: result.email })}</Alert>}<Button type="submit" variant="outlined">{t('sendLink')}</Button></Stack></Form></>}</Stack></Panel></Page>;
}
