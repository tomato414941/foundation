import { Form, Link, useActionData, useLoaderData, useSearchParams } from 'react-router';
import { Button, List, ListItem, ListItemText, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/principals';
import { Relation, listOf } from '../../../shared/contracts';
import { actionResult, api, formText } from '../api';
import { Copy, ErrorNotice, Page, Paging, Panel, SaveBar } from '../components';
import { useWorkspace } from './workspace';
import { rekeySharing } from '../keys';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) { return api(`/principals/${params.owner}/relations?${new URL(request.url).searchParams}`, { signal: request.signal }, listOf(Relation)); }
export async function clientAction({ params, request }: Route.ClientActionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const subjectId = formText(form, 'subjectId'), relation = formText(form, 'relation'), principalId = formText(form, 'principalId') || params.owner;
    const remove = formText(form, 'intent') === 'remove';
    const secrets = !remove && relation === 'member' ? await rekeySharing('/relations/recipients?' + new URLSearchParams({ subjectId, principalId })) : undefined;
    await api('/relations', { method: remove ? 'DELETE' : 'POST', body: { subjectId, relation, principalId, ...(secrets ? { secrets } : {}) } });
    return { ok: true };
  });
}
export default function Principals() { const { t } = useTranslation(); const data = useLoaderData<typeof clientLoader>(); const result = useActionData<typeof clientAction>(); const { principal } = useWorkspace(); const [search] = useSearchParams(); return <Page title={t('principals')} actions={principal.permissions.includes('create') && <Button component={Link} to="new" variant="contained">{t('createPrincipal')}</Button>}><ErrorNotice error={result && 'error' in result ? result.error : null} /><Panel title={t('connectedPrincipals')}><List disablePadding>{data.items.map(item => { const incoming = item.principalId === principal.id; const id = incoming ? item.subjectId : item.principalId; return <ListItem key={item.id} disableGutters sx={{ flexWrap: 'wrap', gap: 1 }}><ListItemText primary={<Link to={'/p/' + id}>{incoming ? item.subjectName : item.principalName}</Link>} secondary={`${item.subjectName} → ${t(item.relation)} → ${item.principalName}`} /><Copy value={id} />{principal.permissions.includes('share') && item.relation !== 'owner' && <Form method="post"><input type="hidden" name="subjectId" value={item.subjectId} /><input type="hidden" name="principalId" value={item.principalId} /><input type="hidden" name="relation" value={item.relation} /><Button type="submit" name="intent" value="remove" color="error">{t('removeAccess')}</Button></Form>}</ListItem>; })}</List>{!data.items.length && <Typography color="text.secondary">{t('empty')}</Typography>}<Paging next={data.next} search={search} /></Panel>{principal.permissions.includes('share') && <Panel title={t('add')}><Form method="post"><Stack spacing={3}><TextField name="subjectId" label={t('subject')} required fullWidth /><TextField select name="relation" label={t('relation')} defaultValue="agent">{['agent', 'member', 'payer'].map(value => <MenuItem key={value} value={value}>{t(value)}</MenuItem>)}</TextField><Typography variant="body2" color="text.secondary">{t('relationHelp')}</Typography><Typography variant="body2" color="text.secondary">{t('paymentHelp')}</Typography><Button type="submit" variant="contained">{t('add')}</Button></Stack></Form></Panel>}</Page>; }
