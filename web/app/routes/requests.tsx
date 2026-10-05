import { Link, useLoaderData, useSearchParams } from 'react-router';
import { Button, List, ListItemButton, ListItemText, Paper } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/requests';
import { ApprovalRequest, listOf } from '../../../shared/contracts';
import { api, signedIn } from '../api';
import { DateText, Empty, Page, Paging, State, usePolling } from '../components';
export async function clientLoader({ request }: Route.ClientLoaderArgs) { await signedIn(request); return api('/requests?' + new URL(request.url).searchParams, { signal: request.signal }, listOf(ApprovalRequest)); }
export default function Requests() { const { t } = useTranslation(); const data = useLoaderData<typeof clientLoader>(); const [search] = useSearchParams(); usePolling(data.items.some(item => ['pending', 'running'].includes(item.state)), 15000); return <Page title={t('requests')} actions={<Button component={Link} to="new" variant="contained">{t('newRequest')}</Button>}>{data.items.length ? <Paper variant="outlined"><List>{data.items.map(item => <ListItemButton key={item.id} component={Link} to={'/requests/' + item.id}><ListItemText primary={item.message || item.from.name} secondary={<>{item.from.name} → {item.to?.name ?? '—'} · <DateText value={item.createdAt} /></>} /><State value={item.state} /></ListItemButton>)}</List></Paper> : <Empty />}<Paging next={data.next} search={search} /></Page>; }
