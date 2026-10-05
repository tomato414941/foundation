import { Form, Link, useLoaderData, useSearchParams } from 'react-router';
import { Button, List, ListItemButton, ListItemText, Paper } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/runs';
import { Run, listOf } from '../../../shared/contracts';
import { api } from '../api';
import { DateText, Empty, Page, Paging, State, usePolling } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) { const query = new URL(request.url).searchParams; return api(`/principals/${params.owner}/runs?${query}`, { signal: request.signal }, listOf(Run)); }
export default function Runs() { const { t } = useTranslation(); const data = useLoaderData<typeof clientLoader>(); const [search] = useSearchParams(); usePolling(data.items.some(item => ['queued', 'running'].includes(item.state))); return <Page title={t('runs')} actions={<Button component={Link} to="new" variant="contained">{t('http')}</Button>}>{data.items.length ? <Paper variant="outlined"><List>{data.items.map(item => <ListItemButton component={Link} to={'/runs/' + item.id} key={item.id}><ListItemText primary={t(item.kind === 'http' ? 'http' : item.kind === 'command' ? 'command' : 'functions')} secondary={<DateText value={item.createdAt} />} /><State value={item.state} /></ListItemButton>)}</List></Paper> : <Empty />}<Paging next={data.next} search={search} /></Page>; }
