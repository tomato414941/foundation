import { Form, Link, useLoaderData, useSearchParams, useParams } from 'react-router';
import { Alert, Button, InputAdornment, Stack, TextField } from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import AddIcon from '@mui/icons-material/Add';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource-list';
import { Resource, listOf } from '../../../shared/contracts';
import { api } from '../api';
import { ErrorNotice, Page, Paging, usePolling } from '../components';
import { ResourceTable } from '../resource-table';
import { resourceKind } from '../navigation';
import { useWorkspace } from './workspace';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) { const search = new URL(request.url).searchParams; const query = new URLSearchParams({ kind: resourceKind(params.section), limit: '50' }); for (const key of ['query', 'after']) if (search.has(key)) query.set(key, search.get(key)!); return api(`/principals/${params.owner}/resources?${query}`, { signal: request.signal }, listOf(Resource)); }
export default function ResourceList() { const { t } = useTranslation(); const data = useLoaderData<typeof clientLoader>(); const { principal, session } = useWorkspace(); const [search] = useSearchParams(); const { section = 'services' } = useParams(); const available = section === 'objects' ? session.features.objects : section === 'environments' ? session.features.environments : true; usePolling(data.items.some(item => item.kind === 'environment' && ['starting', 'stopping'].includes(item.data.state))); return <Page title={t(section)} actions={available && principal.createKinds.includes(resourceKind(section)) && <Button component={Link} to="new" startIcon={<AddIcon />} variant="contained">{t(section === 'services' ? 'connect' : section === 'objects' ? 'upload' : 'create')}</Button>}><ErrorNotice error={search.get('error')} />{!available && <Alert severity="info">{t('featureUnavailable')}</Alert>}<Form method="get"><Stack direction="row" spacing={1}><TextField size="small" label={t('search')} name="query" defaultValue={search.get('query') ?? ''} fullWidth slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchIcon /></InputAdornment> } }} /><Button type="submit">{t('search')}</Button></Stack></Form><ResourceTable items={data.items} search={!!search.get('query')} /><Paging next={data.next} search={search} />{section === 'services' && <Stack direction="row" spacing={2}><Button component={Link} to={'/p/' + principal.id + '/definitions'}>{t('definitions')}</Button><Button component={Link} to={'/p/' + principal.id + '/apps'}>{t('apps')}</Button></Stack>}</Page>; }
