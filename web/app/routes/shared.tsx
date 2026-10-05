import { useLoaderData } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/shared';
import { Resource, listOf } from '../../../shared/contracts';
import { api, signedIn } from '../api';
import { Page } from '../components';
import { ResourceTable } from '../resource-table';
export async function clientLoader({ request }: Route.ClientLoaderArgs) { await signedIn(request); return api('/resources/shared', { signal: request.signal }, listOf(Resource)); }
export default function Shared() { const { t } = useTranslation(); const data = useLoaderData<typeof clientLoader>(); return <Page title={t('shared')}><ResourceTable items={data.items} kinds /></Page>; }
