import { useLoaderData, Link } from 'react-router';
import { Button, Stack } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/home';
import { Resource, listOf } from '../../../shared/contracts';
import { api } from '../api';
import { Page } from '../components';
import { ResourceTable } from '../resource-table';
import { useWorkspace } from './workspace';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  return api(`/principals/${params.owner}/resources?limit=20`, { signal: request.signal }, listOf(Resource));
}
export default function Home() {
  const { t } = useTranslation();
  const { principal } = useWorkspace();
  const data = useLoaderData<typeof clientLoader>();
  const prefix = '/p/' + principal.id;
  return (
    <Page
      title={principal.name}
      actions={
        principal.createKinds.includes('connection') ? (
          <Button component={Link} to={prefix + '/services/new'} variant="contained">
            {t('connect')}
          </Button>
        ) : null
      }
    >
      <ResourceTable items={data.items} kinds />
      <Stack direction="row" spacing={2}>
        <Button component={Link} to={prefix + '/definitions'}>
          {t('definitions')}
        </Button>
        <Button component={Link} to={prefix + '/apps'}>
          {t('apps')}
        </Button>
      </Stack>
    </Page>
  );
}
