import { Outlet, useLoaderData, useLocation, Link as RouterLink, useOutletContext } from 'react-router';
import { Breadcrumbs, Box, Link, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/workspace';
import { Principal } from '../../../shared/contracts';
import type { PrincipalView } from '../../../shared/contracts';
import { api, ApiFailure, signedIn } from '../api';
export async function clientLoader({ request, params }: Route.ClientLoaderArgs) {
  const session = await signedIn(request);
  let principal: Pick<PrincipalView, 'id' | 'name' | 'permissions' | 'publicKey' | 'createKinds'>;
  try {
    principal = await api('/principals/' + params.owner, { signal: request.signal }, Principal);
  } catch (error) {
    if (!(error instanceof ApiFailure) || error.status !== 403) throw error;
    principal = {
      ...(await api<Pick<PrincipalView, 'id' | 'name' | 'publicKey'>>('/identities/' + params.owner, {
        signal: request.signal,
      })),
      permissions: [],
      createKinds: [],
    };
  }
  return { session, principal };
}
export type WorkspaceContext = Awaited<ReturnType<typeof clientLoader>>;
export function useWorkspace() {
  return useOutletContext<WorkspaceContext>();
}
export default function Workspace() {
  const data = useLoaderData<typeof clientLoader>();
  const { t } = useTranslation();
  const location = useLocation();
  const section = location.pathname.split('/')[3];
  return (
    <>
      <Box sx={{ maxWidth: 1120, mx: 'auto', mb: 3 }}>
        <Breadcrumbs>
          <Link component={RouterLink} to={'/p/' + data.principal.id}>
            {data.principal.name}
          </Link>
          {section && <Typography color="text.primary">{t(section)}</Typography>}
        </Breadcrumbs>
      </Box>
      <Outlet context={data} />
    </>
  );
}
