import { Outlet, useLoaderData, useLocation, useMatches, Link as RouterLink, useOutletContext } from 'react-router';
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '../components/ui/breadcrumb';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/workspace';
import { Principal, Resource } from '../../../shared/contracts';
import type { PrincipalView } from '../../../shared/contracts';
import { api, ApiFailure, signedIn } from '../api';
import { reprotectInBackground } from '../keys';
export async function clientLoader({ request, params }: Route.ClientLoaderArgs) {
  const session = await signedIn(request);
  if (session.principal && !session.requestId) reprotectInBackground(session.principal.id);
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
  const segments = location.pathname.split('/');
  const section = segments[3], detail = segments[4], operation = segments[5];
  const resource = useMatches().map(match => {
    const value = match.loaderData;
    if (!value || typeof value !== 'object') return null;
    const candidate = 'resource' in value ? value.resource : 'target' in value ? value.target : value;
    const parsed = Resource.safeParse(candidate);
    return parsed.success ? parsed.data : null;
  }).find(item => item?.id === detail);
  const sectionPath = `/p/${data.principal.id}/${section}`;
  const detailLabel = resource?.name ?? t(section === 'settings' ? detail ?? 'general'
    : detail === 'new' ? section === 'services' ? 'connect' : section === 'objects' ? 'upload' : 'create' : 'details');
  return (
    <>
      <Breadcrumb aria-label={t('breadcrumb')} className="mx-auto mb-6 max-w-6xl">
        <BreadcrumbList className="text-xs">
          <BreadcrumbItem>
            <BreadcrumbLink asChild>
              <RouterLink className="inline-flex min-h-8 items-center" to={'/p/' + data.principal.id}>{data.principal.name}</RouterLink>
            </BreadcrumbLink>
          </BreadcrumbItem>
          {section && (
            <>
              <BreadcrumbSeparator />
              <BreadcrumbItem>
                {detail ? <BreadcrumbLink asChild>
                  <RouterLink className="inline-flex min-h-8 items-center" to={sectionPath + (section === 'settings' ? '/general' : '')}>{t(section)}</RouterLink>
                </BreadcrumbLink> : <BreadcrumbPage>{t(section)}</BreadcrumbPage>}
              </BreadcrumbItem>
            </>
          )}
          {detail && <>
            <BreadcrumbSeparator />
            <BreadcrumbItem>
              {operation && (resource || section === 'settings') ? <BreadcrumbLink asChild>
                <RouterLink className="inline-flex min-h-8 items-center" to={sectionPath + '/' + detail}>{detailLabel}</RouterLink>
              </BreadcrumbLink> : <BreadcrumbPage>{detailLabel}</BreadcrumbPage>}
            </BreadcrumbItem>
          </>}
          {operation && <><BreadcrumbSeparator /><BreadcrumbItem>
            <BreadcrumbPage>{t(operation === 'run' ? 'execute' : operation === 'new' ? 'create' : operation)}</BreadcrumbPage>
          </BreadcrumbItem></>}
        </BreadcrumbList>
      </Breadcrumb>
      <Outlet context={data} />
    </>
  );
}
