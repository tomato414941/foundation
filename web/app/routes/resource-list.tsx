import { Form, Link, useLoaderData, useSearchParams, useParams } from 'react-router';
import { Plus, Search } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Notice } from '../components';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/resource-list';
import { Resource, listOf } from '../../../shared/contracts';
import { api } from '../api';
import { ErrorNotice, Page, Paging, usePolling } from '../components';
import { ResourceTable } from '../resource-table';
import { resourceKind } from '../navigation';
import { useWorkspace } from './workspace';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const search = new URL(request.url).searchParams;
  const query = new URLSearchParams({ kind: resourceKind(params.section), limit: '50' });
  for (const key of ['query', 'after']) if (search.has(key)) query.set(key, search.get(key)!);
  return api(
    `/principals/${params.owner}/resources?${query}`,
    { signal: request.signal },
    listOf(Resource),
  );
}
export default function ResourceList() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const { principal, session } = useWorkspace();
  const [search] = useSearchParams();
  const { section = 'services' } = useParams();
  const available =
    section === 'objects'
      ? session.features.objects
      : section === 'environments'
        ? session.features.environments
        : true;
  usePolling(
    data.items.some(
      (item) => item.kind === 'environment' && (item.data.deletion
        ? item.data.deletion.state === 'pending' : ['starting', 'stopping'].includes(item.data.state)),
    ),
  );
  return (
    <Page
      title={t(section)}
      actions={
        available &&
        principal.createKinds.includes(resourceKind(section)) && (
          <Button asChild>
            <Link to="new">
              <Plus className="size-4" />
              {t(section === 'services' ? 'connect' : section === 'objects' ? 'upload' : 'create')}
            </Link>
          </Button>
        )
      }
    >
      <ErrorNotice error={search.get('error')} />
      {section === 'environments' && search.get('deleted') === '1' && <Notice tone="success">{t('environmentDeleted')}</Notice>}
      {!available && <Notice>{t('featureUnavailable')}</Notice>}
      <Form method="get" className="flex items-center gap-2">
        <div className="relative min-w-0 flex-1 sm:max-w-sm">
          <Search
            className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground"
            aria-hidden="true"
          />
          <Input
            type="search"
            name="query"
            aria-label={t('search')}
            placeholder={t('search')}
            defaultValue={search.get('query') ?? ''}
            className="h-9 pl-9"
          />
        </div>
        <Button type="submit" variant="outline" className="h-9">
          {t('search')}
        </Button>
      </Form>
      <ResourceTable items={data.items} search={!!search.get('query')} />
      <Paging next={data.next} search={search} />
      {section === 'services' && (
        <div className="flex flex-wrap gap-2">
          <Button asChild variant="ghost">
            <Link to={'/p/' + principal.id + '/definitions'}>{t('definitions')}</Link>
          </Button>
          <Button asChild variant="ghost">
            <Link to={'/p/' + principal.id + '/methods'}>{t('methods')}</Link>
          </Button>
          <Button asChild variant="ghost">
            <Link to={'/p/' + principal.id + '/apps'}>{t('apps')}</Link>
          </Button>
        </div>
      )}
    </Page>
  );
}
