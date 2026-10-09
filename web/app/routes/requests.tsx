import { Button } from '../components/ui/button';
import { Link, useLoaderData, useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/requests';
import { ApprovalRequest, listOf } from '../../../shared/contracts';
import { api, signedIn } from '../api';
import { DateText, Empty, Page, Paging, ProposalText, State, usePolling } from '../components';
export async function clientLoader({ request }: Route.ClientLoaderArgs) {
  await signedIn(request);
  return api(
    '/requests?' + new URL(request.url).searchParams,
    { signal: request.signal },
    listOf(ApprovalRequest),
  );
}
export default function Requests() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const [search] = useSearchParams();
  usePolling(
    data.items.some((item) => ['pending', 'running'].includes(item.state)),
    15000,
  );
  return (
    <Page
      title={t('requests')}
      actions={
        <Button variant="default" asChild>
          <Link to="new">{t('newRequest')}</Link>
        </Button>
      }
    >
      {data.items.length ? (
        <div className="overflow-hidden rounded-xl border bg-card">
          <ul className="divide-y divide-border">
            {data.items.map((item) => (
              <li key={item.id}>
                <Link
                  to={'/requests/' + item.id}
                  className="flex items-center gap-4 p-4 transition-colors hover:bg-accent/50 focus-visible:outline-2 focus-visible:outline-ring"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="font-medium wrap-anywhere">
                      {item.proposal ? <ProposalText proposal={item.proposal} /> : item.message || item.from.name}
                    </div>
                    <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
                      {
                        <>
                          {item.from.name} → {item.to?.name ?? '—'} · <DateText value={item.createdAt} />
                        </>
                      }
                    </div>
                  </div>
                  <State value={item.state} />
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <Empty />
      )}
      <Paging next={data.next} search={search} />
    </Page>
  );
}
