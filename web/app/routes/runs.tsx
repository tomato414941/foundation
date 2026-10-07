import { Button } from '../components/ui/button';
import { Link, useLoaderData, useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/runs';
import { listOf } from '../../../shared/contracts';
import { Task } from '../../../shared/execution';
import { api } from '../api';
import { DateText, Empty, Page, Paging, State, usePolling } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const query = new URL(request.url).searchParams;
  return api(`/principals/${params.owner}/executions?${query}`, { signal: request.signal }, listOf(Task));
}
export default function Runs() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const [search] = useSearchParams();
  usePolling(data.items.some((item) => ['queued', 'running'].includes(item.state)));
  return (
    <Page
      title={t('runs')}
      actions={
        <Button variant="default" asChild>
          <Link to="new">{t('http')}</Link>
        </Button>
      }
    >
      {data.items.length ? (
        <div className="overflow-hidden rounded-xl border bg-card">
          <ul className="divide-y divide-border">
            {data.items.map((item) => (
              <li key={item.id}>
                <Link
                  to={'/runs/' + item.id}
                  className="flex items-center gap-4 p-4 transition-colors hover:bg-accent/50 focus-visible:outline-2 focus-visible:outline-ring"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="font-medium wrap-anywhere">
                      {t(
                        item.kind === 'http'
                          ? 'http'
                          : item.kind === 'command'
                            ? 'command'
                            : 'functions',
                      )}
                    </div>
                    <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
                      {<DateText value={item.createdAt} />}
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
