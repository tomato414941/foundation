import { Button } from '../components/ui/button';
import { Link, useLoaderData, useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/runs';
import { listOf } from '../../../shared/contracts';
import { Task } from '../../../shared/execution';
import { Invocation } from '../../../shared/function-api';
import { api } from '../api';
import { DateText, Empty, Page, Paging, State, usePolling } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const query = new URL(request.url).searchParams;
  const limit = Math.min(100, Math.max(1, Number(query.get('limit') ?? 100)));
  const [runs, invocations] = await Promise.all([
    api(`/principals/${params.owner}/executions?${query}`, { signal: request.signal }, listOf(Task)),
    api(`/principals/${params.owner}/invocations?${query}`, { signal: request.signal }, listOf(Invocation)),
  ]);
  const all = [...runs.items, ...invocations.items.map(item => ({ ...item, kind: 'function' as const }))]
    .sort((left, right) => left.id.localeCompare(right.id));
  const items = all.slice(0, limit);
  return { items, next: all.length > limit || runs.next || invocations.next ? items.at(-1)?.id ?? null : null };
}
export default function Runs() {
  const { t } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const [search] = useSearchParams();
  usePolling(data.items.some((item) => ['queued', 'running'].includes(item.state) ||
    ('functionId' in item && item.error?.code === 'cancellation_pending')));
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
                  to={('functionId' in item ? '/invocations/' : '/runs/') + item.id}
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
