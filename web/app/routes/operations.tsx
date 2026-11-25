import { Link, useLoaderData, useSearchParams } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { Route } from './+types/operations';
import { listOf } from '../../../shared/contracts';
import { OperationView } from '../../../shared/operations';
import { api } from '../api';
import { DateText, Empty, Page, Paging, State, usePolling } from '../components';
export async function clientLoader({ params, request }: Route.ClientLoaderArgs) {
  const query = new URL(request.url).searchParams;
  return api(`/principals/${params.owner}/operations?${query}`, { signal: request.signal }, listOf(OperationView));
}
// The operations made on what the principal holds, the latest first.
export default function Operations() {
  const { t, i18n } = useTranslation();
  const data = useLoaderData<typeof clientLoader>();
  const [search] = useSearchParams();
  usePolling(data.items.some(item => item.state === 'in_progress'));
  return (
    <Page title={t('operations')}>
      {data.items.length ? (
        <div className="overflow-hidden rounded-xl border bg-card">
          <ul className="divide-y divide-border">
            {data.items.map((item) => (
              <li key={item.id}>
                <Link
                  to={'/operations/' + item.id}
                  className="flex items-center gap-4 p-4 transition-colors hover:bg-accent/50 focus-visible:outline-2 focus-visible:outline-ring"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="font-medium wrap-anywhere">
                      {item.title[i18n.language === 'ja' ? 'ja' : 'en']}
                    </div>
                    <div className="text-xs leading-relaxed text-muted-foreground wrap-anywhere">
                      {item.actor.name} · <DateText value={item.createdAt} />{item.requestId && <> · {t('fromRequest')}</>}
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
