import { Link } from 'react-router';
import { Code2, File, KeyRound, Link2, Plug, Terminal } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { ResourceView } from '../../shared/contracts';
import { Bytes, DateText, Empty, State } from './components';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './components/ui/table';
import { resourcePath, sectionFor } from './navigation';
import { connectionMethodName } from './connection-method-labels';

export function ResourceTable({
  items,
  kinds = false,
  search = false,
}: {
  items: ResourceView[];
  kinds?: boolean;
  search?: boolean;
}) {
  const { t } = useTranslation();
  if (!items.length) return <Empty search={search} />;
  return (
    <div className="overflow-hidden rounded-xl border bg-card">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="px-5 text-xs font-normal text-muted-foreground">{t('name')}</TableHead>
            <TableHead className="hidden px-5 text-xs font-normal text-muted-foreground sm:table-cell">
              {t(kinds ? 'kind' : 'status')}
            </TableHead>
            <TableHead className="hidden px-5 text-xs font-normal text-muted-foreground lg:table-cell">
              {t('updated')}
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((item) => {
            const state = item.kind === 'environment' && item.data.deletion
              ? item.data.deletion.state === 'failed' ? 'deleteFailed' : 'deleting'
              : 'state' in item.data ? item.data.state : null;
            const stateBadge = state && <State value={state}
              label={item.kind === 'environment' && state === 'running' ? t('state.environmentRunning') : undefined} />;
            const Icon =
              item.kind === 'connection'
                ? Link2
                : item.kind === 'variable'
                  ? KeyRound
                  : item.kind === 'object'
                    ? File
                    : item.kind === 'environment'
                      ? Terminal
                      : item.kind === 'function'
                        ? Code2
                        : Plug;
            return (
              <TableRow key={item.id}>
                <TableCell className="px-5 py-4">
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border bg-background/60 text-muted-foreground">
                      <Icon className="size-4" aria-hidden="true" />
                    </span>
                    <div className="min-w-0 space-y-1">
                      <Link
                        to={resourcePath(item)}
                        className="font-medium whitespace-normal underline-offset-4 hover:underline wrap-anywhere"
                      >
                        {item.name}
                      </Link>
                      {item.kind === 'connection' && (
                        <>
                          <p className="text-xs whitespace-normal text-muted-foreground wrap-anywhere">
                            {connectionMethodName(item.data.methodName, t)}
                          </p>
                          <p className="text-xs whitespace-normal text-muted-foreground wrap-anywhere">
                            {item.data.account || t('accountUnverified')}
                            {item.data.account &&
                              !item.data.accountVerified &&
                              ' · ' + t('accountUnverified')}
                          </p>
                        </>
                      )}
                      <div className="flex gap-2 text-xs text-muted-foreground sm:hidden">
                        {stateBadge}
                        {item.kind === 'object' && <Bytes value={item.data.size} />}
                        {item.kind === 'variable' && <Bytes value={item.data.bytes} />}
                      </div>
                    </div>
                  </div>
                </TableCell>
                <TableCell className="hidden px-5 py-4 text-muted-foreground sm:table-cell">
                  {kinds ? (
                    t(sectionFor(item.kind))
                  ) : state ? (
                    stateBadge
                  ) : item.kind === 'object' ? (
                    <Bytes value={item.data.size} />
                  ) : item.kind === 'variable' ? (
                    <Bytes value={item.data.bytes} />
                  ) : (
                    '—'
                  )}
                </TableCell>
                <TableCell className="hidden px-5 py-4 text-xs text-muted-foreground lg:table-cell">
                  <DateText value={item.updatedAt} />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
