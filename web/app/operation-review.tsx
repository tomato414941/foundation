import { Fragment } from 'react';
import { z } from 'zod';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Principal, Resource } from '../../shared/contracts';
import type { JsonValue, ResourceView } from '../../shared/contracts';
import { api, ApiFailure } from './api';
import { DateText, Detail } from './components';
import { hasSection, resourcePath } from './navigation';

// What an operation awaiting approval would do, in the words of its fields: the items it names by their names, and
// times as dates, leaving out what only keeps concurrent changes apart.

const NamedPrincipal = Principal.pick({ id: true, name: true });
type NamedPrincipal = z.infer<typeof NamedPrincipal>;
export type ReviewValue =
  | { kind: 'text'; text: string }
  | { kind: 'empty' }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'time'; value: string }
  | { kind: 'principal'; name: string; approver: boolean }
  | { kind: 'approver' }
  | { kind: 'identifier'; name: string; id: string; approver: boolean }
  | { kind: 'approverId' }
  | { kind: 'resource'; resource: ResourceView }
  | { kind: 'newVariable'; name: string }
  | { kind: 'replacedValue'; resource: ResourceView }
  | { kind: 'unknown'; id: string }
  | { kind: 'list'; items: ReviewValue[] }
  | { kind: 'group'; rows: ReviewRow[] };
export interface ReviewRow { field: string; value: ReviewValue; literal?: boolean }

// Fields that never say what the operation does: those that keep concurrent changes apart, and the method digest that
// connect operations made before Foundation stopped pinning methods still hold in the history.
const hidden = new Set(['version', 'revision', 'methodDigest']);
const times = new Set(['expiresAt']);
// Fields naming an item or principal by its ID, and fields holding what the requester passes on as it is.
const reference = (field: string) => /Ids?$/.test(field) || ['id', 'to', 'users'].includes(field);
const data = new Set(['headers', 'default', 'data', 'settings', 'labels', 'fields', 'content', 'outputs']);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface ReviewContext {
  approver: NamedPrincipal | null; requester?: NamedPrincipal; principals: NamedPrincipal[]; inspect: boolean; signal: AbortSignal;
}

// Describes the fields of an input, looking up the items it names at most once each.
export function reviewer({ approver, requester, principals, inspect, signal }: ReviewContext) {
  const known = new Map(principals.map(principal => [principal.id, principal]));
  if (requester) known.set(requester.id, requester);
  if (approver) known.set(approver.id, approver);
  const pending = new Map<string, Promise<ReviewValue>>();
  const ignoreMissing = <T,>(promise: Promise<T>) => promise.catch(error => {
    if (error instanceof ApiFailure && [403, 404].includes(error.status)) return null;
    throw error;
  });
  const principal = (value: NamedPrincipal): ReviewValue => ({ kind: 'principal', name: value.name, approver: value.id === approver?.id });
  const item = (id: string) => {
    const found = known.get(id);
    if (found) return Promise.resolve(principal(found));
    if (!inspect) return Promise.resolve<ReviewValue>({ kind: 'unknown', id });
    if (!pending.has(id)) pending.set(id, (async (): Promise<ReviewValue> => {
      const resource = await ignoreMissing(api('/resources/' + id, { signal }, Resource));
      if (resource) return { kind: 'resource', resource };
      const named = await ignoreMissing(api('/identities/' + id, { signal }, NamedPrincipal));
      return named ? principal(named) : { kind: 'unknown', id };
    })());
    return pending.get(id)!;
  };
  // What the requester passes on keeps its own keys and text; only the participants it names are filled in.
  const passed = (input: JsonValue): ReviewValue => {
    if (input === '$approver') return approver ? { kind: 'identifier', name: approver.name, id: approver.id, approver: true } : { kind: 'approverId' };
    if (input === '$requester' && requester) return { kind: 'identifier', name: requester.name, id: requester.id, approver: false };
    if (Array.isArray(input)) return input.length ? { kind: 'list', items: input.map(passed) } : { kind: 'text', text: '[]' };
    if (input && typeof input === 'object') return Object.keys(input).length
      ? { kind: 'group', rows: Object.entries(input).map(([field, child]) => ({ field, value: passed(child), literal: true })) }
      : { kind: 'text', text: '{}' };
    return { kind: 'text', text: typeof input === 'string' ? input : JSON.stringify(input) };
  };
  const value = async (field: string, input: JsonValue): Promise<ReviewValue> => {
    if (data.has(field)) return passed(input);
    if (input === null || input === '') return { kind: 'empty' };
    if (typeof input === 'boolean') return { kind: 'boolean', value: input };
    if (typeof input === 'number') return { kind: 'text', text: String(input) };
    if (Array.isArray(input)) return input.length ? { kind: 'list', items: await Promise.all(input.map(child => value(field, child))) } : { kind: 'empty' };
    if (typeof input === 'object') return { kind: 'group', rows: await rows(input) };
    if (input === '$approver') return approver ? principal(approver) : { kind: 'approver' };
    if (input === '$requester' && requester) return principal(requester);
    if (reference(field) && uuid.test(input)) return item(input);
    if (times.has(field) && !Number.isNaN(Date.parse(input))) return { kind: 'time', value: input };
    return { kind: 'text', text: input };
  };
  const rows = (input: Record<string, JsonValue>): Promise<ReviewRow[]> => Promise.all(Object.entries(input)
    .filter(([field]) => !hidden.has(field))
    .map(async ([field, child]): Promise<ReviewRow> => ({ field, value: await value(field, child) })));
  return rows;
}

// An item by its name, linked to it where it has a page.
function ResourceName({ resource }: { resource: ResourceView }) {
  return hasSection(resource.kind)
    ? <Link className="underline underline-offset-4" to={resourcePath(resource)}>{resource.name}</Link> : <>{resource.name}</>;
}

function Value({ field, value }: { field: string; value: ReviewValue }) {
  const { t } = useTranslation();
  switch (value.kind) {
    case 'text': return <span className="whitespace-pre-wrap">{value.text}</span>;
    case 'empty': return <span className="text-muted-foreground">{t(times.has(field) ? 'reviewNoExpiry' : 'reviewNone')}</span>;
    case 'boolean': return <>{t(value.value ? 'reviewYes' : 'reviewNo')}</>;
    case 'time': return <DateText value={value.value} />;
    case 'principal': return <>{value.approver ? t('reviewYouNamed', { name: value.name }) : value.name}</>;
    case 'approver': return <>{t('reviewApprover')}</>;
    case 'identifier': return <span>{t(value.approver ? 'reviewYourId' : 'reviewIdOf', { name: value.name })} <code className="text-xs">{value.id}</code></span>;
    case 'approverId': return <>{t('reviewApproverId')}</>;
    case 'resource': return <ResourceName resource={value.resource} />;
    case 'newVariable': return <span className="flex min-w-0 flex-col">{value.name}
      <span className="text-sm text-muted-foreground">{t('reviewNewVariable')}</span></span>;
    case 'replacedValue': return <span className="flex min-w-0 flex-col"><ResourceName resource={value.resource} />
      <span className="text-sm text-muted-foreground">{t('reviewReplacedValue')}</span></span>;
    case 'unknown': return <span>{t('reviewUnknownItem')} <code className="text-xs text-muted-foreground">{value.id}</code></span>;
    case 'list': return <ul className="flex min-w-0 flex-col gap-1.5">
      {value.items.map((item, index) => <li key={index}><Value field={field} value={item} /></li>)}
    </ul>;
    case 'group': return <div className="flex min-w-0 flex-col gap-2 border-l pl-3"><ReviewRows rows={value.rows} /></div>;
  }
}

export function ReviewRows({ rows }: { rows: ReviewRow[] }) {
  const { t } = useTranslation();
  return <>{rows.map(row => <Fragment key={row.field}>
    <Detail label={row.literal ? row.field : t('reviewField.' + row.field, { defaultValue: row.field })}><Value field={row.field} value={row.value} /></Detail>
  </Fragment>)}</>;
}

// Settings left as they usually are stay folded until someone looks for them; any other value is shown.
const usual: Record<string, JsonValue> = { timeoutSeconds: 60 };
const folded = (row: ReviewRow) => row.field in usual && row.value.kind === 'text' && row.value.text === String(usual[row.field]);

export function OperationReview({ rows }: { rows: ReviewRow[] }) {
  const { t } = useTranslation();
  const main = rows.filter(row => !folded(row)), more = rows.filter(folded);
  if (!rows.length) return <p className="text-muted-foreground">{t('reviewNothingToShow')}</p>;
  return <div className="flex min-w-0 flex-col gap-3">
    <ReviewRows rows={main} />
    {more.length > 0 && <details className="group min-w-0">
      <summary className="w-fit cursor-pointer text-sm text-muted-foreground">{t('reviewMore')}</summary>
      <div className="mt-3 flex min-w-0 flex-col gap-3"><ReviewRows rows={more} /></div>
    </details>}
  </div>;
}
