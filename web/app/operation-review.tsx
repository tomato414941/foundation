import { Fragment } from 'react';
import { z } from 'zod';
import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Principal, Resource } from '../../shared/contracts';
import type { JsonValue, ResourceView } from '../../shared/contracts';
import type { ExecutionView } from '../../shared/executions';
import { api, ApiFailure } from './api';
import { DateText, Detail } from './components';
import { hasSection, resourcePath } from './navigation';

// What an operation awaiting approval would do, in the words of its fields: the items it names by their names, keys by
// their fingerprints, and times as dates, leaving out what only keeps concurrent changes apart.

const NamedPrincipal = Principal.pick({ id: true, name: true });
type NamedPrincipal = z.infer<typeof NamedPrincipal>;
export type ReviewValue =
  | { kind: 'text'; text: string }
  | { kind: 'command'; parts: string[] }
  | { kind: 'empty' }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'time'; value: string }
  | { kind: 'principal'; name: string; approver: boolean }
  | { kind: 'approver' }
  | { kind: 'identifier'; name: string; id: string; approver: boolean }
  | { kind: 'approverId' }
  | { kind: 'resource'; resource: ResourceView }
  | { kind: 'unknown'; id: string }
  | { kind: 'key'; algorithm: string; fingerprint: string; comment: string }
  | { kind: 'list'; items: ReviewValue[] }
  | { kind: 'group'; rows: ReviewRow[] };
export interface ReviewRow { field: string; value: ReviewValue; literal?: boolean }

// Fields that only keep concurrent changes apart, never what the operation does.
const hidden = new Set(['version', 'revision', 'functionVersion', 'methodDigest', 'programDigest']);
const times = new Set(['expiresAt']);
const keys = new Set(['hostKeys', 'publicKey', 'authorizedKeys']);
// Fields naming an item or principal by its ID, and fields holding what the requester passes on as it is.
const reference = (field: string) => /Ids?$/.test(field) || ['id', 'to', 'users'].includes(field);
const data = new Set(['arguments', 'headers', 'body', 'stdin', 'default', 'data', 'settings', 'labels', 'fields', 'content', 'outputs', 'save']);
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const sshKey = /^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) ([A-Za-z0-9+/]+={0,2})(?: (.*))?$/;
const algorithms: Record<string, string> = { 'ssh-ed25519': 'ED25519', 'ssh-rsa': 'RSA', 'ssh-dss': 'DSA',
  'ecdsa-sha2-nistp256': 'ECDSA P-256', 'ecdsa-sha2-nistp384': 'ECDSA P-384', 'ecdsa-sha2-nistp521': 'ECDSA P-521',
  'sk-ssh-ed25519@openssh.com': 'ED25519-SK', 'sk-ecdsa-sha2-nistp256@openssh.com': 'ECDSA-SK' };

// The fingerprint OpenSSH shows for a key, or null for text that only looks like one.
async function fingerprint(key: string) {
  let bytes: Uint8Array<ArrayBuffer>;
  try { bytes = Uint8Array.from(atob(key), character => character.charCodeAt(0)); } catch { return null; }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return 'SHA256:' + btoa(String.fromCharCode(...digest)).replace(/=+$/, '');
}

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
    if (field === 'command' && Array.isArray(input) && input.every(part => typeof part === 'string'))
      return { kind: 'command', parts: input as string[] };
    if (Array.isArray(input)) return input.length ? { kind: 'list', items: await Promise.all(input.map(child => value(field, child))) } : { kind: 'empty' };
    if (typeof input === 'object') return { kind: 'group', rows: await rows(input) };
    if (input === '$approver') return approver ? principal(approver) : { kind: 'approver' };
    if (input === '$requester' && requester) return principal(requester);
    if (reference(field) && uuid.test(input)) return item(input);
    if (times.has(field) && !Number.isNaN(Date.parse(input))) return { kind: 'time', value: input };
    const key = keys.has(field) ? sshKey.exec(input) : null;
    const digest = key && await fingerprint(key[2]!);
    if (key && digest) return { kind: 'key', algorithm: algorithms[key[1]!] ?? key[1]!, fingerprint: digest, comment: key[3] ?? '' };
    return { kind: 'text', text: input };
  };
  const rows = (input: Record<string, JsonValue>): Promise<ReviewRow[]> => Promise.all(Object.entries(input)
    .filter(([field]) => !hidden.has(field))
    .map(async ([field, child]): Promise<ReviewRow> => ({ field, value: await value(field, child) })));
  return rows;
}

export function loadOperationReviews(operations: ExecutionView['operations'], context: ReviewContext) {
  const rows = reviewer(context);
  return Promise.all(operations.map(operation => operation.execution === 'keyholder' ? null : rows(operation.input)));
}

// A program and its arguments as they are passed, one by one, without a shell to expand or split them.
export function CommandArguments({ parts }: { parts: string[] }) {
  return <ol className="flex min-w-0 flex-wrap gap-1.5">
    {parts.map((part, index) => <li key={index} className="min-w-0">
      <code className="block rounded border bg-background/60 px-1.5 py-0.5 text-sm whitespace-pre-wrap wrap-anywhere">{part}</code>
    </li>)}
  </ol>;
}

// An item by its name, with what tells it apart from others of the same name where its name alone would not.
function ResourceName({ resource }: { resource: ResourceView }) {
  const name = hasSection(resource.kind)
    ? <Link className="underline underline-offset-4" to={resourcePath(resource)}>{resource.name}</Link> : resource.name;
  const detail = resource.kind === 'ssh_host' ? resource.data.address + ':' + resource.data.port
    : resource.kind === 'ssh_key' ? resource.data.fingerprint : null;
  return detail ? <span className="flex min-w-0 flex-col">{name}<code className="text-xs wrap-anywhere">{detail}</code></span> : <>{name}</>;
}

function Value({ field, value }: { field: string; value: ReviewValue }) {
  const { t } = useTranslation();
  switch (value.kind) {
    case 'text': return <span className="whitespace-pre-wrap">{value.text}</span>;
    case 'command': return <CommandArguments parts={value.parts} />;
    case 'empty': return <span className="text-muted-foreground">{t(times.has(field) ? 'reviewNoExpiry' : 'reviewNone')}</span>;
    case 'boolean': return <>{t(value.value ? 'reviewYes' : 'reviewNo')}</>;
    case 'time': return <DateText value={value.value} />;
    case 'principal': return <>{value.approver ? t('reviewYouNamed', { name: value.name }) : value.name}</>;
    case 'approver': return <>{t('reviewApprover')}</>;
    case 'identifier': return <span>{t(value.approver ? 'reviewYourId' : 'reviewIdOf', { name: value.name })} <code className="text-xs">{value.id}</code></span>;
    case 'approverId': return <>{t('reviewApproverId')}</>;
    case 'resource': return <ResourceName resource={value.resource} />;
    case 'unknown': return <span>{t('reviewUnknownItem')} <code className="text-xs text-muted-foreground">{value.id}</code></span>;
    case 'key': return <span className="flex min-w-0 flex-col">
      <span>{value.algorithm}{value.comment && <span className="text-muted-foreground"> · {value.comment}</span>}</span>
      <code className="text-xs wrap-anywhere">{value.fingerprint}</code>
    </span>;
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
const usual: Record<string, JsonValue> = { authorizedKeysFile: '.ssh/authorized_keys', timeoutSeconds: 60 };
const folded = (row: ReviewRow) => row.field in usual && row.value.kind === 'text' && row.value.text === String(usual[row.field]);

// What holds whatever an operation does, said once for all the operations of a request: before approval what approving
// alone does not do, and once done what is left to do. Registering a host leaves allowing a key and applying it, unless
// the same request also allowed one, which leaves only applying it.
const notes: Record<string, [string, string]> = { 'ssh.host.create': ['noteSSHHost', 'nextSSHHost'],
  'ssh.access.grant': ['noteSSHApply', 'noteSSHApply'], 'ssh.access.revoke': ['noteSSHApply', 'noteSSHApply'],
  'ssh.key.revoke': ['noteSSHApply', 'noteSSHApply'] };
export function OperationNotes({ operations, done = false }: { operations: Array<{ name: string }>; done?: boolean }) {
  const { t } = useTranslation();
  let keys = [...new Set(operations.flatMap(operation => notes[operation.name] ? [notes[operation.name]![done ? 1 : 0]] : []))];
  if (done && keys.includes('noteSSHApply')) keys = keys.filter(key => key !== 'nextSSHHost');
  return keys.length ? <>{keys.map(key => <p key={key} className={done ? 'leading-relaxed' : 'text-sm leading-relaxed text-muted-foreground'}>{t(key)}</p>)}</> : null;
}

const SSHAuthorization = z.object({ account: z.string(), status: z.enum(['applied', 'pending', 'removed', 'remains_unmanaged']),
  key: z.object({ name: z.string(), fingerprint: z.string() }).nullable(),
  host: z.object({ name: z.string(), address: z.string(), port: z.number() }).nullable() });
// Only the operations that return an SSH authorization have their results read as one.
const authorizations = new Set(['ssh.access.grant', 'ssh.access.revoke']);
export const knownResult = (name: string, value: JsonValue) => authorizations.has(name) && SSHAuthorization.safeParse(value).success;
// A result read as what it is, for the results knownResult recognizes.
export function KnownResult({ value }: { value: JsonValue }) {
  const { t } = useTranslation();
  const authorization = SSHAuthorization.safeParse(value);
  if (!authorization.success) return null;
  const { host, key, account, status } = authorization.data;
  return <div className="flex min-w-0 flex-col gap-3">
    {host && <Detail label={t('reviewField.hostId')}><span className="flex min-w-0 flex-col">{host.name}<code className="text-xs wrap-anywhere">{host.address + ':' + host.port}</code></span></Detail>}
    {key && <Detail label={t('reviewField.keyId')}><span className="flex min-w-0 flex-col">{key.name}<code className="text-xs wrap-anywhere">{key.fingerprint}</code></span></Detail>}
    <Detail label={t('reviewField.account')}>{account}</Detail>
    <Detail label={t('sshApplied')}>{t('sshStatus.' + status)}</Detail>
  </div>;
}

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
