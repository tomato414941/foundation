import { Link } from 'react-router';
import { useTranslation } from 'react-i18next';
import { Principal, Resource } from '../../shared/contracts';
import type { JsonValue } from '../../shared/contracts';
import type { DefinitionCall, ExecutionView } from '../../shared/executions';
import { api } from './api';
import { hasSection, resourcePath } from './navigation';
import { KnownResult, knownResult } from './operation-review';
import { Button } from './components/ui/button';
import { JsonView } from './components';

// Who started the execution: its creator, or the principal it acts for when that is another.
export async function loadInitiator(item: ExecutionView, signal: AbortSignal) {
  if (item.actorId === item.creator.id) return item.creator;
  try { return await api('/principals/' + item.actorId, { signal }, Principal); }
  catch (error) { if (signal.aborted) throw error; return { id: item.actorId, name: item.actorId }; }
}

export function executionTitle(operation: ExecutionView['operations'][number], language: string) {
  return language === 'ja' ? operation.title.ja : operation.title.en;
}

function OutputText({ text }: { text: string }) {
  return <pre className="m-0 max-h-[480px] overflow-auto rounded-lg border bg-background/60 p-4 font-mono text-sm leading-relaxed whitespace-pre-wrap wrap-anywhere">{text}</pre>;
}

export function ExecutionResult({ invocation, value }: { invocation: DefinitionCall; value: JsonValue }) {
  const { t } = useTranslation();
  const resource = Resource.safeParse(value);
  if (resource.success) return hasSection(resource.data.kind)
    ? <Button asChild variant="outline"><Link to={resourcePath(resource.data)}>{resource.data.name}</Link></Button>
    : <p className="font-medium wrap-anywhere">{resource.data.name}</p>;
  const principal = Principal.safeParse(value);
  if (principal.success) return <Button asChild variant="outline"><Link to={'/p/' + principal.data.id}>{principal.data.name}</Link></Button>;
  if (value && typeof value === 'object' && !Array.isArray(value) && value.kind === 'connected' &&
    typeof value.id === 'string' && typeof invocation.input.ownerId === 'string')
    return <Button asChild variant="outline"><Link to={resourcePath({ ownerId: invocation.input.ownerId, kind: 'connection', id: value.id })}>{t('executionOpenConnection')}</Link></Button>;
  if (knownResult(invocation.name, value)) return <KnownResult value={value} />;
  if (typeof value === 'string') return value ? <OutputText text={value} /> : <p className="text-muted-foreground">{t('executionNoTextOutput')}</p>;
  return <JsonView value={value} />;
}
