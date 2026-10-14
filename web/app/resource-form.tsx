import { Button } from './components/ui/button';
import { SelectItem } from './components/ui/select';
import { InputField, TextareaField, SelectField } from './form-fields';
import { Notice } from './components';
import { useState } from 'react';
import { Form, Link, redirect, useActionData, useLoaderData, useNavigation } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { LoaderFunctionArgs, ActionFunctionArgs } from 'react-router';
import { CatalogEntry, CatalogMethod, FunctionDefinition, Resource, Payment, Usage, listOf } from '../../shared/contracts';
import type { CatalogConnectionMethod } from '../../shared/contracts';
import { decode } from '../../shared/encryption';
import { AppMaterial, ConnectionMaterial } from '../../shared/connections';
import type { ConnectionState } from '../../shared/connections';
import { isProtected } from '../../shared/protected';
import { actionResult, api, ApiFailure, errorCode, formText, jsonField, session, upload } from './api';
import { decryptVariable, requireKeys } from './keys';
import { executionClient, custodyClient, functionClient } from './custody';
import { availableEnvironments, EnvironmentChoice } from './environments';
import { EnvironmentForm } from './environment-form';
import { ConnectionFields, connectionNeedsMaterial, ConnectionMethodHelp, ConnectionPreparation, connectionFields, connectionInitialValues } from './connection-form';
import { sshSettings } from './ssh';
import { ErrorNotice, JsonField, Page, Panel, SaveBar } from './components';
import { resourceKind, resourcePath } from './navigation';
import { useWorkspace } from './routes/workspace';
import { connectionMethodName } from './connection-method-labels';
import { connectionMethod } from '../../shared/connection-methods';
import { connectionSubmission } from './execution-forms/connections';
import { httpConnections, httpRequestFromForm, RequestFields } from './http-request';
export async function formLoader({ params, request }: LoaderFunctionArgs) {
  const kind = resourceKind(params.section);
  const query = new URL(request.url).searchParams;
  const id = params.id ?? query.get('connection');
  const ownedItems = async (resourceKind: string) => {
    try {
      return await api(
        `/principals/${params.owner}/resources?kind=${resourceKind}&limit=200`,
        { signal: request.signal },
        listOf(Resource),
      );
    } catch (error) {
      if (error instanceof ApiFailure && error.status === 403) return { items: [], next: null };
      throw error;
    }
  };
  const [
    resource,
    catalog,
    apps,
    sessionData,
    payment,
    usage,
    methods,
    connections,
    shared,
    environments,
    httpConnectionItems,
  ] = await Promise.all([
    id ? api((kind === 'function' ? '/functions/' : '/resources/') + id, { signal: request.signal }, Resource) : null,
    ['connection', 'app'].includes(kind)
      ? api('/catalog', { signal: request.signal }, listOf(CatalogEntry))
      : null,
    kind === 'connection' ? ownedItems('app') : null,
    session(request),
    ['object', 'environment'].includes(kind)
      ? api(`/principals/${params.owner}/payment`, { signal: request.signal }, Payment)
      : null,
    kind === 'environment'
      ? api(`/principals/${params.owner}/usage`, { signal: request.signal }, Usage)
      : null,
    ['connection', 'app'].includes(kind)
      ? api('/connection-methods', { signal: request.signal }, listOf(CatalogMethod))
      : null,
    kind === 'connection' && !id ? ownedItems('connection') : null,
    kind === 'connection'
      ? api('/resources/shared', { signal: request.signal }, listOf(Resource))
      : null,
    ['variable', 'app'].includes(kind) ? availableEnvironments(params.owner!) : [],
    kind === 'function' ? httpConnections(params.owner!, request.signal) : [],
  ]);
  if (resource && (resource.ownerId !== params.owner || resource.kind !== kind))
    throw new Response('Not found', { status: 404 });
  let content = '',
    binary = false,
    locked = false;
  let appMaterial: ReturnType<typeof AppMaterial.parse> | null = null;
  let pinnedMethod: CatalogConnectionMethod | null = null;
  let connection: ReturnType<typeof connectionInitialValues> | undefined;
  let selectedExecutors: string[] = [];
  if (kind === 'function') {
    try { await custodyClient(); } catch (error) { if (errorCode(error) !== 'key_locked') throw error; locked = true; }
  }
  if (resource && isProtected(resource.kind)) {
    try {
      const client = await custodyClient(), item = await client.read(resource.id);
      selectedExecutors = environments.filter(environment => environment.kind === 'environment' &&
        item.content.policy.grants.some(grant => 'actor' in grant && grant.actor.id === client.binding.id && grant.executor.principalId === environment.data.executorId)).map(environment => environment.id);
      if (resource.kind === 'app') appMaterial = AppMaterial.parse(JSON.parse(decode(await client.reveal(resource.id))));
      if (resource.kind === 'connection') {
        const state = ConnectionMaterial.parse(JSON.parse(decode(await client.reveal(resource.id))));
        pinnedMethod = methods?.items.find(method => method.id === state.methodId) ?? { ...state.method, id: state.methodId, builtin: false, availability: 'ready', defaultName: state.method.name,
          registration: { kind: connectionMethod(state.method).browserAuthorization ? 'authorization' : 'input', device: 'browser', browserExchange: 'unknown', tokenAlternatives: [] } };
        connection = connectionInitialValues(state);
      }
    } catch (error) { if (errorCode(error) !== 'key_locked') throw error; locked = true; }
  }
  if (resource?.kind === 'variable') {
    try {
      const bytes = await decryptVariable(resource.id, sessionData.principal!.id);
      try {
        content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        binary = true;
      }
    } catch (error) {
      if (errorCode(error) !== 'key_locked') throw error;
      locked = true;
    }
  }
  return {
    kind,
    resource,
    payment,
    usage,
    catalog: catalog?.items ?? [],
    apps: [
      ...new Map(
        [...(apps?.items ?? []), ...(shared?.items ?? [])]
          .filter((item) => item.kind === 'app')
          .map((item) => [item.id, item]),
      ).values(),
    ],
    methods: methods?.items ?? [],
    connections: [
      ...new Map(
        [...(connections?.items ?? []), ...(shared?.items ?? [])]
          .filter((item) => item.kind === 'connection' && item.permissions.includes('use'))
          .map((item) => [item.id, item]),
      ).values(),
    ],
    pinnedMethod,
    connection,
    appMaterial,
    environments,
    httpConnections: httpConnectionItems,
    selectedExecutors,
    content,
    binary,
    locked,
    serviceId: query.get('service'),
    methodId: query.get('method'),
    environmentId: query.get('environment'),
  };
}
export async function formAction({ params, request }: ActionFunctionArgs) {
  return actionResult(async () => {
    const form = await request.formData();
    const kind = resourceKind(params.section);
    const owner = params.owner!;
    const name = formText(form, 'name');
    const back = `/p/${owner}/${params.section}`;
    const existing = params.id ? await api((kind === 'function' ? '/functions/' : '/resources/') + params.id, {}, Resource) : null;
    const version = Number(formText(form, 'version'));
    if (kind === 'connection') {
      await requireKeys();
      const client = await executionClient();
      const selected = (await api('/connection-methods', {}, listOf(CatalogMethod))).items.find(method => method.id === formText(form, 'methodId'));
      if (!selected) throw new ApiFailure('invalid_input');
      const methodId = selected.id;
      const connectionId = formText(form, 'connectionId');
      let previous: ConnectionState | undefined;
      if (connectionId && connectionNeedsMaterial(selected, form))
        previous = ConnectionMaterial.parse(JSON.parse(decode(await client.custody.reveal(connectionId))));
      const prepared = connectionSubmission({ ownerId: owner, methodId,
        name: name || existing?.name || selected.defaultName,
        ...(connectionId ? { connectionId } : {}) }, form, selected, previous);
      const progress = await client.execute({ name: 'connection.connect', input: prepared.input }, prepared.material);
      if ('kind' in progress && progress.kind === 'saved') return redirect(resourcePath(progress.resource));
      if (!('flow' in progress)) throw new ApiFailure('invalid_input');
      return redirect('/connections/' + progress.flow.id);
    }
    if (kind === 'object') {
      const file = form.get('file');
      if (!(file instanceof File) || !file.name) throw new ApiFailure('invalid_input');
      const item = await upload(
        owner,
        file,
        name || file.name,
        existing ? { id: existing.id, version } : undefined,
      );
      return redirect(back + '/' + item.id);
    }
    let body: Record<string, unknown> = { kind, name };
    if (kind === 'variable' || kind === 'app') {
      await requireKeys();
      const client = await executionClient();
      const file = form.get('file');
      const value = file instanceof File && file.name ? new Uint8Array(await file.arrayBuffer()) : String(form.get('value') ?? '');
      const result = await client.execute({ name: kind === 'app' ? 'app.save' : 'variable.save', input: {
        ownerId: owner, name, environmentIds: form.getAll('environments').map(String),
        ...(existing ? { resourceId: existing.id, version } : {}),
        ...(kind === 'app' ? { methodId: formText(form, 'methodId'), clientId: formText(form, 'clientId') } : {}),
      } }, { value, clientSecret: formText(form, 'clientSecret') || undefined, fields: connectionFields(form) });
      if (!('kind' in result) || result.kind !== 'saved') throw new ApiFailure('invalid_input');
      return redirect(resourcePath(result.resource));
    } else if (kind === 'environment') {
      if (!name) delete body.name;
      body.options = {
        size: formText(form, 'size'),
        lifetime: {
          idleSeconds: formText(form, 'idle') ? Number(formText(form, 'idle')) * 60 : null,
          maxSeconds: formText(form, 'maximum') ? Number(formText(form, 'maximum')) * 60 : null,
        },
        ...(form.has('sshKeys') ? { ssh: sshSettings(form) } : {}),
      };
    } else if (kind === 'function') {
      const definition = {
        description: formText(form, 'description'),
        program: formText(form, 'programKind') === 'command' ? {
          kind: 'command', command: jsonField(form, 'command', []),
          inputs: jsonField(form, 'inputs', []), timeoutSeconds: Number(formText(form, 'timeoutSeconds')),
        } : { kind: 'http', responseFormat: formText(form, 'responseFormat'), request: httpRequestFromForm(form) },
        parameters: jsonField(form, 'parameters', []),
        result: formText(form, 'programKind') === 'http' ? 'json' : formText(form, 'result'),
      };
      await requireKeys();
      const saved = await (await functionClient(true)).save({
        ownerId: owner, name, definition: FunctionDefinition.parse(definition),
        ...(existing ? { resourceId: existing.id, version } : {}),
      });
      return redirect(resourcePath(saved));
    } else if (kind === 'service' || kind === 'method')
      body.definition = { ...jsonField<Record<string, unknown>>(form, 'definition', {}), name };
    if (existing) {
      delete body.kind;
      delete body.methodId;
      body.version = version;
    }
    const result = await api(
      existing ? '/resources/' + existing.id : `/principals/${owner}/resources`,
      { method: existing ? 'PATCH' : 'POST', body },
      Resource,
    );
    return redirect(resourcePath(result));
  });
}
export default function ResourceForm() {
  const data = useLoaderData<typeof formLoader>();
  const result = useActionData<typeof formAction>();
  const { principal, session: sessionData } = useWorkspace();
  const { t } = useTranslation();
  const navigation = useNavigation();
  const existing = data.resource;
  const back = existing
    ? resourcePath(existing)
    : `/p/${principal.id}/${Object.entries({ connection: 'services', variable: 'variables', object: 'objects', environment: 'environments', function: 'functions', service: 'definitions', method: 'methods', app: 'apps' }).find(([key]) => key === data.kind)?.[1]}`;
  const eligibleMethods = data.methods.filter((item) => data.kind !== 'app' || connectionMethod(item).requiresApp);
  const preferred = (methods: CatalogConnectionMethod[]) =>
    methods.find(method => method.id === 'http:bearer') ??
    methods.find(method => method.registration.device === 'browser' && connectionMethod(method).browserAuthorization &&
      !connectionMethod(method).requiresApp) ??
    methods.find(method => method.registration.device === 'browser' && !connectionMethod(method).requiresApp) ??
    methods.find(method => method.registration.device === 'browser') ?? methods[0];
  const [serviceId, setServiceId] = useState(
    existing?.kind === 'connection'
      ? (existing.data.services[0]?.id ?? '')
      : existing?.kind === 'app'
        ? (data.catalog.find((item) =>
            Object.values(item.methods).some((method) => method.id === existing.data.methodId),
          )?.id ?? '')
        : (data.serviceId ?? (data.methodId ? data.catalog.find(item =>
            Object.values(item.methods).some(method => method.id === data.methodId))?.id ?? '' : '')),
  );
  const service = data.catalog.find((item) => item.id === serviceId);
  const initialMethod = existing && (existing.kind === 'connection' || existing.kind === 'app')
    ? existing.data.methodId : data.methodId;
  const [targetId, setTargetId] = useState(service?.targets?.find(target =>
    target.methods.some(key => service.methods[key]?.id === initialMethod))?.id ?? service?.targets?.[0]?.id ?? '');
  const targets = service?.targets?.filter(target => target.methods.some(key =>
    eligibleMethods.some(method => method.id === service.methods[key]?.id))) ?? [];
  const target = targets.find(item => item.id === targetId) ?? targets[0];
  const offered = (entry: typeof service, selectedTarget?: string) =>
    entry
      ? Object.entries(entry.methods).filter(([key]) => !entry.targets?.length ||
          (entry.targets.find(item => item.id === selectedTarget) ?? entry.targets[0])?.methods.includes(key)).flatMap(([, method]) =>
          eligibleMethods.filter((item) => item.id === method.id),
        )
      : eligibleMethods.filter(method => !data.catalog.some(item =>
          Object.values(item.methods).some(candidate => candidate.id === method.id)));
  const methods = offered(service, target?.id);
  const [methodId, setMethodId] = useState(
    existing && (existing.kind === 'connection' || existing.kind === 'app')
      ? existing.data.methodId
      : (data.methodId ?? preferred(methods)?.id ?? ''),
  );
  const method = eligibleMethods.find((item) => item.id === methodId) ?? data.pinnedMethod ?? undefined;
  const [fileName, setFileName] = useState('');
  const executorChoice = ['variable', 'app'].includes(data.kind) && <details className="rounded-md border p-4">
    <summary className="cursor-pointer text-sm">{t('optionalExecutionAccess')}</summary>
    <div className="mt-4"><EnvironmentChoice items={data.environments} multiple
      selected={data.environmentId ? [data.environmentId] : data.selectedExecutors} /></div>
  </details>;
  const matchingApps = data.apps.filter(
    (item) => item.kind === 'app' && item.data.methodId === methodId && item.permissions.includes('use'),
  );
  const existingConnections = data.connections.filter(
    (item) => item.kind === 'connection' && item.data.methodId === methodId,
  );
  const methodUnavailable =
    data.kind === 'connection' &&
    (!method ||
      method.availability === 'unavailable');
  // Client credentials are entered with the connection itself, so only an application approved in a browser can be missing.
  const appMissing = data.kind === 'connection' && !!method && connectionMethod(method).requiresApp &&
    connectionMethod(method).browserAuthorization && matchingApps.length === 0;
  const spec = existing?.kind === 'function' ? FunctionDefinition.parse(existing.data) : undefined;
  const [programKind, setProgramKind] = useState(spec?.program.kind ?? 'command');
  const unavailable =
    data.kind === 'environment'
      ? !sessionData.features.environments
      : data.kind === 'object'
        ? !sessionData.features.objects
        : false;
  const nameField = (
    <InputField
      name="name"
      label={t('name')}
      defaultValue={existing?.name ?? ''}
      required={!['environment', 'connection', 'object'].includes(data.kind) || data.kind === 'connection' && !service}
      hint={data.kind === 'object' && fileName ? fileName : undefined}
      maxLength={200}
    />
  );
  return (
    <Page
      title={
        existing && data.kind === 'connection'
          ? t('reconnect') + ' — ' + existing.name
          : t(
              existing ? 'editItem' : 'newItem',
              existing ? { name: existing.name } : { kind: t('singular.' + data.kind) },
            )
      }
      narrow
    >
      <ErrorNotice error={result && 'error' in result ? result.error : null} />
      {unavailable && <Notice tone={'info'}>{t('featureUnavailable')}</Notice>}
      {data.kind !== 'environment' && data.payment?.required && !data.payment.active && (
        <Notice
          action={
            sessionData.principals.some(
              (item) => item.id === data.payment?.payer?.id && item.permissions.includes('manage_billing'),
            ) ? (
              <Button variant="ghost" asChild>
                <Link to={'/p/' + data.payment.payer?.id + '/settings/billing'}>{t('addPayment')}</Link>
              </Button>
            ) : undefined
          }
          tone={'info'}
        >
          {t('paymentRequired')}
        </Notice>
      )}
      {data.locked ? (
        <Notice
          action={
            <Button variant="ghost" asChild>
              <Link to="/account">{t('unlock')}</Link>
            </Button>
          }
          tone={'warning'}
        >
          {t('keyLocked')}
        </Notice>
      ) : (
        <Form method="post" encType="multipart/form-data">
          <div className={`flex min-w-0 flex-col gap-6 ${data.kind === 'environment' ? 'pb-[calc(12rem+env(safe-area-inset-bottom))] sm:pb-0' : ''}`}>
            <input type="hidden" name="version" value={existing?.version ?? ''} />
            {existing?.kind === 'connection' && (
              <input type="hidden" name="connectionId" value={existing.id} />
            )}
              <>
                {data.kind !== 'environment' && nameField}
                {data.kind === 'variable' && (
                  <Panel>
                    {!sessionData.principal?.publicKey && (
                      <Notice
                        action={
                          <Button variant="ghost" asChild>
                            <Link to="/account">{t('addPasskey')}</Link>
                          </Button>
                        }
                        tone={'info'}
                      >
                        {t('keyLocked')}
                      </Notice>
                    )}
                    {!data.binary && (
                      <TextareaField
                        name="value"
                        label={t('value')}
                        defaultValue={data.content}
                        autoComplete="off"
                        rows={5}
                        spellCheck={false}
                      />
                    )}
                    <InputField type="file" name="file" label={t('file')} />
                  </Panel>
                )}
                {data.kind === 'object' && (
                  <InputField
                    type="file"
                    required
                    name="file"
                    label={t('file')}
                    onChange={(event) =>
                      setFileName((event.target as HTMLInputElement).files?.[0]?.name ?? '')
                    }
                  />
                )}
                {['connection', 'app'].includes(data.kind) && (
                  <Panel>
                    <SelectField
                      label={t('service')}
                      value={serviceId || 'none'}
                      disabled={!!existing && !(existing.kind === 'connection' && !existing.data.services.length)}
                      onValueChange={(value) => {
                        const selectedId = value === 'none' ? '' : value;
                        setServiceId(selectedId);
                        const next = data.catalog.find((item) => item.id === selectedId);
                        const nextTarget = next?.targets?.find(target => target.methods.some(key =>
                          eligibleMethods.some(method => method.id === next.methods[key]?.id)));
                        setTargetId(nextTarget?.id ?? '');
                        setMethodId(preferred(offered(next, nextTarget?.id))?.id ?? '');
                      }}
                    >
                      <SelectItem value="none">{t('noService')}</SelectItem>
                      {data.catalog
                        .filter(
                          (item) =>
                            data.kind !== 'app' ||
                            Object.values(item.methods).some((method) => connectionMethod(method).application !== 'none'),
                        )
                        .map((item) => (
                          <SelectItem key={item.id} value={item.id}>
                            {item.name}
                          </SelectItem>
                        ))}
                    </SelectField>
                    {targets.length > 1 && <SelectField label={t('serviceTarget')}
                      value={target?.id ?? ''} disabled={!!existing && data.kind !== 'connection'}
                      onValueChange={value => {
                        setTargetId(value);
                        setMethodId(preferred(offered(service, value))?.id ?? '');
                      }}>
                      {targets.map(item => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}
                    </SelectField>}
                    <SelectField
                      key={serviceId + ':' + (target?.id ?? '')}
                      name="methodId"
                      label={t('method')}
                      value={methodId}
                      disabled={!!existing && data.kind !== 'connection'}
                      onValueChange={(value) => setMethodId(value)}
                    >
                      {(existing && data.kind === 'app' && method ? [method] : [...methods, ...(data.pinnedMethod && !methods.some(item => item.id === data.pinnedMethod?.id) ? [data.pinnedMethod] : [])]).map((item) => (
                        <SelectItem key={item.id} value={item.id}>
                          {connectionMethodName(item.name, t, service?.name)}
                        </SelectItem>
                      ))}
                    </SelectField>
                    {existing && <input type="hidden" name="methodId" value={methodId} />}
                    <ConnectionMethodHelp method={method} connecting={data.kind === 'connection'} />
                    {!existing && !!existingConnections.length && (
                      <Notice tone={'info'}>
                        <p className="leading-relaxed text-sm">{t('existingConnections')}</p>
                        {existingConnections.map((item) => (
                          <Button key={item.id} variant="ghost" asChild>
                            <Link to={resourcePath(item)}>{item.name}</Link>
                          </Button>
                        ))}
                      </Notice>
                    )}
                    {methodUnavailable && (
                      <Notice tone={'info'}>
                        {t(
                          method?.availability === 'app-required' ? 'appRequired' : 'methodUnavailable',
                        )}
                      </Notice>
                    )}
                    <ConnectionFields key={methodId} purpose={data.kind === 'app' ? 'app' : 'connection'}
                      method={method} existing={existing} appMaterial={data.appMaterial} apps={matchingApps} reusableFields={data.connection?.reusableFields}
                      appSetupUrl={method ? `/p/${principal.id}/apps/new?method=${encodeURIComponent(method.id)}&service=${encodeURIComponent(serviceId)}` : undefined} />
                  </Panel>
                )}
                {executorChoice}
                <ConnectionPreparation method={data.kind === 'connection' ? method : undefined}
                  initial={data.connection} newConnection={data.kind === 'connection' && !existing}
                  />
                {data.kind === 'environment' && (
                  <EnvironmentForm owner={principal} usage={data.usage}
                    payment={data.payment} canManageBilling={principal.permissions.includes('manage_billing')}
                    canManagePayment={sessionData.principals.some(item => item.id === data.payment?.payer?.id && item.permissions.includes('manage_billing'))}
                    ssh={sessionData.features.ssh} available={!unavailable} back={back} busy={navigation.state === 'submitting'} />
                )}
                {data.kind === 'function' && (
                  <>
                    <TextareaField
                      name="description"
                      label={t('description')}
                      defaultValue={spec?.description ?? ''}
                      rows={2}
                    />
                    <SelectField name="programKind" label={t('functionProgram')} value={programKind} onValueChange={value => setProgramKind(value as 'command' | 'http')}>
                      <SelectItem value="command">{t('command')}</SelectItem>
                      <SelectItem value="http">{t('http')}</SelectItem>
                    </SelectField>
                    {programKind === 'http' ? <Panel title={t('http')}>
                      <RequestFields value={spec?.program.kind === 'http' ? spec.program.request : undefined}
                        connections={data.httpConnections} />
                      <SelectField name="responseFormat" label={t('functionResponseFormat')} defaultValue={spec?.program.kind === 'http' ? spec.program.responseFormat : 'json'}>
                        <SelectItem value="json">JSON</SelectItem>
                        <SelectItem value="text">{t('functionText')}</SelectItem>
                      </SelectField>
                      <p className="text-sm text-muted-foreground">{t('functionHttpResultHelp')}</p>
                    </Panel> : <Panel title={t('command')}>
                      <JsonField name="command" label={t('functionCommand')} value={spec?.program.kind === 'command' ? spec.program.command : ['node', '-e', 'let input=""; process.stdin.on("data", chunk => input += chunk); process.stdin.on("end", () => console.log(JSON.stringify(JSON.parse(input))));']} />
                      <p className="text-sm text-muted-foreground">{t('functionArgumentsHelp')}</p>
                      <JsonField name="inputs" label={t('functionInputs')} value={spec?.program.kind === 'command' ? spec.program.inputs : []} />
                      <InputField name="timeoutSeconds" label={t('functionTimeout')} type="number" min={1} max={3600} required defaultValue={spec?.program.kind === 'command' ? spec.program.timeoutSeconds : 60} />
                    </Panel>}
                    <JsonField
                      name="parameters"
                      label={t('parameters')}
                      value={spec?.parameters ?? []}
                    />
                    {programKind === 'command' && <SelectField name="result" label={t('functionResult')} defaultValue={spec?.result ?? 'json'}>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="text">{t('functionText')}</SelectItem>
                    </SelectField>}
                    <p className="text-sm text-muted-foreground">{t('functionResultDisclosure')}</p>
                  </>
                )}
                {(data.kind === 'service' || data.kind === 'method') && (
                  <JsonField
                    name="definition"
                    label={t('definition')}
                    rows={15}
                    value={
                      existing?.kind === 'service' || existing?.kind === 'method'
                        ? existing.data
                        : data.kind === 'method'
                          ? {
                              kind: 'token',
                              config: {
                                fields: [
                                  { name: 'token', label: 'API key', secret: true, required: true },
                                ],
                                outputs: { API_KEY: '/token' },
                              },
                            }
                          : {
                              methods: {},
                            }
                    }
                  />
                )}
              </>
            {data.kind !== 'environment' && !unavailable && !methodUnavailable && !appMissing && (
              <SaveBar
                back={back}
                label={
                  data.kind === 'connection'
                    ? 'connect'
                    : existing
                      ? 'save'
                      : data.kind === 'object'
                        ? 'upload'
                        : 'create'
                }
                busy={navigation.state === 'submitting'}
              />
            )}
          </div>
        </Form>
      )}
    </Page>
  );
}
