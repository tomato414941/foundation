import { Button } from './components/ui/button';
import { SelectItem } from './components/ui/select';
import { InputField, TextareaField, SelectField } from './form-fields';
import { Notice } from './components';
import { useEffect, useState } from 'react';
import { z } from 'zod';
import { Form, Link, redirect, useActionData, useLoaderData, useNavigation } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { LoaderFunctionArgs, ActionFunctionArgs } from 'react-router';
import { CatalogEntry, CatalogMethod, Resource, Payment, Usage, listOf } from '../../shared/contracts';
import type { CatalogConnectionMethod, ResourceView } from '../../shared/contracts';
import { decode, encode } from '../../shared/encryption';
import { canonical } from '../../shared/authority';
import { AppMaterial, ConnectionMaterial, requiresApp } from '../../shared/connections';
import { contentTypeOf, isProtected } from '../../shared/protected';
import { actionResult, api, ApiFailure, formText, jsonField, session, upload } from './api';
import { decryptVariable } from './keys';
import { connectionClient, custodyClient } from './custody';
import { availableEnvironments, EnvironmentChoice } from './environments';
import { sshSettings } from './ssh';
import { ErrorNotice, ExternalLink, JsonField, Page, Panel, SaveBar } from './components';
import { resourceKind, resourcePath } from './navigation';
import { useWorkspace } from './routes/workspace';
import { serviceLabels } from './service-labels';
import { connectionMethodName } from './connection-method-labels';
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
  ] = await Promise.all([
    id ? api('/resources/' + id, { signal: request.signal }, Resource) : null,
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
    isProtected(kind) ? availableEnvironments(params.owner!) : [],
  ]);
  if (resource && (resource.ownerId !== params.owner || resource.kind !== kind))
    throw new Response('Not found', { status: 404 });
  let content = '',
    binary = false,
    locked = false;
  let appMaterial: ReturnType<typeof AppMaterial.parse> | null = null;
  let pinnedMethod: CatalogConnectionMethod | null = null;
  let selectedExecutors: string[] = [];
  if (resource && isProtected(resource.kind)) {
    try {
      const client = await custodyClient(), item = await client.read(resource.id);
      selectedExecutors = environments.filter(environment => environment.kind === 'environment' &&
        item.content.policy.grants.some(grant => grant.actor.id === client.binding.id && grant.executor.principalId === environment.data.executorId)).map(environment => environment.id);
      if (resource.kind === 'app') appMaterial = AppMaterial.parse(JSON.parse(decode(await client.reveal(resource.id))));
      if (resource.kind === 'connection') {
        const state = ConnectionMaterial.parse(JSON.parse(decode(await client.reveal(resource.id))));
        pinnedMethod = { ...state.method, id: state.methodId, builtin: false, availability: 'ready' };
      }
    } catch { locked = true; }
  }
  if (resource?.kind === 'variable') {
    try {
      const bytes = await decryptVariable(resource.id, sessionData.principal!.id);
      try {
        content = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      } catch {
        binary = true;
      }
    } catch {
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
    appMaterial,
    environments,
    selectedExecutors,
    content,
    binary,
    locked,
    serviceId: query.get('service'),
    methodId: query.get('method'),
    approvalId: query.get('approval'),
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
    const existing = params.id ? await api('/resources/' + params.id, {}, Resource) : null;
    const version = Number(formText(form, 'version'));
    if (kind === 'connection') {
      const client = await connectionClient();
      const selected = (await api('/connection-methods', {}, listOf(CatalogMethod))).items.find(method => method.id === formText(form, 'methodId'));
      if (!selected) throw new ApiFailure('invalid_input');
      const { id: methodId, builtin: _builtin, availability: _availability, ...method } = selected;
      const fields = Object.fromEntries(
        [...form.entries()]
          .filter(([key]) => key.startsWith('field.'))
          .map(([key, value]) => [key.slice(6), String(value)]),
      );
      const progress = await client.start({
        ownerId: owner, environmentId: formText(form, 'environmentId'), methodId, method,
        name: name || existing?.name || method.name,
        ...(formText(form, 'approvalId') ? { approvalId: formText(form, 'approvalId') } : {}),
        appId: formText(form, 'appId') || undefined,
        fields,
        ...(method.kind === 'role' ? { role: { arn: formText(form, 'arn'), region: formText(form, 'region'), externalId: formText(form, 'externalId') } } : {}),
        ...(form.has('scopes') ? { scopes: formText(form, 'scopes').split(/\s+/).filter(Boolean) } : {}),
        ...(formText(form, 'connectionId') ? { connectionId: formText(form, 'connectionId') } : {}),
      });
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
      const client = await custodyClient();
      const previous = existing ? await client.read(existing.id) : undefined;
      if (previous && previous.version !== version) throw new ApiFailure('changed');
      const environments = await Promise.all(form.getAll('environments').map(id => client.environment(String(id))));
      const policy = await client.policy(owner, contentTypeOf(kind), environments, { previous: previous?.content.policy });
      const file = form.get('file');
      let content =
        file instanceof File && file.name
          ? new Uint8Array(await file.arrayBuffer())
          : encode(String(form.get('value') ?? ''));
      let metadata;
      if (kind === 'app') {
        const old = previous ? AppMaterial.parse(JSON.parse(decode(await client.reveal(previous.content.policy.id)))) : null;
        const fields = Object.fromEntries([...form.entries()].filter(([key]) => key.startsWith('field.')).map(([key, value]) => [key.slice(6), String(value)]));
        const app = AppMaterial.parse({ format: 1, methodId: formText(form, 'methodId'), clientId: formText(form, 'clientId'), fields,
          generation: old && old.methodId === formText(form, 'methodId') && old.clientId === formText(form, 'clientId') && canonical(old.fields) === canonical(fields) ? old.generation : crypto.randomUUID(),
          ...(formText(form, 'clientSecret') || old?.clientSecret ? { clientSecret: formText(form, 'clientSecret') || old?.clientSecret } : {}) });
        content = encode(canonical(app));
        metadata = { methodId: app.methodId, clientId: app.clientId, generation: app.generation };
      }
      return redirect(resourcePath(await client.save(name, content, policy, { previous, metadata })));
    } else if (kind === 'environment') {
      if (!name) delete body.name;
      body.options = {
        image: formText(form, 'image') || undefined,
        size: formText(form, 'size'),
        lifetime: {
          idleSeconds: Number(formText(form, 'idle')) * 60,
          maxSeconds: Number(formText(form, 'maximum')) * 60,
        },
        ...(form.has('sshKeys') ? { ssh: sshSettings(form) } : {}),
      };
    } else if (kind === 'function')
      body.definition = {
        description: formText(form, 'description'),
        request: {
          url: formText(form, 'url'),
          method: formText(form, 'httpMethod'),
          headers: jsonField(form, 'headers', {}),
          ...(formText(form, 'body') ? { body: String(form.get('body')) } : {}),
          bindings: jsonField(form, 'bindings', []),
        },
        parameters: jsonField(form, 'parameters', []),
        save: jsonField(form, 'save', {}),
      };
    else if (kind === 'service' || kind === 'method')
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
export function RequestFields({
  value,
}: {
  value?: Extract<
    ResourceView,
    {
      kind: 'function';
    }
  >['data']['request'];
}) {
  const { t } = useTranslation();
  return (
    <>
      <InputField
        name="url"
        label={t('url')}
        defaultValue={value?.url ?? ''}
        required
        placeholder="https://api.example.com/items"
      />
      <SelectField name="httpMethod" label={t('httpMethod')} defaultValue={value?.method ?? 'GET'}>
        {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map((method) => (
          <SelectItem key={method} value={method}>
            {method}
          </SelectItem>
        ))}
      </SelectField>
      <JsonField name="headers" label={t('headers')} value={value?.headers ?? {}} rows={3} />
      <TextareaField
        name="body"
        label={t('body')}
        defaultValue={value?.body ?? (value?.json === undefined ? '' : JSON.stringify(value.json))}
        rows={3}
      />
      <JsonField name="bindings" label={t('bindings')} value={value?.bindings ?? []} rows={3} />
    </>
  );
}
export default function ResourceForm() {
  const data = useLoaderData<typeof formLoader>();
  const result = useActionData<typeof formAction>();
  const { principal, session: sessionData } = useWorkspace();
  const { t, i18n } = useTranslation();
  const navigation = useNavigation();
  const existing = data.resource;
  const back = existing
    ? resourcePath(existing)
    : `/p/${principal.id}/${Object.entries({ connection: 'services', variable: 'variables', object: 'objects', environment: 'environments', function: 'functions', service: 'definitions', method: 'methods', app: 'apps' }).find(([key]) => key === data.kind)?.[1]}`;
  const eligibleMethods = data.methods.filter((item) => data.kind !== 'app' || item.kind === 'oauth');
  const preferred = (methods: CatalogConnectionMethod[]) =>
    methods.find((item) => item.kind === 'oauth' && item.availability === 'ready') ??
    methods.find((item) => item.kind === 'token') ??
    methods[0];
  const [serviceId, setServiceId] = useState(
    existing?.kind === 'connection'
      ? (existing.data.services[0]?.id ?? '')
      : existing?.kind === 'app'
        ? (data.catalog.find((item) =>
            Object.values(item.methods).some((method) => method.id === existing.data.methodId),
          )?.id ?? '')
        : (data.serviceId ?? (data.methodId ? '' : (data.catalog[0]?.id ?? ''))),
  );
  const service = data.catalog.find((item) => item.id === serviceId);
  const offered = (entry: typeof service) =>
    entry
      ? Object.values(entry.methods).flatMap((method) =>
          eligibleMethods.filter((item) => item.id === method.id),
        )
      : eligibleMethods;
  const methods = offered(service);
  const [methodId, setMethodId] = useState(
    existing && (existing.kind === 'connection' || existing.kind === 'app')
      ? existing.data.methodId
      : (data.methodId ?? preferred(methods)?.id ?? ''),
  );
  const method = data.pinnedMethod ?? eligibleMethods.find((item) => item.id === methodId);
  const clientCredentials = method?.kind === 'oauth' && method.config.grantType === 'client_credentials';
  const shopifyClientCredentials = clientCredentials && methodId === 'shopify:client_credentials';
  const ovhClientCredentials = clientCredentials && methodId.startsWith('ovh:');
  const [fileName, setFileName] = useState('');
  // An IAM role is made in the owner's own AWS console, trusting the identity the chosen executor runs as.
  const roleSetup = data.kind === 'connection' && method?.kind === 'role';
  const [environmentId, setEnvironmentId] = useState(data.environmentId ?? data.selectedExecutors[0] ?? '');
  const executor = data.environments.find((item) => item.id === environmentId);
  const awsPrincipal = executor?.kind === 'environment' ? executor.data.awsPrincipal : undefined;
  const [externalId] = useState(() => crypto.randomUUID().replaceAll('-', ''));
  const [region, setRegion] = useState('ap-northeast-1');
  const [templateUrl, setTemplateUrl] = useState('');
  useEffect(() => {
    if (!roleSetup || !awsPrincipal || templateUrl) return;
    const controller = new AbortController();
    api('/aws/role-template', { signal: controller.signal }, z.object({ url: z.string() }))
      .then((result) => setTemplateUrl(result.url))
      .catch(() => {});
    return () => controller.abort();
  }, [roleSetup, awsPrincipal, templateUrl]);
  const consoleUrl =
    roleSetup && awsPrincipal && templateUrl
      ? 'https://console.aws.amazon.com/cloudformation/home?' + new URLSearchParams({ region }) +
        '#/stacks/create/review?' + new URLSearchParams({ templateURL: templateUrl,
          stackName: 'foundation-' + externalId.slice(0, 12), param_PrincipalArn: awsPrincipal, param_ExternalId: externalId })
      : '';
  const executorChoice = isProtected(data.kind) && (
    <EnvironmentChoice items={data.environments} multiple={data.kind !== 'connection'} onChange={setEnvironmentId}
      selected={data.environmentId ? [data.environmentId] : data.selectedExecutors} />
  );
  const fields =
    method &&
    ((data.kind === 'app' && method.kind === 'oauth') ||
      (data.kind === 'connection' && method.kind === 'token'))
      ? method.config.fields
      : [];
  const labelService = methodId.startsWith('sakura:') ? 'sakura-vps' : methodId.split(':')[0];
  const matchingApps = data.apps.filter(
    (item) => item.kind === 'app' && item.data.methodId === methodId && item.permissions.includes('use'),
  );
  const existingConnections = data.connections.filter(
    (item) => item.kind === 'connection' && item.data.methodId === methodId,
  );
  const methodUnavailable =
    data.kind === 'connection' &&
    (!method ||
      method.availability === 'unavailable' ||
      (requiresApp(method) && !matchingApps.length));
  const spec = existing?.kind === 'function' ? existing.data : undefined;
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
      required={!['environment', 'connection', 'object'].includes(data.kind)}
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
      {data.payment?.required && !data.payment.active && (
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
          <div className={`flex min-w-0 flex-col gap-6 ${data.kind === 'environment' ? 'pb-[calc(5rem+env(safe-area-inset-bottom))] sm:pb-0' : ''}`}>
            <input type="hidden" name="version" value={existing?.version ?? ''} />
            {data.approvalId && <input type="hidden" name="approvalId" value={data.approvalId} />}
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
                      disabled={!!existing}
                      onValueChange={(value) => {
                        const selectedId = value === 'none' ? '' : value;
                        setServiceId(selectedId);
                        const next = data.catalog.find((item) => item.id === selectedId);
                        setMethodId(preferred(offered(next))?.id ?? '');
                      }}
                    >
                      <SelectItem value="none">{t('allMethods')}</SelectItem>
                      {data.catalog
                        .filter(
                          (item) =>
                            data.kind !== 'app' ||
                            Object.values(item.methods).some((method) => method.kind === 'oauth'),
                        )
                        .map((item) => (
                          <SelectItem key={item.id} value={item.id}>
                            {item.name}
                          </SelectItem>
                        ))}
                    </SelectField>
                    <SelectField
                      key={serviceId}
                      name="methodId"
                      label={t('method')}
                      value={methodId}
                      disabled={!!existing}
                      onValueChange={(value) => setMethodId(value)}
                    >
                      {(existing && method ? [method] : methods).map((item) => (
                        <SelectItem key={item.id} value={item.id}>
                          {connectionMethodName(item.name, t, service?.name)}
                        </SelectItem>
                      ))}
                    </SelectField>
                    {existing && <input type="hidden" name="methodId" value={methodId} />}
                    {method?.kind === 'oauth' && (
                      <p className="text-sm text-muted-foreground">
                        OAuth 2.0 / {clientCredentials ? 'Client Credentials' : 'Authorization Code'}
                      </p>
                    )}
                    {clientCredentials && (
                      <Notice tone="info">
                        <p>{t('clientCredentialsHelp')}</p>
                        {shopifyClientCredentials && <p className="mt-2">{t('shopifyClientCredentialsHelp')}</p>}
                        {ovhClientCredentials && <>
                          <p className="mt-2">{t('ovhApiRegionHelp')}</p>
                          <p className="mt-2">{t('ovhClientCredentialsHelp')}</p>
                          {method?.docs && <ExternalLink href={method.docs}>{t('docs')}</ExternalLink>}
                        </>}
                      </Notice>
                    )}
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
                    <div key={methodId} className="flex min-w-0 flex-col gap-6">
                      {data.kind === 'connection' && method?.kind === 'oauth' && (
                        <>
                          {requiresApp(method) && <SelectField
                            key={methodId}
                            name="appId"
                            label={t('app')}
                            defaultValue={
                              existing?.kind === 'connection'
                                ? (existing.data.appId ?? '')
                                : (matchingApps[0]?.id ?? '')
                            }
                          >
                            {matchingApps.map((item) => (
                              <SelectItem key={item.id} value={item.id}>
                                {item.name}
                              </SelectItem>
                            ))}
                          </SelectField>}
                          {!shopifyClientCredentials && <InputField
                            name="scopes"
                            label={t('scopes')}
                            defaultValue={
                              existing?.kind === 'connection'
                                ? existing.data.scopes.join(' ')
                                : method.config.scopes.default.join(' ')
                            }
                            hint={t('scopesHelp')}
                          />}
                          {method.config.scopes.docs && (
                            <ExternalLink href={method.config.scopes.docs}>{t('docs')}</ExternalLink>
                          )}
                        </>
                      )}
                      {data.kind === 'app' && (
                        <>
                          <InputField
                            name="clientId"
                            required
                            label={t('clientId')}
                            defaultValue={existing?.kind === 'app' ? existing.data.clientId : ''}
                          />
                          <InputField
                            name="clientSecret"
                            type="password"
                            autoComplete="new-password"
                            required={!existing && clientCredentials && method?.kind === 'oauth' && method.config.clientAuth !== 'none'}
                            label={t('clientSecret')}
                            hint={existing ? t('unchangedSecret') : undefined}
                          />
                          {!clientCredentials && <InputField
                            label={t('callbackUrl')}
                            value={
                              typeof window !== 'undefined'
                                ? window.location.origin + '/oauth/callback'
                                : ''
                            }
                            readOnly={true}
                          />}
                        </>
                      )}
                      {fields.map((field) => (
                        <InputField
                          key={field.name}
                          name={'field.' + field.name}
                          label={
                            i18n.language === 'ja'
                              ? (serviceLabels[`${labelService}.${method?.kind}.${field.name}.label`] ??
                                field.label)
                              : field.label
                          }
                          type={field.secret ? 'password' : 'text'}
                          required={field.required ?? true}
                          defaultValue={
                            existing?.kind === 'app'
                              ? (data.appMaterial?.fields[field.name] ?? '')
                              : data.kind === 'app' && method?.kind === 'oauth'
                                ? (method.config.defaults[field.name] ?? '')
                                : ''
                          }
                          placeholder={field.placeholder}
                          autoComplete="off"
                          hint={
                            i18n.language === 'ja'
                              ? (serviceLabels[`${labelService}.${method?.kind}.${field.name}.note`] ??
                                field.note)
                              : field.note
                          }
                        />
                      ))}
                      {(method?.kind === 'token'
                        ? (method.config.console ?? method.console)
                        : method?.console) && (
                        <ExternalLink
                          href={
                            (method?.kind === 'token'
                              ? (method.config.console ?? method.console)
                              : method?.console)!
                          }
                        >
                          {t('serviceConsole')}
                        </ExternalLink>
                      )}
                    </div>
                  </Panel>
                )}
                {roleSetup && executorChoice}
                {roleSetup && <Panel title={t('role')}>
                  {executor && (awsPrincipal
                    ? <>
                        <p className="text-sm leading-relaxed text-muted-foreground">{t('createRoleHelp')}</p>
                        {consoleUrl && <ExternalLink href={consoleUrl}>{t('createRole')}</ExternalLink>}
                      </>
                    : <Notice tone="warning">{t('executorWithoutAws')}</Notice>)}
                  <InputField name="arn" label={t('roleArn')} required hint={t('roleArnHelp')}
                    defaultValue={existing?.kind === 'connection' ? existing.data.accountId ?? '' : ''} />
                  <InputField name="region" label={t('region')} value={region} onChange={event => setRegion(event.target.value)} required />
                  <InputField name="externalId" label="External ID" required minLength={16} defaultValue={externalId} hint={t('externalIdHelp')} />
                </Panel>}
                {!roleSetup && executorChoice}
                {data.kind === 'environment' && (
                  <>
                    <Panel>
                      {nameField}
                      <InputField name="image" label={t('image')} placeholder={t('defaultImage')} />
                      <SelectField name="size" label={t('size')} defaultValue="small">
                        {['small', 'medium', 'large'].map((value) => (
                          <SelectItem key={value} value={value}>
                            {t(value)}
                          </SelectItem>
                        ))}
                      </SelectField>
                      <InputField
                        type="number"
                        name="idle"
                        label={t('idle')}
                        defaultValue={60}
                        required
                        min={1}
                        max={1440}
                      />
                      <InputField
                        type="number"
                        name="maximum"
                        label={t('maximum')}
                        defaultValue={60}
                        required
                        min={1}
                        max={1440}
                      />
                      <Notice tone="info">{t('managedEnvironmentHelp')}</Notice>
                    </Panel>
                    {sessionData.features.ssh && <Panel title="SSH">
                      <TextareaField name="sshKeys" label={t('sshAuthorizedKeysOptional')} rows={3}
                        hint={t('sshCreateHelp')} spellCheck={false} autoCapitalize="off" autoCorrect="off"
                        className="font-mono text-xs" />
                    </Panel>}
                    <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 px-1 text-xs text-muted-foreground">
                      {data.usage && (
                        <p className="leading-relaxed">
                          {t('computeUsage', {
                            used: Math.ceil(data.usage.computeSeconds / 60),
                            limit: Math.floor(data.usage.computeLimit / 60),
                          })}
                        </p>
                      )}
                      <Link to={'/p/' + principal.id + '/settings/billing'}
                        className="inline-flex min-h-11 items-center underline underline-offset-4 hover:text-foreground">
                        {t('billing')}
                      </Link>
                    </div>
                  </>
                )}
                {data.kind === 'function' && (
                  <>
                    <TextareaField
                      name="description"
                      label={t('description')}
                      defaultValue={spec?.description ?? ''}
                      rows={2}
                    />
                    <Panel title={t('http')}>
                      <RequestFields value={spec?.request} />
                    </Panel>
                    <JsonField
                      name="parameters"
                      label={t('parameters')}
                      value={spec?.parameters ?? []}
                    />
                    <JsonField name="save" label={t('saveOutputs')} value={spec?.save ?? {}} />
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
            {!unavailable && !methodUnavailable && (
              <SaveBar
                back={back}
                fixedOnMobile={data.kind === 'environment'}
                label={
                  data.kind === 'connection'
                    ? 'connect'
                    : existing
                      ? 'save'
                      : data.kind === 'environment'
                        ? 'start'
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
