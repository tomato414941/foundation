import { Button } from './components/ui/button';
import { SelectItem } from './components/ui/select';
import { InputField, TextareaField, SelectField, CheckboxField } from './form-fields';
import { Notice } from './components';
import { useState } from 'react';
import { Form, Link, redirect, useActionData, useLoaderData, useNavigation } from 'react-router';
import { useTranslation } from 'react-i18next';
import type { LoaderFunctionArgs, ActionFunctionArgs } from 'react-router';
import { CatalogEntry, Resource, Payment, Usage, listOf } from '../../shared/contracts';
import type { ResourceView } from '../../shared/contracts';
import { encode } from '../../shared/encryption';
import { actionResult, api, ApiFailure, formText, jsonField, session, upload } from './api';
import { decryptSecret, sealSecret } from './keys';
import { ErrorNotice, ExternalLink, JsonField, JsonView, Page, Panel, SaveBar } from './components';
import { resourceKind, resourcePath } from './navigation';
import { useWorkspace } from './routes/workspace';
import { serviceLabels } from './service-labels';
type ConnectionResult =
  | {
      kind: 'connected';
      resource: ResourceView;
      returnTo: string;
    }
  | {
      kind: 'authorize';
      url: string;
    }
  | {
      kind: 'role';
      id: string;
      externalId: string;
      principalArn: string;
    }
  | {
      kind: 'review';
      id: string;
    };
export async function formLoader({ params, request }: LoaderFunctionArgs) {
  const kind = resourceKind(params.section);
  const query = new URL(request.url).searchParams;
  const id = params.id ?? query.get('connection');
  const [resource, catalog, apps, sessionData, payment, usage] = await Promise.all([
    id ? api('/resources/' + id, { signal: request.signal }, Resource) : null,
    ['connection', 'app'].includes(kind)
      ? api('/catalog', { signal: request.signal }, listOf(CatalogEntry))
      : null,
    kind === 'connection'
      ? api(
          `/principals/${params.owner}/resources?kind=app`,
          { signal: request.signal },
          listOf(Resource),
        )
      : null,
    session(request),
    ['object', 'environment'].includes(kind)
      ? api(`/principals/${params.owner}/payment`, { signal: request.signal }, Payment)
      : null,
    kind === 'environment'
      ? api(`/principals/${params.owner}/usage`, { signal: request.signal }, Usage)
      : null,
  ]);
  if (resource && (resource.ownerId !== params.owner || resource.kind !== kind))
    throw new Response('Not found', { status: 404 });
  let content = '',
    binary = false,
    locked = false;
  if (resource?.kind === 'secret') {
    try {
      const bytes = await decryptSecret(resource.id, sessionData.principal!.id);
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
    apps: apps?.items ?? [],
    content,
    binary,
    locked,
    serviceId: query.get('service'),
  };
}
function connectRedirect(result: ConnectionResult) {
  if (result.kind === 'authorize') return redirect(result.url);
  if (result.kind === 'connected') return redirect(resourcePath(result.resource));
  if (result.kind === 'review') return redirect('/services/review/' + result.id);
  return result;
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
      if (formText(form, 'roleId'))
        return connectRedirect(
          await api<ConnectionResult>(`/connections/${formText(form, 'roleId')}/role`, {
            method: 'POST',
            body: { arn: formText(form, 'arn'), region: formText(form, 'region') },
          }),
        );
      const fields = Object.fromEntries(
        [...form.entries()]
          .filter(([key]) => key.startsWith('field.'))
          .map(([key, value]) => [key.slice(6), String(value)]),
      );
      const input = {
        serviceId: formText(form, 'serviceId'),
        scheme: formText(form, 'scheme'),
        name: name || undefined,
        appId: formText(form, 'appId') || 'foundation',
        fields,
        returnTo: back,
        ...(form.has('scopes') ? { scopes: formText(form, 'scopes').split(/\s+/).filter(Boolean) } : {}),
        ...(formText(form, 'connectionId') ? { connectionId: formText(form, 'connectionId') } : {}),
      };
      return connectRedirect(
        await api<ConnectionResult>(`/principals/${owner}/connections`, { method: 'POST', body: input }),
      );
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
    if (kind === 'secret') {
      const data = await session();
      const id = existing?.id ?? crypto.randomUUID();
      const file = form.get('file');
      const content =
        file instanceof File && file.name
          ? new Uint8Array(await file.arrayBuffer())
          : encode(String(form.get('value') ?? ''));
      const allowUse = form.has('allowUse');
      const sealed = await sealSecret(
        id,
        owner,
        content,
        data.server,
        allowUse,
        existing?.kind === 'secret' ? existing.data.recipients : [],
        !!existing,
      );
      body = existing
        ? { name, version, sealed, bytes: content.length, allowUse }
        : { kind, id, name, sealed, bytes: content.length, allowUse };
    } else if (kind === 'environment')
      body.options = {
        image: formText(form, 'image') || undefined,
        size: formText(form, 'size'),
        lifetime: {
          idleSeconds: Number(formText(form, 'idle')) * 60,
          maxSeconds: Number(formText(form, 'maximum')) * 60,
        },
        identityId:
          formText(form, 'identityId') === 'none' ? null : formText(form, 'identityId') || null,
      };
    else if (kind === 'function')
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
    else if (kind === 'service') body.definition = jsonField(form, 'definition', {});
    else if (kind === 'app')
      body = {
        ...body,
        serviceId: formText(form, 'serviceId'),
        clientId: formText(form, 'clientId'),
        ...(formText(form, 'clientSecret') ? { clientSecret: formText(form, 'clientSecret') } : {}),
        fields: Object.fromEntries(
          [...form.entries()]
            .filter(([key]) => key.startsWith('field.'))
            .map(([key, value]) => [key.slice(6), String(value)]),
        ),
      };
    if (existing) {
      delete body.kind;
      delete body.serviceId;
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
    : `/p/${principal.id}/${Object.entries({ connection: 'services', secret: 'secrets', object: 'objects', environment: 'environments', function: 'functions', service: 'definitions', app: 'apps' }).find(([key]) => key === data.kind)?.[1]}`;
  const [serviceId, setServiceId] = useState(
    existing && (existing.kind === 'connection' || existing.kind === 'app')
      ? existing.data.serviceId
      : (data.serviceId ?? data.catalog[0]?.id ?? ''),
  );
  const service = data.catalog.find((item) => item.id === serviceId);
  const schemes = service ? (Object.keys(service.auth) as Array<'oauth' | 'token' | 'role'>) : [];
  const [scheme, setScheme] = useState<'oauth' | 'token' | 'role'>(
    existing?.kind === 'connection'
      ? existing.data.scheme
      : schemes.includes('oauth') && service?.available.includes('oauth')
        ? 'oauth'
        : schemes.includes('token')
          ? 'token'
          : (schemes[0] ?? 'oauth'),
  );
  const [fileName, setFileName] = useState('');
  const fields =
    data.kind === 'app'
      ? (service?.auth.oauth?.fields ?? [])
      : scheme === 'token'
        ? (service?.auth.token?.fields ?? [])
        : scheme === 'oauth'
          ? (service?.auth.oauth?.fields ?? [])
          : [];
  const role = result && 'kind' in result && result.kind === 'role' ? result : null;
  const spec = existing?.kind === 'function' ? existing.data : undefined;
  const unavailable =
    data.kind === 'environment'
      ? !sessionData.features.environments
      : data.kind === 'object'
        ? !sessionData.features.objects
        : false;
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
              (item) => item.id === data.payment?.payer?.id && item.permissions.includes('billing'),
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
          <div className="flex min-w-0 flex-col gap-6">
            <input type="hidden" name="version" value={existing?.version ?? ''} />
            {existing?.kind === 'connection' && (
              <input type="hidden" name="connectionId" value={existing.id} />
            )}
            {role ? (
              <Panel title={t('role')}>
                <input type="hidden" name="roleId" value={role.id} />
                <p className="leading-relaxed">{t('roleHelp')}</p>
                <JsonView
                  value={{
                    Version: '2012-10-17',
                    Statement: [
                      {
                        Effect: 'Allow',
                        Principal: { AWS: role.principalArn },
                        Action: 'sts:AssumeRole',
                        Condition: { StringEquals: { 'sts:ExternalId': role.externalId } },
                      },
                    ],
                  }}
                />
                <InputField name="arn" label={t('roleArn')} required />
                <InputField name="region" label={t('region')} defaultValue="ap-northeast-1" required />
              </Panel>
            ) : (
              <>
                <InputField
                  name="name"
                  label={t('name')}
                  defaultValue={existing?.name ?? ''}
                  required={!['environment', 'connection', 'object'].includes(data.kind)}
                  hint={data.kind === 'object' && fileName ? fileName : undefined}
                  maxLength={200}
                />
                {data.kind === 'secret' && (
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
                    <CheckboxField
                      name="allowUse"
                      defaultChecked={existing?.kind === 'secret' && existing.data.allowUse}
                      label={t('allowUse')}
                    />
                    <p className="leading-relaxed text-muted-foreground text-sm">{t('allowUseHelp')}</p>
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
                      name="serviceId"
                      label={t('service')}
                      value={serviceId}
                      disabled={!!existing}
                      onValueChange={(value) => {
                        setServiceId(value);
                        const next = data.catalog.find((item) => item.id === value);
                        setScheme(
                          next?.available.includes('oauth')
                            ? 'oauth'
                            : next?.auth.token
                              ? 'token'
                              : next?.auth.role
                                ? 'role'
                                : 'oauth',
                        );
                      }}
                    >
                      {data.catalog
                        .filter((item) => data.kind !== 'app' || item.auth.oauth)
                        .map((item) => (
                          <SelectItem key={item.id} value={item.id}>
                            {item.name}
                          </SelectItem>
                        ))}
                    </SelectField>
                    {existing && <input type="hidden" name="serviceId" value={serviceId} />}
                    {data.kind === 'connection' && (
                      <>
                        <SelectField
                          name="scheme"
                          label={t('method')}
                          value={scheme}
                          onValueChange={(value) => setScheme(value as typeof scheme)}
                        >
                          {schemes.map((value) => (
                            <SelectItem key={value} value={value}>
                              {t(value)}
                            </SelectItem>
                          ))}
                        </SelectField>
                        {scheme === 'oauth' && (
                          <>
                            <SelectField
                              name="appId"
                              label={t('app')}
                              defaultValue={
                                existing?.kind === 'connection'
                                  ? (existing.data.appId ?? 'foundation')
                                  : 'foundation'
                              }
                            >
                              <SelectItem
                                disabled={!service?.available.includes('oauth')}
                                value={'foundation'}
                              >
                                {t('foundationApp')}
                              </SelectItem>
                              {data.apps
                                .filter(
                                  (item) => item.kind === 'app' && item.data.serviceId === serviceId,
                                )
                                .map((item) => (
                                  <SelectItem key={item.id} value={item.id}>
                                    {item.name}
                                  </SelectItem>
                                ))}
                            </SelectField>
                            <InputField
                              key={serviceId}
                              name="scopes"
                              label={t('scopes')}
                              defaultValue={
                                existing?.kind === 'connection'
                                  ? existing.data.scopes.join(' ')
                                  : (service?.auth.oauth?.scopes.default.join(' ') ?? '')
                              }
                              hint={t('scopesHelp')}
                            />
                            {service?.auth.oauth?.scopes.docs && (
                              <ExternalLink href={service.auth.oauth.scopes.docs}>
                                {t('docs')}
                              </ExternalLink>
                            )}
                          </>
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
                          label={t('clientSecret')}
                          hint={existing ? t('unchangedSecret') : undefined}
                        />
                        <InputField
                          label={t('callbackUrl')}
                          value={
                            typeof window !== 'undefined'
                              ? window.location.origin + '/oauth/callback'
                              : ''
                          }
                          readOnly={true}
                        />
                      </>
                    )}
                    {fields.map((field) => (
                      <InputField
                        key={serviceId + '.' + scheme + '.' + field.name}
                        name={'field.' + field.name}
                        label={
                          i18n.language === 'ja'
                            ? (serviceLabels[
                                `${serviceId}.${data.kind === 'app' ? 'oauth' : scheme}.${field.name}.label`
                              ] ?? field.label)
                            : field.label
                        }
                        type={field.secret ? 'password' : 'text'}
                        required={field.required ?? scheme === 'token'}
                        defaultValue={
                          existing?.kind === 'app' ? (existing.data.fields[field.name] ?? '') : ''
                        }
                        placeholder={field.placeholder}
                        autoComplete="off"
                        hint={
                          i18n.language === 'ja'
                            ? (serviceLabels[
                                `${serviceId}.${data.kind === 'app' ? 'oauth' : scheme}.${field.name}.note`
                              ] ?? field.note)
                            : field.note
                        }
                      />
                    ))}
                    {(scheme === 'token' ? service?.auth.token?.console : service?.console) && (
                      <ExternalLink
                        href={(scheme === 'token' ? service?.auth.token?.console : service?.console)!}
                      >
                        {t('serviceConsole')}
                      </ExternalLink>
                    )}
                  </Panel>
                )}
                {data.kind === 'environment' && (
                  <Panel>
                    <p className="leading-relaxed text-muted-foreground text-sm">
                      {t('environmentBudgetHelp')}
                    </p>
                    {data.usage && (
                      <p className="leading-relaxed text-sm">
                        {t('computeUsage', {
                          used: Math.ceil(data.usage.computeSeconds / 60),
                          limit: Math.floor(data.usage.computeLimit / 60),
                        })}
                      </p>
                    )}
                    <Button variant="ghost" asChild>
                      <Link to={'/p/' + principal.id + '/settings/billing'}>{t('billing')}</Link>
                    </Button>
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
                    <SelectField name="identityId" label={t('identity')} defaultValue="none">
                      <SelectItem value="none">{t('none')}</SelectItem>
                      {sessionData.principals
                        .filter((item) => item.permissions.includes('credentials'))
                        .map((item) => (
                          <SelectItem key={item.id} value={item.id}>
                            {item.name}
                          </SelectItem>
                        ))}
                    </SelectField>
                  </Panel>
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
                {data.kind === 'service' && (
                  <JsonField
                    name="definition"
                    label={t('definition')}
                    rows={15}
                    value={
                      existing?.kind === 'service'
                        ? existing.data
                        : {
                            name: '',
                            auth: {
                              token: {
                                fields: [
                                  { name: 'token', label: 'API key', secret: true, required: true },
                                ],
                                outputs: { API_KEY: '/token' },
                              },
                            },
                          }
                    }
                  />
                )}
              </>
            )}
            {!unavailable && (
              <SaveBar
                back={back}
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
