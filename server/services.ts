import { randomUUID } from 'node:crypto';
import { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { z } from 'zod';
import safeRegex from 'safe-regex2';
import type { Resources, ResourceRow } from './resources.js';
import type { Actor } from './authorization.js';
import { Catalog, legacyMethod } from './catalog.js';
import type { Configuration } from './config.js';
import type { Queryable } from './database.js';
import { Vault, token, digest } from './vault.js';
import { OAuth } from './oauth.js';
import type { OAuthApp, OAuthToken, OAuthSpec } from './oauth.js';
import { AuthKind, ConnectionInput, LegacyServiceDefinition, MethodDefinition } from '../shared/contracts.js';
import type {
  ConnectInput,
  MethodDescription,
  LegacyServiceDescription,
  SourceReference,
  NewResourceInput,
  JsonValue,
} from '../shared/contracts.js';
import { atPointer, textValue } from '../shared/values.js';
import { DomainError, fail, required } from './errors.js';

interface ConnectionState {
  formatVersion: 2;
  methodId: string;
  method: MethodDescription;
  app: OAuthApp;
  oauth?: OAuthToken;
  fields?: Record<string, string>;
  role?: { arn: string; externalId: string; region: string };
  appVersion?: number;
}
type LegacyConnectionState = Omit<ConnectionState, 'formatVersion' | 'methodId' | 'method'> & {
  service: LegacyServiceDescription;
};
type SelectedInput = ConnectInput & { methodId: string };
interface Consent {
  formatVersion: 2;
  actor: Actor;
  ownerId: string;
  input: SelectedInput;
  method: MethodDescription;
  app: OAuthApp;
  verifier: string;
  connectionVersion?: number;
  result?: OAuthToken;
  tokenFields?: Record<string, string>;
  externalId?: string;
}
type LegacyConsent = Omit<Consent, 'formatVersion' | 'input' | 'method'> & {
  input: ConnectInput;
  service: LegacyServiceDescription;
};
export type ConnectionResult =
  | { kind: 'connected'; resource: Awaited<ReturnType<Resources['view']>>; returnTo: string }
  | { kind: 'authorize'; url: string }
  | {
      kind: 'review';
      id: string;
      before: Record<string, JsonValue>;
      after: Record<string, JsonValue>;
      returnTo: string;
    }
  | { kind: 'role'; id: string; externalId: string; principalArn: string };
export interface RoleCredentials extends Record<string, string> {
  AWS_ACCESS_KEY_ID: string;
  AWS_SECRET_ACCESS_KEY: string;
  AWS_SESSION_TOKEN: string;
  AWS_DEFAULT_REGION: string;
}
export interface RoleProvider {
  obtain(arn: string, externalId: string, region: string): Promise<RoleCredentials>;
}
export class AwsRoles implements RoleProvider {
  async obtain(arn: string, externalId: string, region: string) {
    const sts = new STSClient({ region });
    try {
      const response = await sts.send(
        new AssumeRoleCommand({
          RoleArn: arn,
          RoleSessionName: 'foundation-' + randomUUID().slice(0, 8),
          ExternalId: externalId,
          DurationSeconds: 3600,
        }),
      );
      const key = response.Credentials;
      if (!key?.AccessKeyId || !key.SecretAccessKey || !key.SessionToken)
        fail(502, 'invalid_response', 'AWS did not return credentials.');
      const client = new STSClient({
        region,
        credentials: {
          accessKeyId: key.AccessKeyId,
          secretAccessKey: key.SecretAccessKey,
          sessionToken: key.SessionToken,
        },
      });
      try {
        const identity = await client.send(new GetCallerIdentityCommand({}));
        if (identity.Account !== arn.split(':')[4])
          fail(502, 'account_changed', 'The AWS account could not be verified.');
      } finally {
        client.destroy();
      }
      return {
        AWS_ACCESS_KEY_ID: key.AccessKeyId,
        AWS_SECRET_ACCESS_KEY: key.SecretAccessKey,
        AWS_SESSION_TOKEN: key.SessionToken,
        AWS_DEFAULT_REGION: region,
      };
    } catch (error) {
      if (error instanceof DomainError) throw error;
      fail(502, 'role_denied', 'Check the IAM role and its trust policy.');
    } finally {
      sts.destroy();
    }
  }
}
export class Services {
  resolve?: (actor: Actor, source: SourceReference) => Promise<string>;
  checkApproval?: (actor: Actor, connection?: Queryable) => Promise<void>;
  completed?: (actor: Actor, result: JsonValue) => Promise<void>;
  cancelled?: (actor: Actor) => Promise<void>;
  constructor(
    readonly resources: Resources,
    readonly catalog: Catalog,
    readonly vault: Vault,
    readonly oauth: OAuth,
    readonly config: Configuration,
    readonly roles: RoleProvider = new AwsRoles(),
  ) {}
  private selectedInput(input: ConnectInput, methodId: string): SelectedInput {
    const { serviceId: _serviceId, scheme: _scheme, ...rest } = input;
    return { ...ConnectionInput.parse({ ...rest, methodId }), methodId };
  }
  private async readState(row: ResourceRow): Promise<ConnectionState> {
    const value = await this.vault.decrypt<ConnectionState | LegacyConnectionState>(
      required(row.private_data),
      'resource:' + row.id,
    );
    if ('method' in value) {
      if (value.formatVersion !== 2 || value.methodId !== row.data.methodId)
        fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
      return { ...value, method: MethodDefinition.parse(value.method) };
    }
    const kind = AuthKind.parse(row.data.scheme),
      methodId = await this.catalog.legacyMethodId(String(row.data.serviceId), kind),
      { service, ...state } = value;
    return {
      ...state,
      formatVersion: 2,
      methodId,
      method: legacyMethod(LegacyServiceDefinition.parse(service), kind),
    };
  }
  private async readConsent(value: Consent | LegacyConsent): Promise<Consent> {
    if ('method' in value) return value;
    const kind = AuthKind.parse(value.input.scheme),
      methodId = await this.catalog.legacyMethodId(required(value.input.serviceId), kind),
      { service, input, ...consent } = value;
    return {
      ...consent,
      formatVersion: 2,
      input: this.selectedInput(input, methodId),
      method: legacyMethod(LegacyServiceDefinition.parse(service), kind),
    };
  }
  private data(state: ConnectionState, account: string, appId: string | null, status = 'ready') {
    return {
      methodId: state.methodId,
      methodName: state.method.name,
      methodKind: state.method.kind,
      account,
      accountId: state.role?.arn ?? (state.oauth?.accountVerified ? state.oauth.account : null),
      accountVerified: state.role ? true : (state.oauth?.accountVerified ?? false),
      scopes: state.oauth?.scopes ?? [],
      scopesStatus: state.oauth?.scopesStatus ?? 'unknown',
      outputs:
        state.method.kind === 'role'
          ? ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION']
          : Object.keys(state.method.config.outputs),
      state: status,
      appId,
    };
  }
  private references(methodId: string, appId: string | null) {
    return [...(this.catalog.methods.has(methodId) ? [] : [methodId]), ...(appId ? [appId] : [])];
  }
  async initialize() {
    await this.resources.db.transaction(async (connection) => {
      await connection.query('SELECT pg_advisory_xact_lock(736023747)');
      const rows = await this.resources.db.all<ResourceRow>(
        "SELECT * FROM resources WHERE kind='connection' AND NOT(data ? 'methodId') FOR UPDATE",
        [],
        connection,
      );
      for (const row of rows) {
        const state = await this.readState(row),
          appId = typeof row.data.appId === 'string' ? row.data.appId : null,
          data = this.data(
            state,
            String(row.data.account ?? state.method.name),
            appId,
            String(row.data.state),
          );
        await connection.query('UPDATE resources SET data=$2,private_data=$3 WHERE id=$1', [
          row.id,
          JSON.stringify(data),
          await this.vault.encrypt(state, 'resource:' + row.id),
        ]);
        await this.resources.references(row.id, this.references(state.methodId, appId), connection);
      }
      const pending = await this.resources.db.all<{ id: string; data: { sealed: string } }>(
        "SELECT id,data FROM challenges WHERE kind IN ('service','service-review') AND expires_at>now() FOR UPDATE",
        [],
        connection,
      );
      for (const row of pending) {
        const value = await this.vault.decrypt<Consent | LegacyConsent>(row.data.sealed, 'consent:' + row.id);
        if ('method' in value) continue;
        const consent = await this.readConsent(value);
        await connection.query('UPDATE challenges SET data=$2 WHERE id=$1', [
          row.id,
          JSON.stringify({ sealed: await this.vault.encrypt(consent, 'consent:' + row.id) }),
        ]);
      }
    });
  }
  async definition(actor: Actor, row: ResourceRow) {
    if (row.kind !== 'connection') fail(400, 'wrong_kind', 'Choose a connection.');
    await this.resources.authorization.requireResource(actor, row, 'update');
    const state = await this.readState(row);
    return this.catalog.methodView(state.methodId, state.method);
  }
  private async allowed(actor: Actor, ownerId: string, input: SelectedInput) {
    if (input.connectionId) {
      const row = await this.resources.get(input.connectionId);
      if (row.kind !== 'connection' || row.owner_id !== ownerId || row.data.methodId !== input.methodId)
        fail(400, 'wrong_connection', 'Use the same connection method, or create a new connection.');
      await this.resources.authorization.requireResource(actor, row, 'update');
      return row;
    }
    if (!(await this.resources.authorization.canCreate(actor, ownerId, 'connection')))
      fail(403, 'forbidden', 'You cannot connect services for this principal.');
    return null;
  }
  private fields(
    definitions: Array<{ name: string; required?: boolean; pattern?: string }>,
    input: Record<string, string>,
    defaults: Record<string, string> = {},
  ) {
    const values = { ...defaults, ...input };
    for (const field of definitions) {
      if (field.required !== false && !values[field.name] && !Object.hasOwn(defaults, field.name))
        fail(400, 'missing_field', 'Complete the required service fields.');
      if (values[field.name] && (values[field.name]!.length > 16384 || /\u0000/.test(values[field.name]!)))
        fail(400, 'invalid_field', 'Check the service fields.');
      if (field.pattern && (!safeRegex(field.pattern) || field.pattern.length > 200))
        fail(400, 'invalid_pattern', 'Use a simple field validation pattern.');
      if (
        field.pattern &&
        values[field.name] &&
        !new RegExp(field.pattern, 'u').test(values[field.name]!.slice(0, 1000))
      )
        fail(400, 'invalid_field', 'Check the service fields.');
    }
    if (Object.keys(input).some((key) => !definitions.some((field) => field.name === key)))
      fail(400, 'invalid_field', 'Remove unrecognized service fields.');
    return values;
  }
  private async app(actor: Actor, id: string, methodId: string, spec: OAuthSpec): Promise<OAuthApp> {
    if (id === 'foundation') {
      const app = this.catalog.foundationApp(methodId);
      if (!app && spec.adapter !== 'openrouter')
        fail(409, 'app_required', 'Add an OAuth application to connect this service.');
      return {
        clientId: app?.clientId ?? '',
        ...(app?.clientSecret ? { clientSecret: app.clientSecret } : {}),
        fields: this.fields(spec.fields, app?.fields ?? {}, spec.defaults),
      };
    }
    const row = await this.resources.get(id);
    if (row.kind !== 'app' || row.data.methodId !== methodId)
      fail(400, 'wrong_app', 'Choose an application for this connection method.');
    await this.resources.authorization.requireResource(actor, row, 'use');
    const privateData = await this.vault.decrypt<{ clientSecret?: string }>(
      required(row.private_data),
      'resource:' + id,
    );
    return {
      clientId: String(row.data.clientId),
      ...privateData,
      fields: this.fields(spec.fields, row.data.fields as Record<string, string>, spec.defaults),
      version: row.version,
    };
  }
  async createDefinition(
    actor: Actor,
    ownerId: string,
    input: Extract<NewResourceInput, { kind: 'app' | 'service' | 'method' }>,
  ) {
    if (!(await this.resources.authorization.canCreate(actor, ownerId, input.kind)))
      fail(403, 'forbidden', 'You cannot create this item for this principal.');
    if (input.kind === 'service') {
      return this.catalog.createService(actor, ownerId, input.name, input.definition);
    }
    if (input.kind === 'method') {
      return this.resources.insert(
        ownerId,
        'method',
        input.name,
        MethodDefinition.parse({ ...input.definition, name: input.name }) as unknown as Record<
          string,
          JsonValue
        >,
      );
    }
    const selected = await this.catalog.select(actor, {
      ...input,
      ...(input.methodId ? {} : { scheme: 'oauth' }),
    });
    if (selected.definition.kind !== 'oauth')
      fail(400, 'oauth_unavailable', 'This connection method does not use OAuth applications.');
    const spec = selected.definition.config,
      fields = this.fields(spec.fields, input.fields, spec.defaults),
      id = randomUUID();
    return this.resources.db.transaction(async (connection) =>
      this.resources.insert(
        ownerId,
        'app',
        input.name,
        { methodId: selected.id, clientId: input.clientId, fields },
        {
          id,
          privateData: await this.vault.encrypt({ clientSecret: input.clientSecret }, 'resource:' + id),
          references: this.references(selected.id, null),
        },
        connection,
      ),
    );
  }
  async begin(
    actor: Actor,
    ownerId: string,
    request: ConnectInput,
    browser: string,
  ): Promise<ConnectionResult> {
    let selected;
    if (request.connectionId) {
      const row = await this.resources.get(request.connectionId);
      if (row.kind !== 'connection') fail(400, 'wrong_connection', 'Choose a connection.');
      await this.resources.authorization.requireResource(actor, row, 'update');
      const state = await this.readState(row);
      const requestedId =
        request.methodId ??
        (await this.catalog.legacyMethodId(required(request.serviceId), required(request.scheme)));
      if (requestedId !== state.methodId)
        fail(400, 'wrong_connection', 'Use the same connection method, or create a new connection.');
      selected = { id: state.methodId, definition: state.method };
    } else selected = await this.catalog.select(actor, request);
    let input = this.selectedInput(request, selected.id);
    if (actor.approvalId) input = { ...input, returnTo: '/requests/' + actor.approvalId };
    const previous = await this.allowed(actor, ownerId, input),
      old = previous ? await this.readState(previous) : null,
      method = old?.method ?? selected.definition;
    if (
      !input.returnTo.startsWith('/') ||
      input.returnTo.startsWith('//') ||
      /[\\\u0000-\u001f]/.test(input.returnTo)
    )
      fail(400, 'invalid_return', 'Choose a page within Foundation.');
    if (method.kind === 'token') {
      const fields: Record<string, string> = {};
      for (const [key, value] of Object.entries(input.fields))
        fields[key] = typeof value === 'string' ? value : await required(this.resolve)(actor, value);
      const data = this.fields(method.config.fields, fields),
        app = { clientId: '', fields: {} };
      if (previous) {
        return this.requestReview(
          {
            formatVersion: 2,
            actor,
            ownerId,
            input,
            method,
            app,
            verifier: token(),
            connectionVersion: previous.version,
            tokenFields: data,
          },
          previous,
          randomUUID(),
          browser,
        );
      }
      return this.store(
        actor,
        ownerId,
        input,
        { formatVersion: 2, methodId: selected.id, method, app, fields: data },
        previous,
      );
    }
    const id = randomUUID(),
      app =
        method.kind === 'oauth'
          ? await this.app(actor, input.appId, selected.id, method.config)
          : { clientId: '', fields: {} };
    if (
      old &&
      method.kind === 'oauth' &&
      JSON.stringify(Object.entries(old.app.fields).sort()) !==
        JSON.stringify(Object.entries(app.fields).sort())
    )
      fail(
        409,
        'connection_target_changed',
        'Create a new connection when changing the service account or target.',
      );
    const consent: Consent = {
      formatVersion: 2,
      actor,
      ownerId,
      input,
      method,
      app,
      verifier: token(),
      ...(previous ? { connectionVersion: previous.version } : {}),
    };
    if (method.kind === 'role') {
      if (!this.config.FOUNDATION_AWS_PRINCIPAL_ARN)
        fail(503, 'role_unavailable', 'AWS role connections are not configured.');
      consent.externalId = token();
    }
    await this.resources.db.pool.query(
      "INSERT INTO challenges(id,kind,principal_id,browser_hash,data,expires_at) VALUES($1,'service',$2,$3,$4,now()+interval '15 minutes')",
      [
        id,
        actor.id,
        digest(browser),
        JSON.stringify({ sealed: await this.vault.encrypt(consent, 'consent:' + id) }),
      ],
    );
    if (method.kind === 'role')
      return {
        kind: 'role',
        id,
        externalId: consent.externalId!,
        principalArn: this.config.FOUNDATION_AWS_PRINCIPAL_ARN,
      };
    const spec = method.config,
      scopes = [...new Set([...spec.scopes.default, ...(input.scopes ?? [])])];
    return {
      kind: 'authorize',
      url: this.oauth.authorize(
        spec,
        app,
        id,
        consent.verifier,
        this.config.origin + '/oauth/callback',
        scopes,
      ),
    };
  }
  private reviewValues(consent: Consent, previous: ResourceRow) {
    return {
      before: {
        account: String(previous.data.account),
        accountId: previous.data.accountId ?? null,
        accountVerified: Boolean(previous.data.accountVerified),
        scopes: previous.data.scopes ?? [],
        scopesStatus: previous.data.scopesStatus ?? 'unknown',
      },
      after: {
        account: consent.result?.accountName ?? String(previous.data.account),
        accountId: consent.result?.accountVerified ? consent.result.account : null,
        accountVerified: consent.result?.accountVerified ?? false,
        scopes: consent.result?.scopes ?? [],
        scopesStatus: consent.result?.scopesStatus ?? 'unknown',
      },
    };
  }
  private async requestReview(
    consent: Consent,
    previous: ResourceRow,
    id: string,
    browser: string,
  ): Promise<ConnectionResult> {
    await this.resources.db.pool.query(
      "INSERT INTO challenges(id,kind,principal_id,browser_hash,data,expires_at) VALUES($1,'service-review',$2,$3,$4,now()+interval '15 minutes')",
      [
        id,
        consent.actor.id,
        digest(browser),
        JSON.stringify({ sealed: await this.vault.encrypt(consent, 'consent:' + id) }),
      ],
    );
    return { kind: 'review', id, ...this.reviewValues(consent, previous), returnTo: consent.input.returnTo };
  }
  private async consent(id: string, browser: string, kind = 'service'): Promise<Consent> {
    const row = await this.resources.db.one<{ data: { sealed: string } }>(
      'DELETE FROM challenges WHERE id=$1 AND kind=$2 AND browser_hash=$3 AND expires_at>now() RETURNING data',
      [id, kind, digest(browser)],
    );
    if (!row) fail(400, 'invalid_state', 'Start the connection again.');
    const value = await this.readConsent(
      await this.vault.decrypt<Consent | LegacyConsent>(row.data.sealed, 'consent:' + id),
    );
    await this.resources.authorization.active(value.actor);
    await this.checkApproval?.(value.actor);
    const previous = await this.allowed(value.actor, value.ownerId, value.input);
    if (previous && previous.version !== value.connectionVersion)
      fail(409, 'changed', 'This connection changed. Start again.');
    if (value.input.appId !== 'foundation' && value.method.kind === 'oauth') {
      const current = await this.app(
        value.actor,
        value.input.appId,
        value.input.methodId,
        value.method.config,
      );
      if (current.version !== value.app.version)
        fail(409, 'changed', 'The OAuth application changed. Start again.');
    }
    return value;
  }
  async callback(id: string, code: string, browser: string): Promise<ConnectionResult> {
    const consent = await this.consent(id, browser);
    if (consent.method.kind !== 'oauth') fail(400, 'invalid_state', 'Start the connection again.');
    const previous = consent.input.connectionId ? await this.resources.get(consent.input.connectionId) : null;
    const old = previous ? await this.readState(previous) : undefined;
    const spec = consent.method.config,
      scopes = [...new Set([...spec.scopes.default, ...(consent.input.scopes ?? [])])];
    const result = await this.oauth.exchange(
      spec,
      consent.app,
      code,
      consent.verifier,
      this.config.origin + '/oauth/callback',
      scopes,
      old?.oauth,
    );
    if (
      previous &&
      (!result.accountVerified ||
        !previous.data.accountVerified ||
        JSON.stringify([...result.scopes].sort()) !==
          JSON.stringify([...((previous.data.scopes as string[]) ?? [])].sort()) ||
        result.scopesStatus !== previous.data.scopesStatus ||
        old?.app.clientId !== consent.app.clientId ||
        previous.data.appId !== (consent.input.appId === 'foundation' ? null : consent.input.appId))
    ) {
      consent.result = result;
      return this.requestReview(consent, previous, id, browser);
    }
    const connected = await this.store(
      consent.actor,
      consent.ownerId,
      consent.input,
      {
        formatVersion: 2,
        methodId: consent.input.methodId,
        method: consent.method,
        app: consent.app,
        oauth: result,
      },
      previous,
      consent.connectionVersion,
    );
    await this.completed?.(consent.actor, connected as unknown as JsonValue);
    return connected;
  }
  async review(actor: Actor, id: string, browser: string, accept: boolean) {
    const consent = await this.consent(id, browser, 'service-review');
    if (actor.id !== consent.actor.id || (actor.requestId && actor.requestId !== consent.actor.approvalId))
      fail(403, 'forbidden', 'Use the account that started this connection.');
    if (!accept) {
      await this.cancelled?.(consent.actor);
      return { kind: 'cancelled' as const, returnTo: consent.input.returnTo };
    }
    const connected = await this.store(
      consent.actor,
      consent.ownerId,
      consent.input,
      {
        formatVersion: 2,
        methodId: consent.input.methodId,
        method: consent.method,
        app: consent.app,
        ...(consent.method.kind === 'token'
          ? { fields: required(consent.tokenFields) }
          : { oauth: required(consent.result) }),
      },
      consent.input.connectionId ? await this.resources.get(consent.input.connectionId) : null,
      consent.connectionVersion,
    );
    await this.completed?.(consent.actor, connected as unknown as JsonValue);
    return connected;
  }
  async cancel(id: string, browser: string) {
    const consent = await this.consent(id, browser);
    await this.cancelled?.(consent.actor);
    return consent.input.returnTo;
  }
  async pendingReview(actor: Actor, id: string, browser: string) {
    const row = await this.resources.db.one<{ data: { sealed: string } }>(
      "SELECT data FROM challenges WHERE id=$1 AND kind='service-review' AND browser_hash=$2 AND expires_at>now()",
      [id, digest(browser)],
    );
    if (!row) fail(400, 'invalid_state', 'Start the connection again.');
    const consent = await this.readConsent(
      await this.vault.decrypt<Consent | LegacyConsent>(row.data.sealed, 'consent:' + id),
    );
    if (actor.id !== consent.actor.id || (actor.requestId && actor.requestId !== consent.actor.approvalId))
      fail(403, 'forbidden', 'Use the account that started this connection.');
    await this.resources.authorization.active(consent.actor);
    await this.checkApproval?.(consent.actor);
    const previous = required(await this.allowed(consent.actor, consent.ownerId, consent.input));
    if (previous.version !== consent.connectionVersion)
      fail(409, 'changed', 'This connection changed. Start again.');
    return {
      id,
      ...this.reviewValues(consent, previous),
    };
  }
  async completeRole(actor: Actor, id: string, browser: string, arn: string, region: string) {
    const consent = await this.consent(id, browser);
    if (
      actor.id !== consent.actor.id ||
      (actor.requestId && actor.requestId !== consent.actor.approvalId) ||
      consent.method.kind !== 'role'
    )
      fail(403, 'forbidden', 'Use the account that started this connection.');
    z.string()
      .regex(/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/)
      .parse(arn);
    z.string()
      .regex(/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/)
      .parse(region);
    const role = { arn, region, externalId: required(consent.externalId) };
    const previous = consent.input.connectionId ? await this.resources.get(consent.input.connectionId) : null;
    if (previous) {
      const state = await this.readState(previous);
      if (state.role?.arn !== arn || state.role.region !== region)
        fail(
          409,
          'connection_target_changed',
          'Create a new connection when changing the service account or target.',
        );
    }
    await this.roles.obtain(arn, role.externalId, region);
    const connected = await this.store(
      consent.actor,
      consent.ownerId,
      consent.input,
      { formatVersion: 2, methodId: consent.input.methodId, method: consent.method, app: consent.app, role },
      previous,
      consent.connectionVersion,
    );
    await this.completed?.(consent.actor, connected as unknown as JsonValue);
    return connected;
  }
  private async store(
    actor: Actor,
    ownerId: string,
    input: SelectedInput,
    state: ConnectionState,
    previous: ResourceRow | null,
    expectedVersion = previous?.version,
  ): Promise<ConnectionResult> {
    if (previous && previous.version !== expectedVersion)
      fail(409, 'changed', 'This connection changed. Start again.');
    await this.allowed(actor, ownerId, input);
    const account = state.oauth?.accountName ?? state.role?.arn.split(':')[4] ?? '';
    const data = this.data(
      state,
      account,
      state.method.kind === 'oauth' && input.appId !== 'foundation' ? input.appId : null,
    );
    const id = previous?.id ?? randomUUID(),
      privateData = await this.vault.encrypt(state, 'resource:' + id);
    const references = this.references(state.methodId, data.appId);
    const row = await this.resources.db.transaction(async (connection) => {
      await this.checkApproval?.(actor, connection);
      const row = previous
        ? await this.resources.update(
            previous,
            { name: input.name ?? previous.name, data, privateData },
            connection,
          )
        : await this.resources.insert(
            ownerId,
            'connection',
            input.name ??
              (state.method.name + (!account || account === state.method.name ? '' : ' · ' + account)).slice(
                0,
                200,
              ),
            data,
            { id, privateData },
            connection,
          );
      await this.resources.references(id, references, connection);
      await this.resources.audit.record(
        ownerId,
        actor.id,
        'connection.connect',
        id,
        { methodId: input.methodId },
        connection,
      );
      return row;
    });
    return { kind: 'connected', resource: await this.resources.view(actor, row), returnTo: input.returnTo };
  }
  async outputs(actor: Actor, row: ResourceRow): Promise<Record<string, string>> {
    if (row.kind !== 'connection') fail(400, 'wrong_kind', 'This item is not a connection.');
    await this.resources.authorization.requireResource(actor, row, 'use');
    if (row.data.state !== 'ready')
      fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
    try {
      const outputs = await this.resources.db.transaction(async (connection) => {
        const locked = required(
          await this.resources.db.one<ResourceRow>(
            'SELECT * FROM resources WHERE id=$1 FOR UPDATE',
            [row.id],
            connection,
          ),
        );
        await this.resources.authorization.requireResource(actor, locked, 'use', connection);
        if (locked.data.state !== 'ready')
          fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
        const state = await this.readState(locked);
        if (state.method.kind === 'role' && state.role)
          return this.roles.obtain(state.role.arn, state.role.externalId, state.role.region);
        if (state.method.kind === 'token' && state.fields)
          return Object.fromEntries(
            Object.entries(state.method.config.outputs).map(([name, pointer]) => [
              name,
              textValue(atPointer(state.fields, pointer)),
            ]),
          );
        if (state.method.kind !== 'oauth' || !state.oauth)
          fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
        state.oauth = await this.oauth.refresh(state.method.config, state.app, state.oauth);
        const approvedScopes = new Set(locked.data.scopes as string[]);
        const broadened = state.oauth.scopes.some((scope) => !approvedScopes.has(scope));
        await this.resources.update(
          locked,
          {
            privateData: await this.vault.encrypt(state, 'resource:' + locked.id),
            data: {
              ...locked.data,
              scopes: broadened ? (locked.data.scopes ?? []) : state.oauth.scopes,
              scopesStatus: state.oauth.scopesStatus ?? 'unknown',
              accountVerified: state.oauth.accountVerified ?? false,
              accountId: state.oauth.accountVerified ? state.oauth.account : null,
              ...(broadened ? { state: 'reconnect' } : {}),
            },
          },
          connection,
        );
        if (broadened) return null;
        return this.oauth.outputs(state.method.config, state.app, state.oauth);
      });
      if (outputs === null)
        fail(409, 'reconnect_required', 'Reconnect to review the changed service permissions.');
      return outputs;
    } catch (error) {
      if (error instanceof DomainError && ['reconnect_required', 'account_changed'].includes(error.code))
        await this.resources.db.pool.query(
          "UPDATE resources SET data=jsonb_set(data,'{state}','\"reconnect\"'),version=version+1 WHERE id=$1 AND data->>'state'<>'reconnect'",
          [row.id],
        );
      throw error;
    }
  }
  async remove(actor: Actor, row: ResourceRow, revoke = true) {
    await this.resources.authorization.requireResource(actor, row, 'delete');
    if (revoke && row.kind === 'connection') {
      const state = await this.readState(row);
      if (state.method.kind === 'oauth' && state.oauth)
        await this.oauth.revoke(state.method.config, state.app, state.oauth);
    }
    await this.resources.delete(actor, row);
  }
}
