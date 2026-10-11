import { randomUUID } from 'node:crypto';
import { JsonObject } from '../shared/contracts.js';
import { ConnectionMaterial, TokenMaterial } from '../shared/connections.js';
import type { AppState, ConnectionState } from '../shared/connections.js';
import { connectionMethod, selectScopes } from '../shared/connection-methods.js';
import { OAuth } from '../server/oauth.js';
import { oauthService } from '../server/oauth-service.js';
import type { OAuthToken } from '../server/oauth.js';
import type { Transport } from '../server/transport.js';
import { fail } from '../server/errors.js';
import { connectionFields } from './connection-fields.js';
import type { AuthorizationContext, ConnectionCheckpoint, ConnectionProvider, ConnectionStart, RenewalContext } from './connection-provider.js';

function specification(value: ConnectionStart | ConnectionState) {
  if (value.method.kind !== 'oauth') throw new Error('Use an OAuth connection provider.');
  return value.method.config;
}
function application(app: AppState | null): AppState {
  if (!app) fail(409, 'app_required', 'Choose an OAuth application.');
  return app;
}
function scopes(input: ConnectionStart) {
  const definition = specification(input).scopes;
  // Older clients sent additions; current clients send the complete selection.
  return selectScopes(definition, input.requestedScopes ?? [...definition.default, ...input.scopes]);
}
function material(input: ConnectionStart, app: AppState, token: OAuthToken) {
  return ConnectionMaterial.parse({ format: 1, methodId: input.methodId, method: input.method,
    generation: randomUUID(), appId: input.appId, appGeneration: input.appId ? app.generation : null, oauth: token });
}
function checkpoint(value: ConnectionCheckpoint) {
  return { token: TokenMaterial.parse(value.token), response: JsonObject.parse(value.response) };
}

export class OAuthConnection implements ConnectionProvider {
  constructor(readonly transport: Transport) {}
  private oauth(signal?: AbortSignal) {
    return new OAuth({ send: request => this.transport.send({ ...request,
      ...(signal ? { signal: AbortSignal.any([signal, ...(request.signal ? [request.signal] : [])]) } : {}),
    }) });
  }
  validate(input: ConnectionStart, app: AppState | null) {
    const spec = specification(input), value = application(app);
    oauthService(spec);
    connectionFields(spec.fields, value.fields, spec.defaults);
    if (connectionMethod(input.method).requiresApp && spec.clientAuth !== 'none' && !value.clientSecret)
      fail(409, 'app_required', 'Add a client secret to this OAuth application.');
  }
  async start(context: AuthorizationContext) {
    const { input, signal } = context, spec = specification(input), app = application(context.app);
    if (spec.grantType !== 'client_credentials') return { kind: 'authorize' as const,
      url: await this.oauth(signal).authorize(spec, app, context.state, context.verifier, input.redirectUri!, scopes(input)) };
    await context.dispatch();
    const token = await this.oauth(signal).clientCredentials(spec, app, scopes(input), undefined,
      (token, response) => context.receive({ token, response }));
    return { kind: 'ready' as const, material: material(input, app, token) };
  }
  async exchange(context: AuthorizationContext, value: string, received?: ConnectionCheckpoint) {
    const { input, signal } = context, spec = specification(input), app = application(context.app);
    const parameters = new URLSearchParams(value);
    if (parameters.getAll('state').length !== 1 || parameters.get('state') !== context.state)
      fail(400, 'invalid_state', 'Start the connection again.');
    let token: OAuthToken;
    if (received) {
      const saved = checkpoint(received);
      token = await this.oauth(signal).inspect(spec, app, saved.token, saved.response);
    } else {
      await context.dispatch();
      token = await this.oauth(signal).exchange(spec, app, { parameters, state: context.state }, context.verifier,
        input.redirectUri!, scopes(input), undefined, (token, response) => context.receive({ token, response }));
    }
    return material(input, app, token);
  }
  needsRenewal(value: ConnectionState) {
    return value.oauth!.expiresAt !== null && value.oauth!.expiresAt < Date.now() + 60_000;
  }
  async renew(context: RenewalContext) {
    const token = await this.oauth(context.signal).refresh(specification(context.material), application(context.app),
      context.material.oauth!, (token, response) => context.receive({ token, response }));
    return ConnectionMaterial.parse({ ...context.material, oauth: token });
  }
  async recover(value: ConnectionState, app: AppState | null, received: ConnectionCheckpoint) {
    const saved = checkpoint(received);
    const token = await this.oauth().inspect(specification(value), application(app), saved.token, saved.response);
    return ConnectionMaterial.parse({ ...value, oauth: token });
  }
  async outputs(value: ConnectionState, app: AppState | null) {
    return this.oauth().outputs(specification(value), application(app), value.oauth!);
  }
  async revoke(value: ConnectionState, app: AppState | null, signal: AbortSignal) {
    await this.oauth(signal).revoke(specification(value), application(app), value.oauth!);
  }
}
