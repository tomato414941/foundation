import { JsonObject } from '../shared/contracts.js';
import { ConnectionMaterial, TokenMaterial } from '../shared/connections.js';
import { oauthConnectionFacts } from '../shared/connection-facts.js';
import type { AppState, ConnectionState } from '../shared/connections.js';
import { selectScopes } from '../shared/connection-methods.js';
import { OAuth } from '../shared/oauth.js';
import type { OAuthToken } from '../shared/oauth.js';
import type { Transport } from '../server/transport.js';
import { fail } from '../server/errors.js';
import type { ConnectionCheckpoint, ConnectionProvider, RenewalContext } from './connection-provider.js';

function specification(value: ConnectionState) {
  if (value.method.kind !== 'oauth') throw new Error('Use an OAuth connection provider.');
  return value.method.config;
}
function application(app: AppState | null): AppState {
  if (!app) fail(409, 'app_required', 'Choose an OAuth application.');
  return app;
}
function checkpoint(value: ConnectionCheckpoint) {
  return { token: TokenMaterial.parse(value.token), response: JsonObject.parse(value.response) };
}

export class OAuthConnection implements ConnectionProvider {
  facts = oauthConnectionFacts;
  constructor(readonly transport: Transport) {}
  private oauth(signal?: AbortSignal) {
    return new OAuth({ send: request => this.transport.send({ ...request,
      ...(signal ? { signal: AbortSignal.any([signal, ...(request.signal ? [request.signal] : [])]) } : {}),
    }) });
  }
  needsRenewal(value: ConnectionState) {
    return !value.oauth || value.oauth.expiresAt !== null && value.oauth.expiresAt < Date.now() + 60_000;
  }
  async renew(context: RenewalContext) {
    const value = context.material, spec = specification(value), app = application(context.app);
    const scopes = ('requestedScopes' in value ? value.requestedScopes : undefined) ?? value.oauth?.requestedScopes;
    const receive = (token: OAuthToken, response: Record<string, unknown>) => context.receive({ token, response });
    const token = spec.grantType === 'client_credentials'
      ? await this.oauth(context.signal).clientCredentials(spec, app, scopes ?? selectScopes(spec.scopes), value.oauth, receive)
      : await this.oauth(context.signal).refresh(spec, app, value.oauth!, receive);
    return ConnectionMaterial.parse({ ...context.material, oauth: token });
  }
  async recover(value: ConnectionState, _app: AppState | null, received: ConnectionCheckpoint) {
    const saved = checkpoint(received);
    const token = saved.token;
    return ConnectionMaterial.parse({ ...value, oauth: token });
  }
  async outputs(value: ConnectionState, app: AppState | null) {
    return this.oauth().outputs(specification(value), application(app), value.oauth!);
  }
  async revoke(value: ConnectionState, app: AppState | null, signal: AbortSignal) {
    if (value.oauth) await this.oauth(signal).revoke(specification(value), application(app), value.oauth);
  }
}
