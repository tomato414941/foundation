import type * as oauth from 'oauth4webapi';
import { fail } from './errors.js';
import type { OAuthApp, OAuthSpec, OAuthToken } from './oauth-values.js';
import type { OutboundRequest, OutboundResponse, Transport } from './http.js';

interface ServiceContext { spec: OAuthSpec; app: OAuthApp; transport: Transport }
export interface OAuthService {
  redirectUri?(app: OAuthApp, redirectUri: string): string;
  authorize?(parameters: Record<string, string>, redirectUri: string): void;
  exchange?(context: ServiceContext & { url(): string; authorization: { parameters: URLSearchParams; state: string }; verifier: string }): Promise<OutboundResponse>;
  accessTokenField?: string;
  recognizedTokenTypes?: oauth.RecognizedTokenTypes;
  normalizeToken?(data: Record<string, unknown>): void;
  tokenParameters?(parameters: URLSearchParams): void;
  clientCredentialsParameters?(parameters: Record<string, string>): Record<string, string>;
  revokeRequest?(context: ServiceContext & { url: string; current: OAuthToken }): OutboundRequest;
}
export function basicCredentials(clientId: string, secret: string) {
  return btoa(Array.from(new TextEncoder().encode(clientId + ':' + secret), value => String.fromCharCode(value)).join(''));
}
const tokenTypes: oauth.RecognizedTokenTypes = Object.assign(Object.create(null), {
  dpop: () => fail(502, 'invalid_response', 'The service returned an unsupported token.'),
});
const ebay: OAuthService = {
  redirectUri: app => app.fields.ruName!,
  recognizedTokenTypes: Object.assign(Object.create(null), tokenTypes, { 'user access token': () => {} }),
};
const openrouter: OAuthService = {
  authorize(parameters, redirectUri) {
    delete parameters.response_type; delete parameters.client_id; delete parameters.redirect_uri;
    parameters.callback_url = redirectUri; parameters.key_label = 'Foundation';
  },
  async exchange({ spec, transport, url, authorization, verifier }) {
    const parameters = authorization.parameters;
    if (parameters.getAll('state').length !== 1 || parameters.get('state') !== authorization.state ||
      parameters.getAll('code').length !== 1 || !parameters.get('code'))
      fail(400, 'invalid_state', 'Start the connection again.');
    return transport.send({ url: url(), method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({ ...spec.tokenParams, code: parameters.get('code'), code_verifier: verifier,
        code_challenge_method: 'S256' }) });
  },
  accessTokenField: 'key',
};
const githubRevocation: OAuthService = {
  revokeRequest({ app, url, current }) {
    return { url, method: 'DELETE', headers: {
      authorization: 'Basic ' + basicCredentials(app.clientId, app.clientSecret ?? ''),
      'content-type': 'application/json',
    }, body: JSON.stringify({ access_token: current.accessToken }) };
  },
};
const vultr: OAuthService = {
  tokenParameters(parameters) {
    const redirect = parameters.get('redirect_uri');
    if (redirect !== null) {
      parameters.set('redirect_url', redirect);
      parameters.delete('redirect_uri');
    }
  },
};
export function oauthService(spec: OAuthSpec, endpoint?: string): OAuthService {
  const url = endpoint ? new URL(endpoint) : undefined;
  return { recognizedTokenTypes: tokenTypes,
    ...(url?.hostname.endsWith('.myshopify.com') && url.pathname === '/admin/oauth/access_token' ? {
      normalizeToken(data: Record<string, unknown>) { if (data.token_type === undefined) data.token_type = 'bearer'; },
      ...(spec.grantType === 'client_credentials' ? {
        clientCredentialsParameters() { return { ...spec.tokenParams }; },
      } : {}),
    } : {}),
    ...(url?.hostname === 'api.notion.com' && url.pathname === '/v1/oauth/token' ? {
      normalizeToken(data: Record<string, unknown>) { if (data.refresh_token === null) delete data.refresh_token; },
    } : {}),
    ...(spec.adapter === 'ebay' ? ebay : spec.adapter === 'openrouter' ? openrouter : spec.adapter === 'vultr' ? vultr : {}),
    ...(spec.revoke?.style === 'github' ? githubRevocation : {}),
  };
}
