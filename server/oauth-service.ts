import * as oauth from 'oauth4webapi';
import { atPointer } from '../shared/values.js';
import type { OAuthApp, OAuthSpec, OAuthToken } from './oauth-values.js';
import { digest, strings } from './oauth-values.js';
import { fail } from './errors.js';
import { responseJson } from './transport.js';
import type { OutboundRequest, OutboundResponse, Transport } from './transport.js';

interface ServiceContext {
  spec: OAuthSpec;
  app: OAuthApp;
  transport: Transport;
}
interface InspectionContext extends ServiceContext {
  current: OAuthToken;
  configuration(): { server: oauth.AuthorizationServer; client: oauth.Client };
  authentication(method: OAuthSpec['clientAuth']): oauth.ClientAuth;
  options(): oauth.HttpRequestOptions<'POST', URLSearchParams>;
  json(response: Response): Promise<Record<string, unknown>>;
}
export interface OAuthService {
  redirectUri?(app: OAuthApp, redirectUri: string): string;
  authorize?(parameters: Record<string, string>, redirectUri: string): void;
  exchange?(context: ServiceContext & { url(): string; authorization: { parameters: URLSearchParams; state: string }; verifier: string }): Promise<OutboundResponse>;
  accessTokenField?: string;
  allowAccountChange?: boolean;
  refreshInspection?: boolean;
  recognizedTokenTypes?: oauth.RecognizedTokenTypes;
  normalizeToken?(data: Record<string, unknown>): void;
  clientCredentialsParameters?(parameters: Record<string, string>): Record<string, string>;
  inspect?(context: InspectionContext): Promise<OAuthToken>;
  identityRequest?(context: ServiceContext & { url: string; current: OAuthToken }): OutboundRequest;
  verifyIdentity?(context: ServiceContext & { current: OAuthToken; response: OutboundResponse; data: Record<string, unknown> }): void;
  revokeRequest?(context: ServiceContext & { url: string; current: OAuthToken }): OutboundRequest;
}

const tokenTypes: oauth.RecognizedTokenTypes = Object.assign(Object.create(null), {
  dpop: () => fail(502, 'invalid_response', 'The service returned an unsupported token.'),
});
const ebay: OAuthService = {
  redirectUri: app => app.fields.ruName!,
  recognizedTokenTypes: Object.assign(Object.create(null), tokenTypes, { 'user access token': () => {} }),
  refreshInspection: true,
  async inspect(context) {
    const { app, current } = context;
    const { server, client } = context.configuration();
    const response = await oauth.introspectionRequest(
      { ...server, introspection_endpoint: server.token_endpoint + '/introspect' },
      client, context.authentication('basic'), current.accessToken,
      { ...context.options(), additionalParameters: { token_type_hint: 'access_token' } },
    );
    let data: Record<string, unknown>;
    try {
      data = await oauth.processIntrospectionResponse(server, client,
        Response.json(await context.json(response), { status: response.status }));
    } catch {
      fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
    }
    if (data.active !== true || data.client_id !== app.clientId ||
      typeof data.sub !== 'string' || !data.sub || typeof data.exp !== 'number' || data.exp * 1000 <= Date.now())
      fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
    return { ...current, account: data.sub,
      accountName: typeof data.username === 'string' ? data.username : data.sub,
      scopes: strings(data.scope), scopesStatus: 'reported', accountVerified: true,
      expiresAt: Math.min(current.expiresAt ?? Infinity, data.exp * 1000) };
  },
};
const openrouter: OAuthService = {
  authorize(parameters, redirectUri) {
    delete parameters.response_type;
    delete parameters.client_id;
    delete parameters.redirect_uri;
    parameters.callback_url = redirectUri;
    parameters.key_label = 'Foundation';
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
  allowAccountChange: true,
  refreshInspection: true,
  async inspect({ transport, current }) {
    const response = await transport.send({ url: 'https://openrouter.ai/api/v1/key',
      headers: { authorization: 'Bearer ' + current.accessToken } });
    const data = responseJson(response);
    if (response.status !== 200 || !data.data || typeof data.data !== 'object')
      fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
    const info = data.data as Record<string, unknown>;
    return { ...current, account: digest(current.accessToken),
      accountName: typeof info.label === 'string' ? info.label : 'OpenRouter', facts: info };
  },
};
const github: OAuthService = {
  verifyIdentity({ current, response }) {
    if (response.headers['x-oauth-scopes'] !== undefined) {
      current.scopes = strings(response.headers['x-oauth-scopes'].replaceAll(',', ' '));
      current.scopesStatus = 'reported';
    }
  },
};
const githubRevocation: OAuthService = {
  revokeRequest({ app, url, current }) {
    return { url, method: 'DELETE',
      headers: {
        authorization: 'Basic ' + Buffer.from(app.clientId + ':' + (app.clientSecret ?? '')).toString('base64'),
        'content-type': 'application/json',
      },
      body: JSON.stringify({ access_token: current.accessToken }),
    };
  },
};
const google: OAuthService = {
  verifyIdentity({ data }) {
    if (data.email_verified !== true)
      fail(502, 'invalid_response', 'The service account could not be verified.');
  },
};
const namedServices: Readonly<Record<string, OAuthService>> = Object.assign(Object.create(null), {
  ebay, openrouter, github, google,
});
const endpointServices: Array<{ matches(url: URL): boolean; service(spec: OAuthSpec, url: URL): OAuthService }> = [
  {
    matches: url => url.hostname.endsWith('.myshopify.com'),
    service(spec, url) {
      return {
        ...(url.pathname === '/admin/oauth/access_token' ? {
          normalizeToken(data: Record<string, unknown>) {
            if (data.token_type === undefined) data.token_type = 'bearer';
          },
          ...(spec.grantType === 'client_credentials' ? {
            clientCredentialsParameters() {
              // Shopify scopes are configured on the application, never sent with this grant.
              return { ...spec.tokenParams };
            },
          } : {}),
        } : {}),
        ...(spec.grantType === 'client_credentials' && /^\/admin\/api\/[^/]+\/graphql\.json$/.test(url.pathname) ? {
          identityRequest({ spec, url, current }: ServiceContext & { url: string; current: OAuthToken }) {
            return { url, method: spec.identity!.method,
              headers: { ...spec.identity!.headers, 'content-type': 'application/json', 'X-Shopify-Access-Token': current.accessToken },
              body: JSON.stringify({ query: '{ shop { id name myshopifyDomain } }' }) };
          },
          verifyIdentity({ app, data }: ServiceContext & { current: OAuthToken; response: OutboundResponse; data: Record<string, unknown> }) {
            if ((Array.isArray(data.errors) ? data.errors.length : Boolean(data.errors)) ||
              atPointer(data, '/data/shop/myshopifyDomain') !== app.fields.shop + '.myshopify.com')
              fail(502, 'invalid_response', 'The Shopify store could not be verified.');
          },
        } : {}),
      };
    },
  },
  {
    matches: url => url.hostname === 'api.notion.com' && url.pathname === '/v1/oauth/token',
    service: () => ({ normalizeToken(data) { if (data.refresh_token === null) delete data.refresh_token; } }),
  },
];

export function oauthService(spec: OAuthSpec, endpoint?: string): OAuthService {
  const url = endpoint ? new URL(endpoint) : undefined;
  const endpointService = url ? endpointServices.find(service => service.matches(url))?.service(spec, url) : undefined;
  const named = spec.adapter ? namedServices[spec.adapter] : undefined;
  if (spec.adapter && !named) fail(400, 'invalid_input', 'Choose a supported service authentication adapter.');
  return { recognizedTokenTypes: tokenTypes, ...endpointService, ...named,
    ...(spec.revoke?.style === 'github' ? githubRevocation : {}),
    ...(endpointService?.verifyIdentity || named?.verifyIdentity ? {
      verifyIdentity(context) {
        endpointService?.verifyIdentity?.(context);
        named?.verifyIdentity?.(context);
      },
    } : {}),
  };
}
