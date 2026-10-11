import * as oauth from 'oauth4webapi';
import { atPointer, textValue } from '../shared/values.js';
import { publicUrl, responseJson } from './transport.js';
import type { Transport } from './transport.js';
import { DomainError, fail } from './errors.js';
import { oauthService } from './oauth-service.js';
import { digest, expandUrl, lifetime, strings } from './oauth-values.js';
import type { OAuthApp, OAuthSpec, OAuthToken, TokenCheckpoint } from './oauth-values.js';
export { expandUrl } from './oauth-values.js';
export type { OAuthApp, OAuthSpec, OAuthToken, TokenCheckpoint } from './oauth-values.js';

export class OAuth {
  constructor(readonly transport: Transport) {}
  private appValues(spec: OAuthSpec, app: OAuthApp) {
    return { ...spec.defaults, ...app.fields, clientId: app.clientId };
  }
  async authorize(
    spec: OAuthSpec,
    app: OAuthApp,
    state: string,
    verifier: string,
    redirectUri: string,
    scopes: string[],
  ) {
    if (spec.grantType === 'client_credentials' || !spec.authorizeUrl)
      fail(400, 'wrong_grant', 'This connection exchanges application credentials directly.');
    const url = new URL(expandUrl(spec.authorizeUrl, this.appValues(spec, app)));
    const params: Record<string, string> = {
      ...spec.authorizeParams,
      response_type: 'code',
      client_id: app.clientId,
      redirect_uri: oauthService(spec).redirectUri?.(app, redirectUri) ?? redirectUri,
      state,
    };
    if (scopes.length) params.scope = scopes.join(spec.scopes.separator);
    if (spec.pkce) {
      params.code_challenge = await oauth.calculatePKCECodeChallenge(verifier);
      params.code_challenge_method = 'S256';
    }
    oauthService(spec).authorize?.(params, redirectUri);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    return url.href;
  }
  private configuration(spec: OAuthSpec, app: OAuthApp) {
    const server: oauth.AuthorizationServer = {
      issuer: spec.issuer ?? new URL(expandUrl(
        spec.grantType === 'client_credentials' ? spec.tokenUrl : spec.authorizeUrl!, this.appValues(spec, app),
      )).origin,
      token_endpoint: expandUrl(spec.tokenUrl, this.appValues(spec, app)),
    };
    if (spec.issuer) publicUrl(spec.issuer);
    return { server, client: { client_id: app.clientId } };
  }
  private authentication(app: OAuthApp, method: OAuthSpec['clientAuth']): oauth.ClientAuth {
    if (method === 'none') return oauth.None();
    if (!app.clientSecret) fail(409, 'app_required', 'Add a client secret to this OAuth application.');
    return method === 'basic'
      ? oauth.ClientSecretBasic(app.clientSecret)
      : oauth.ClientSecretPost(app.clientSecret);
  }
  private options(
    format: OAuthSpec['tokenFormat'] = 'form',
  ): oauth.HttpRequestOptions<'POST', URLSearchParams> {
    return {
      [oauth.customFetch]: async (url, { body, headers, method, signal }) => {
        const response = await this.transport.send({
          url,
          method,
          headers: format === 'json' ? { ...headers, 'content-type': 'application/json' } : headers,
          body: format === 'json' ? JSON.stringify(Object.fromEntries(body)) : body.toString(),
          signal,
        });
        return new Response(
          [204, 205, 304].includes(response.status) ? null : new Uint8Array(response.body),
          {
            status: response.status,
            headers: response.headers,
          },
        );
      },
    };
  }
  private async json(response: Response) {
    return responseJson({
      status: response.status,
      headers: {},
      body: new Uint8Array(await response.arrayBuffer()),
    });
  }
  private checkResponse(spec: OAuthSpec, status: number, data: Record<string, unknown>, refresh = false) {
    if (status >= 400 || data.error || (spec.okPointer && atPointer(data, spec.okPointer) !== true)) {
      if (refresh && (data.error === 'invalid_grant' || data.error === 'invalid_token'))
        fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
      if (status === 429) fail(503, 'service_rate_limit', 'The service is busy. Try again later.');
      fail(502, 'authorization_failed', 'The service did not authorize this connection.');
    }
    return data;
  }
  private async tokenResponse(spec: OAuthSpec, app: OAuthApp, response: Response, refresh = false) {
    if (response.status === 429) fail(503, 'service_rate_limit', 'The service is busy. Try again later.');
    const data = this.checkResponse(spec, response.status, await this.json(response), refresh);
    const { server, client } = this.configuration(spec, app);
    const endpoint = new URL(server.token_endpoint!);
    const normalized = { ...data };
    // inspect() resolves the service account; OIDC ID tokens are not used to authenticate sessions.
    delete normalized.id_token;
    oauthService(spec, endpoint.href).normalizeToken?.(normalized);
    if (normalized.expires_in !== undefined) normalized.expires_in = lifetime(normalized.expires_in);
    try {
      const processResponse = refresh
        ? oauth.processRefreshTokenResponse
        : spec.grantType === 'client_credentials'
          ? oauth.processClientCredentialsResponse
          : oauth.processAuthorizationCodeResponse;
      const result = await processResponse(
        server,
        client,
        Response.json(normalized, { status: response.status }),
        {
          recognizedTokenTypes: oauthService(spec, endpoint.href).recognizedTokenTypes,
        },
      );
      return { ...data, ...result };
    } catch (error) {
      if (error instanceof DomainError) throw error;
      fail(502, 'invalid_response', 'The service did not return a valid access token.');
    }
  }
  private token(
    spec: OAuthSpec,
    data: Record<string, unknown>,
    scopes: string[],
    previous?: OAuthToken,
    refreshing = false,
  ): OAuthToken {
    const accessToken = data[oauthService(spec).accessTokenField ?? 'access_token'];
    if (
      typeof accessToken !== 'string' ||
      !accessToken ||
      accessToken.length > 16384 ||
      /[\s\u0000-\u001f]/.test(accessToken)
    )
      fail(502, 'invalid_response', 'The service did not return a valid access token.');
    const expiresAt = data.expires_in === undefined ? null : Date.now() + lifetime(data.expires_in) * 1000;
    const refreshToken = data.refresh_token ?? previous?.refreshToken;
    if (
      refreshToken !== undefined &&
      (typeof refreshToken !== 'string' || !refreshToken || refreshToken.length > 16384)
    )
      fail(502, 'invalid_response', 'The service returned an invalid refresh token.');
    const extra = { ...previous?.extra };
    for (const key of spec.keep) if (typeof data[key] === 'string') extra[key] = data[key];
    const result: OAuthToken = {
      accessToken,
      ...(refreshToken ? { refreshToken: String(refreshToken) } : {}),
      expiresAt,
      scopes:
        data.scope !== undefined
          ? strings(data.scope, spec.scopes.separator)
          : refreshing
            ? (previous?.scopes ?? scopes)
            : scopes,
      scopesStatus:
        data.scope !== undefined
          ? 'reported'
          : refreshing
            ? (previous?.scopesStatus ?? 'unknown')
            : scopes.length
              ? 'requested'
              : 'unknown',
      account: previous?.account ?? '',
      accountName: previous?.accountName ?? '',
      accountVerified: previous?.accountVerified ?? false,
      extra,
      facts: {},
    };
    if (data.refresh_token_expires_in !== undefined) {
      result.refreshExpiresAt = Date.now() + lifetime(data.refresh_token_expires_in) * 1000;
    }
    if (previous?.refreshExpiresAt && refreshToken === previous.refreshToken)
      result.refreshExpiresAt = Math.min(result.refreshExpiresAt ?? Infinity, previous.refreshExpiresAt);
    return result;
  }
  async exchange(
    spec: OAuthSpec,
    app: OAuthApp,
    authorization: { parameters: URLSearchParams; state: string },
    verifier: string,
    redirectUri: string,
    scopes: string[],
    previous?: OAuthToken,
    checkpoint?: TokenCheckpoint,
  ) {
    if (spec.grantType === 'client_credentials')
      fail(400, 'wrong_grant', 'This connection exchanges application credentials directly.');
    let data: Record<string, unknown>;
    const service = oauthService(spec);
    if (service.exchange) {
      const response = await service.exchange({ spec, app, transport: this.transport,
        url: () => expandUrl(spec.tokenUrl, this.appValues(spec, app)), authorization, verifier });
      data = this.checkResponse(spec, response.status, responseJson(response));
    } else {
      const { server, client } = this.configuration(spec, app);
      let response: Response;
      try {
        const parameters = oauth.validateAuthResponse(
          server,
          client,
          authorization.parameters,
          authorization.state,
        );
        response = await oauth.authorizationCodeGrantRequest(
          server,
          client,
          this.authentication(app, spec.clientAuth),
          parameters,
          service.redirectUri?.(app, redirectUri) ?? redirectUri,
          spec.pkce ? verifier : oauth.nopkce,
          { ...this.options(spec.tokenFormat), additionalParameters: spec.tokenParams },
        );
      } catch (error) {
        if (
          error instanceof oauth.OperationProcessingError ||
          error instanceof oauth.AuthorizationResponseError
        )
          fail(400, 'invalid_state', 'Start the connection again.');
        throw error;
      }
      data = await this.tokenResponse(spec, app, response);
    }
    const received = this.token(spec, data, scopes, previous);
    await checkpoint?.(received, data);
    const result = await this.inspect(spec, app, received, data);
    if (previous && result.account !== previous.account && !service.allowAccountChange)
      fail(409, 'account_changed', 'Reconnect using the same service account.');
    return result;
  }
  async clientCredentials(
    spec: OAuthSpec, app: OAuthApp, scopes: string[], previous?: OAuthToken, checkpoint?: TokenCheckpoint,
  ): Promise<OAuthToken> {
    if (spec.grantType !== 'client_credentials')
      fail(400, 'wrong_grant', 'Choose a client credentials connection method.');
    const { server, client } = this.configuration(spec, app);
    const service = oauthService(spec, server.token_endpoint!);
    const parameters = { ...spec.tokenParams, ...(scopes.length ? { scope: scopes.join(spec.scopes.separator) } : {}) };
    const response = await oauth.clientCredentialsGrantRequest(
      server, client, this.authentication(app, spec.clientAuth),
      service.clientCredentialsParameters?.(parameters) ?? parameters,
      this.options(spec.tokenFormat),
    );
    const data = await this.tokenResponse(spec, app, response);
    const received = { ...this.token(spec, data, scopes, previous, Boolean(previous)), requestedScopes: scopes };
    await checkpoint?.(received, data);
    const result = await this.inspect(spec, app, received, data);
    if (previous && result.account !== previous.account)
      fail(409, 'account_changed', 'Reconnect using the same service account.');
    return result;
  }
  async refresh(spec: OAuthSpec, app: OAuthApp, previous: OAuthToken, checkpoint?: TokenCheckpoint): Promise<OAuthToken> {
    let current = previous;
    if (previous.expiresAt !== null && previous.expiresAt < Date.now() + 60_000) {
      if (spec.grantType === 'client_credentials') {
        if (!previous.requestedScopes) fail(409, 'reconnect_required', 'Reconnect this service to select its renewal scopes.');
        return this.clientCredentials(spec, app, previous.requestedScopes, previous, checkpoint);
      }
      if (!previous.refreshToken || (previous.refreshExpiresAt && previous.refreshExpiresAt <= Date.now()))
        fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
      const { server, client } = this.configuration(spec, app);
      const response = await oauth.refreshTokenGrantRequest(
        server,
        client,
        this.authentication(app, spec.clientAuth),
        previous.refreshToken,
        { ...this.options(spec.tokenFormat), additionalParameters: spec.tokenParams },
      );
      const data = await this.tokenResponse(spec, app, response, true);
      current = this.token(spec, data, previous.scopes, previous, true);
      await checkpoint?.(current, data);
    }
    if (spec.identity?.url || oauthService(spec).refreshInspection)
      current = await this.inspect(spec, app, current);
    if (current.account !== previous.account)
      fail(409, 'account_changed', 'Reconnect using the same service account.');
    return current;
  }
  async inspect(
    spec: OAuthSpec,
    app: OAuthApp,
    current: OAuthToken,
    tokenResponse?: Record<string, unknown>,
  ): Promise<OAuthToken> {
    let data: Record<string, unknown> = tokenResponse ?? {};
    const service = oauthService(spec);
    if (service.inspect) return service.inspect({ spec, app, transport: this.transport, current,
      configuration: () => this.configuration(spec, app),
      authentication: method => this.authentication(app, method),
      options: () => this.options(), json: response => this.json(response) });
    if (spec.identity?.url) {
      const url = expandUrl(spec.identity.url, {
        ...this.appValues(spec, app), ...current.extra, accessToken: current.accessToken, refreshToken: current.refreshToken ?? '',
      });
      const identityService = oauthService(spec, url);
      const response = await this.transport.send(identityService.identityRequest?.({ spec, app, transport: this.transport, url, current }) ?? {
        url, method: spec.identity.method,
        headers: { ...spec.identity.headers, authorization: 'Bearer ' + current.accessToken },
      });
      data = responseJson(response);
      if (response.status === 401 || response.status === 403)
        fail(409, 'reconnect_required', 'Reconnect this service to renew access.');
      if (response.status >= 400) fail(502, 'invalid_response', 'The service account could not be verified.');
      identityService.verifyIdentity?.({ spec, app, transport: this.transport, current, response, data });
    } else if (spec.identity?.from === 'app') data = this.appValues(spec, app);
    const first = (pointers: string | string[]) => {
      for (const pointer of Array.isArray(pointers) ? pointers : [pointers]) {
        const value = atPointer(data, pointer);
        if ((typeof value === 'string' && value) || typeof value === 'number') return String(value);
      }
      return '';
    };
    const id = spec.identity?.id;
    const account = id
      ? Array.isArray(id)
        ? id
            .map((pointer) => first(pointer))
            .filter(Boolean)
            .join(':')
        : first(id)
      : current.account || app.fields.domain || app.fields.shop || digest(current.accessToken);
    if (!account || account.length > 1000)
      fail(502, 'invalid_response', 'The service account could not be verified.');
    return {
      ...current,
      account,
      accountName: spec.identity ? first(spec.identity.name) || account : account,
      accountVerified: Boolean(spec.identity?.url || (spec.identity?.from === 'token' && tokenResponse)),
    };
  }
  async revoke(spec: OAuthSpec, app: OAuthApp, current: OAuthToken) {
    if (!spec.revoke)
      fail(409, 'manual_revoke', 'Remove access in the service settings, then remove this connection.');
    const url = expandUrl(spec.revoke.url, {
      ...this.appValues(spec, app),
      accessToken: current.accessToken,
      refreshToken: current.refreshToken ?? '',
    });
    if (spec.revoke.style === 'rfc7009') {
      const { server, client } = this.configuration(spec, app);
      const authentication =
        spec.revoke.auth === 'none' && spec.clientAuth !== 'none'
          ? () => {}
          : this.authentication(app, spec.revoke.auth ?? spec.clientAuth);
      const response = await oauth.revocationRequest(
        { ...server, revocation_endpoint: url },
        client,
        authentication,
        current.refreshToken ?? current.accessToken,
        this.options(),
      );
      try {
        await oauth.processRevocationResponse(response);
      } catch {
        fail(502, 'revoke_failed', 'Access could not be removed at the service. Try again.');
      }
      return;
    }
    const headers: Record<string, string> = {};
    const auth = spec.revoke.auth ?? spec.clientAuth;
    if (spec.revoke.style === 'bearer') headers.authorization = 'Bearer ' + current.accessToken;
    else if (auth === 'basic')
      headers.authorization =
        'Basic ' + Buffer.from(app.clientId + ':' + (app.clientSecret ?? '')).toString('base64');
    const response = await this.transport.send(oauthService(spec).revokeRequest?.({
      spec, app, transport: this.transport, url, current,
    }) ?? {
      url,
      method: spec.revoke.style === 'bearer' ? 'POST' : 'DELETE',
      headers,
    });
    if (response.status >= 300)
      fail(502, 'revoke_failed', 'Access could not be removed at the service. Try again.');
  }
  outputs(spec: OAuthSpec, app: OAuthApp, value: OAuthToken): Record<string, string> {
    const data = {
      ...this.appValues(spec, app),
      ...value.extra,
      ...value,
      expiresAt: value.expiresAt === null ? '' : String(value.expiresAt),
    };
    return Object.fromEntries(
      Object.entries(spec.outputs).map(([name, pointer]) => [name, textValue(atPointer(data, pointer))]),
    );
  }
}
