import { GoogleClient, GOOGLE_BASE_SCOPES, GOOGLE_SCOPE_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_GOOGLE_CLIENT_ID || '', clientSecret: env.FOUNDATION_GOOGLE_CLIENT_SECRET || '' });
export const create = env => googleOauth(new GoogleClient(configuration(env)));

export function googleOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { GOOGLE_OAUTH_ACCESS_TOKEN: secret.access_token, CLOUDSDK_AUTH_ACCESS_TOKEN: secret.access_token,
      GOOGLE_ACCOUNT_EMAIL: subject, GOOGLE_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    kind: 'oauth', available: client.enabled, variables: ['GOOGLE_OAUTH_ACCESS_TOKEN', 'CLOUDSDK_AUTH_ACCESS_TOKEN', 'GOOGLE_ACCOUNT_EMAIL', 'GOOGLE_OAUTH_EXPIRES_AT'],
    scopes: { base: GOOGLE_BASE_SCOPES, documentationUrl: GOOGLE_SCOPE_DOCS },
    // The holder may bring their own OAuth app: the same scheme, built around their client.
    oauthClient: client, withClient: googleOauth,
    authorization: {
      begin: (context, previous) => client.authorize({ ...context, email: previous?.subject }),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
