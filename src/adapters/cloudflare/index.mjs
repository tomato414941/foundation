import { CloudflareClient, CLOUDFLARE_BASE_SCOPES, CLOUDFLARE_SCOPE_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_CLOUDFLARE_CLIENT_ID || '', clientSecret: env.FOUNDATION_CLOUDFLARE_CLIENT_SECRET || '' });
export const create = env => cloudflareOauth(new CloudflareClient(configuration(env)));

export function cloudflareOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { CLOUDFLARE_API_TOKEN: secret.access_token, CLOUDFLARE_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    kind: 'oauth', available: client.enabled, variables: ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_OAUTH_EXPIRES_AT'],
    scopes: { base: CLOUDFLARE_BASE_SCOPES, documentationUrl: CLOUDFLARE_SCOPE_DOCS },
    // The holder may bring their own OAuth app: the same scheme, built around their client.
    oauthClient: client, withClient: cloudflareOauth,
    authorization: {
      // Reconnecting shows the holder what changed (the accounts it reaches, its scopes, its app) before it is kept.
      changes: (result, previous) => client.changes(result.privateState, previous.privateState),
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous)),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
