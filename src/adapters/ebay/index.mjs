import { EbayClient, EBAY_BASE_SCOPES, EBAY_SCOPE_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_EBAY_CLIENT_ID || '', clientSecret: env.FOUNDATION_EBAY_CLIENT_SECRET || '', ruName: env.FOUNDATION_EBAY_RUNAME || '' });
export const create = env => ebayOauth(new EbayClient(configuration(env)));

export function ebayOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { EBAY_ACCESS_TOKEN: secret.access_token, EBAY_ACCOUNT_ID: subject, EBAY_USERNAME: secret.identity.username, EBAY_OAUTH_EXPIRES_AT: String(secret.expires_at) } } });
  return {
    kind: 'oauth', available: client.enabled, variables: ['EBAY_ACCESS_TOKEN', 'EBAY_ACCOUNT_ID', 'EBAY_USERNAME', 'EBAY_OAUTH_EXPIRES_AT'],
    scopes: { base: EBAY_BASE_SCOPES, documentationUrl: EBAY_SCOPE_DOCS },
    // The owner may bring their own OAuth app: the same scheme, built around their client. eBay names the
    // redirect by the app's RuName, which the catalog asks for.
    oauthClient: client, withClient: ebayOauth,
    authorization: {
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous)),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
