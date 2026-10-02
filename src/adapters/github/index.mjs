import { GitHubClient, GITHUB_BASE_SCOPES, GITHUB_SCOPE_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_GITHUB_CLIENT_ID || '', clientSecret: env.FOUNDATION_GITHUB_CLIENT_SECRET || '' });
export const create = env => githubOauth(new GitHubClient(configuration(env)));

export function githubOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret),
    expiresAt: secret.expires_at, credentials: { environment: { GH_TOKEN: secret.access_token, GITHUB_TOKEN: secret.access_token } } });
  return {
    kind: 'oauth', available: client.enabled, variables: ['GH_TOKEN', 'GITHUB_TOKEN'],
    scopes: { base: GITHUB_BASE_SCOPES, documentationUrl: GITHUB_SCOPE_DOCS },
    // The owner may bring their own OAuth app: the same scheme, built around their client.
    oauthClient: client, withClient: githubOauth,
    authorization: {
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
