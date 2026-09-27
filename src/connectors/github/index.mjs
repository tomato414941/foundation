import { GitHubClient, GITHUB_API, GITHUB_DOCS, GITHUB_SETTINGS, GITHUB_BASE_SCOPES, GITHUB_SCOPE_DOCS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_GITHUB_CLIENT_ID || '', clientSecret: env.FOUNDATION_GITHUB_CLIENT_SECRET || '' });
export const create = env => [githubOauth(new GitHubClient(configuration(env)))];

const service = (name, icon, management_url, api) => Object.freeze({ name, icon, management_url, api });
const GITHUB = service('GitHub', 'code', GITHUB_SETTINGS, { base_url: GITHUB_API, documentation_url: GITHUB_DOCS });

export function githubOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret),
    expiresAt: secret.expires_at, credentials: { environment: { GH_TOKEN: secret.access_token, GITHUB_TOKEN: secret.access_token } } });
  return {
    id: 'github.oauth', service: GITHUB, label: 'GitHubで接続', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: 'GitHubでログインし、リポジトリへのアクセスを許可します。',
    access: { name: 'GitHubアカウントの操作', description: '接続のときに許可した権限の範囲で、GitHubのリポジトリや組織を操作できます。', restrictions: 'GitHub側の許可は解除時に取り消せます。' },
    scopes: { base: GITHUB_BASE_SCOPES, documentationUrl: GITHUB_SCOPE_DOCS },
    ai: 'gh and most tools read it directly. For git push/pull, run gh auth setup-git inside the exec, then use git. Ask for the scopes the work needs in input.scopes (GitHub OAuth scopes such as repo, workflow, read:org, gist). facts.scopes, requested_scopes, missing_scopes and additional_scopes say what was granted.',
    variables: ['GH_TOKEN', 'GITHUB_TOKEN'],
    // The holder may bring their own OAuth app: the same connector, built around their client.
    oauthClient: client, withClient: githubOauth,
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
