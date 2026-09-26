import { GitHubClient, GITHUB_API, GITHUB_DOCS, GITHUB_SETTINGS } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_GITHUB_CLIENT_ID || '', clientSecret: env.FOUNDATION_GITHUB_CLIENT_SECRET || '' });
export const create = env => [githubOauth(new GitHubClient(configuration(env)))];

const service = (name, icon, management_url, api) => Object.freeze({ name, icon, management_url, api });
const GITHUB = service('GitHub', 'code', GITHUB_SETTINGS, { base_url: GITHUB_API, documentation_url: GITHUB_DOCS });

export function githubOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret),
    expiresAt: secret.expires_at, credentials: { environment: { GH_TOKEN: secret.access_token, GITHUB_TOKEN: secret.access_token } } });
  return {
    id: 'github.oauth', service: GITHUB, label: 'GitHubで接続', provider: 'github', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: 'GitHubでログインし、リポジトリへのアクセスを許可します。',
    access: { name: 'リポジトリの読み書き', description: 'あなたがアクセスできるすべてのリポジトリ (非公開を含む) の読み書き、Actions のワークフローの変更、Gist の作成、組織の閲覧', restrictions: 'リポジトリや組織の削除・管理者設定の変更は要求しません。GitHub側の許可は解除時に取り消せます。' },
    ai: 'gh and most tools read it directly. For git push/pull, run gh auth setup-git inside the exec, then use git. Requested scopes: repo, workflow, read:org, gist. Inspect facts.scopes, missing_scopes and additional_scopes; differences are reported, not blocked.',
    variables: ['GH_TOKEN', 'GITHUB_TOKEN'],
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
