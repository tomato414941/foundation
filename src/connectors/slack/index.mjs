import { SlackClient, SLACK_API, SLACK_DOCS, SLACK_SCOPE_DOCS, SLACK_SETTINGS, SLACK_BASE_SCOPES } from './client.mjs';

export const configuration = env => ({ clientId: env.FOUNDATION_SLACK_CLIENT_ID || '', clientSecret: env.FOUNDATION_SLACK_CLIENT_SECRET || '' });
export const create = env => [slackOauth(new SlackClient(configuration(env)))];

const service = Object.freeze({ name: 'Slack', icon: 'network', management_url: SLACK_SETTINGS, api: { base_url: SLACK_API, documentation_url: SLACK_DOCS } });

export function slackOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { SLACK_BOT_TOKEN: secret.access_token, SLACK_TEAM_ID: secret.identity.team_id,
      ...(secret.expires_at === null ? {} : { SLACK_TOKEN_EXPIRES_AT: String(secret.expires_at) }) } } });
  return {
    id: 'slack.oauth', service, label: 'Slackで接続', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: 'Slackのワークスペースを選び、アプリの追加を許可します。',
    access: { name: 'Slackワークスペースの操作', description: '接続のときに許可したBotの権限の範囲で、ワークスペースを操作できます。', restrictions: 'アプリを追加したワークスペースが対象です。' },
    revocationNote: 'Slack側で取り消すと、このワークスペースからアプリのBotトークンが使えなくなります。',
    scopes: { base: SLACK_BASE_SCOPES, documentationUrl: SLACK_SCOPE_DOCS },
    ai: 'Ask for the bot scopes the work needs in input.scopes (Slack scope names such as channels:read, chat:write). SLACK_BOT_TOKEN is a Bearer token for the Slack Web API (https://slack.com/api/<method>) in the workspace SLACK_TEAM_ID; facts.label is the workspace name. A rotating token (facts.rotating) is renewed by Foundation; SLACK_TOKEN_EXPIRES_AT is Unix time in milliseconds.',
    variables: ['SLACK_BOT_TOKEN', 'SLACK_TEAM_ID', 'SLACK_TOKEN_EXPIRES_AT'],
    // The holder may bring their own Slack app: the same connector, built around their client.
    oauthClient: client, withClient: slackOauth,
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    revoke: privateState => client.revoke(privateState),
  };
}
