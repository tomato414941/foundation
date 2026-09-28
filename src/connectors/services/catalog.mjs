import { fail } from '../../errors.mjs';

// Services Foundation knows by name: how each speaks OAuth 2.0 (see oauth2/client.mjs for what "oauth" may say), what
// it is called, and what a connection delivers. A service is added here as data; only a service that cannot be
// described this way needs a connector of its own.
//
// Each entry's addresses and departures from the standard follow the service's own documentation; the service's
// documentation is where to look when one stops working.
const hostPart = (label, pattern) => value => { if (!pattern.test(value)) fail(400, 'invalid_app', `${label}を確認してください。`); };

export const SERVICES = [
  {
    key: 'slack', name: 'Slack', tokenVariable: 'SLACK_BOT_TOKEN', variables: { SLACK_TEAM_ID: 'account' }, explain: { SLACK_TEAM_ID: 'the workspace ID' },
    intro: 'Slackのワークスペースを選び、アプリの追加を許可します。', access: 'Slackワークスペースの操作', restrictions: 'アプリを追加したワークスペースが対象です。',
    api: 'https://slack.com/api', docs: 'https://api.slack.com/methods', management: 'https://api.slack.com/apps',
    scopes: { base: [], docs: 'https://api.slack.com/scopes' }, tokenUse: 'a bot token for the Slack Web API (https://slack.com/api/<method>)',
    oauth: { authorize: 'https://slack.com/oauth/v2/authorize', token: 'https://slack.com/api/oauth.v2.access', scopeSeparator: ',', pkce: false,
      clientAuth: 'body', okField: 'ok', subjectPrefix: 'team:',
      identity: { url: 'https://slack.com/api/auth.test', method: 'POST', id: 'team_id', label: 'team' },
      revoke: { url: 'https://slack.com/api/auth.revoke', style: 'bearer' } },
  },
  {
    key: 'microsoft', name: 'Microsoft 365', variable: 'MICROSOFT', intro: 'Microsoftアカウントでログインし、アクセスを許可します。',
    api: 'https://graph.microsoft.com/v1.0', docs: 'https://learn.microsoft.com/graph/api/overview', management: 'https://myapps.microsoft.com/',
    scopes: { base: ['offline_access', 'User.Read'], docs: 'https://learn.microsoft.com/graph/permissions-reference' },
    hint: 'Scopes are Microsoft Graph permissions such as Mail.Read, Files.ReadWrite or Calendars.ReadWrite.',
    appFields: [{ name: 'tenant', label: 'テナント（任意）', note: '組織のアカウントだけに限るときに、テナントIDを入れます。空なら個人と組織の両方のアカウントで使えます。', check: hostPart('テナント', /^[A-Za-z0-9.-]{1,100}$/) }],
    oauth: { authorize: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize', token: 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token',
      defaults: { tenant: 'common' }, clientAuth: 'body', identity: { url: 'https://graph.microsoft.com/v1.0/me', id: 'id', label: ['mail', 'userPrincipalName', 'displayName'] } },
  },
  {
    key: 'notion', name: 'Notion', intro: 'Notionのワークスペースを選び、共有するページを許可します。', restrictions: '接続のときに共有したページとデータベースが対象です。',
    api: 'https://api.notion.com/v1', docs: 'https://developers.notion.com/reference/intro', management: 'https://www.notion.so/profile/integrations',
    hint: 'Every request also needs a "Notion-Version" header (for example 2022-06-28).',
    variables: { NOTION_WORKSPACE_ID: 'account' }, explain: { NOTION_WORKSPACE_ID: 'the workspace ID' },
    oauth: { authorize: 'https://api.notion.com/v1/oauth/authorize', authorizeParams: { owner: 'user' }, token: 'https://api.notion.com/v1/oauth/token',
      tokenFormat: 'json', subjectPrefix: 'workspace:', identity: { from: 'token', id: 'workspace_id', label: 'workspace_name' } },
  },
  {
    key: 'atlassian', name: 'Atlassian', intro: 'Atlassianアカウントでログインし、JiraやConfluenceへのアクセスを許可します。',
    api: 'https://api.atlassian.com', docs: 'https://developer.atlassian.com/cloud/', management: 'https://id.atlassian.com/manage-profile/apps',
    scopes: { base: ['offline_access', 'read:me'], docs: 'https://developer.atlassian.com/cloud/jira/platform/scopes-for-oauth-2-3LO-and-forge-apps/' },
    hint: 'Find the site (cloud ID) with GET https://api.atlassian.com/oauth/token/accessible-resources, then call https://api.atlassian.com/ex/jira/<cloudid>/... or /ex/confluence/<cloudid>/...',
    oauth: { authorize: 'https://auth.atlassian.com/authorize', authorizeParams: { audience: 'api.atlassian.com', prompt: 'consent' }, token: 'https://auth.atlassian.com/oauth/token',
      clientAuth: 'body', tokenFormat: 'json', identity: { url: 'https://api.atlassian.com/me', id: 'account_id', label: ['email', 'name'] } },
  },
  {
    key: 'dropbox', name: 'Dropbox', api: 'https://api.dropboxapi.com/2', docs: 'https://www.dropbox.com/developers/documentation/http/documentation',
    management: 'https://www.dropbox.com/account/connected_apps', scopes: { base: ['account_info.read'], docs: 'https://developers.dropbox.com/oauth-guide' },
    oauth: { authorize: 'https://www.dropbox.com/oauth2/authorize', authorizeParams: { token_access_type: 'offline' }, token: 'https://api.dropboxapi.com/oauth2/token',
      identity: { url: 'https://api.dropboxapi.com/2/users/get_current_account', method: 'POST', json: null, id: 'account_id', label: ['email', 'name.display_name'] },
      revoke: { url: 'https://api.dropboxapi.com/2/auth/token/revoke', style: 'bearer' } },
  },
  {
    key: 'box', name: 'Box', api: 'https://api.box.com/2.0', docs: 'https://developer.box.com/reference/', management: 'https://app.box.com/account/security',
    scopes: { base: [], docs: 'https://developer.box.com/guides/api-calls/permissions-and-errors/scopes/' },
    oauth: { authorize: 'https://account.box.com/api/oauth2/authorize', token: 'https://api.box.com/oauth2/token', clientAuth: 'body',
      identity: { url: 'https://api.box.com/2.0/users/me', id: 'id', label: ['login', 'name'] }, revoke: { url: 'https://api.box.com/oauth2/revoke', style: 'rfc7009' } },
  },
  {
    key: 'freee', name: 'freee', intro: 'freeeのアカウントでログインし、会計などへのアクセスを許可します。', api: 'https://api.freee.co.jp', docs: 'https://developer.freee.co.jp/reference',
    management: 'https://app.secure.freee.co.jp/developers/applications', scopes: { base: [], docs: 'https://developer.freee.co.jp/startguide/basic/oauth' },
    oauth: { authorize: 'https://accounts.secure.freee.co.jp/public_api/authorize', token: 'https://accounts.secure.freee.co.jp/public_api/token', clientAuth: 'body',
      identity: { url: 'https://api.freee.co.jp/api/1/users/me', id: 'user.id', label: ['user.email', 'user.display_name'] },
      revoke: { url: 'https://accounts.secure.freee.co.jp/public_api/revoke', style: 'rfc7009' } },
  },
  {
    key: 'chatwork', name: 'Chatwork', api: 'https://api.chatwork.com/v2', docs: 'https://developer.chatwork.com/reference', management: 'https://www.chatwork.com/service/packages/chatwork/subpackages/oauth/client_list.php',
    scopes: { base: ['users.profile.me:read', 'offline_access'], docs: 'https://developer.chatwork.com/docs/oauth' },
    oauth: { authorize: 'https://www.chatwork.com/packages/oauth2/login.php', token: 'https://oauth.chatwork.com/token',
      identity: { url: 'https://api.chatwork.com/v2/me', id: 'account_id', label: ['name', 'chatwork_id'] } },
  },
  {
    key: 'kintone', name: 'kintone', intro: '自分のkintoneにログインし、アクセスを許可します。', restrictions: 'OAuthアプリを登録したkintoneのドメインが対象です。',
    docs: 'https://cybozu.dev/ja/kintone/docs/rest-api/', scopes: { base: [], docs: 'https://cybozu.dev/ja/common/docs/oauth-client/' },
    variables: { KINTONE_DOMAIN: 'app.domain' }, explain: { KINTONE_DOMAIN: 'the kintone domain (https://<KINTONE_DOMAIN>/k/v1/...)' },
    appFields: [{ name: 'domain', label: 'kintoneのドメイン', required: true, leading: true, placeholder: 'example.cybozu.com', check: hostPart('kintoneのドメイン', /^[a-z0-9][a-z0-9-]{0,62}\.(cybozu\.com|kintone\.com|cybozu\.cn)$/) }],
    oauth: { authorize: 'https://{domain}/oauth2/authorization', token: 'https://{domain}/oauth2/token', clientAuth: 'body' },
  },
  {
    key: 'gitlab', name: 'GitLab', api: 'https://gitlab.com/api/v4', docs: 'https://docs.gitlab.com/api/rest/', management: 'https://gitlab.com/-/user_settings/applications',
    scopes: { base: ['read_user'], docs: 'https://docs.gitlab.com/integration/oauth_provider/#view-all-authorized-applications' },
    oauth: { authorize: 'https://gitlab.com/oauth/authorize', token: 'https://gitlab.com/oauth/token', clientAuth: 'body',
      identity: { url: 'https://gitlab.com/api/v4/user', id: 'id', label: ['username', 'email'] }, revoke: { url: 'https://gitlab.com/oauth/revoke', style: 'rfc7009' } },
  },
  {
    key: 'bitbucket', name: 'Bitbucket', api: 'https://api.bitbucket.org/2.0', docs: 'https://developer.atlassian.com/cloud/bitbucket/rest/', management: 'https://bitbucket.org/account/settings/app-authorizations/',
    oauth: { authorize: 'https://bitbucket.org/site/oauth2/authorize', token: 'https://bitbucket.org/site/oauth2/access_token',
      identity: { url: 'https://api.bitbucket.org/2.0/user', id: 'uuid', label: ['username', 'display_name'] } },
  },
  {
    key: 'linear', name: 'Linear', api: 'https://api.linear.app/graphql', docs: 'https://linear.app/developers/graphql', management: 'https://linear.app/settings/account/security',
    scopes: { base: ['read'], docs: 'https://linear.app/developers/oauth-2-0-authentication' }, tokenUse: 'sent as "Authorization: Bearer <token>" to the GraphQL endpoint',
    oauth: { authorize: 'https://linear.app/oauth/authorize', token: 'https://api.linear.app/oauth/token', scopeSeparator: ',', clientAuth: 'body',
      identity: { url: 'https://api.linear.app/graphql', method: 'POST', json: { query: '{ viewer { id name email } }' }, id: 'data.viewer.id', label: ['data.viewer.email', 'data.viewer.name'] },
      revoke: { url: 'https://api.linear.app/oauth/revoke', style: 'bearer' } },
  },
  {
    key: 'asana', name: 'Asana', api: 'https://app.asana.com/api/1.0', docs: 'https://developers.asana.com/reference/rest-api-reference', management: 'https://app.asana.com/0/my-apps',
    scopes: { base: [], docs: 'https://developers.asana.com/docs/oauth-scopes' },
    oauth: { authorize: 'https://app.asana.com/-/oauth_authorize', token: 'https://app.asana.com/-/oauth_token', clientAuth: 'body',
      identity: { url: 'https://app.asana.com/api/1.0/users/me', id: 'data.gid', label: ['data.email', 'data.name'] }, revoke: { url: 'https://app.asana.com/-/oauth_revoke', style: 'rfc7009' } },
  },
  {
    key: 'discord', name: 'Discord', api: 'https://discord.com/api/v10', docs: 'https://discord.com/developers/docs/reference', management: 'https://discord.com/developers/applications',
    scopes: { base: ['identify'], docs: 'https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes' },
    oauth: { authorize: 'https://discord.com/oauth2/authorize', token: 'https://discord.com/api/oauth2/token',
      identity: { url: 'https://discord.com/api/users/@me', id: 'id', label: ['username', 'global_name'] }, revoke: { url: 'https://discord.com/api/oauth2/token/revoke', style: 'rfc7009' } },
  },
  {
    key: 'zoom', name: 'Zoom', api: 'https://api.zoom.us/v2', docs: 'https://developers.zoom.us/docs/api/', management: 'https://marketplace.zoom.us/user/installed',
    scopes: { base: [], docs: 'https://developers.zoom.us/docs/integrations/oauth-scopes-overview/' },
    oauth: { authorize: 'https://zoom.us/oauth/authorize', token: 'https://zoom.us/oauth/token',
      identity: { url: 'https://api.zoom.us/v2/users/me', id: 'id', label: 'email', optional: true }, revoke: { url: 'https://zoom.us/oauth/revoke', style: 'rfc7009' } },
  },
  {
    key: 'hubspot', name: 'HubSpot', api: 'https://api.hubapi.com', docs: 'https://developers.hubspot.com/docs/api-reference/overview', management: 'https://app.hubspot.com/',
    scopes: { base: ['oauth'], docs: 'https://developers.hubspot.com/docs/apps/legacy-apps/authentication/scopes' },
    oauth: { authorize: 'https://app.hubspot.com/oauth/authorize', token: 'https://api.hubapi.com/oauth/v1/token', clientAuth: 'body',
      identity: { url: 'https://api.hubapi.com/oauth/v1/access-tokens/{access_token}', id: ['hub_id', 'user_id'], label: ['user', 'hub_domain'] },
      revoke: { url: 'https://api.hubapi.com/oauth/v1/refresh-tokens/{refresh_token}', style: 'delete' } },
  },
  {
    key: 'salesforce', name: 'Salesforce', docs: 'https://developer.salesforce.com/docs/apis', management: 'https://login.salesforce.com/',
    scopes: { base: ['refresh_token', 'id'], docs: 'https://help.salesforce.com/s/articleView?id=xcloud.remoteaccess_oauth_tokens_scopes.htm' },
    variables: { SALESFORCE_INSTANCE_URL: 'kept.instance_url' }, explain: { SALESFORCE_INSTANCE_URL: "the org's API base URL (<SALESFORCE_INSTANCE_URL>/services/data/...)" },
    oauth: { authorize: 'https://login.salesforce.com/services/oauth2/authorize', token: 'https://login.salesforce.com/services/oauth2/token', clientAuth: 'body', keep: ['instance_url', 'id'],
      identity: { url: '{id}', id: ['organization_id', 'user_id'], label: ['username', 'email'] }, revoke: { url: 'https://login.salesforce.com/services/oauth2/revoke', style: 'rfc7009', auth: 'none' } },
  },
  {
    key: 'spotify', name: 'Spotify', api: 'https://api.spotify.com/v1', docs: 'https://developer.spotify.com/documentation/web-api', management: 'https://www.spotify.com/account/apps/',
    scopes: { base: [], docs: 'https://developer.spotify.com/documentation/web-api/concepts/scopes' },
    oauth: { authorize: 'https://accounts.spotify.com/authorize', token: 'https://accounts.spotify.com/api/token',
      identity: { url: 'https://api.spotify.com/v1/me', id: 'id', label: ['email', 'display_name'] } },
  },
  {
    key: 'x', name: 'X', variable: 'X', api: 'https://api.x.com/2', docs: 'https://docs.x.com/x-api/introduction', management: 'https://x.com/settings/connected_apps',
    scopes: { base: ['tweet.read', 'users.read', 'offline.access'], docs: 'https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code' },
    oauth: { authorize: 'https://x.com/i/oauth2/authorize', token: 'https://api.x.com/2/oauth2/token',
      identity: { url: 'https://api.x.com/2/users/me', id: 'data.id', label: 'data.username' }, revoke: { url: 'https://api.x.com/2/oauth2/revoke', style: 'rfc7009' } },
  },
  {
    key: 'shopify', name: 'Shopify', intro: '自分のストアで、アプリのインストールを許可します。', restrictions: 'OAuthアプリを登録したストアが対象です。',
    docs: 'https://shopify.dev/docs/api/admin-graphql', scopes: { base: [], docs: 'https://shopify.dev/docs/api/usage/access-scopes' },
    tokenUse: 'sent in the "X-Shopify-Access-Token" header to https://<SHOPIFY_SHOP>.myshopify.com/admin/api/<version>/graphql.json',
    variables: { SHOPIFY_SHOP: 'app.shop' }, explain: { SHOPIFY_SHOP: 'the store name (<SHOPIFY_SHOP>.myshopify.com)' },
    appFields: [{ name: 'shop', label: 'ストア名', required: true, leading: true, placeholder: 'example（example.myshopify.com の場合）', check: hostPart('ストア名', /^[a-z0-9][a-z0-9-]{0,62}$/) }],
    oauth: { authorize: 'https://{shop}.myshopify.com/admin/oauth/authorize', token: 'https://{shop}.myshopify.com/admin/oauth/access_token', scopeSeparator: ',', pkce: false,
      clientAuth: 'body', subjectPrefix: 'shop:', identity: { from: 'app', id: 'shop' } },
  },
  {
    key: 'zendesk', name: 'Zendesk', restrictions: 'OAuthアプリを登録したZendeskのサブドメインが対象です。',
    docs: 'https://developer.zendesk.com/api-reference/', scopes: { base: ['read'], docs: 'https://developer.zendesk.com/api-reference/ticketing/oauth/oauth_tokens/' },
    variables: { ZENDESK_SUBDOMAIN: 'app.subdomain' }, explain: { ZENDESK_SUBDOMAIN: 'the Zendesk subdomain (https://<ZENDESK_SUBDOMAIN>.zendesk.com/api/v2/...)' },
    appFields: [{ name: 'subdomain', label: 'サブドメイン', required: true, leading: true, placeholder: 'example（example.zendesk.com の場合）', check: hostPart('サブドメイン', /^[a-z0-9][a-z0-9-]{0,62}$/) }],
    oauth: { authorize: 'https://{subdomain}.zendesk.com/oauth/authorizations/new', token: 'https://{subdomain}.zendesk.com/oauth/tokens', clientAuth: 'body',
      identity: { url: 'https://{subdomain}.zendesk.com/api/v2/users/me.json', id: 'user.id', label: ['user.email', 'user.name'] } },
  },
  {
    key: 'airtable', name: 'Airtable', api: 'https://api.airtable.com/v0', docs: 'https://airtable.com/developers/web/api/introduction', management: 'https://airtable.com/create/oauth',
    scopes: { base: ['user.email:read'], docs: 'https://airtable.com/developers/web/api/scopes' },
    oauth: { authorize: 'https://airtable.com/oauth2/v1/authorize', token: 'https://airtable.com/oauth2/v1/token',
      identity: { url: 'https://api.airtable.com/v0/meta/whoami', id: 'id', label: 'email' } },
  },
  {
    key: 'calendly', name: 'Calendly', api: 'https://api.calendly.com', docs: 'https://developer.calendly.com/api-docs', management: 'https://calendly.com/integrations',
    oauth: { authorize: 'https://auth.calendly.com/oauth/authorize', token: 'https://auth.calendly.com/oauth/token', clientAuth: 'body',
      identity: { url: 'https://api.calendly.com/users/me', id: 'resource.uri', label: ['resource.email', 'resource.name'] }, revoke: { url: 'https://auth.calendly.com/oauth/revoke', style: 'rfc7009' } },
  },
  {
    key: 'digitalocean', name: 'DigitalOcean', api: 'https://api.digitalocean.com/v2', docs: 'https://docs.digitalocean.com/reference/api/', management: 'https://cloud.digitalocean.com/account/api/applications',
    scopes: { base: ['read'], docs: 'https://docs.digitalocean.com/reference/api/oauth/' },
    oauth: { authorize: 'https://cloud.digitalocean.com/v1/oauth/authorize', token: 'https://cloud.digitalocean.com/v1/oauth/token', clientAuth: 'body',
      identity: { from: 'token', id: 'info.uuid', label: ['info.email', 'info.name'] } },
  },
  {
    key: 'heroku', name: 'Heroku', api: 'https://api.heroku.com', docs: 'https://devcenter.heroku.com/articles/platform-api-reference', management: 'https://dashboard.heroku.com/account/applications',
    scopes: { base: ['identity'], docs: 'https://devcenter.heroku.com/articles/oauth#scopes' },
    hint: 'Send "Accept: application/vnd.heroku+json; version=3" with every request.',
    oauth: { authorize: 'https://id.heroku.com/oauth/authorize', token: 'https://id.heroku.com/oauth/token', clientAuth: 'body',
      identity: { url: 'https://api.heroku.com/account', headers: { accept: 'application/vnd.heroku+json; version=3' }, id: 'id', label: 'email' } },
  },
  {
    key: 'netlify', name: 'Netlify', api: 'https://api.netlify.com/api/v1', docs: 'https://docs.netlify.com/api/get-started/', management: 'https://app.netlify.com/user/applications',
    oauth: { authorize: 'https://app.netlify.com/authorize', token: 'https://api.netlify.com/oauth/token', clientAuth: 'body',
      identity: { url: 'https://api.netlify.com/api/v1/user', id: 'id', label: ['email', 'full_name'] } },
  },
];
