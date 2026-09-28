import { OAuth2Client } from '../oauth2/client.mjs';
import { SERVICES } from './catalog.mjs';

// Services known by name, each described as data (catalog.mjs) and spoken to by the one OAuth 2.0 client. Foundation
// offers its own app for one when its configuration holds FOUNDATION_<KEY>_CLIENT_ID and _SECRET; anyone may connect
// through an app of their own either way. A service whose addresses depend on the holder's own site (a kintone
// domain, a Shopify shop) can only be reached through the holder's app.
export const configuration = (definition, env) => {
  const prefix = 'FOUNDATION_' + definition.key.toUpperCase() + '_';
  return { clientId: env[prefix + 'CLIENT_ID'] || '', clientSecret: env[prefix + 'CLIENT_SECRET'] || '' };
};
const ownSiteOnly = definition => (definition.appFields ?? []).some(field => field.required);

export function serviceClient(definition, settings = {}, options = {}) {
  if (Boolean(settings.clientId) !== Boolean(settings.clientSecret)) throw new Error(`Both Foundation ${definition.name} client ID and client secret are required`);
  const { name } = definition;
  return new OAuth2Client(ownSiteOnly(definition) ? {} : settings, { ...options, profile: { ...definition.oauth, name,
    unavailable: [503, `現在Foundationの${name}アプリは使えません。自分のOAuthアプリを選んでください。`] } });
}

export function serviceConnector(definition, client) {
  const { key, name, variable = key.toUpperCase() } = definition, revocable = client.revocable;
  const tokenVariable = definition.tokenVariable ?? variable + '_ACCESS_TOKEN', expiresVariable = variable + '_TOKEN_EXPIRES_AT';
  const extra = definition.variables ?? {};
  const source = (secret, path) => path === 'account' ? secret.identity?.id : path.startsWith('kept.') ? secret.kept?.[path.slice(5)] : path.startsWith('app.') ? client.value(path.slice(4)) : undefined;
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret), expiresAt: secret.expires_at,
    credentials: { environment: { [tokenVariable]: secret.access_token,
      ...Object.fromEntries(Object.entries(extra).map(([variableName, path]) => [variableName, source(secret, path)]).filter(([, value]) => typeof value === 'string' && value)),
      ...(secret.expires_at === null ? {} : { [expiresVariable]: String(secret.expires_at) }) } } });
  return {
    id: key + '.oauth', service: { name, icon: 'network', management_url: definition.management || '', api: { base_url: definition.api || '', documentation_url: definition.docs || '' } },
    label: name + 'で接続', register: 'oauth', credentialType: 'oauth2_access_token', available: client.enabled,
    intro: definition.intro ?? `${name}のアカウントでログインし、アクセスを許可します。`,
    access: { name: definition.access ?? name + 'の操作', description: definition.scopes ? `接続のときに許可した権限の範囲で、${name}を操作できます。` : `${name}のOAuthアプリに設定した権限の範囲で、${name}を操作できます。`,
      restrictions: definition.restrictions ?? '許可したアカウントが対象です。' },
    revocationNote: revocable ? `接続を解除すると、${name}側の許可も取り消せます。` : `接続を解除しても、${name}側の許可は残ります。不要なら${name}の画面で取り消してください。`,
    ...(definition.scopes ? { scopes: { base: definition.scopes.base ?? [], documentationUrl: definition.scopes.docs } } : {}),
    ai: [definition.scopes ? `Ask for the scopes the work needs in input.scopes, as ${name} names them.` : `${name} grants what the OAuth app is set up for; input.scopes is not used.`,
      `${tokenVariable} is an access token for ${name}${definition.api ? ' (' + definition.api + ')' : ''}` + (definition.tokenUse ? ', ' + definition.tokenUse : ', sent as "Authorization: Bearer <token>"') + '.',
      ...Object.entries(extra).map(([variableName, path]) => `${variableName} is ${definition.explain?.[variableName] ?? path}.`),
      `${expiresVariable}, when present, is Unix time in milliseconds; Foundation renews the token when it can.`, definition.hint ?? ''].filter(Boolean).join(' '),
    variables: [tokenVariable, ...Object.keys(extra), expiresVariable],
    oauthClient: client, withClient: other => serviceConnector(definition, other),
    ...(definition.appFields ? { appFields: definition.appFields } : {}),
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
    ...(revocable ? { revoke: privateState => client.revoke(privateState) } : {}),
  };
}

export const create = env => SERVICES.map(definition => serviceConnector(definition, serviceClient(definition, configuration(definition, env))));
