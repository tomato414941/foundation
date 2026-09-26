import { OpenRouterClient, OPENROUTER_API, OPENROUTER_DOCS } from './client.mjs';

export const create = () => [openrouterOauth(new OpenRouterClient())];

const service = (name, icon, management_url, api) => Object.freeze({ name, icon, management_url, api });
const OPENROUTER = service('OpenRouter', 'network', 'https://openrouter.ai/keys', { base_url: OPENROUTER_API, documentation_url: OPENROUTER_DOCS });

export function openrouterOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret),
    expiresAt: secret.expires_at, credentials: { environment: { OPENROUTER_API_KEY: secret.access_token } } });
  return {
    id: 'openrouter.oauth', service: OPENROUTER, label: 'OpenRouterで接続', provider: 'openrouter', register: 'oauth', available: client.enabled, canReconnect: false, credentialType: 'api_key',
    // OpenRouter makes the key before Foundation receives it, so a registration that fails can leave one behind.
    failureNote: { text: '登録できなくても、OpenRouterで作成済みのキーが残る場合があります。', link: '不要なキーはOpenRouterで削除してください', href: 'https://openrouter.ai/keys' },
    intro: 'OpenRouterでログインし、Foundation用のキーを作成します。',
    access: { name: 'APIキーの利用', description: 'このキーの権限でOpenRouter APIを利用できます。モデルの実行は課金を伴う場合があります。', restrictions: '利用上限と有効期限はOpenRouter側の設定が適用されます。読み取り専用のキーではありません。' },
    ai: 'Inspect facts.key_info, including is_management_key and is_provisioning_key (null means unknown), before use. Broader permissions are reported, not blocked. Model calls can incur charges.',
    variables: ['OPENROUTER_API_KEY'],
    authorization: {
      kind: 'oauth',
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
  };
}
