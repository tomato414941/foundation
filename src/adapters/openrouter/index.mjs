import { OpenRouterClient } from './client.mjs';

export const create = () => openrouterOauth(new OpenRouterClient());

// OpenRouter makes a key for Foundation at its consent screen; no app is registered, and a key cannot be made
// again in its place: reconnecting is registering anew.
export function openrouterOauth(client) {
  const result = ({ subject, secret }) => ({ subject, privateState: secret, facts: client.facts(secret),
    expiresAt: secret.expires_at, credentials: { environment: { OPENROUTER_API_KEY: secret.access_token } } });
  return {
    kind: 'oauth', available: client.enabled, canReconnect: false, variables: ['OPENROUTER_API_KEY'],
    authorization: {
      begin: context => client.authorize(context),
      complete: async (context, previous) => result(await client.exchange(context, previous && { subject: previous.subject, secret: previous.privateState })),
    },
    obtain: async ({ subject, privateState }) => result({ subject, secret: await client.token(privateState, { subject }) }),
  };
}
