import type { MethodDescription } from './contracts.js';

export type ConnectionField = Extract<MethodDescription, { kind: 'token' }>['config']['fields'][number];
export type ConnectionFamily = MethodDescription['kind'];
export interface ConnectionMethodBehavior {
  family: ConnectionFamily;
  application: 'required' | 'implicit' | 'none';
  requiresApp: boolean;
  browserAuthorization: boolean;
  fields: ConnectionField[];
  outputs: string[];
}

// These capabilities are derived from the saved definition, never added to its signed representation.
export function connectionMethod(method: MethodDescription): ConnectionMethodBehavior {
  switch (method.kind) {
    case 'oauth':
      const application = method.config.application;
      return {
        family: 'oauth', application, requiresApp: application === 'required',
        browserAuthorization: method.config.grantType !== 'client_credentials',
        fields: method.config.fields,
        outputs: Object.keys(method.config.outputs),
      };
    case 'token':
      return { family: 'token', application: 'none', requiresApp: false, browserAuthorization: false,
        fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    case 'ovh': {
      const browser = method.config.authorization === 'consumer_key';
      return { family: 'ovh', application: browser ? 'required' : 'none', requiresApp: browser,
        browserAuthorization: browser, fields: method.config.fields, outputs: Object.keys(method.config.outputs) };
    }
    case 'aws':
      return { family: 'aws', application: 'none', requiresApp: false, browserAuthorization: false, fields: [],
        outputs: ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_DEFAULT_REGION', 'AWS_REGION'] };
  }
}

export function selectScopes(definition: { default: string[]; required?: string[] }, selected?: string[]) {
  return [...new Set([...(definition.required ?? []), ...(selected ?? definition.default)])];
}

export function requiresApp(method: MethodDescription) {
  return connectionMethod(method).requiresApp;
}

// These endpoints currently reject browser token exchanges. Other endpoints are tried directly.
const cliTokenHosts = new Set(['airtable.com', 'dash.cloudflare.com', 'api.ebay.com', 'accounts.secure.freee.co.jp',
  'github.com', 'id.heroku.com', 'api.hubapi.com', 'api.netlify.com', 'api.notion.com', 'api.render.com',
  'login.salesforce.com', 'cloud.digitalocean.com', 'api.x.com', 'zoom.us']);
export function browserExchange(method: MethodDescription): 'available' | 'unavailable' | 'unknown' {
  if (!connectionMethod(method).browserAuthorization || method.kind === 'ovh') return 'available';
  if (method.kind !== 'oauth') return 'available';
  try {
    const host = new URL(method.config.tokenUrl).hostname;
    if (cliTokenHosts.has(host) || host === 'login.microsoftonline.com' && method.config.clientAuth !== 'none') return 'unavailable';
    return method.config.tokenUrl.includes('{') ? 'unknown' : 'available';
  } catch { return 'unknown'; }
}
