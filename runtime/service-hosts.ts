import { Template } from '@fedify/uri-template';
import type { MethodDescription } from '../shared/contracts.js';
import { fail } from '../server/errors.js';

// Where each built-in connection method sends what it holds, as this CLI was built: the hosts of its token, device
// authorization, registration and API endpoints. A host in braces is filled from the connection's own sealed fields.
// Foundation may change a method's paths and settings, but not send its tokens elsewhere: a host missing here stops
// the CLI until it is updated.
export const knownHosts: Record<string, string[]> = {
  'airtable:oauth': ['airtable.com'],
  'asana:oauth': ['app.asana.com'],
  'atlassian:oauth': ['auth.atlassian.com'],
  'bitbucket:oauth': ['bitbucket.org'],
  'box:oauth': ['api.box.com'],
  'calendly:oauth': ['auth.calendly.com'],
  'chatwork:oauth': ['oauth.chatwork.com'],
  'cloudflare:oauth': ['dash.cloudflare.com'],
  'digitalocean:oauth': ['cloud.digitalocean.com'],
  'discord:oauth': ['discord.com'],
  'dropbox:oauth': ['api.dropboxapi.com'],
  'ebay:oauth': ['api.ebay.com'],
  'freee:oauth': ['accounts.secure.freee.co.jp'],
  'github:device': ['github.com'],
  'github:oauth': ['github.com'],
  'gitlab:oauth': ['gitlab.com'],
  'google:oauth': ['oauth2.googleapis.com'],
  'heroku:oauth': ['id.heroku.com'],
  'hubspot:oauth': ['api.hubapi.com'],
  'kintone:oauth': ['{domain}'],
  'linear:oauth': ['api.linear.app'],
  'microsoft:oauth': ['login.microsoftonline.com'],
  'netlify:oauth': ['api.netlify.com'],
  'notion:oauth': ['api.notion.com'],
  'openrouter:oauth': ['openrouter.ai'],
  'ovh:api_key': ['api.us.ovhcloud.com', 'ca.api.ovh.com', 'eu.api.ovh.com'],
  'ovh:client_credentials': ['api.us.ovhcloud.com', 'ca.api.ovh.com', 'ca.ovh.com', 'eu.api.ovh.com', 'us.ovhcloud.com', 'www.ovh.com'],
  'ovh:consumer_key': ['api.us.ovhcloud.com', 'ca.api.ovh.com', 'eu.api.ovh.com'],
  'ovh:pat': ['api.us.ovhcloud.com', 'ca.api.ovh.com', 'eu.api.ovh.com'],
  'render:oauth': ['api.render.com'],
  'runpod:mcp-oauth': ['mcp.getrunpod.io'],
  'salesforce:oauth': ['login.salesforce.com'],
  'shopify:client_credentials': ['{shop}.myshopify.com'],
  'shopify:oauth': ['{shop}.myshopify.com'],
  'slack:oauth': ['slack.com'],
  'spotify:oauth': ['accounts.spotify.com'],
  'vultr:oauth': ['api.vultr.com'],
  'x:oauth': ['api.x.com'],
  'zendesk:oauth': ['{subdomain}.zendesk.com'],
  'zoom:oauth': ['zoom.us'],
};
const endpointKeys = new Set(['tokenUrl', 'deviceAuthorizationUrl', 'registrationUrl', 'issuer', 'apiBaseUrl']);
// The endpoint URL templates a method's settings name, wherever they are, as in the values a setting's choice gives.
export function endpointTemplates(config: unknown, key?: string): string[] {
  if (Array.isArray(config)) return config.flatMap(value => endpointTemplates(value, key));
  if (config && typeof config === 'object') return Object.entries(config).flatMap(([name, value]) => endpointTemplates(value, name));
  return typeof config === 'string' && key && endpointKeys.has(key) ? [config] : [];
}
const hostOf = (template: string, values: Record<string, string>) => {
  try { return new URL(new Template(template).expand(values)).host; } catch { return null; }
};
// Refuses to use a built-in method that Foundation describes with an endpoint host this CLI does not know for it.
// Hosts are compared once filled: those this CLI knows only from the connection's sealed fields, those Foundation
// names as the connection's code would fill them.
export function requireKnownHosts(methodId: string, method: MethodDescription, sealed: Record<string, string>) {
  const known = knownHosts[methodId];
  if (!known) return;
  const allowed = new Set(known.map(host => hostOf('https://' + host + '/', sealed)).filter(host => host));
  const config = method.config as { fields?: Array<{ name: string; choices?: Array<{ value: string; values?: Record<string, string> }> }>;
    defaults?: Record<string, string> };
  const chosen = Object.assign({}, ...(config.fields ?? []).map(field =>
    field.choices?.find(choice => choice.value === sealed[field.name])?.values ?? {})) as Record<string, string>;
  const values = { ...(config.defaults ?? {}), ...chosen, ...sealed };
  for (const template of endpointTemplates(method.config)) {
    const host = hostOf(template, values);
    if (!host || !allowed.has(host))
      fail(409, 'unknown_service_host', 'Foundation describes ' + methodId + ' with ' + (host ?? 'an endpoint') +
        ', which this CLI does not know for it. Install the CLI Foundation was released with.');
  }
}
