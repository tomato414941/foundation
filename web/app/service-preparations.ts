import type { CatalogConnectionMethod } from '../../shared/contracts';
import { connectionMethod } from '../../shared/connection-methods';

interface ServicePreparation { instructions: string[]; scopes: boolean; docs?: boolean }
const preparations: Array<{ authorization: 'application' | 'browser'; matches(method: CatalogConnectionMethod): boolean; preparation: ServicePreparation }> = [
  { authorization: 'browser', matches: method => method.id === 'runpod:mcp-oauth',
    preparation: { instructions: [], scopes: false } },
  { authorization: 'application', matches: method => method.id === 'shopify:client_credentials',
    preparation: { instructions: ['shopifyClientCredentialsHelp'], scopes: false } },
  { authorization: 'application', matches: method => method.id.startsWith('ovh:'),
    preparation: { instructions: ['ovhApiRegionHelp', 'ovhClientCredentialsHelp'], scopes: true, docs: true } },
  { authorization: 'browser', matches: method => method.id === 'vultr:oauth',
    preparation: { instructions: ['vultrOAuthHelp'], scopes: false, docs: true } },
];
export function servicePreparation(method: CatalogConnectionMethod): ServicePreparation {
  const authorization = connectionMethod(method).browserAuthorization ? 'browser' : 'application';
  return preparations.find(item => item.authorization === authorization && item.matches(method))?.preparation
    ?? { instructions: [], scopes: true };
}
