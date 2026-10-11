import type { CatalogConnectionMethod } from '../../shared/contracts';
import { connectionMethod } from '../../shared/connection-methods';

interface ServicePreparation { instructions: string[]; scopes: boolean; docs?: boolean }
const preparations: Array<{ matches(method: CatalogConnectionMethod): boolean; preparation: ServicePreparation }> = [
  { matches: method => method.id === 'shopify:client_credentials',
    preparation: { instructions: ['shopifyClientCredentialsHelp'], scopes: false } },
  { matches: method => method.id.startsWith('ovh:'),
    preparation: { instructions: ['ovhApiRegionHelp', 'ovhClientCredentialsHelp'], scopes: true, docs: true } },
];
export function servicePreparation(method: CatalogConnectionMethod): ServicePreparation {
  return !connectionMethod(method).browserAuthorization
    ? preparations.find(item => item.matches(method))?.preparation ?? { instructions: [], scopes: true }
    : { instructions: [], scopes: true };
}
