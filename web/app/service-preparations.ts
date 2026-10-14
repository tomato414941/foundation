import type { CatalogConnectionMethod } from '../../shared/contracts';
export function servicePreparation(method: CatalogConnectionMethod) {
  const definition = method.preparation;
  return { instructions: definition?.instructions ?? [], docs: definition?.docs ?? false,
    scopes: definition?.scopeSelection !== 'hidden', scopesRequired: definition?.scopeSelection === 'required' };
}
