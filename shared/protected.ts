import { ContentTypes } from './custody.js';
import type { ContentTypeId } from './custody.js';

// The resource kinds whose content is encrypted, and the content type each one seals.
export const ProtectedKinds = ['variable', 'connection', 'app'] as const;
export type ProtectedKindName = (typeof ProtectedKinds)[number];
const contentTypes: Record<ProtectedKindName, ContentTypeId> = {
  variable: ContentTypes.value, connection: ContentTypes.tokenSet, app: ContentTypes.clientCredential,
};
export const isProtected = (kind: string): kind is ProtectedKindName => (ProtectedKinds as readonly string[]).includes(kind);
export const contentTypeOf = (kind: ProtectedKindName) => contentTypes[kind];
export const kindOf = (type: ContentTypeId) =>
  ProtectedKinds.find(kind => contentTypes[kind] === type)!;
