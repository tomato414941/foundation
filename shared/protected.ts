// The resource kinds whose content is sealed: a value, a connection's tokens, and an application's credentials.
export const ProtectedKinds = ['variable', 'connection', 'app'] as const;
export type ProtectedKindName = (typeof ProtectedKinds)[number];
export const isProtected = (kind: string): kind is ProtectedKindName => (ProtectedKinds as readonly string[]).includes(kind);
