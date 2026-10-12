import { z } from 'zod';

export const OvhAccessRule = z.object({
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']),
  path: z.string().min(1).max(1000).regex(/^\/[^\s\u0000]*$/),
}).strict();
export const OvhConnectionInfo = z.object({
  account: z.string().min(1), identities: z.array(z.string()),
  user: z.string().nullable(), description: z.string().nullable(),
  roles: z.array(z.string()).nullable(),
  credentialId: z.number().int().positive(),
  rules: z.array(OvhAccessRule), allowedIPs: z.array(z.string()).nullable(),
  expiresAt: z.number().nullable(),
}).strict();
export type OvhInfo = z.infer<typeof OvhConnectionInfo>;

export function ovhAccessRules(scopes: string[]) {
  return scopes.map(scope => {
    const match = scope.match(/^(GET|POST|PUT|DELETE|PATCH) (\/[^\s\u0000]*)$/);
    if (!match) throw new Error('Use one HTTP method and API path for each OVH permission.');
    return OvhAccessRule.parse({ method: match[1], path: match[2] });
  });
}
