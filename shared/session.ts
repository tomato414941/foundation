import { z } from 'zod';
import { Principal, Id, Name, Locale, PublicKey, Sealed } from './contracts.js';

export const Features = z.object({
  email: z.boolean(),
  environments: z.boolean(),
  objects: z.boolean(),
  payments: z.boolean(),
});
export const Session = z.object({
  principal: Principal.nullable(),
  credentialId: Id.nullable(),
  requestId: Id.nullable(),
  server: z.object({ id: Id, name: Name, publicKey: PublicKey }),
  features: Features,
  principals: z.array(Principal),
});
export type SessionView = z.infer<typeof Session>;
export const EmailStart = z
  .object({
    email: z.email().max(254),
    returnTo: z.string().max(2048).optional(),
    locale: Locale.default('ja'),
    principalId: Id.optional(),
  })
  .strict();
export const PasskeyStart = z
  .object({
    intent: z.enum(['register', 'authenticate']),
    name: Name.optional(),
    principalId: Id.optional(),
    returnTo: z.string().max(2048).optional(),
  })
  .strict();
export const PasskeyVerify = z
  .object({
    challengeId: Id,
    credential: z.json(),
    publicKey: PublicKey.optional(),
    wrappedKey: z.string().max(16384).optional(),
  })
  .strict();
export const Injection = z.object({ id: Id, context: z.string(), sealed: Sealed });
