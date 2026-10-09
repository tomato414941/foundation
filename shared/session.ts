import { z } from 'zod';
import { Principal, Id, Name, Locale, PublicKey, WrappedKey } from './contracts.js';

export const Features = z.object({
  email: z.boolean(),
  environments: z.boolean(),
  objects: z.boolean(),
  payments: z.boolean(),
});
export const Session = z.object({
  principal: Principal.nullable(),
  credentialId: Id.nullable(),
  wrappedKey: WrappedKey.nullable(),
  requestId: Id.nullable(),
  server: z.object({ name: Name }),
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
    existingPublicKey: PublicKey.optional(),
    wrappedKey: WrappedKey.optional(),
  })
  .strict();
