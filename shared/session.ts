import { z } from 'zod';
import { Principal, Id, Name, Locale, PublicKey, Time, WrappedKey } from './contracts.js';

// A request to make new keys after every copy of the private key was lost, and when it can be completed.
export const KeyReset = z.object({ requestedAt: Time, readyAt: Time }).strict();
export const Features = z.object({
  email: z.boolean(),
  environments: z.boolean(),
  ssh: z.boolean(),
  storage: z.boolean(),
  payments: z.boolean(),
});
export const Session = z.object({
  principal: Principal.nullable(),
  credentialId: Id.nullable(),
  wrappedKey: WrappedKey.nullable(),
  requestId: Id.nullable(),
  keyReset: KeyReset.nullable(),
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
    credentialId: Id.optional(),
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
// The new keys, and the private key wrapped for the passkey this session signed in with.
export const KeyResetCompletion = z.object({ publicKey: PublicKey, wrappedKey: WrappedKey }).strict();
