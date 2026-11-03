import { z } from 'zod';
import type { JWK } from 'jose';
import { Id, Json, Sealed, Time } from './contracts.js';
import { Signature, sign } from './authority.js';

// A change that takes more than the token sending it: the server names it, the confirmation is made for exactly it,
// and the change is sent again with the confirmation in the Foundation-Confirmation header.
export const ConfirmationOperation = z.object({
  action: z.string().regex(/^[a-z][a-zA-Z]*(\.[a-z][a-zA-Z]*)+$/).max(64),
  principalId: Id,
}).catchall(Json);
export type ConfirmationOperation = z.infer<typeof ConfirmationOperation>;
// Signing with the identity's keys, a code sent to one of its email addresses, or one of its passkeys; an identity that
// has an encryption key but no signing key yet opens a secret sealed for that key instead of signing.
export const ConfirmationMethod = z.enum(['signature', 'decryption', 'email', 'passkey']);
export type ConfirmationMethod = z.infer<typeof ConfirmationMethod>;
// What the identity's signing key signs to confirm the change.
export const ConfirmationChallenge = z.object({
  confirmationId: Id, principalId: Id, credentialId: Id, bindingId: Id.nullable(), operation: z.string(), nonce: z.string(),
}).strict();
export const ConfirmationView = z.object({
  id: Id,
  operation: ConfirmationOperation,
  methods: z.array(ConfirmationMethod),
  state: z.enum(['pending', 'confirmed', 'held']),
  expiresAt: Time,
  challenge: ConfirmationChallenge,
  // The secret sealed for the identity's encryption key, when it confirms by opening it.
  sealed: Sealed.nullable(),
}).strict();
export type ConfirmationView = z.infer<typeof ConfirmationView>;
export const ConfirmationProof = z.discriminatedUnion('method', [
  z.object({ method: z.literal('signature'), signature: Signature }).strict(),
  z.object({ method: z.literal('decryption'), secret: z.string().min(1).max(200) }).strict(),
  z.object({ method: z.literal('email'), code: z.string().min(1).max(32) }).strict(),
  z.object({ method: z.literal('passkey'), credential: z.json() }).strict(),
]);
export type ConfirmationProof = z.infer<typeof ConfirmationProof>;
// The details of a confirmation_required or confirmation_invalid error.
export const ConfirmationNeeded = z.object({ operation: ConfirmationOperation, methods: z.array(ConfirmationMethod) });
export type ConfirmationNeeded = z.infer<typeof ConfirmationNeeded>;
export const confirmationHeader = 'foundation-confirmation';
export const confirmationCodes = ['confirmation_required', 'confirmation_invalid'];

export const signConfirmation = (view: ConfirmationView, key: JWK | CryptoKey) =>
  sign(view.challenge, key, 'operation-confirmation');
export const decryptionContext = (id: string) => 'operation-confirmation:' + id;

// Confirms a change through the API with the first method the prover can use, and returns the confirmation's ID.
export async function confirmOperation(
  api: { json<T>(path: string, options?: { method?: string; body?: unknown }, schema?: z.ZodType<T>): Promise<T> },
  needed: ConfirmationNeeded,
  prove: (view: ConfirmationView, api: Parameters<typeof confirmOperation>[0]) => Promise<ConfirmationProof>,
) {
  const view = await api.json('/api/confirmations', { method: 'POST', body: { operation: needed.operation } }, ConfirmationView);
  await api.json('/api/confirmations/' + view.id + '/proof', { method: 'POST', body: await prove(view, api) }, ConfirmationView);
  return view.id;
}
