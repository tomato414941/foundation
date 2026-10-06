import { z } from 'zod';
import { Id, JweSealed, KeySharingItem, P256Key, PublicKey, WrappedKey } from './contracts.js';

export const KeyMigrationStart = z.object({ publicKey: P256Key }).strict();
export const KeyMigrationPlan = z.object({
  challengeId: Id,
  publicKey: PublicKey,
  credentials: z.array(z.object({
    id: Id,
    name: z.string(),
    wrappedKey: z.string(),
    options: z.json(),
  })),
  items: z.array(KeySharingItem),
});
export const KeyMigrationCommit = z.object({
  challengeId: Id,
  credentials: z.array(z.object({
    id: Id,
    credential: z.json(),
    wrappedKey: WrappedKey,
  }).strict()).min(1).max(100),
  items: z.array(z.object({
    id: Id,
    version: z.number().int().positive(),
    sealed: JweSealed,
  }).strict()).max(1000),
}).strict();
export type KeyMigrationInput = z.infer<typeof KeyMigrationCommit>;
