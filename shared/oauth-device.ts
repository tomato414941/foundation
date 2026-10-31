import { z } from 'zod';

export const DeviceAuthorization = z.object({
  deviceCode: z.string().min(1).max(16384),
  userCode: z.string().min(1).max(1000),
  verificationUri: z.url(), verificationUriComplete: z.url().optional(),
  expiresAt: z.number().int().positive(),
  intervalSeconds: z.number().int().positive(), nextPollAt: z.number().int().positive(),
}).strict();
export type DeviceAuthorizationState = z.infer<typeof DeviceAuthorization>;
