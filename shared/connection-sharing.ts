import { z } from 'zod';
import { KeyUpdates } from './protocol.js';

export const ConnectionSharePermission = z.enum(['read', 'reveal', 'update']);
export const ConnectionShare = z.object({
  permission: ConnectionSharePermission.nullable(),
  protection: KeyUpdates.valueType.optional(),
}).strict();
