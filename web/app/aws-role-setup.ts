import { AwsRoleSetup, awsRoleReturn } from '../../shared/aws-setup';
import type { AwsRoleSetupValues } from '../../shared/aws-setup';
import { AwsRoleArn } from '../../shared/aws';
import { z } from 'zod';

const Record = AwsRoleSetup.extend({ expiresAt: z.number().int().positive(), arn: AwsRoleArn.optional() }).strict();
type SetupStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
export const awsRoleSetupKey = (id: string) => 'foundation.aws-role-setup.' + id;

// Only public setup values cross tabs. Credentials and approvals remain in the connection flow.
export function rememberAwsRoleSetup(input: AwsRoleSetupValues, storage: SetupStorage = localStorage, now = Date.now()) {
  const setup = AwsRoleSetup.parse(input);
  storage.setItem(awsRoleSetupKey(setup.id), JSON.stringify({ ...setup, expiresAt: now + 3_600_000 }));
}
function read(id: string, storage: SetupStorage, now: number) {
  const raw = storage.getItem(awsRoleSetupKey(id));
  if (!raw) return null;
  const result = Record.safeParse(JSON.parse(raw));
  if (!result.success || result.data.id !== id || result.data.expiresAt <= now) return null;
  return result.data;
}
export function completeAwsRoleSetup(url: URL, storage: SetupStorage = localStorage, now = Date.now()) {
  try {
    const returned = awsRoleReturn(url), record = read(returned.id, storage, now);
    if (!record || new URL(record.returnUrl).origin !== url.origin || new URL(record.returnUrl).pathname !== url.pathname ||
      record.principalArn.split(':')[1] !== returned.arn.split(':')[1] || (record.arn && record.arn !== returned.arn)) return null;
    storage.setItem(awsRoleSetupKey(record.id), JSON.stringify({ ...record, arn: returned.arn }));
    return returned;
  } catch { return null; }
}
export function consumeAwsRoleSetup(input: AwsRoleSetupValues, storage: SetupStorage = localStorage, now = Date.now()) {
  try {
    const record = read(input.id, storage, now);
    if (!record?.arn || Object.entries(input).some(([key, value]) => record[key as keyof AwsRoleSetupValues] !== value)) return null;
    storage.removeItem(awsRoleSetupKey(input.id));
    return record.arn;
  } catch { return null; }
}
