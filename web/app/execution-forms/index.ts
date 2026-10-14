import type { RegisteredForm } from './types';
import { connectionForm } from './connections';
import { functionForm } from './functions';
import { variableForm } from './variables';
import { runForm } from './runs';

export const executionForms = new Map<string, RegisteredForm>([
  ['connection.connect', connectionForm], ['connection.authorize', connectionForm], ['app.save', connectionForm],
  ['function.save', functionForm], ['function.configure', functionForm], ['variable.save', variableForm],
  ['run.execute', runForm], ['connection.revoke', runForm],
]);
