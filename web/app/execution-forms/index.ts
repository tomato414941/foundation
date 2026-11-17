import type { RegisteredForm } from './types';
import { connectionForm } from './connections';
import { variableForm } from './variables';

export const executionForms = new Map<string, RegisteredForm>([
  ['connection.connect', connectionForm], ['connection.authorize', connectionForm], ['app.save', connectionForm],
  ['variable.save', variableForm],
]);
