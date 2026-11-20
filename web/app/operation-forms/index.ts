import type { RegisteredForm } from './types';
import { connectionForm } from './connections';
import { variableForm } from './variables';

export const operationForms = new Map<string, RegisteredForm>([
  ['connection.connect', connectionForm], ['app.save', connectionForm],
  ['variable.save', variableForm],
]);
