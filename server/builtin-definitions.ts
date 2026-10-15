import type { Authorization } from './authorization.js';
import type { Principals } from './principals.js';
import type { Relations } from './relations.js';
import type { Resources } from './resources.js';
import type { Catalog } from './catalog.js';
import type { Environments } from './environments.js';
import type { Files } from './files.js';
import type { Billing } from './billing.js';
import type { Processes } from './processes.js';
import type { Integrations } from './integrations.js';
import type { Custody } from './custody.js';
import type { Delegation } from './delegation.js';
import type { Functions } from './functions.js';
import type { Invocations } from './invocations.js';
import { DefinitionRegistry } from './definitions.js';
import { definePrincipals } from './operation-definitions/principals.js';
import { defineResources } from './operation-definitions/resources.js';
import { defineEnvironments } from './operation-definitions/environments.js';
import { defineProcesses } from './operation-definitions/processes.js';
import { defineFiles } from './operation-definitions/files.js';
import { defineBilling } from './operation-definitions/billing.js';
import { defineFunctions } from './operation-definitions/functions.js';
import { defineConnections } from './operation-definitions/connections.js';
import { defineRuns } from './operation-definitions/runs.js';

export interface OperationServices {
  authorization: Authorization; principals: Principals; relations: Relations; resources: Resources;
  catalog: Catalog; environments: Environments; files: Files; billing: Billing;
  processes: Processes; integrations: Integrations; custody: Custody; delegation: Delegation; functions: Functions; invocations: Invocations;
}

export function builtinDefinitions(services: OperationServices) {
  const definitions = new DefinitionRegistry();
  definePrincipals(definitions, services);
  defineResources(definitions, services);
  defineEnvironments(definitions, services);
  defineProcesses(definitions, services);
  defineFiles(definitions, services);
  defineBilling(definitions, services);
  defineFunctions(definitions, services);
  defineConnections(definitions, services);
  defineRuns(definitions, services);
  return definitions;
}
