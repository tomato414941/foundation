import type { ResourceKindName, ResourceView } from '../../shared/contracts';
export const sections = {
  services: 'connection',
  variables: 'variable',
  storage: 'object',
  environments: 'environment',
  functions: 'function',
  definitions: 'service',
  methods: 'method',
  apps: 'app',
} as const;
export type Section = keyof typeof sections;
export const sectionFor = (kind: ResourceKindName) =>
  Object.entries(sections).find(([, value]) => value === kind)![0] as Section;
export const resourcePath = (resource: Pick<ResourceView, 'ownerId' | 'kind' | 'id'>) =>
  `/p/${resource.ownerId}/${sectionFor(resource.kind)}/${resource.id}`;
export function resourceKind(section: string | undefined) {
  const result = sections[section as Section];
  if (!result) throw new Response('Not found', { status: 404 });
  return result;
}
