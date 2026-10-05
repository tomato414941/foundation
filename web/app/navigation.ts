import type { ResourceKindName, ResourceView } from '../../shared/contracts';
export const sections = {
  services: 'connection',
  secrets: 'secret',
  objects: 'object',
  environments: 'environment',
  functions: 'function',
  definitions: 'service',
  apps: 'app',
} as const;
export type Section = keyof typeof sections;
export const sectionFor = (kind: ResourceKindName) =>
  Object.entries(sections).find(([, value]) => value === kind)![0] as Section;
export const resourcePath = (resource: ResourceView) =>
  `/p/${resource.ownerId}/${sectionFor(resource.kind)}/${resource.id}`;
export function resourceKind(section: string | undefined) {
  const result = sections[section as Section];
  if (!result) throw new Response('Not found', { status: 404 });
  return result;
}
