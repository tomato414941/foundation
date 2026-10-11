import { z } from 'zod';
import { Id } from './contracts.js';
import { AwsPrincipal } from './runtime-protocol.js';
import { AwsRegion, AwsRoleArn } from './aws.js';

export const AwsRolePermission = z.enum(['ReadOnlyAccess', 'AdministratorAccess']);
export type AwsRolePermissionName = z.infer<typeof AwsRolePermission>;
export const AwsRoleSetup = z.object({
  id: Id, environmentId: Id, principalArn: AwsPrincipal, region: AwsRegion,
  externalId: z.string().min(16).max(128).regex(/^[\w+=,.@:\/-]+$/), permission: AwsRolePermission,
  returnUrl: z.url().refine(value => {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password &&
      url.pathname === '/connections/aws/complete' && !url.search && !url.hash;
  }, 'Return to the Foundation AWS connection screen.'),
}).strict();
export type AwsRoleSetupValues = z.infer<typeof AwsRoleSetup>;
export const AwsRoleReturn = z.object({ id: Id, arn: AwsRoleArn }).strict();

export function awsRoleCreateUrl(templateUrl: string, input: AwsRoleSetupValues) {
  const setup = AwsRoleSetup.parse(input), template = new URL(templateUrl), callback = new URL(setup.returnUrl);
  if (template.protocol !== 'https:' || template.username || template.password) throw new Error('Use an HTTPS template URL.');
  callback.searchParams.set('state', setup.id);
  const partition = setup.principalArn.split(':')[1];
  return 'https://console.aws.amazon.com/cloudformation/home?' + new URLSearchParams({ region: setup.region }) +
    '#/stacks/create/review?' + new URLSearchParams({ templateURL: template.href,
      stackName: 'foundation-' + setup.id.slice(0, 12), param_PrincipalArn: setup.principalArn,
      param_ExternalId: setup.externalId, param_Policies: `arn:${partition}:iam::aws:policy/${setup.permission}`,
      param_ReturnUrl: callback.href,
    });
}

export function awsRoleReturn(url: URL) {
  const fragment = new URLSearchParams(url.hash.slice(1));
  if (url.searchParams.getAll('state').length !== 1 || fragment.getAll('arn').length !== 1)
    throw new Error('Use the return link from the AWS stack.');
  return AwsRoleReturn.parse({ id: url.searchParams.get('state'), arn: fragment.get('arn') });
}
