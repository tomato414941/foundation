type Statement = { Effect: 'Allow'; Action: string | string[]; Resource: string | string[]; Condition?: Record<string, unknown> };
const allow = (Action: string | string[], Resource: string | string[], Condition?: Record<string, unknown>): Statement =>
  ({ Effect: 'Allow', Action, Resource, ...(Condition ? { Condition } : {}) });
const managed = (values: string[]) => ({ StringEquals: { 'aws:ResourceTag/foundation:managed': values } });
const create = (values: string[]) => ({ StringEquals: { 'aws:RequestTag/foundation:managed': values } });
const reads = ['DescribeVpcs', 'DescribeNetworkAcls', 'DescribeRouteTables', 'DescribeSubnets', 'DescribeSecurityGroups',
  'DescribeImages', 'DescribeInstances', 'DescribeVolumes'];

export function runnerPolicy(region: string, account: string, network: { vpc: string; acl: string; route: string; defaultAcl: string }, ami: string) {
  const arn = (kind: string, id = '*') => `arn:aws:ec2:${region}:${account}:${kind}/${id}`;
  return { Version: '2012-10-17', Statement: [
    allow(reads.map(name => 'ec2:' + name), '*'),
    allow('ec2:RunInstances', `arn:aws:ec2:${region}::image/${ami}`),
    allow('ec2:RunInstances', [arn('instance'), arn('volume'), arn('network-interface')], create(['environment'])),
    allow('ec2:RunInstances', [arn('subnet'), arn('security-group')],
      { StringEquals: { 'aws:ResourceTag/foundation:managed': 'environment', 'ec2:Vpc': arn('vpc', network.vpc) } }),
    allow(['ec2:CreateSubnet', 'ec2:CreateSecurityGroup'], arn('vpc', network.vpc)),
    allow('ec2:CreateSubnet', arn('subnet'), create(['environment'])),
    allow('ec2:CreateSecurityGroup', arn('security-group'), create(['environment'])),
    allow('ec2:CreateTags', [arn('subnet'), arn('security-group'), arn('instance'), arn('volume'), arn('network-interface')],
      { StringEquals: { 'ec2:CreateAction': ['CreateSubnet', 'CreateSecurityGroup', 'RunInstances'] } }),
    allow('ec2:AssociateRouteTable', arn('route-table', network.route)),
    allow('ec2:ReplaceNetworkAclAssociation', [arn('network-acl', network.acl), arn('network-acl', network.defaultAcl)]),
    allow(['ec2:AssociateRouteTable', 'ec2:ReplaceNetworkAclAssociation', 'ec2:DeleteSubnet'], arn('subnet'), managed(['environment'])),
    allow(['ec2:AuthorizeSecurityGroupIngress', 'ec2:DeleteSecurityGroup'], arn('security-group'), managed(['environment'])),
    allow(['ec2:StartInstances', 'ec2:StopInstances', 'ec2:TerminateInstances'], arn('instance'), managed(['environment'])),
    allow('ec2:DeleteVolume', arn('volume'), managed(['environment'])),
  ] };
}

// Provisioning and image publication use a separate operator role, never a guest instance profile.
export function builderPolicy(region: string, account: string, bucket: string, vpc?: string) {
  const arn = (kind: string) => `arn:aws:ec2:${region}:${account}:${kind}/*`;
  return { Version: '2012-10-17', Statement: [
    allow([...reads, 'DescribeInternetGateways', 'DescribeSnapshots', 'GetConsoleOutput'].map(name => 'ec2:' + name), '*'),
    allow(['CreateVpc', 'CreateInternetGateway', 'CreateRouteTable', 'CreateNetworkAcl', 'CreateSubnet', 'CreateSecurityGroup', 'CreateImage']
      .map(name => 'ec2:' + name), '*', create(['environment-network', 'environment', 'environment-image'])),
    allow(['CreateSubnet', 'CreateSecurityGroup', 'CreateRouteTable', 'CreateNetworkAcl', 'ModifyVpcAttribute',
      'AttachInternetGateway', 'CreateRoute', 'CreateNetworkAclEntry', 'AssociateRouteTable', 'ReplaceNetworkAclAssociation']
      .map(name => 'ec2:' + name), '*', managed(['environment-network'])),
    allow(['AssociateRouteTable', 'ReplaceNetworkAclAssociation', 'AuthorizeSecurityGroupIngress', 'StartInstances', 'StopInstances', 'TerminateInstances',
      'DeleteVolume', 'DeleteSubnet', 'DeleteSecurityGroup', 'CreateImage'].map(name => 'ec2:' + name), '*', managed(['environment'])),
    allow(['ec2:DeregisterImage', 'ec2:DeleteSnapshot'], '*', managed(['environment-image'])),
    ...(vpc ? [allow('ec2:ReplaceNetworkAclAssociation', arn('network-acl'),
      { StringEquals: { 'ec2:Vpc': `arn:aws:ec2:${region}:${account}:vpc/${vpc}` } })] : []),
    allow('ec2:RunInstances', `arn:aws:ec2:${region}::image/*`),
    allow('ec2:RunInstances', [arn('instance'), arn('volume'), arn('network-interface')], create(['environment'])),
    allow('ec2:RunInstances', [arn('subnet'), arn('security-group')], managed(['environment'])),
    allow('ec2:CreateTags', '*', { StringEquals: { 'ec2:CreateAction': ['CreateVpc', 'CreateInternetGateway', 'CreateRouteTable',
      'CreateNetworkAcl', 'CreateSubnet', 'CreateSecurityGroup', 'RunInstances', 'CreateImage'] } }),
    allow('ssm:GetParameter', `arn:aws:ssm:${region}::parameter/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id`),
    allow(['s3:PutObject', 's3:GetObject', 's3:DeleteObject'], `arn:aws:s3:::${bucket}/foundation-environment-images/*`),
  ] };
}
