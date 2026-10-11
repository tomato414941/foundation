import {
  EC2Client, DescribeVpcsCommand, CreateVpcCommand, ModifyVpcAttributeCommand,
  DescribeInternetGatewaysCommand, CreateInternetGatewayCommand, AttachInternetGatewayCommand,
  DescribeRouteTablesCommand, CreateRouteTableCommand, CreateRouteCommand,
  DescribeNetworkAclsCommand, CreateNetworkAclCommand, CreateNetworkAclEntryCommand,
} from '@aws-sdk/client-ec2';
import { privateNetworks } from '../../server/ec2-runner.js';

const Tags = [{ Key: 'foundation:managed', Value: 'environment-network' }, { Key: 'Name', Value: 'foundation-environments' }];
const filter = [{ Name: 'tag:foundation:managed', Values: ['environment-network'] }];

export async function provisionNetwork(client: EC2Client, zone: string) {
  const existing = (await client.send(new DescribeVpcsCommand({ Filters: filter }))).Vpcs ?? [];
  if (existing.length > 1) throw new Error('Resolve duplicate environment VPCs.');
  const vpc = existing[0] ?? (await client.send(new CreateVpcCommand({ CidrBlock: '10.80.0.0/16',
    TagSpecifications: [{ ResourceType: 'vpc', Tags }] }))).Vpc;
  if (!vpc?.VpcId || vpc.CidrBlock !== '10.80.0.0/16') throw new Error('Use the dedicated environment VPC.');
  const VpcId = vpc.VpcId;
  await client.send(new ModifyVpcAttributeCommand({ VpcId, EnableDnsSupport: { Value: true } }));
  await client.send(new ModifyVpcAttributeCommand({ VpcId, EnableDnsHostnames: { Value: true } }));
  const gateways = (await client.send(new DescribeInternetGatewaysCommand({ Filters: filter }))).InternetGateways ?? [];
  if (gateways.length > 1) throw new Error('Resolve duplicate environment internet gateways.');
  const gateway = gateways[0] ?? (await client.send(new CreateInternetGatewayCommand({ TagSpecifications: [{ ResourceType: 'internet-gateway', Tags }] }))).InternetGateway;
  if (!gateway?.InternetGatewayId) throw new Error('The internet gateway could not be identified.');
  if (gateway.Attachments?.some(item => item.VpcId !== VpcId)) throw new Error('Use a dedicated internet gateway.');
  if (!gateway.Attachments?.some(item => item.VpcId === VpcId))
    await client.send(new AttachInternetGatewayCommand({ VpcId, InternetGatewayId: gateway.InternetGatewayId }));
  const routes = (await client.send(new DescribeRouteTablesCommand({ Filters: [...filter, { Name: 'vpc-id', Values: [VpcId] }] }))).RouteTables ?? [];
  if (routes.length > 1) throw new Error('Resolve duplicate environment route tables.');
  const table = routes[0] ?? (await client.send(new CreateRouteTableCommand({ VpcId, TagSpecifications: [{ ResourceType: 'route-table', Tags }] }))).RouteTable;
  if (!table?.RouteTableId) throw new Error('The route table could not be identified.');
  if (!table.Routes?.some(item => item.DestinationCidrBlock === '0.0.0.0/0'))
    await client.send(new CreateRouteCommand({ RouteTableId: table.RouteTableId, DestinationCidrBlock: '0.0.0.0/0', GatewayId: gateway.InternetGatewayId }));
  const acls = (await client.send(new DescribeNetworkAclsCommand({ Filters: [...filter, { Name: 'vpc-id', Values: [VpcId] }] }))).NetworkAcls ?? [];
  if (acls.length > 1) throw new Error('Resolve duplicate environment network ACLs.');
  const acl = acls[0] ?? (await client.send(new CreateNetworkAclCommand({ VpcId, TagSpecifications: [{ ResourceType: 'network-acl', Tags }] }))).NetworkAcl;
  if (!acl?.NetworkAclId || acl.IsDefault) throw new Error('Use a dedicated environment network ACL.');
  for (const Egress of [false, true]) for (const [index, CidrBlock] of [...privateNetworks, '0.0.0.0/0'].entries()) {
    const RuleNumber = index < privateNetworks.length ? 100 + index : 200;
    const RuleAction = index < privateNetworks.length ? 'deny' : 'allow';
    const found = acl.Entries?.find(item => item.Egress === Egress && item.RuleNumber === RuleNumber);
    if (found) {
      if (found.CidrBlock !== CidrBlock || found.RuleAction !== RuleAction || found.Protocol !== '-1')
        throw new Error('Resolve conflicting environment network rules.');
    } else await client.send(new CreateNetworkAclEntryCommand({ NetworkAclId: acl.NetworkAclId,
      RuleNumber, Egress, Protocol: '-1', RuleAction, CidrBlock }));
  }
  const defaultAcl = (await client.send(new DescribeNetworkAclsCommand({ Filters: [
    { Name: 'vpc-id', Values: [VpcId] }, { Name: 'default', Values: ['true'] },
  ] }))).NetworkAcls?.[0]?.NetworkAclId;
  if (!defaultAcl) throw new Error('The default network ACL could not be identified.');
  return { EC2_ENVIRONMENT_VPC: VpcId, EC2_ENVIRONMENT_ACL: acl.NetworkAclId, EC2_ENVIRONMENT_DEFAULT_ACL: defaultAcl,
    EC2_ENVIRONMENT_ROUTE_TABLE: table.RouteTableId, EC2_ENVIRONMENT_ZONE: zone };
}

if (import.meta.url === 'file://' + process.argv[1]) {
  const region = process.env.AWS_REGION ?? 'ap-northeast-1';
  const result = await provisionNetwork(new EC2Client({ region }), process.env.EC2_ENVIRONMENT_ZONE ?? region + 'a');
  for (const [key, value] of Object.entries(result)) process.stdout.write(key + '=' + value + '\n');
}
