import {
  EC2Client, DescribeVpcsCommand, DescribeNetworkAclsCommand, DescribeRouteTablesCommand,
  DescribeSubnetsCommand, CreateSubnetCommand, AssociateRouteTableCommand, ReplaceNetworkAclAssociationCommand,
  DescribeSecurityGroupsCommand, CreateSecurityGroupCommand, AuthorizeSecurityGroupIngressCommand,
  DescribeImagesCommand, DescribeInstancesCommand, RunInstancesCommand, StartInstancesCommand, StopInstancesCommand,
  TerminateInstancesCommand, DescribeVolumesCommand, DeleteVolumeCommand, DeleteSubnetCommand, DeleteSecurityGroupCommand,
} from '@aws-sdk/client-ec2';
import type { Instance, Tag, Filter } from '@aws-sdk/client-ec2';
import type { EnvironmentOptions } from '../shared/contracts.js';
import type { Configuration } from './config.js';
import type { Runner } from './runner.js';
import { DomainError, fail } from './errors.js';

const managed = 'foundation:managed', environmentTag = 'foundation:environment';
const sizes = { small: 't3.micro', medium: 't3.small', large: 'c7i.xlarge' } as const;
export const privateNetworks = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'];
const pause = (milliseconds: number) => new Promise<void>(resolve => setTimeout(resolve, milliseconds));
function tags(id: string): Tag[] {
  return [{ Key: managed, Value: 'environment' }, { Key: environmentTag, Value: id }, { Key: 'Name', Value: 'foundation-' + id }];
}
function filters(id: string): Filter[] {
  return [{ Name: 'tag:' + managed, Values: ['environment'] }, { Name: 'tag:' + environmentTag, Values: [id] }];
}
function owned(value: { Tags?: Tag[] }) {
  return value.Tags?.some(tag => tag.Key === managed && tag.Value === 'environment') &&
    value.Tags.some(tag => tag.Key === environmentTag && tag.Value);
}
function providerError(error: unknown, name: string) { return error instanceof Error && error.name === name; }
function single<T>(rows: T[], kind: string): T | null {
  if (rows.length > 1) fail(409, 'runner_ambiguous', 'Resolve duplicate environment ' + kind + ' before continuing.');
  return rows[0] ?? null;
}

// Each environment occupies one subnet; AWS enforces its ACL outside the guest.
export class EC2Runner implements Runner {
  readonly enabled: boolean;
  constructor(readonly config: Configuration,
    readonly client = new EC2Client({ region: config.AWS_REGION,
      requestHandler: { connectionTimeout: 5_000, requestTimeout: 30_000 }, maxAttempts: 3 }),
    readonly sleep = pause) {
    this.enabled = Boolean(config.EC2_ENVIRONMENT_AMI && config.EC2_ENVIRONMENT_VPC &&
      config.EC2_ENVIRONMENT_ACL && config.EC2_ENVIRONMENT_ROUTE_TABLE && config.EC2_ENVIRONMENT_ZONE);
  }
  private async call<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.enabled) fail(503, 'environments_unavailable', 'Environments are not configured.');
    try { return await operation(); }
    catch (error) {
      if (error instanceof DomainError) throw error;
      fail(502, 'runner_unavailable', 'The environment provider could not complete the operation.');
    }
  }
  private async wait<T>(read: () => Promise<T>, ready: (value: T) => boolean): Promise<T> {
    for (let attempt = 0; attempt < 120; attempt++) {
      const value = await read();
      if (ready(value)) return value;
      await this.sleep(5_000);
    }
    fail(502, 'runner_unavailable', 'The environment provider has not finished the operation.');
  }
  private async network() {
    const vpc = (await this.client.send(new DescribeVpcsCommand({ VpcIds: [this.config.EC2_ENVIRONMENT_VPC] }))).Vpcs?.[0];
    if (vpc?.CidrBlock !== '10.80.0.0/16' || vpc.State !== 'available' ||
      !vpc.Tags?.some(tag => tag.Key === managed && tag.Value === 'environment-network'))
      fail(503, 'network_unavailable', 'The isolated environment network is not configured.');
    const acl = (await this.client.send(new DescribeNetworkAclsCommand({ NetworkAclIds: [this.config.EC2_ENVIRONMENT_ACL] }))).NetworkAcls?.[0];
    if (!acl || acl.VpcId !== vpc.VpcId || acl.IsDefault) fail(503, 'network_unavailable', 'The isolated environment network is not configured.');
    for (const egress of [false, true]) {
      const rules = acl.Entries?.filter(rule => rule.Egress === egress) ?? [];
      // Reject earlier allows that could bypass a deny, including IPv6 rules.
      if (rules.length !== privateNetworks.length + 2 || !privateNetworks.every((cidr, index) =>
        rules.some(rule => rule.RuleNumber === 100 + index && rule.RuleAction === 'deny' && rule.Protocol === '-1' && rule.CidrBlock === cidr)) ||
        !rules.some(rule => rule.RuleNumber === 200 && rule.RuleAction === 'allow' && rule.Protocol === '-1' && rule.CidrBlock === '0.0.0.0/0') ||
        !rules.some(rule => rule.RuleNumber === 32767 && rule.RuleAction === 'deny'))
        fail(503, 'network_unavailable', 'The environment network does not enforce isolation.');
    }
    const route = (await this.client.send(new DescribeRouteTablesCommand({ RouteTableIds: [this.config.EC2_ENVIRONMENT_ROUTE_TABLE] }))).RouteTables?.[0];
    if (!route || route.VpcId !== vpc.VpcId || route.Routes?.length !== 2 ||
      !route.Routes.some(item => item.DestinationCidrBlock === '0.0.0.0/0' && item.GatewayId?.startsWith('igw-') && item.State === 'active') ||
      !route.Routes.some(item => item.DestinationCidrBlock === vpc.CidrBlock && item.GatewayId === 'local'))
      fail(503, 'network_unavailable', 'The environment internet route is not configured.');
  }
  private async subnet(id: string, slot: number) {
    if (!Number.isInteger(slot) || slot < 0 || slot > 4091) throw new Error('Use a reserved environment network slot.');
    const CidrBlock = `10.80.${slot >> 4}.${(slot & 15) * 16}/28`;
    const read = async () => single((await this.client.send(new DescribeSubnetsCommand({
      Filters: [...filters(id), { Name: 'vpc-id', Values: [this.config.EC2_ENVIRONMENT_VPC] }],
    }))).Subnets ?? [], 'subnets');
    let subnet = await read();
    if (!subnet) {
      try { subnet = (await this.client.send(new CreateSubnetCommand({ VpcId: this.config.EC2_ENVIRONMENT_VPC,
        AvailabilityZone: this.config.EC2_ENVIRONMENT_ZONE, CidrBlock,
        TagSpecifications: [{ ResourceType: 'subnet', Tags: tags(id) }] }))).Subnet ?? null; }
      catch (error) {
        // A lost response or a competing lease must recover the same subnet, never allocate another CIDR.
        for (let attempt = 0; attempt < 6; attempt++) {
          subnet = await read();
          if (subnet) break;
          await this.sleep(5_000);
        }
        if (!subnet) throw error;
      }
    }
    if (!subnet?.SubnetId || subnet.CidrBlock !== CidrBlock)
      fail(502, 'runner_response', 'The reserved environment subnet could not be identified.');
    return subnet;
  }
  private async connectSubnet(subnetId: string) {
    const tables = await this.client.send(new DescribeRouteTablesCommand({ Filters: [{ Name: 'association.subnet-id', Values: [subnetId] }] }));
    if (!tables.RouteTables?.some(table => table.RouteTableId === this.config.EC2_ENVIRONMENT_ROUTE_TABLE))
      await this.client.send(new AssociateRouteTableCommand({ SubnetId: subnetId, RouteTableId: this.config.EC2_ENVIRONMENT_ROUTE_TABLE }));
    const acls = await this.client.send(new DescribeNetworkAclsCommand({ Filters: [{ Name: 'association.subnet-id', Values: [subnetId] }] }));
    const current = acls.NetworkAcls?.[0], association = current?.Associations?.find(item => item.SubnetId === subnetId);
    if (!association?.NetworkAclAssociationId) fail(502, 'runner_response', 'The environment network could not be identified.');
    if (current?.NetworkAclId !== this.config.EC2_ENVIRONMENT_ACL)
      await this.client.send(new ReplaceNetworkAclAssociationCommand({ AssociationId: association.NetworkAclAssociationId,
        NetworkAclId: this.config.EC2_ENVIRONMENT_ACL }));
    const verified = (await this.client.send(new DescribeNetworkAclsCommand({ Filters: [{ Name: 'association.subnet-id', Values: [subnetId] }] }))).NetworkAcls?.[0];
    if (verified?.NetworkAclId !== this.config.EC2_ENVIRONMENT_ACL)
      fail(503, 'network_unavailable', 'The environment network does not enforce isolation.');
  }
  private async group(id: string) {
    let group = single((await this.client.send(new DescribeSecurityGroupsCommand({ Filters: filters(id) }))).SecurityGroups ?? [], 'security groups');
    if (!group) {
      try {
        const result = await this.client.send(new CreateSecurityGroupCommand({ VpcId: this.config.EC2_ENVIRONMENT_VPC,
          GroupName: 'foundation-' + id, Description: 'SSH for one Foundation environment',
          TagSpecifications: [{ ResourceType: 'security-group', Tags: tags(id) }] }));
        group = (await this.client.send(new DescribeSecurityGroupsCommand({ GroupIds: [result.GroupId!] }))).SecurityGroups?.[0] ?? null;
      } catch (error) {
        group = single((await this.client.send(new DescribeSecurityGroupsCommand({ Filters: filters(id) }))).SecurityGroups ?? [], 'security groups');
        if (!group) throw error;
      }
    }
    if (!group?.GroupId || group.VpcId !== this.config.EC2_ENVIRONMENT_VPC || !owned(group))
      fail(503, 'network_unavailable', 'The environment security group is not configured.');
    if (!group.IpPermissions?.length) {
      try { await this.client.send(new AuthorizeSecurityGroupIngressCommand({ GroupId: group.GroupId,
        IpPermissions: [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }] })); }
      catch (error) { if (!providerError(error, 'InvalidPermission.Duplicate')) throw error; }
    } else {
      const [rule] = group.IpPermissions;
      if (group.IpPermissions.length !== 1 || rule?.IpProtocol !== 'tcp' || rule.FromPort !== 22 || rule.ToPort !== 22 ||
        rule.IpRanges?.length !== 1 || rule.IpRanges[0]?.CidrIp !== '0.0.0.0/0' ||
        rule.Ipv6Ranges?.length || rule.UserIdGroupPairs?.length || rule.PrefixListIds?.length)
        fail(503, 'network_unavailable', 'The environment security group must allow only SSH.');
    }
    return group.GroupId;
  }
  private async instance(id: string): Promise<Instance | null> {
    try {
      const rows = (await this.client.send(new DescribeInstancesCommand({ InstanceIds: [id] }))).Reservations?.flatMap(row => row.Instances ?? []) ?? [];
      const found = single(rows, 'instances');
      if (found && (!owned(found) || (found.VpcId !== this.config.EC2_ENVIRONMENT_VPC &&
        !['shutting-down', 'terminated'].includes(found.State?.Name ?? ''))))
        fail(403, 'runner_resource', 'Choose a managed environment instance.');
      return found;
    } catch (error) { if (providerError(error, 'InvalidInstanceID.NotFound')) return null; throw error; }
  }
  async find(id: string) {
    return this.call(async () => {
      const rows = (await this.client.send(new DescribeInstancesCommand({ Filters: [
        ...filters(id), { Name: 'vpc-id', Values: [this.config.EC2_ENVIRONMENT_VPC] },
        { Name: 'instance-state-name', Values: ['pending', 'running', 'stopping', 'stopped', 'shutting-down'] },
      ] }))).Reservations?.flatMap(row => row.Instances ?? []) ?? [];
      return single(rows, 'instances')?.InstanceId ?? null;
    });
  }
  async findVolume(id: string) {
    return this.call(async () => single((await this.client.send(new DescribeVolumesCommand({ Filters: filters(id) }))).Volumes ?? [], 'disks')?.VolumeId ?? null);
  }
  async start(id: string, options: EnvironmentOptions, environment: Record<string, string>,
    created: (machineId: string, volumeId: string, host: string) => Promise<void>, networkSlot: number) {
    return this.call(async () => {
      await this.network();
      const subnet = await this.subnet(id, networkSlot);
      if (!subnet.SubnetId || subnet.AvailabilityZone !== this.config.EC2_ENVIRONMENT_ZONE || subnet.Ipv6CidrBlockAssociationSet?.length)
        fail(503, 'network_unavailable', 'The environment subnet is not configured.');
      await this.connectSubnet(subnet.SubnetId);
      const group = await this.group(id);
      let machine = await this.find(id);
      if (!machine) {
        const image = (await this.client.send(new DescribeImagesCommand({ ImageIds: [this.config.EC2_ENVIRONMENT_AMI] }))).Images?.[0];
        if (image?.Architecture !== 'x86_64' || image.State !== 'available' || image.RootDeviceType !== 'ebs' || !image.RootDeviceName)
          fail(503, 'image_unavailable', 'The environment machine image is not configured.');
        const root = image.BlockDeviceMappings?.find(item => item.DeviceName === image.RootDeviceName)?.Ebs;
        const content = Object.entries({ XDG_CONFIG_HOME: '/data/config',
          FOUNDATION_EXECUTOR_BOOTSTRAP: environment.FOUNDATION_EXECUTOR_BOOTSTRAP ?? '' })
          .map(([key, value]) => key + '=' + JSON.stringify(value)).join('\n') + '\n';
        const userData = '#cloud-config\n' + JSON.stringify({ write_files: [{ path: '/etc/foundation/environment.env',
          permissions: '0600', owner: 'root:root', encoding: 'b64', content: Buffer.from(content).toString('base64') },
          { path: '/etc/systemd/system/foundation-environment.service.d/runtime.conf', permissions: '0644', owner: 'root:root',
            content: '[Service]\nRuntimeDirectory=sshd\nRuntimeDirectoryMode=0755\nStandardOutput=journal+console\nStandardError=journal+console\n' }],
          runcmd: [['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', 'foundation-environment.service']] });
        if (Buffer.byteLength(userData) > 16_384) fail(400, 'bootstrap_too_large', 'The environment configuration is too large.');
        try {
          machine = (await this.client.send(new RunInstancesCommand({ ImageId: image.ImageId, ClientToken: id,
            MinCount: 1, MaxCount: 1, InstanceType: sizes[options.size],
            NetworkInterfaces: [{ DeviceIndex: 0, SubnetId: subnet.SubnetId, Groups: [group], AssociatePublicIpAddress: true, DeleteOnTermination: true }],
            MetadataOptions: { HttpTokens: 'required', HttpEndpoint: 'enabled', HttpPutResponseHopLimit: 1, InstanceMetadataTags: 'disabled' },
            BlockDeviceMappings: [{ DeviceName: image.RootDeviceName, Ebs: { Encrypted: true, VolumeType: 'gp3',
              VolumeSize: Math.max(this.config.EC2_ENVIRONMENT_DISK_GB, root?.VolumeSize ?? 0), DeleteOnTermination: false } }],
            UserData: Buffer.from(userData).toString('base64'),
            TagSpecifications: (['instance', 'volume', 'network-interface'] as const).map(ResourceType => ({ ResourceType, Tags: tags(id) })),
          }))).Instances?.[0]?.InstanceId ?? null;
        } catch (error) { machine = await this.find(id); if (!machine) throw error; }
      }
      if (!machine) fail(502, 'runner_response', 'The environment instance could not be identified.');
      const ready = await this.wait(() => this.instance(machine!), value => value?.State?.Name === 'running' && Boolean(value.PublicIpAddress));
      const volume = ready?.BlockDeviceMappings?.find(item => item.DeviceName === ready.RootDeviceName)?.Ebs?.VolumeId;
      if (!volume || !ready?.PublicIpAddress) fail(502, 'runner_response', 'The environment disk or SSH address could not be identified.');
      await created(machine, volume, ready.PublicIpAddress);
      return machine;
    });
  }
  async resume(machineId: string) {
    return this.call(async () => {
      await this.network();
      let machine = await this.instance(machineId);
      if (machine?.State?.Name === 'stopping')
        machine = await this.wait(() => this.instance(machineId), value => value?.State?.Name !== 'stopping');
      if (!machine?.SubnetId || !['stopped', 'pending', 'running'].includes(machine.State?.Name ?? ''))
        fail(409, 'environment_unavailable', 'The environment instance is no longer available.');
      await this.connectSubnet(machine.SubnetId);
      if (machine.State?.Name === 'stopped') {
        try { await this.client.send(new StartInstancesCommand({ InstanceIds: [machineId] })); }
        catch (error) {
          const current = await this.instance(machineId);
          if (!['pending', 'running'].includes(current?.State?.Name ?? '')) throw error;
        }
      }
      const ready = await this.wait(() => this.instance(machineId), value => value?.State?.Name === 'running' && Boolean(value.PublicIpAddress));
      const volumeId = ready?.BlockDeviceMappings?.find(item => item.DeviceName === ready.RootDeviceName)?.Ebs?.VolumeId;
      if (!volumeId || !ready?.PublicIpAddress)
        fail(502, 'runner_response', 'The environment disk or SSH address could not be identified.');
      return { volumeId, host: ready.PublicIpAddress };
    });
  }
  async stop(machineId: string) {
    await this.call(async () => {
      let machine = await this.instance(machineId);
      if (machine?.State?.Name === 'pending') machine = await this.wait(() => this.instance(machineId), value => !value || value.State?.Name !== 'pending');
      if (!machine || ['stopped', 'terminated'].includes(machine.State?.Name ?? '')) return;
      if (machine.State?.Name === 'shutting-down') {
        await this.wait(() => this.instance(machineId), value => !value || value.State?.Name === 'terminated');
        return;
      }
      if (machine.State?.Name !== 'stopping') await this.client.send(new StopInstancesCommand({ InstanceIds: [machineId] }));
      await this.wait(() => this.instance(machineId), value => !value || ['stopped', 'terminated'].includes(value.State?.Name ?? ''));
    });
  }
  async terminate(machineId: string) {
    await this.call(async () => {
      const machine = await this.instance(machineId);
      if (!machine || machine.State?.Name === 'terminated') return;
      await this.client.send(new TerminateInstancesCommand({ InstanceIds: [machineId] }));
      await this.wait(() => this.instance(machineId), value => !value || value.State?.Name === 'terminated');
    });
  }
  async removeVolume(volumeId: string) {
    await this.call(async () => {
      const read = async () => {
        try { return (await this.client.send(new DescribeVolumesCommand({ VolumeIds: [volumeId] }))).Volumes?.[0] ?? null; }
        catch (error) { if (providerError(error, 'InvalidVolume.NotFound')) return null; throw error; }
      };
      const volume = await read();
      if (!volume) return;
      if (!owned(volume)) fail(403, 'runner_resource', 'Choose a managed environment disk.');
      if (volume.State !== 'deleting') {
        await this.wait(read, value => !value || value.State === 'available');
        try { await this.client.send(new DeleteVolumeCommand({ VolumeId: volumeId })); }
        catch (error) { if (!providerError(error, 'InvalidVolume.NotFound')) throw error; }
      }
      await this.wait(read, value => !value);
    });
  }
  async removeNetwork(id: string) {
    await this.call(async () => {
      const subnets = (await this.client.send(new DescribeSubnetsCommand({ Filters: filters(id) }))).Subnets ?? [];
      for (const subnet of subnets) {
        if (subnet.VpcId !== this.config.EC2_ENVIRONMENT_VPC) fail(403, 'runner_resource', 'Choose a managed environment subnet.');
        await this.wait(async () => {
          try { await this.client.send(new DeleteSubnetCommand({ SubnetId: subnet.SubnetId })); return true; }
          catch (error) {
            if (providerError(error, 'InvalidSubnetID.NotFound')) return true;
            if (providerError(error, 'DependencyViolation')) return false;
            throw error;
          }
        }, value => value);
      }
      const groups = (await this.client.send(new DescribeSecurityGroupsCommand({ Filters: filters(id) }))).SecurityGroups ?? [];
      for (const group of groups) {
        if (group.VpcId !== this.config.EC2_ENVIRONMENT_VPC) fail(403, 'runner_resource', 'Choose a managed environment security group.');
        await this.wait(async () => {
          try { await this.client.send(new DeleteSecurityGroupCommand({ GroupId: group.GroupId })); return true; }
          catch (error) {
            if (providerError(error, 'InvalidGroup.NotFound')) return true;
            if (providerError(error, 'DependencyViolation')) return false;
            throw error;
          }
        }, value => value);
      }
      await this.wait(async () => {
        const subnet = await this.client.send(new DescribeSubnetsCommand({ Filters: filters(id) }));
        const group = await this.client.send(new DescribeSecurityGroupsCommand({ Filters: filters(id) }));
        return !subnet.Subnets?.length && !group.SecurityGroups?.length;
      }, value => value);
    });
  }
}
