import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { EC2Client } from '@aws-sdk/client-ec2';
import { configuration } from '../server/config.js';
import { EC2Runner, privateNetworks } from '../server/ec2-runner.js';
import { EnvironmentInput } from '../shared/contracts.js';

// The provider keeps resources after a lost response and completes transitions on subsequent reads.
class Provider {
  subnets: any[] = [];
  groups: any[] = [];
  instances: any[] = [];
  volumes: any[] = [];
  requests: any[] = [];
  loseSubnetResponse = false;
  loseRunResponse = false;
  unsafeNetwork = false;
  id = 0;
  acl = {
    NetworkAclId: 'acl-123', VpcId: 'vpc-123', IsDefault: false,
    Entries: [false, true].flatMap(Egress => [
      ...privateNetworks.map((CidrBlock, index) => ({ Egress, CidrBlock, RuleNumber: 100 + index, RuleAction: 'deny', Protocol: '-1' })),
      { Egress, CidrBlock: '0.0.0.0/0', RuleNumber: 200, RuleAction: 'allow', Protocol: '-1' },
      { Egress, CidrBlock: '0.0.0.0/0', RuleNumber: 32767, RuleAction: 'deny', Protocol: '-1' },
    ]),
  };
  matching(rows: any[], input: any) {
    return rows.filter(row => (input.Filters ?? []).every((filter: any) => {
      const name = filter.Name;
      const value = name.startsWith('tag:') ? row.Tags?.find((tag: any) => tag.Key === name.slice(4))?.Value
        : name === 'vpc-id' ? row.VpcId : name === 'instance-state-name' ? row.State.Name : undefined;
      return filter.Values.includes(value);
    }));
  }
  async send(command: any): Promise<any> {
    const name = command.constructor.name, input = command.input;
    this.requests.push({ name, input });
    if (name === 'DescribeVpcsCommand') return { Vpcs: [{ VpcId: 'vpc-123', CidrBlock: '10.80.0.0/16', State: 'available',
      Tags: [{ Key: 'foundation:managed', Value: 'environment-network' }] }] };
    if (name === 'DescribeNetworkAclsCommand') {
      if (input.NetworkAclIds) return { NetworkAcls: [{ ...this.acl, Entries: this.unsafeNetwork ? this.acl.Entries.slice(1) : this.acl.Entries }] };
      const subnet = this.subnets.find(row => row.SubnetId === input.Filters[0].Values[0]);
      return { NetworkAcls: [{ ...this.acl, NetworkAclId: subnet.acl ?? 'acl-default',
        Associations: [{ SubnetId: subnet.SubnetId, NetworkAclAssociationId: 'aclassoc-' + subnet.SubnetId }] }] };
    }
    if (name === 'ReplaceNetworkAclAssociationCommand') {
      this.subnets.find(row => 'aclassoc-' + row.SubnetId === input.AssociationId).acl = input.NetworkAclId;
      return {};
    }
    if (name === 'DescribeRouteTablesCommand') {
      if (!input.RouteTableIds) return { RouteTables: this.subnets.some(row => row.SubnetId === input.Filters[0].Values[0] && row.route)
        ? [{ RouteTableId: 'rtb-123' }] : [] };
      return { RouteTables: [{ RouteTableId: 'rtb-123', VpcId: 'vpc-123', Routes: [
        { DestinationCidrBlock: '10.80.0.0/16', GatewayId: 'local', State: 'active' },
        { DestinationCidrBlock: '0.0.0.0/0', GatewayId: 'igw-123', State: 'active' },
      ] }] };
    }
    if (name === 'AssociateRouteTableCommand') { this.subnets.find(row => row.SubnetId === input.SubnetId).route = true; return {}; }
    if (name === 'DescribeSubnetsCommand') return { Subnets: this.matching(this.subnets, input) };
    if (name === 'CreateSubnetCommand') {
      const Subnet = { ...input, SubnetId: 'subnet-' + ++this.id, State: 'available', Tags: input.TagSpecifications[0].Tags };
      this.subnets.push(Subnet);
      if (this.loseSubnetResponse) { this.loseSubnetResponse = false; throw new Error('Response lost'); }
      return { Subnet };
    }
    if (name === 'DescribeSecurityGroupsCommand') return { SecurityGroups: input.GroupIds
      ? this.groups.filter(row => input.GroupIds.includes(row.GroupId)) : this.matching(this.groups, input) };
    if (name === 'CreateSecurityGroupCommand') {
      const group = { GroupId: 'sg-' + ++this.id, VpcId: input.VpcId, Tags: input.TagSpecifications[0].Tags, IpPermissions: [] };
      this.groups.push(group); return { GroupId: group.GroupId };
    }
    if (name === 'AuthorizeSecurityGroupIngressCommand') {
      this.groups.find(row => row.GroupId === input.GroupId).IpPermissions = input.IpPermissions; return {};
    }
    if (name === 'DescribeImagesCommand') return { Images: [{ ImageId: 'ami-123', Architecture: 'x86_64', State: 'available',
      RootDeviceType: 'ebs', RootDeviceName: '/dev/sda1', BlockDeviceMappings: [{ DeviceName: '/dev/sda1', Ebs: { VolumeSize: 8 } }] }] };
    if (name === 'RunInstancesCommand') {
      const network = input.NetworkInterfaces[0];
      assert.equal(this.subnets.find(row => row.SubnetId === network.SubnetId).acl, 'acl-123');
      const instance = { InstanceId: 'i-' + ++this.id, VpcId: 'vpc-123', SubnetId: network.SubnetId,
        Tags: input.TagSpecifications.find((row: any) => row.ResourceType === 'instance').Tags,
        State: { Name: 'running' }, PublicIpAddress: '203.0.113.' + this.id, RootDeviceName: '/dev/sda1',
        BlockDeviceMappings: [{ DeviceName: '/dev/sda1', Ebs: { VolumeId: 'vol-' + this.id } }] };
      this.instances.push(instance);
      this.volumes.push({ VolumeId: 'vol-' + this.id, State: 'in-use', Tags: instance.Tags, Encrypted: true });
      if (this.loseRunResponse) { this.loseRunResponse = false; throw new Error('Response lost'); }
      return { Instances: [instance] };
    }
    if (name === 'DescribeInstancesCommand') {
      const rows = input.InstanceIds ? this.instances.filter(row => input.InstanceIds.includes(row.InstanceId)) : this.matching(this.instances, input);
      for (const row of rows) {
        if (row.State.Name === 'stopping') row.State.Name = 'stopped';
        if (row.State.Name === 'shutting-down') {
          row.State.Name = 'terminated';
          delete row.VpcId;
          this.volumes.find(volume => volume.VolumeId === row.BlockDeviceMappings[0].Ebs.VolumeId).State = 'available';
        }
      }
      return { Reservations: [{ Instances: rows }] };
    }
    if (name === 'StopInstancesCommand' || name === 'TerminateInstancesCommand') {
      this.instances.find(row => row.InstanceId === input.InstanceIds[0]).State.Name = name === 'StopInstancesCommand' ? 'stopping' : 'shutting-down'; return {};
    }
    if (name === 'StartInstancesCommand') {
      const instance = this.instances.find(row => row.InstanceId === input.InstanceIds[0]);
      instance.State.Name = 'running';
      instance.PublicIpAddress = '203.0.113.' + ++this.id;
      return {};
    }
    if (name === 'DescribeVolumesCommand') return { Volumes: input.VolumeIds ? this.volumes.filter(row => input.VolumeIds.includes(row.VolumeId)) : this.matching(this.volumes, input) };
    if (name === 'DeleteVolumeCommand') {
      assert.equal(this.volumes.find(row => row.VolumeId === input.VolumeId).State, 'available');
      this.volumes = this.volumes.filter(row => row.VolumeId !== input.VolumeId); return {};
    }
    if (name === 'DeleteSubnetCommand') { this.subnets = this.subnets.filter(row => row.SubnetId !== input.SubnetId); return {}; }
    if (name === 'DeleteSecurityGroupCommand') { this.groups = this.groups.filter(row => row.GroupId !== input.GroupId); return {}; }
    throw new Error('Unexpected provider command: ' + name);
  }
}
async function setup(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), 'foundation-ec2-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const config = await configuration({ DATABASE_URL: 'postgres://localhost/foundation', FOUNDATION_DATA: directory,
    FOUNDATION_KEY: Buffer.alloc(32).toString('base64url'), EC2_ENVIRONMENT_AMI: 'ami-123', EC2_ENVIRONMENT_VPC: 'vpc-123',
    EC2_ENVIRONMENT_ACL: 'acl-123', EC2_ENVIRONMENT_ROUTE_TABLE: 'rtb-123', EC2_ENVIRONMENT_ZONE: 'ap-northeast-1a' });
  const provider = new Provider(), client = new EC2Client({ region: config.AWS_REGION });
  t.mock.method(client, 'send', provider.send.bind(provider));
  return { provider, runner: new EC2Runner(config, client, async () => {}) };
}
const bootstrap = { keys: await new (await import('../server/ssh-client.js')).OpenSSH().keys(), authorizedKeys: [] };

test('環境ごとにVM・暗号化ディスク・サブネットとSSHアドレスを割り当て、AWS側で内部通信を制限する', async t => {
  const { provider, runner } = await setup(t), connections: any[] = [];
  for (const size of ['small', 'medium', 'large'] as const)
    await runner.start(randomUUID(), EnvironmentInput.parse({ size }), bootstrap, async (machine, volume, host) => { connections.push({ machine, volume, host }); }, connections.length);
  for (const field of ['machine', 'volume', 'host']) assert.equal(new Set(connections.map(value => value[field])).size, 3);
  assert.equal(new Set(provider.instances.map(value => value.SubnetId)).size, 3);
  assert.equal(provider.volumes.every(value => value.Encrypted), true);
  for (const group of provider.groups) assert.deepEqual(group.IpPermissions,
    [{ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }] }]);
  for (const request of provider.requests.filter(value => value.name === 'RunInstancesCommand')) {
    assert.equal(request.input.MetadataOptions.HttpTokens, 'required');
    assert.equal(request.input.MetadataOptions.HttpPutResponseHopLimit, 1);
    assert.equal(request.input.IamInstanceProfile, undefined);
    const data = Buffer.from(request.input.UserData, 'base64').toString();
    assert.ok(data.startsWith('#cloud-config\n'));
    const cloud = JSON.parse(data.slice('#cloud-config\n'.length));
    assert.equal(cloud.ssh_keys.ed25519_private, bootstrap.keys.hostPrivateKey);
    assert.equal(cloud.ssh_keys.ed25519_public, bootstrap.keys.hostPublicKey);
    assert.equal(cloud.write_files[0].permissions, '0644');
    assert.equal(cloud.write_files[0].content.trim(), bootstrap.keys.publicKey.trim());
  }
});

test('サブネット作成と起動応答の喪失を回復し、再試行で同じVM・ディスク・ネットワークを使用する', async t => {
  const { provider, runner } = await setup(t), id = randomUUID(), results: string[] = [];
  provider.loseSubnetResponse = provider.loseRunResponse = true;
  for (let attempt = 0; attempt < 2; attempt++)
    results.push(await runner.start(id, EnvironmentInput.parse({}), bootstrap, async () => {}, 0));
  assert.equal(results[0], results[1]);
  assert.equal(provider.instances.length, 1);
  assert.equal(provider.volumes.length, 1);
  assert.equal(provider.subnets.length, 1);
  assert.equal(provider.groups.length, 1);
});

test('停止ではVMとディスクを保持し、削除では終了完了後にディスク・ネットワークを削除する', async t => {
  const { provider, runner } = await setup(t), id = randomUUID();
  const machine = await runner.start(id, EnvironmentInput.parse({}), bootstrap, async () => {}, 0);
  const volume = (await runner.findVolume(id))!;
  await runner.stop(machine);
  assert.equal(provider.instances[0].State.Name, 'stopped');
  assert.equal(provider.volumes[0].State, 'in-use');
  assert.equal(await runner.find(id), machine);
  await runner.terminate(machine);
  assert.equal(provider.instances[0].State.Name, 'terminated');
  await runner.removeVolume(volume);
  await runner.removeNetwork(id);
  assert.equal(await runner.findVolume(id), null);
  assert.equal(provider.subnets.length, 0);
  assert.equal(provider.groups.length, 0);
  await runner.terminate(machine); await runner.removeVolume(volume); await runner.removeNetwork(id);
});

test('内部通信を許す設定を検知して起動を拒否し、管理対象のVMだけを停止する', async t => {
  const { provider, runner } = await setup(t);
  provider.unsafeNetwork = true;
  await assert.rejects(runner.start(randomUUID(), EnvironmentInput.parse({}), bootstrap, async () => {}, 0), { code: 'network_unavailable' });
  provider.instances.push({ InstanceId: 'i-platform', VpcId: 'vpc-other', State: { Name: 'running' }, Tags: [] });
  await assert.rejects(runner.stop('i-platform'), { code: 'runner_resource' });
  assert.equal(provider.instances[0].State.Name, 'running');
});

test('停止したVMを同じディスクとネットワークで起動し、新しいSSHアドレスを返す', async t => {
  const { provider, runner } = await setup(t), id = randomUUID();
  let originalHost = '';
  const machine = await runner.start(id, EnvironmentInput.parse({}), bootstrap,
    async (_machine, _volume, host) => { originalHost = host; }, 0);
  const volumeId = await runner.findVolume(id), subnet = provider.instances[0].SubnetId;
  await runner.stop(machine);
  const restarted = await runner.resume(machine);
  assert.equal(restarted.volumeId, volumeId);
  assert.notEqual(restarted.host, originalHost);
  assert.equal(provider.instances[0].State.Name, 'running');
  assert.equal(provider.instances[0].SubnetId, subnet);
  assert.equal(await runner.find(id), machine);
  assert.deepEqual(await runner.resume(machine), restarted);
});
