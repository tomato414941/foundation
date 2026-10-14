import { EC2Client, CreateSubnetCommand, AssociateRouteTableCommand, DescribeNetworkAclsCommand,
  ReplaceNetworkAclAssociationCommand, CreateSecurityGroupCommand, RunInstancesCommand,
  GetConsoleOutputCommand, DescribeInstancesCommand, StopInstancesCommand, CreateImageCommand,
  DescribeImagesCommand, TerminateInstancesCommand, DeregisterImageCommand, DeleteSnapshotCommand } from '@aws-sdk/client-ec2';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { configuration } from '../../server/config.js';
import { EC2Runner } from '../../server/ec2-runner.js';
import { provisionNetwork } from './network.js';

const execute = promisify(execFile);
const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
const region = process.env.AWS_REGION ?? 'ap-northeast-1';
const functionImage = process.env.ENVIRONMENT_FUNCTION_IMAGE ?? '';
const bucket = process.env.FOUNDATION_BUCKET ?? '';
if (!/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(functionImage) || !bucket)
  throw new Error('Set ENVIRONMENT_FUNCTION_IMAGE to a pinned image and FOUNDATION_BUCKET to a private artifact bucket.');
const client = new EC2Client({ region }), objects = new S3Client({ region });
const network = await provisionNetwork(client, process.env.EC2_ENVIRONMENT_ZONE ?? region + 'a');
const base = process.env.EC2_BASE_AMI ?? (await execute('aws', ['ssm', 'get-parameter', '--region', region, '--name',
  '/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id', '--query', 'Parameter.Value', '--output', 'text'])).stdout.trim();
if (!/^ami-[a-f0-9]+$/.test(base)) throw new Error('Use an Ubuntu 24.04 amd64 base AMI.');
const id = randomUUID(), revision = (await execute('git', ['rev-parse', 'HEAD'])).stdout.trim();
const imageName = 'foundation-environment-' + revision.slice(0, 12) + '-' + id.slice(0, 8);
const temporary = await mkdtemp(join(tmpdir(), 'foundation-image-'));
const config = await configuration({ DATABASE_URL: 'postgres://localhost/foundation', FOUNDATION_DATA: temporary,
  FOUNDATION_KEY: Buffer.alloc(32).toString('base64url'), AWS_REGION: region, EC2_ENVIRONMENT_AMI: base, ...network });
const runner = new EC2Runner(config, client);
const Tags = [{ Key: 'foundation:managed', Value: 'environment' }, { Key: 'foundation:environment', Value: id }];
const key = 'foundation-environment-images/' + revision + '-' + id + '.tar';
let machine: string | undefined, image: string | undefined, success = false, failure: unknown;
const wait = async (condition: () => Promise<boolean>) => {
  for (let attempt = 0; attempt < 120; attempt++) { if (await condition()) return; await delay(10_000); }
  throw new Error('The image provider did not finish the operation.');
};
try {
  const archive = join(temporary, 'image.tar');
  await execute('tar', ['-cf', archive, '-C', 'cli/dist', 'cli.mjs', '-C', '../../deploy/environment',
    'install.sh', 'ssh-session.sh', 'foundation-environment.service']);
  const Body = await readFile(archive);
  await objects.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body, ContentType: 'application/x-tar', ServerSideEncryption: 'AES256' }));
  const url = await getSignedUrl(objects, new GetObjectCommand({ Bucket: bucket, Key: key }), { expiresIn: 1800 });
  let subnetId: string | undefined;
  for (let slot = 4095; slot >= 4092; slot--) {
    try {
      subnetId = (await client.send(new CreateSubnetCommand({ VpcId: network.EC2_ENVIRONMENT_VPC,
        AvailabilityZone: network.EC2_ENVIRONMENT_ZONE, CidrBlock: `10.80.${slot >> 4}.${(slot & 15) * 16}/28`,
        TagSpecifications: [{ ResourceType: 'subnet', Tags }] }))).Subnet?.SubnetId;
      break;
    } catch (error) { if (!(error instanceof Error && error.name === 'InvalidSubnet.Conflict')) throw error; }
  }
  if (!subnetId) throw new Error('The image subnet could not be created.');
  await client.send(new AssociateRouteTableCommand({ SubnetId: subnetId, RouteTableId: network.EC2_ENVIRONMENT_ROUTE_TABLE }));
  const acl = (await client.send(new DescribeNetworkAclsCommand({ Filters: [{ Name: 'association.subnet-id', Values: [subnetId] }] }))).NetworkAcls?.[0];
  const association = acl?.Associations?.find(item => item.SubnetId === subnetId)?.NetworkAclAssociationId;
  if (!association) throw new Error('The image subnet ACL could not be identified.');
  await client.send(new ReplaceNetworkAclAssociationCommand({ AssociationId: association, NetworkAclId: network.EC2_ENVIRONMENT_ACL }));
  const group = (await client.send(new CreateSecurityGroupCommand({ VpcId: network.EC2_ENVIRONMENT_VPC,
    GroupName: 'foundation-image-' + id, Description: 'Foundation image builder; no incoming connections',
    TagSpecifications: [{ ResourceType: 'security-group', Tags }] }))).GroupId;
  if (!group) throw new Error('The image security group could not be created.');
  const data = '#!/bin/bash\nset -euo pipefail\numask 077\nmkdir -p /opt/foundation-image\n' +
    'curl --fail --silent --show-error --location ' + quote(url) + ' -o /tmp/foundation-image.tar\n' +
    'tar -xf /tmp/foundation-image.tar -C /opt/foundation-image\n' +
    'FOUNDATION_IMAGE_FUNCTION=' + quote(functionImage) + ' bash /opt/foundation-image/install.sh\n';
  machine = (await client.send(new RunInstancesCommand({ ImageId: base, ClientToken: id, MinCount: 1, MaxCount: 1, InstanceType: 't3.small',
    NetworkInterfaces: [{ DeviceIndex: 0, SubnetId: subnetId, Groups: [group], AssociatePublicIpAddress: true, DeleteOnTermination: true }],
    MetadataOptions: { HttpTokens: 'required', HttpPutResponseHopLimit: 1 },
    BlockDeviceMappings: [{ DeviceName: '/dev/sda1', Ebs: { Encrypted: true, VolumeType: 'gp3', VolumeSize: 16, DeleteOnTermination: true } }],
    UserData: Buffer.from(data).toString('base64'),
    TagSpecifications: (['instance', 'volume', 'network-interface'] as const).map(ResourceType => ({ ResourceType, Tags })),
  }))).Instances?.[0]?.InstanceId;
  if (!machine) throw new Error('The image builder could not be identified.');
  process.stdout.write('Building environment image on ' + machine + '\n');
  await wait(async () => {
    const output = await client.send(new GetConsoleOutputCommand({ InstanceId: machine, Latest: true }));
    return Buffer.from(output.Output ?? '', 'base64').toString().includes('FOUNDATION_IMAGE_READY');
  });
  await client.send(new StopInstancesCommand({ InstanceIds: [machine] }));
  await wait(async () => (await client.send(new DescribeInstancesCommand({ InstanceIds: [machine!] }))).Reservations?.[0]?.Instances?.[0]?.State?.Name === 'stopped');
  const imageTags = [{ Key: 'foundation:managed', Value: 'environment-image' }, { Key: 'foundation:revision', Value: revision }];
  image = (await client.send(new CreateImageCommand({ InstanceId: machine, Name: imageName, NoReboot: true,
    TagSpecifications: (['image', 'snapshot'] as const).map(ResourceType => ({ ResourceType, Tags: imageTags })) }))).ImageId;
  if (!image) throw new Error('The environment image could not be identified.');
  process.stdout.write('Waiting for environment image ' + image + '\n');
  await wait(async () => {
    const state = (await client.send(new DescribeImagesCommand({ ImageIds: [image!] }))).Images?.[0]?.State;
    if (state === 'failed') throw new Error('The environment image failed to build.');
    return state === 'available';
  });
  success = true;
  for (const [name, value] of Object.entries({ ...network, EC2_ENVIRONMENT_AMI: image, ENVIRONMENT_FUNCTION_IMAGE: functionImage }))
    process.stdout.write(name + '=' + value + '\n');
} catch (error) { failure = error; }
finally {
  // Keep the first failure visible, but attempt every cleanup operation.
  const failures: unknown[] = [];
  if (!machine) try { machine = await runner.find(id) ?? undefined; } catch (error) { failures.push(error); }
  if (!image) try {
    image = (await client.send(new DescribeImagesCommand({ Owners: ['self'], Filters: [{ Name: 'name', Values: [imageName] }] }))).Images?.[0]?.ImageId;
  } catch (error) { failures.push(error); }
  if (machine) {
    try { await client.send(new TerminateInstancesCommand({ InstanceIds: [machine] }));
      await wait(async () => (await client.send(new DescribeInstancesCommand({ InstanceIds: [machine!] }))).Reservations?.[0]?.Instances?.[0]?.State?.Name === 'terminated');
    } catch (error) { failures.push(error); }
  }
  try { await runner.removeNetwork(id); } catch (error) { failures.push(error); }
  if (image && !success) {
    try {
      const found = (await client.send(new DescribeImagesCommand({ ImageIds: [image] }))).Images?.[0];
      await client.send(new DeregisterImageCommand({ ImageId: image }));
      for (const item of found?.BlockDeviceMappings ?? []) if (item.Ebs?.SnapshotId)
        await client.send(new DeleteSnapshotCommand({ SnapshotId: item.Ebs.SnapshotId }));
    } catch (error) { failures.push(error); }
  }
  try { await objects.send(new DeleteObjectCommand({ Bucket: bucket, Key: key })); } catch (error) { failures.push(error); }
  await rm(temporary, { recursive: true, force: true });
  if (failure || failures.length) throw new AggregateError([...(failure ? [failure] : []), ...failures], 'Image build or cleanup requires attention.');
}
