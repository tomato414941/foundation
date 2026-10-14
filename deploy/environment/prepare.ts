import { EC2Client, DescribeImagesCommand } from '@aws-sdk/client-ec2';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { provisionNetwork } from './network.js';

const region = process.env.AWS_REGION ?? 'ap-northeast-1';
const client = new EC2Client({ region });
const { stdout } = await promisify(execFile)('aws', ['ssm', 'get-parameter', '--region', region, '--name',
  '/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id',
  '--query', 'Parameter.Value', '--output', 'text'], { timeout: 30_000 });
const id = stdout.trim();
if (!/^ami-[a-f0-9]+$/.test(id)) throw new Error('The Ubuntu image could not be identified.');
const image = (await client.send(new DescribeImagesCommand({ ImageIds: [id], Owners: ['099720109477'] }))).Images?.[0];
if (image?.State !== 'available' || image.Architecture !== 'x86_64' || image.RootDeviceType !== 'ebs')
  throw new Error('Use an available official Ubuntu amd64 image.');
const network = await provisionNetwork(client, process.env.EC2_ENVIRONMENT_ZONE ?? region + 'a');
for (const [name, value] of Object.entries({ ...network, EC2_ENVIRONMENT_AMI: id }))
  process.stdout.write(name + '=' + value + '\n');
