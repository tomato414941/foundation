import { IAMClient, PutRolePolicyCommand } from '@aws-sdk/client-iam';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { runnerPolicy } from './permissions.js';

const region = process.env.AWS_REGION ?? 'ap-northeast-1';
const role = process.argv[2];
const network = { vpc: process.env.EC2_ENVIRONMENT_VPC, acl: process.env.EC2_ENVIRONMENT_ACL,
  defaultAcl: process.env.EC2_ENVIRONMENT_DEFAULT_ACL, route: process.env.EC2_ENVIRONMENT_ROUTE_TABLE };
const ami = process.env.EC2_ENVIRONMENT_AMI;
if (!role || !/^[\w+=,.@-]{1,64}$/.test(role) || !network.vpc || !network.acl || !network.defaultAcl || !network.route || !ami)
  throw new Error('Pass the Foundation host role name and set the EC2 environment configuration.');
const account = (await new STSClient({ region }).send(new GetCallerIdentityCommand({}))).Account;
if (!account) throw new Error('The AWS account could not be identified.');
const policy = runnerPolicy(region, account, network as { vpc: string; acl: string; defaultAcl: string; route: string }, ami);
await new IAMClient({ region }).send(new PutRolePolicyCommand({ RoleName: role, PolicyName: 'foundation-environments', PolicyDocument: JSON.stringify(policy) }));
process.stdout.write('Configured managed environment permissions for ' + role + '\n');
