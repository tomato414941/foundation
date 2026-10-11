import json
import subprocess


def aws(*args):
    output = subprocess.check_output(["aws", "--profile", "foundation", "--region", "ap-northeast-1", *args, "--output", "json"], text=True)
    return json.loads(output) if output.strip() else {}


def main():
    account = aws("sts", "get-caller-identity")["Account"]
    if account != "052438773980": raise RuntimeError("Configure the Foundation account only.")
    provider = "arn:aws:iam::" + account + ":oidc-provider/token.actions.githubusercontent.com"
    providers = aws("iam", "list-open-id-connect-providers")["OpenIDConnectProviderList"]
    if not any(value["Arn"] == provider for value in providers):
        aws("iam", "create-open-id-connect-provider", "--url", "https://token.actions.githubusercontent.com", "--client-id-list", "sts.amazonaws.com")
    subject = json.loads(subprocess.check_output(["gh", "api", "repos/tomato414941/foundation/actions/oidc/customization/sub"], text=True))
    if not subject.get("use_default") or not subject.get("sub_claim_prefix"):
        raise RuntimeError("Review the repository's custom OIDC subject before configuring its deployment role.")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": provider},
        "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": subject["sub_claim_prefix"] + ":environment:production"}}}]}
    role = "foundation-github-release"
    existing = subprocess.run(["aws", "--profile", "foundation", "iam", "get-role", "--role-name", role], capture_output=True, text=True)
    if existing.returncode:
        if "NoSuchEntity" not in existing.stderr: raise RuntimeError(existing.stderr)
        aws("iam", "create-role", "--role-name", role, "--assume-role-policy-document", json.dumps(trust), "--max-session-duration", "3600")
    else:
        aws("iam", "update-assume-role-policy", "--role-name", role, "--policy-document", json.dumps(trust))
    policy = aws("iam", "get-role-policy", "--role-name", "foundation-environment-builder", "--policy-name", "environment-build")["PolicyDocument"]
    bucket = "foundation-objects-052438773980"
    policy["Statement"].extend([
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::" + bucket,
         "Condition": {"StringLike": {"s3:prefix": ["foundation-releases/*", "foundation-environment-images/*"]}}},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::" + bucket + "/foundation-releases/*"},
        {"Effect": "Allow", "Action": "ssm:SendCommand", "Resource": [
            "arn:aws:ec2:ap-northeast-1:052438773980:instance/i-012a1a04ee760f433",
            "arn:aws:ssm:ap-northeast-1::document/AWS-RunShellScript"]},
        {"Effect": "Allow", "Action": ["ssm:GetCommandInvocation", "ssm:ListCommands"], "Resource": "*"},
    ])
    aws("iam", "put-role-policy", "--role-name", role, "--policy-name", "release", "--policy-document", json.dumps(policy))
    images = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:RunInstances",
        "Resource": "arn:aws:ec2:ap-northeast-1::image/*", "Condition": {
            "StringEquals": {"aws:ResourceTag/foundation:managed": "environment-image", "ec2:Owner": account}}}]}
    network = {"vpc": "vpc-0f12d46647d1fcaee", "acl": "acl-0d084e53022e1e0b6",
               "defaultAcl": "acl-0de9d5d8e8412432e", "route": "rtb-09a152847dd762389"}
    script = "import {runnerPolicy} from './deploy/environment/permissions.ts';" + \
        "console.log(JSON.stringify(runnerPolicy('ap-northeast-1','052438773980',JSON.parse(process.argv[1]),'ami-0')));"
    runner = json.loads(subprocess.check_output(["node", "--import", "tsx", "--input-type=module", "-e", script, json.dumps(network)], text=True))
    runner["Statement"][1] = images["Statement"][0]
    host = "foundation-host-InstanceRole-zM9VZF8jRg4y"
    aws("iam", "put-role-policy", "--role-name", host, "--policy-name", "foundation-environments", "--policy-document", json.dumps(runner))
    policies = aws("iam", "list-role-policies", "--role-name", host)["PolicyNames"]
    if "foundation-release-images" in policies:
        aws("iam", "delete-role-policy", "--role-name", host, "--policy-name", "foundation-release-images")
    body = {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
    subprocess.run(["gh", "api", "--method", "PUT", "repos/tomato414941/foundation/environments/production", "--input", "-"],
                   input=json.dumps(body), text=True, check=True, stdout=subprocess.DEVNULL)
    rules = json.loads(subprocess.check_output(["gh", "api", "repos/tomato414941/foundation/environments/production/deployment-branch-policies"], text=True))
    if not any(value["name"] == "main" for value in rules["branch_policies"]):
        subprocess.run(["gh", "api", "--method", "POST", "repos/tomato414941/foundation/environments/production/deployment-branch-policies", "--input", "-"],
                       input=json.dumps({"name": "main", "type": "branch"}), text=True, check=True, stdout=subprocess.DEVNULL)
    print("Configured GitHub OIDC and the Foundation production deployment target.")


if __name__ == "__main__":
    main()
