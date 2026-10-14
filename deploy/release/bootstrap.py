import json
import subprocess


def aws(*args):
    output = subprocess.run(["aws", "--profile", "foundation", "--region", "ap-northeast-1", *args, "--output", "json"],
                            check=True, capture_output=True, text=True).stdout
    return json.loads(output) if output.strip() else {}


def configure_role(name, trust, policy_name, policy):
    try:
        aws("iam", "get-role", "--role-name", name)
    except subprocess.CalledProcessError as error:
        if "NoSuchEntity" not in (error.stderr or ""):
            raise
        aws("iam", "create-role", "--role-name", name, "--assume-role-policy-document", json.dumps(trust),
            "--max-session-duration", "3600")
    else:
        aws("iam", "update-assume-role-policy", "--role-name", name, "--policy-document", json.dumps(trust))
    aws("iam", "put-role-policy", "--role-name", name, "--policy-name", policy_name, "--policy-document", json.dumps(policy))


def configure_build_role(account, subject_prefix):
    if account != "052438773980":
        raise RuntimeError("Configure the Foundation account only.")
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {
        "Federated": "arn:aws:iam::" + account + ":oidc-provider/token.actions.githubusercontent.com"},
        "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": subject_prefix + ":ref:refs/heads/main"}}}]}
    policy = aws("iam", "get-role-policy", "--role-name", "foundation-environment-builder",
                 "--policy-name", "environment-build")["PolicyDocument"]
    bucket = "foundation-objects-052438773980"
    policy["Statement"].extend([
        {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::" + bucket,
         "Condition": {"StringLike": {"s3:prefix": ["foundation-releases/*", "foundation-environment-images/*"]}}},
        {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
         "Resource": "arn:aws:s3:::" + bucket + "/foundation-releases/*"},
    ])
    configure_role("foundation-github-build", trust, "build", policy)


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
    configure_build_role(account, subject["sub_claim_prefix"])
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": provider},
        "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": subject["sub_claim_prefix"] + ":environment:production"}}}]}
    role = "foundation-github-release"
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
    configure_role(role, trust, "release", policy)
    images = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:RunInstances",
        "Resource": "arn:aws:ec2:ap-northeast-1::image/*", "Condition": {
            "StringEquals": {"ec2:Owner": "099720109477"}}}]}
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
