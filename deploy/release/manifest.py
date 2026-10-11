import hashlib
import json
import re
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate(value):
    checks = {
        "commit": r"[a-f0-9]{40}",
        "image": r"ghcr\.io/tomato414941/foundation@sha256:[a-f0-9]{64}",
        "cliVersion": r"\d+\.\d+\.\d+",
        "cliSha256": r"[a-f0-9]{64}",
        "schemaSha256": r"[a-f0-9]{64}",
        "runtimeSha256": r"[a-f0-9]{64}",
    }
    for name, pattern in checks.items():
        if not isinstance(value.get(name), str) or not re.fullmatch(pattern, value[name]):
            raise ValueError("Invalid release " + name)
    settings = value.get("environment", {})
    patterns = {
        "EC2_ENVIRONMENT_AMI": r"ami-[a-f0-9]+",
        "EC2_ENVIRONMENT_VPC": r"vpc-[a-f0-9]+",
        "EC2_ENVIRONMENT_ACL": r"acl-[a-f0-9]+",
        "EC2_ENVIRONMENT_DEFAULT_ACL": r"acl-[a-f0-9]+",
        "EC2_ENVIRONMENT_ROUTE_TABLE": r"rtb-[a-f0-9]+",
        "EC2_ENVIRONMENT_ZONE": r"ap-northeast-1[a-z]",
        "ENVIRONMENT_COMMAND_IMAGE": r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}",
    }
    if set(settings) != set(patterns):
        raise ValueError("The release must contain its complete environment configuration.")
    for name, pattern in patterns.items():
        if not isinstance(settings[name], str) or not re.fullmatch(pattern, settings[name]):
            raise ValueError("Invalid environment setting " + name)
    return value


def update_environment(text, settings):
    result = text
    for name, value in settings.items():
        pattern = re.compile(r"(?m)^\s*(?:export\s+)?" + re.escape(name) + r"\s*=.*$")
        line = name + "=" + value
        result = pattern.sub(lambda _: line, result) if pattern.search(result) else result.rstrip() + "\n" + line + "\n"
    return result


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
