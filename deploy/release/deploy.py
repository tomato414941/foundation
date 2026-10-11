import argparse
import base64
import io
import json
import os
import re
from pathlib import Path
import subprocess
import tarfile
import time

from manifest import validate


def aws(*args):
    return json.loads(subprocess.check_output(["aws", *args, "--output", "json"], text=True))


def invocation(instance, commands, timeout=1200):
    command = aws("ssm", "send-command", "--instance-ids", instance, "--document-name", "AWS-RunShellScript",
                  "--parameters", json.dumps({"commands": commands, "executionTimeout": [str(timeout)]}),
                  "--comment", "Foundation verified release")
    command_id = command["Command"]["CommandId"]
    print("SSM command: " + command_id, flush=True)
    deadline = time.monotonic() + timeout + 60
    while time.monotonic() < deadline:
        time.sleep(3)
        try:
            result = aws("ssm", "get-command-invocation", "--command-id", command_id, "--instance-id", instance)
        except subprocess.CalledProcessError:
            continue
        if result["Status"] in ["Pending", "InProgress", "Delayed"]: continue
        print(result["StandardOutputContent"], end="", flush=True)
        if result["Status"] != "Success" or result.get("ResponseCode") != 0:
            raise RuntimeError("Deployment command failed: " + result["Status"] + "\n" + result["StandardErrorContent"])
        return result["StandardOutputContent"]
    raise RuntimeError("The deployment is still running. Inspect SSM " + command_id + " before retrying.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--allow-schema-change", action="store_true")
    args = parser.parse_args()
    manifest = validate(json.loads(Path(args.manifest).read_text()))
    instance = os.environ["FOUNDATION_INSTANCE_ID"]
    current = invocation(instance, ["docker inspect --format '{{index .Config.Labels \"org.opencontainers.image.revision\"}}' foundation-v1-foundation-1"], 60).strip()
    if not re.fullmatch(r"[a-f0-9]{40}", current):
        raise RuntimeError("The running container must identify its complete source commit.")
    if current != manifest["commit"]:
        result = subprocess.run(["git", "merge-base", "--is-ancestor", current, manifest["commit"]])
        if result.returncode == 1:
            if os.environ.get('GITHUB_OUTPUT'):
                with open(os.environ['GITHUB_OUTPUT'], 'a') as output: output.write('obsolete=true\n')
            print("Skipping an obsolete release; production already contains a later commit."); return
        if result.returncode: raise RuntimeError("The deployed commit could not be compared with this release.")
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as packed:
        for name in ["host.py", "manifest.py"]:
            packed.add(Path(__file__).with_name(name), arcname=name)
        value = json.dumps(manifest).encode()
        info = tarfile.TarInfo("manifest.json"); info.size = len(value); info.mode = 0o600
        packed.addfile(info, io.BytesIO(value))
    encoded = base64.b64encode(archive.getvalue()).decode()
    directory = "/opt/foundation/releases/" + manifest["commit"] + "/installer"
    script = "set -eu\numask 077\nmkdir -p '" + directory + "'\nprintf '%s' '" + encoded + "' | base64 -d | tar -xz -C '" + directory + "'\n"
    script += "python3 '" + directory + "/host.py' '" + directory + "/manifest.json' --expected-current '" + current + "'" + (" --allow-schema-change" if args.allow_schema_change else "")
    invocation(instance, [script])


if __name__ == "__main__":
    main()
