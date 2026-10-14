import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

from manifest import digest, validate, write_json


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def aws(*args):
    return json.loads(run("aws", *args, "--output", "json"))


def read_object(bucket, key):
    listed = aws("s3api", "list-objects-v2", "--bucket", bucket, "--prefix", key, "--max-keys", "1")
    if not any(value["Key"] == key for value in listed.get("Contents", [])): return None
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory) / "object.json"
        result = subprocess.run(["aws", "s3api", "get-object", "--bucket", bucket, "--key", key, str(target)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError("The release artifact store could not be read: " + result.stderr)
        return json.loads(target.read_text())


def runtime_digest():
    data = hashlib.sha256()
    for name in ["cli/dist/cli.mjs", "deploy/environment/install.sh", "deploy/environment/ssh-session.sh",
                 "deploy/environment/foundation-environment.service"]:
        data.update(name.encode() + b"\0" + Path(name).read_bytes() + b"\0")
    data.update(os.environ["ENVIRONMENT_FUNCTION_IMAGE"].encode())
    return data.hexdigest()


def check_package(directory, manifest):
    with tarfile.open(directory / "cli.tgz", "r:gz") as archive:
        pkg = json.load(archive.extractfile("package/package.json"))
        allowed = {"package/package.json", "package/LICENSE", *("package/" + name for name in pkg["files"])}
        if not set(archive.getnames()).issubset(allowed) or "package/LICENSE" not in archive.getnames():
            raise RuntimeError("The package includes files outside the CLI distribution or is missing its license.")
        code = archive.extractfile("package/dist/cli.mjs").read()
        if pkg["name"] != "@tomato414941/foundation" or pkg["version"] != manifest["cliVersion"] or \
            hashlib.sha256(code).hexdigest() != manifest["cliSha256"]:
            raise RuntimeError("The CLI package does not match this release.")
    prefix = directory / "installed"
    subprocess.run(["npm", "install", "--global", "--offline", "--ignore-scripts", "--no-audit", "--no-fund",
                    "--prefix", str(prefix.resolve()), str((directory / "cli.tgz").resolve())], check=True)
    if run(str(prefix.resolve() / "bin/foundation"), "--version") != manifest["cliVersion"]:
        raise RuntimeError("The installed CLI version does not match the release.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--existing-only", action="store_true")
    args = parser.parse_args()
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    commit = run("git", "rev-parse", "HEAD")
    bucket = os.environ["FOUNDATION_BUCKET"]
    existing = read_object(bucket, "foundation-releases/" + commit + "/manifest.json")
    if existing:
        validate(existing)
        if existing["commit"] != commit: raise RuntimeError("The stored release belongs to another commit.")
        write_json(directory / "manifest.json", existing)
        subprocess.run(["aws", "s3", "cp", "s3://" + bucket + "/foundation-releases/" + commit + "/cli.tgz", str(directory / "cli.tgz"), "--only-show-errors"], check=True)
        check_package(directory, existing)
        print("Reusing the immutable artifacts for " + commit)
        return
    if args.existing_only:
        raise RuntimeError("This commit has no prepared release. Rerun the original release workflow.")
    runtime = runtime_digest()
    key = "foundation-releases/environments/" + runtime + ".json"
    environment = read_object(bucket, key)
    if environment:
        found = aws("ec2", "describe-images", "--image-ids", environment["EC2_ENVIRONMENT_AMI"], "--owners", "self").get("Images", [])
        if not found or found[0]["State"] != "available":
            environment = None
    if not environment:
        process = subprocess.Popen(["node", "--import", "tsx", "deploy/environment/build-image.ts"], stdout=subprocess.PIPE, text=True)
        environment = {}
        for line in process.stdout:
            line = line.rstrip()
            print(line, flush=True)
            if line.startswith("EC2_ENVIRONMENT_") or line.startswith("ENVIRONMENT_FUNCTION_IMAGE="):
                name, value = line.split("=", 1)
                environment[name] = value
        if process.wait():
            raise RuntimeError("The execution environment image could not be built.")
        cache = directory / "environment.json"
        write_json(cache, environment)
        subprocess.run(["aws", "s3api", "put-object", "--bucket", bucket, "--key", key, "--body", str(cache), "--server-side-encryption", "AES256"], check=True, stdout=subprocess.DEVNULL)
    pkg = json.loads(Path("cli/package.json").read_text())
    subprocess.run(["npm", "pack", "--ignore-scripts", "--pack-destination", str(directory.resolve()), "./cli"], check=True, stdout=subprocess.DEVNULL)
    packed = directory / (pkg["name"].replace("@", "").replace("/", "-") + "-" + pkg["version"] + ".tgz")
    packed.rename(directory / "cli.tgz")
    manifest = {
        "commit": commit, "cliVersion": pkg["version"], "cliSha256": digest("cli/dist/cli.mjs"),
        "schemaSha256": digest("server/schema.sql"), "runtimeSha256": runtime, "environment": environment,
    }
    check_package(directory, manifest)
    write_json(directory / "build.json", manifest)


if __name__ == "__main__":
    main()
