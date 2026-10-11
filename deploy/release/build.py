import argparse
import json
import os
from pathlib import Path
import subprocess

from manifest import digest, validate, write_json
from images import pull_image, registry_command


def store_artifact(bucket, key, path):
    result = subprocess.run(["aws", "s3api", "put-object", "--bucket", bucket, "--key", key,
                             "--body", str(path), "--server-side-encryption", "AES256", "--if-none-match", "*"],
                            capture_output=True, text=True)
    if result.returncode == 0: return
    if "PreconditionFailed" not in result.stderr: raise RuntimeError(result.stderr)
    # A retry may encounter a completed upload from an interrupted release.
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        previous = Path(directory) / "artifact"
        subprocess.run(["aws", "s3api", "get-object", "--bucket", bucket, "--key", key, str(previous)],
                       check=True, stdout=subprocess.DEVNULL)
        if digest(previous) != digest(path):
            raise RuntimeError("An immutable release artifact already exists with different contents: " + key)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    args = parser.parse_args()
    directory = Path(args.directory)
    target = directory / "manifest.json"
    if target.exists():
        validate(json.loads(target.read_text())); return
    manifest = json.loads((directory / "build.json").read_text())
    image = "ghcr.io/tomato414941/foundation:" + manifest["commit"]
    registry_command(["docker", "build", "--platform", "linux/arm64", "--label", "org.opencontainers.image.revision=" + manifest["commit"],
                      "--build-arg", "FOUNDATION_RELEASE_COMMIT=" + manifest["commit"], "--tag", image, "."])
    # Test the final container with an ephemeral database and the packaged CLI.
    name = "release-" + manifest["commit"][:12]
    pull_image("public.ecr.aws/docker/library/postgres:18-alpine")
    subprocess.run(["docker", "network", "create", name], check=True, stdout=subprocess.DEVNULL)
    try:
        subprocess.run(["docker", "run", "-d", "--name", name + "-db", "--network", name,
                        "-e", "POSTGRES_USER=foundation", "-e", "POSTGRES_PASSWORD=release-test-only", "-e", "POSTGRES_DB=foundation",
                        "public.ecr.aws/docker/library/postgres:18-alpine"], check=True, stdout=subprocess.DEVNULL)
        import time
        for _ in range(30):
            if subprocess.run(["docker", "exec", name + "-db", "pg_isready", "-h", "127.0.0.1", "-U", "foundation"], capture_output=True).returncode == 0: break
            time.sleep(1)
        else: raise RuntimeError("The disposable database did not become ready.")
        subprocess.run(["docker", "run", "-d", "--name", name + "-app", "--network", name,
                        "-e", "DATABASE_URL=postgres://foundation:release-test-only@" + name + "-db:5432/foundation",
                        "-e", "FOUNDATION_ORIGIN=http://localhost:3417", "-e", "FOUNDATION_LOG_LEVEL=error", image], check=True, stdout=subprocess.DEVNULL)
        for _ in range(60):
            health = subprocess.run(["docker", "inspect", "--format", "{{.State.Health.Status}}", name + "-app"], capture_output=True, text=True)
            if health.stdout.strip() == "healthy": break
            time.sleep(2)
        else: raise RuntimeError("The packaged server did not become healthy.")
        subprocess.run(["docker", "exec", "-e", "RELEASE_SMOKE_MODE=attached", name + "-app", "node", "/app/deploy/release/smoke.mjs"], check=True)
    finally:
        for container in [name + "-app", name + "-db"]:
            subprocess.run(["docker", "rm", "-f", "-v", container], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", name], check=True, stdout=subprocess.DEVNULL)
    registry_command(["docker", "push", image])
    output = subprocess.check_output(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image], text=True)
    manifest["image"] = next(value for value in json.loads(output) if value.startswith("ghcr.io/tomato414941/foundation@"))
    validate(manifest)
    write_json(target, manifest)
    bucket = os.environ["FOUNDATION_BUCKET"]
    for file, key in [(directory / "cli.tgz", "cli.tgz"), (target, "manifest.json")]:
        store_artifact(bucket, "foundation-releases/" + manifest["commit"] + "/" + key, file)


if __name__ == "__main__":
    main()
