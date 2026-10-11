import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from manifest import digest, update_environment, validate, write_json


class Deployment:
    def __init__(self, manifest, root="/opt/foundation", env="/etc/foundation/v1.env", schema_change=False):
        self.manifest = validate(manifest)
        self.root, self.env = Path(root), Path(env)
        self.directory = self.root / "releases" / manifest["commit"]
        self.schema_change = schema_change
        self.previous = self.env.read_bytes()
        self.compose_path = self.root / "v1" / "compose.yaml"
        self.previous_compose = self.compose_path.read_bytes()
        self.changed_schema = False

    def run(self, *command, **kwargs):
        try:
            return subprocess.run(command, check=True, capture_output=True, **kwargs).stdout
        except subprocess.CalledProcessError as error:
            if error.stderr: sys.stderr.write(error.stderr.decode(errors="replace"))
            raise

    def compose(self, *args):
        return self.run("docker", "compose", "--file", str(self.compose_path), "--project-directory", str(self.root / "v1"),
                        "--env-file", str(self.env), "--project-name", "foundation-v1", *args)

    def persist(self, content, path=None):
        path = path or self.env
        stat = path.stat()
        descriptor, name = tempfile.mkstemp(prefix=".foundation-release-", dir=path.parent)
        try:
            os.fchmod(descriptor, stat.st_mode & 0o777)
            os.fchown(descriptor, stat.st_uid, stat.st_gid)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name): os.unlink(name)

    def image_file(self, image, name):
        container = self.run("docker", "create", image).decode().strip()
        try:
            target = self.directory / ("candidate-" + name.rsplit("/", 1)[-1])
            self.run("docker", "cp", container + ":" + name, str(target))
            return target
        finally:
            self.run("docker", "rm", "-v", container)

    def verify(self):
        output = self.run("docker", "exec", "foundation-v1-foundation-1", "node", "/app/deploy/release/smoke.mjs")
        print(output.decode(), end="", flush=True)

    def execute(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        state = self.directory / "state.json"
        if state.exists() and json.loads(state.read_text()).get("verified"):
            actual = self.run("docker", "inspect", "--format", '{{index .Config.Labels "org.opencontainers.image.revision"}}',
                              "foundation-v1-foundation-1").decode().strip()
            if actual == self.manifest["commit"]:
                print(json.dumps({"verified": True, "reused": True, "commit": actual})); return
        image = self.manifest["image"]
        self.run("docker", "pull", image)
        labels = json.loads(self.run("docker", "image", "inspect", "--format", "{{json .Config.Labels}}", image))
        if labels.get("org.opencontainers.image.revision") != self.manifest["commit"]:
            raise RuntimeError("The server image belongs to another commit.")
        cli = self.image_file(image, "/app/release/cli.mjs")
        schema = self.image_file(image, "/app/dist/server/schema.sql")
        compose = self.image_file(image, "/app/compose.yaml")
        if digest(cli) != self.manifest["cliSha256"] or digest(schema) != self.manifest["schemaSha256"]:
            raise RuntimeError("The image does not contain the verified release artifacts.")
        previous_schema = self.run("docker", "exec", "foundation-v1-foundation-1", "cat", "/app/dist/server/schema.sql")
        self.changed_schema = hashlib.sha256(previous_schema).hexdigest() != self.manifest["schemaSha256"]
        if self.changed_schema and not self.schema_change:
            raise RuntimeError("Database schema changes require an explicit migration release.")
        (self.directory / "previous.env").write_bytes(self.previous)
        (self.directory / "previous.env").chmod(0o600)
        (self.directory / "previous-compose.yaml").write_bytes(self.previous_compose)
        (self.directory / "previous-compose.yaml").chmod(0o600)
        if self.changed_schema:
            backup = self.directory / "database.dump"
            with backup.open("wb") as stream:
                backup.chmod(0o600)
                subprocess.run(["docker", "exec", "foundation-v1-postgres-1", "pg_dump", "-U", "foundation", "-d", "foundation", "-Fc"],
                               check=True, stdout=stream, stderr=subprocess.PIPE)
            if not backup.stat().st_size: raise RuntimeError("The database backup is empty.")
        write_json(self.directory / "manifest.json", self.manifest)
        try:
            self.persist(update_environment(self.previous.decode(), {"FOUNDATION_IMAGE": image,
                "FOUNDATION_ENV_FILE": str(self.env), **self.manifest["environment"]}).encode())
            self.persist(compose.read_bytes(), self.compose_path)
            self.compose("up", "-d", "--no-build", "--no-deps", "--wait", "--wait-timeout", "180", "foundation")
            self.verify()
            ready = {**self.manifest, "verifiedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            self.run("docker", "exec", "-i", "foundation-v1-foundation-1", "node", "--input-type=module", "-e",
                     "import{writeFile,rename}from'node:fs/promises';let s='';for await(const c of process.stdin)s+=c;"
                     "const p=process.env.FOUNDATION_DATA+'/release.json';await writeFile(p+'.tmp',s,{mode:384});await rename(p+'.tmp',p);",
                     input=json.dumps(ready).encode())
            write_json(state, {"verified": True, "commit": self.manifest["commit"], "verifiedAt": ready["verifiedAt"]})
            print(json.dumps({"verified": True, "commit": self.manifest["commit"]}))
        except Exception:
            if not self.changed_schema:
                self.persist(self.previous)
                self.persist(self.previous_compose, self.compose_path)
                self.compose("up", "-d", "--no-build", "--no-deps", "--wait", "--wait-timeout", "180", "foundation")
                print(json.dumps({"rollback": "complete", "failedCommit": self.manifest["commit"]}), flush=True)
            else:
                print(json.dumps({"migrationFailed": True, "backup": str(self.directory / "database.dump"),
                                  "automaticDatabaseRestore": False}), flush=True)
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--allow-schema-change", action="store_true")
    args = parser.parse_args()
    lock_path = Path("/opt/foundation/releases/deploy.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        Deployment(json.loads(Path(args.manifest).read_text()), schema_change=args.allow_schema_change).execute()


if __name__ == "__main__":
    main()
