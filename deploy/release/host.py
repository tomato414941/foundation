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


KEPT_IMAGES = 3
# What a server that still opens items sealed in the earlier form has, and what one that no longer opens them lacks.
EARLIER_FORM_READER = "/app/dist/shared/custody-legacy.js"
# Items still sealed in the earlier form that a device could open and seal again: one of the keys they are sealed for is
# the current key of a principal that is also among their authorities.
RESEALABLE_EARLIER_ITEMS = (
    "SELECT count(*) FROM resource_custody c WHERE c.content->'policy'->>'format' IS DISTINCT FROM '3' AND EXISTS ("
    "SELECT 1 FROM jsonb_array_elements(c.content->'policy'->'readers') r "
    "JOIN jsonb_array_elements(c.content->'policy'->'authorities') a ON a->>'id' = r->>'id' "
    "JOIN principal_key_bindings b ON b.binding->>'id' = r->>'id' AND b.retired_at IS NULL)")


class Deployment:
    def __init__(self, manifest, root="/opt/foundation", env="/etc/foundation/v1.env", schema_change=False, expected_current=None,
                 leave_earlier_items=0):
        if leave_earlier_items < 0: raise ValueError("Leave no fewer than zero items in the earlier form.")
        self.manifest = validate(manifest)
        self.leave_earlier_items = leave_earlier_items
        self.root, self.env = Path(root), Path(env)
        self.directory = self.root / "releases" / manifest["commit"]
        self.schema_change = schema_change
        self.expected_current = expected_current
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

    def prune_images(self):
        # Keep the newest releases for a quick rollback and remove older images so the disk does not fill up.
        repository = self.manifest["image"].split("@", 1)[0]
        listed = self.run("docker", "images", "--no-trunc", "--format", "{{.ID}}", repository).decode().split()
        current = self.run("docker", "image", "inspect", "--format", "{{.Id}}", self.manifest["image"]).decode().strip()
        kept = [current] + [image for image in dict.fromkeys(listed) if image != current][:KEPT_IMAGES - 1]
        for image in dict.fromkeys(listed):
            if image in kept: continue
            try:
                self.run("docker", "image", "rm", image)
            except subprocess.CalledProcessError:
                pass

    def verify(self):
        output = self.run("docker", "exec", "foundation-v1-foundation-1", "node", "/app/deploy/release/smoke.mjs")
        print(output.decode(), end="", flush=True)

    def opens_earlier_form(self, image=None):
        # Whether the running server, or the one in the image, still opens items sealed in the earlier form.
        if image is None:
            return subprocess.run(["docker", "exec", "foundation-v1-foundation-1", "test", "-e", EARLIER_FORM_READER],
                                  capture_output=True).returncode == 0
        container = self.run("docker", "create", image).decode().strip()
        try:
            return subprocess.run(["docker", "cp", container + ":" + EARLIER_FORM_READER, "-"], capture_output=True).returncode == 0
        finally:
            self.run("docker", "rm", "-v", container)

    def resealable_earlier_items(self):
        return int(self.run("docker", "exec", "-e", "PGOPTIONS=-c default_transaction_read_only=on", "foundation-v1-postgres-1",
                            "psql", "-U", "foundation", "-d", "foundation", "-At", "-c", RESEALABLE_EARLIER_ITEMS).decode().strip())

    def check_earlier_items(self, image):
        # A release that stops opening items sealed in the earlier form waits while their owners' devices could still seal
        # some of them again, apart from those its operator chose to leave unopened.
        if not self.opens_earlier_form() or self.opens_earlier_form(image): return
        count = self.resealable_earlier_items()
        if count > self.leave_earlier_items:
            raise RuntimeError(str(count) + " item(s) sealed in the earlier form can still be opened and sealed again by their owners' "
                               "devices. Seal them again before this release, or leave them with leave_earlier_items.")

    def execute(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.expected_current:
            actual = self.run("docker", "inspect", "--format", '{{index .Config.Labels "org.opencontainers.image.revision"}}',
                              "foundation-v1-foundation-1").decode().strip()
            if actual not in [self.expected_current, self.manifest["commit"]]:
                raise RuntimeError("Another release was deployed while this release waited. Rerun to compare the current commit.")
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
        self.check_earlier_items(image)
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
                "FOUNDATION_ENV_FILE": str(self.env)}).encode())
            self.persist(compose.read_bytes(), self.compose_path)
            self.compose("run", "--rm", "--no-deps", "foundation", "node", "dist/server/migrate.js")
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
        try:
            self.prune_images()
        except Exception as error:
            print(json.dumps({"imagePruneFailed": str(error)}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--allow-schema-change", action="store_true")
    parser.add_argument("--expected-current", required=True)
    parser.add_argument("--leave-earlier-items", type=int, default=0)
    args = parser.parse_args()
    lock_path = Path("/opt/foundation/releases/deploy.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        Deployment(json.loads(Path(args.manifest).read_text()), schema_change=args.allow_schema_change,
                   expected_current=args.expected_current, leave_earlier_items=args.leave_earlier_items).execute()


if __name__ == "__main__":
    main()
