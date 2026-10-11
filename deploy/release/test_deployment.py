import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from host import Deployment
from manifest import digest, update_environment


class SimulatedDeployment(Deployment):
    def __init__(self, *args, fail=False, old_schema=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fail, self.old_schema = fail, old_schema or b"schema"
        self.applied = []

    def run(self, *command, **kwargs):
        if command[:3] == ("docker", "image", "inspect"):
            return json.dumps({"org.opencontainers.image.revision": self.manifest["commit"]}).encode()
        if command[:2] == ("docker", "inspect"):
            return self.manifest["commit"].encode()
        if "cat" in command: return self.old_schema
        return b""

    def image_file(self, image, name):
        target = self.directory / name.rsplit("/", 1)[-1]
        target.write_bytes(b"schema" if name.endswith("schema.sql") else b"compose" if name.endswith("compose.yaml") else b"cli")
        return target

    def compose(self, *args):
        self.applied.append(self.env.read_text())

    def verify(self):
        if self.fail: raise RuntimeError("The function failed.")


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.env = self.root / "v1.env"
        self.original = "TOKEN='private-test-only'\nFOUNDATION_IMAGE=previous\n"
        self.env.write_text(self.original)
        self.env.chmod(0o600)
        (self.root / "v1").mkdir()
        (self.root / "v1/compose.yaml").write_bytes(b"previous compose")
        self.manifest = {
            "commit": "a" * 40, "image": "ghcr.io/tomato414941/foundation@sha256:" + "b" * 64,
            "cliVersion": "5.1.0", "cliSha256": hashlib.sha256(b"cli").hexdigest(),
            "schemaSha256": hashlib.sha256(b"schema").hexdigest(), "runtimeSha256": "c" * 64,
            "environment": {"EC2_ENVIRONMENT_AMI": "ami-123", "EC2_ENVIRONMENT_VPC": "vpc-123",
                "EC2_ENVIRONMENT_ACL": "acl-123", "EC2_ENVIRONMENT_DEFAULT_ACL": "acl-456",
                "EC2_ENVIRONMENT_ROUTE_TABLE": "rtb-123", "EC2_ENVIRONMENT_ZONE": "ap-northeast-1a",
                "ENVIRONMENT_COMMAND_IMAGE": "docker.io/library/node@sha256:" + "d" * 64},
        }

    def tearDown(self):
        self.temporary.cleanup()

    def deployment(self, **kwargs):
        return SimulatedDeployment(self.manifest, root=self.root, env=self.env, **kwargs)

    def test_deploys_verified_artifacts_and_preserves_private_settings(self):
        deployment = self.deployment()
        deployment.execute()
        self.assertIn("TOKEN='private-test-only'", self.env.read_text())
        self.assertIn(self.manifest["image"], self.env.read_text())
        self.assertTrue(json.loads((deployment.directory / "state.json").read_text())["verified"])
        self.assertEqual((deployment.directory / "previous.env").read_text(), self.original)

    def test_restores_previous_image_and_configuration_after_verification_failure(self):
        deployment = self.deployment(fail=True)
        with self.assertRaisesRegex(RuntimeError, "function failed"):
            deployment.execute()
        self.assertEqual(self.env.read_text(), self.original)
        self.assertEqual(deployment.applied[-1], self.original)
        self.assertEqual((self.root / "v1/compose.yaml").read_bytes(), b"previous compose")

    def test_requires_a_migration_release_for_changed_database_schema(self):
        with self.assertRaisesRegex(RuntimeError, "explicit migration"):
            self.deployment(old_schema=b"previous schema").execute()
        self.assertEqual(self.env.read_text(), self.original)

    def test_reuses_completed_deployment_when_retrying_publication(self):
        first = self.deployment(); first.execute()
        retry = self.deployment(); retry.execute()
        self.assertEqual(len(retry.applied), 0)

    def test_replaces_an_exported_image_setting(self):
        value = update_environment("A=first\nexport FOUNDATION_IMAGE='old'\nB=last\n", {"FOUNDATION_IMAGE": "new"})
        self.assertEqual(value, "A=first\nFOUNDATION_IMAGE=new\nB=last\n")


if __name__ == "__main__":
    unittest.main()
