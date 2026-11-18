import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from host import Deployment
from manifest import digest, update_environment


class SimulatedDeployment(Deployment):
    def __init__(self, *args, fail=False, old_schema=None, running_commit=None, running_opens=False, image_opens=False,
                 resealable=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.fail, self.old_schema = fail, old_schema or b"schema"
        self.running_opens, self.image_opens, self.resealable = running_opens, image_opens, resealable
        self.applied, self.removed = [], []
        self.images = ["sha256:new", "sha256:previous", "sha256:older", "sha256:oldest", "sha256:ancient"]
        self.running_commit = running_commit or self.manifest["commit"]

    def run(self, *command, **kwargs):
        if command[:2] == ("docker", "images"):
            return "\n".join(self.images).encode()
        if command[:3] == ("docker", "image", "inspect") and "{{.Id}}" in command:
            return b"sha256:new"
        if command[:3] == ("docker", "image", "rm"):
            self.removed.append(command[3]); return b""
        if command[:3] == ("docker", "image", "inspect"):
            return json.dumps({"org.opencontainers.image.revision": self.manifest["commit"]}).encode()
        if command[:2] == ("docker", "inspect"):
            return self.running_commit.encode()
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

    def opens_earlier_form(self, image=None):
        return self.running_opens if image is None else self.image_opens

    def resealable_earlier_items(self):
        return self.resealable


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
            "schemaSha256": hashlib.sha256(b"schema").hexdigest(),
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

    def test_keeps_the_newest_three_images_and_removes_older_ones_after_deploying(self):
        deployment = self.deployment()
        deployment.execute()
        self.assertEqual(deployment.removed, ["sha256:oldest", "sha256:ancient"])

    def test_keeps_every_image_when_verification_fails(self):
        deployment = self.deployment(fail=True)
        with self.assertRaises(RuntimeError):
            deployment.execute()
        self.assertEqual(deployment.removed, [])

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

    def test_stops_before_changing_production_when_it_would_stop_opening_items_devices_can_still_seal_again(self):
        deployment = self.deployment(running_opens=True, resealable=3, leave_earlier_items=2)
        with self.assertRaisesRegex(RuntimeError, "3 item\\(s\\) sealed in the earlier form"):
            deployment.execute()
        self.assertEqual(self.env.read_text(), self.original)
        self.assertEqual(deployment.applied, [])
        self.assertFalse((deployment.directory / "previous.env").exists())

    def test_leaves_the_earlier_items_its_operator_chose_to_leave(self):
        self.deployment(running_opens=True, resealable=2, leave_earlier_items=2).execute()
        self.assertIn(self.manifest["image"], self.env.read_text())

    def test_releases_without_counting_earlier_items_while_the_new_server_still_opens_them(self):
        self.deployment(running_opens=True, image_opens=True, resealable=5).execute()
        self.assertIn(self.manifest["image"], self.env.read_text())

    def test_releases_without_counting_earlier_items_once_the_running_server_no_longer_opens_them(self):
        self.deployment(resealable=5).execute()
        self.assertIn(self.manifest["image"], self.env.read_text())

    def test_reuses_completed_deployment_when_retrying_publication(self):
        first = self.deployment(); first.execute()
        retry = self.deployment(); retry.execute()
        self.assertEqual(len(retry.applied), 0)

    def test_replaces_an_exported_image_setting(self):
        value = update_environment("A=first\nexport FOUNDATION_IMAGE='old'\nB=last\n", {"FOUNDATION_IMAGE": "new"})
        self.assertEqual(value, "A=first\nFOUNDATION_IMAGE=new\nB=last\n")

    def test_preserves_a_release_deployed_while_waiting_for_the_host_lock(self):
        deployment = self.deployment(expected_current="b" * 40, running_commit="c" * 40)
        with self.assertRaisesRegex(RuntimeError, "Another release was deployed"):
            deployment.execute()
        self.assertEqual(self.env.read_text(), self.original)
        self.assertEqual(deployment.applied, [])


if __name__ == "__main__":
    unittest.main()
