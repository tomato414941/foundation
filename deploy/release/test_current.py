import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CurrentReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.head = self.directory / "main"
        self.head.write_text("a" * 40)
        self.production = self.directory / "production"
        self.production.write_text("running release")
        self.output = self.directory / "output"
        gh = self.directory / "gh"
        gh.write_text("#!" + sys.executable + "\n" +
            "import os,sys\nfrom pathlib import Path\n" +
            "if os.environ.get('TEST_GITHUB_UNAVAILABLE'): sys.exit(1)\n" +
            "print(Path(os.environ['TEST_MAIN_HEAD']).read_text())\n")
        gh.chmod(0o700)
        self.environment = {**os.environ, "PATH": str(self.directory) + os.pathsep + os.environ["PATH"],
            "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "example/project",
            "GITHUB_OUTPUT": str(self.output), "TEST_MAIN_HEAD": str(self.head)}
        self.publish = [sys.executable, "-c",
            "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('candidate release')", str(self.production)]

    def run_guard(self, command=()):
        self.output.write_text("")
        return subprocess.run([sys.executable, str(Path(__file__).with_name("current.py")), "--", *command],
            env=self.environment, capture_output=True, text=True, timeout=10)

    def test_publishes_the_commit_at_the_head_of_main(self):
        result = self.run_guard(self.publish)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.production.read_text(), "candidate release")
        self.assertEqual(self.output.read_text(), "current=true\n")

    def test_preserves_production_when_the_release_is_older_than_main(self):
        self.head.write_text("b" * 40)
        result = self.run_guard(self.publish)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.production.read_text(), "running release")
        self.assertEqual(self.output.read_text(), "current=false\nobsolete=true\n")
        self.assertIn("Skipping release", result.stdout)

    def test_rechecks_main_before_publishing_after_an_earlier_successful_check(self):
        self.assertEqual(self.run_guard().returncode, 0)
        self.assertEqual(self.output.read_text(), "current=true\n")
        self.head.write_text("b" * 40)
        result = self.run_guard(self.publish)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.production.read_text(), "running release")
        self.assertEqual(self.output.read_text(), "current=false\nobsolete=true\n")

    def test_preserves_production_when_github_cannot_be_read(self):
        self.environment["TEST_GITHUB_UNAVAILABLE"] = "1"
        result = self.run_guard(self.publish)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.production.read_text(), "running release")
        self.assertEqual(self.output.read_text(), "")

    def test_preserves_production_when_github_returns_an_incomplete_commit(self):
        for head in ["", "null", "a" * 7]:
            with self.subTest(head=head):
                self.head.write_text(head)
                result = self.run_guard(self.publish)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.production.read_text(), "running release")
                self.assertEqual(self.output.read_text(), "")

    def test_requires_a_complete_release_commit_before_publishing(self):
        self.environment["GITHUB_SHA"] = "a" * 7
        result = self.run_guard(self.publish)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.production.read_text(), "running release")
        self.assertEqual(self.output.read_text(), "")

    def test_returns_the_publication_failure(self):
        result = self.run_guard([sys.executable, "-c", "raise SystemExit(42)"])
        self.assertEqual(result.returncode, 42)
        self.assertEqual(self.output.read_text(), "current=true\n")


if __name__ == "__main__":
    unittest.main()
