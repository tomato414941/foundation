from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from build import store_artifact


class ArtifactTests(unittest.TestCase):
    def uploaded(self, content):
        def run(command, **kwargs):
            if 'put-object' in command:
                return subprocess.CompletedProcess(command, 1, '', 'PreconditionFailed')
            Path(command[-1]).write_bytes(content)
            return subprocess.CompletedProcess(command, 0)
        return run

    def test_reuses_a_completed_upload_when_retrying_a_release(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cli.tgz'; path.write_bytes(b'tested distribution')
            with patch('build.subprocess.run', self.uploaded(b'tested distribution')):
                store_artifact('test-bucket', 'release/cli.tgz', path)
            self.assertEqual(path.read_bytes(), b'tested distribution')

    def test_rejects_replacement_of_an_existing_immutable_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'cli.tgz'; path.write_bytes(b'changed distribution')
            with patch('build.subprocess.run', self.uploaded(b'tested distribution')):
                with self.assertRaisesRegex(RuntimeError, 'different contents'):
                    store_artifact('test-bucket', 'release/cli.tgz', path)


if __name__ == '__main__':
    unittest.main()
