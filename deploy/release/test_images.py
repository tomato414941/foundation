import subprocess
import unittest
from unittest.mock import Mock

from images import registry_command


class RegistryTests(unittest.TestCase):
    def result(self, code, output):
        return subprocess.CompletedProcess(["docker", "pull", "test-image"], code, output)

    def test_retries_rate_limited_image_download_and_completes(self):
        run = Mock(side_effect=[self.result(1, "toomanyrequests: Rate exceeded\n"), self.result(0, "Downloaded\n")])
        sleep = Mock()
        registry_command(["docker", "pull", "test-image"], run=run, sleep=sleep)
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(5)

    def test_reports_registry_failure_after_bounded_retries(self):
        run = Mock(return_value=self.result(1, "unexpected status: 503 Service Unavailable\n"))
        sleep = Mock()
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            registry_command(["docker", "pull", "test-image"], attempts=3, run=run, sleep=sleep)
        self.assertIn("503", failure.exception.output)
        self.assertEqual(run.call_count, 3)
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 10])

    def test_reports_an_unknown_image_without_retrying(self):
        run = Mock(return_value=self.result(1, "manifest unknown: Requested image not found\n"))
        sleep = Mock()
        with self.assertRaises(subprocess.CalledProcessError):
            registry_command(["docker", "pull", "test-image"], run=run, sleep=sleep)
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()

    def test_reports_a_build_failure_without_retrying(self):
        run = Mock(return_value=self.result(1, "Type error: Cannot assign string to number\n"))
        sleep = Mock()
        with self.assertRaises(subprocess.CalledProcessError):
            registry_command(["docker", "build", "."], run=run, sleep=sleep)
        self.assertEqual(run.call_count, 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
