import base64
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import update_agent


class AgentUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.executable = self.root / 'package/dist/agent.mjs'
        self.executable.parent.mkdir(parents=True)
        self.executable.write_bytes(b'previous-cli')
        self.metadata = self.executable.parent.parent / 'package.json'
        self.metadata.write_bytes(b'{"version":"5.0.1"}')
        self.identity = self.root / 'foundation/identity.json'
        self.identity.parent.mkdir()
        self.identity.write_text(json.dumps({'current': 'executor', 'identities': [{
            'principalId': 'executor', 'origin': 'https://example.com', 'token': 'test-only-token', 'keys': 'retained-test-keys'}]}))
        self.saved_identity = self.identity.read_bytes()
        self.code = b'updated-cli'
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            for name, content in [('package/dist/agent.mjs', self.code), ('package/package.json', b'{"version":"5.1.0"}')]:
                info = tarfile.TarInfo(name); info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        self.packed = buffer.getvalue()
        self.calls, self.started, self.busy = [], False, False

    def tearDown(self):
        self.temporary.cleanup()

    def request(self, url, body=None, token=None):
        if url.endswith('/api/release'):
            return {'cliVersion': '5.1.0', 'agentSha256': hashlib.sha256(self.code).hexdigest()}
        if url.startswith('https://registry.npmjs.org/'):
            return {'dist': {'tarball': 'https://registry.npmjs.org/package.tgz',
                'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(self.packed).digest()).decode()}}
        self.calls.append(body)
        return {'active': int(self.busy), 'sshSessions': 0, 'heartbeatAt': 'new' if self.started else 'previous'}

    def service_command(self, command, **kwargs):
        if 'start' in command: self.started = True
        return subprocess.CompletedProcess(command, 0)

    def update(self, run=None, monotonic=None):
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(self.root)}), \
             patch.object(sys, 'argv', ['update-agent.py', '--environment', 'environment', '--service', 'agent.service']), \
             patch.object(update_agent, 'request', self.request), \
             patch.object(update_agent.shutil, 'which', return_value=str(self.executable)), \
             patch.object(update_agent.urllib.request, 'urlopen', return_value=io.BytesIO(self.packed)), \
             patch.object(update_agent.subprocess, 'run', run or self.service_command), \
             patch.object(update_agent.subprocess, 'check_output', return_value='5.1.0\n'), \
             patch.object(update_agent.time, 'monotonic', side_effect=monotonic, return_value=0):
            update_agent.main()

    def test_updates_the_agent_after_reconnection_and_preserves_identity(self):
        self.update()
        self.assertEqual(self.executable.read_bytes(), self.code)
        self.assertEqual(self.identity.read_bytes(), self.saved_identity)
        self.assertEqual(self.calls[-1], {'paused': False})

    def test_defers_a_busy_environment_and_resumes_claiming(self):
        self.busy = True
        self.update(monotonic=[0, 61])
        self.assertEqual(self.executable.read_bytes(), b'previous-cli')
        self.assertFalse(self.started)
        self.assertEqual(self.calls[-1], {'paused': False})

    def test_restores_the_previous_cli_when_the_updated_service_fails(self):
        def run(command, **kwargs):
            if 'is-active' in command: raise subprocess.CalledProcessError(1, command)
            return self.service_command(command, **kwargs)
        with self.assertRaises(subprocess.CalledProcessError): self.update(run=run)
        self.assertEqual(self.executable.read_bytes(), b'previous-cli')
        self.assertEqual(self.metadata.read_bytes(), b'{"version":"5.0.1"}')
        self.assertEqual(self.identity.read_bytes(), self.saved_identity)
        self.assertEqual(self.calls[-1], {'paused': False})

    def test_keeps_the_current_agent_while_production_verification_is_pending(self):
        with patch.object(self, 'request', side_effect=urllib.error.HTTPError('https://example.com/api/release', 503, 'Pending', {}, None)):
            self.update()
        self.assertEqual(self.executable.read_bytes(), b'previous-cli')
        self.assertEqual(self.identity.read_bytes(), self.saved_identity)

    def test_keeps_the_current_agent_while_cli_publication_is_pending(self):
        original = self.request
        def pending(url, body=None, token=None):
            if url.startswith('https://registry.npmjs.org/'):
                raise urllib.error.HTTPError(url, 404, 'Not published', {}, None)
            return original(url, body, token)
        with patch.object(self, 'request', pending): self.update()
        self.assertEqual(self.executable.read_bytes(), b'previous-cli')
        self.assertEqual(self.identity.read_bytes(), self.saved_identity)


if __name__ == '__main__':
    unittest.main()
