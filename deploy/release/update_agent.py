import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request


def request(url, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token: headers["Authorization"] = "Bearer " + token
    data = None if body is None else json.dumps(body).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=30) as response:
        return json.load(response)


def replace(path, content):
    stat = path.stat()
    descriptor, temporary = tempfile.mkstemp(prefix=".foundation-update-", dir=path.parent)
    try:
        os.fchmod(descriptor, stat.st_mode & 0o777)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    parser.add_argument("--service", required=True)
    args = parser.parse_args()
    path = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))) / "foundation" / "identity.json"
    identities = json.loads(path.read_text())
    identity = next(value for value in identities["identities"] if value["principalId"] == identities["current"])
    origin = identity["origin"]
    release = request(origin + "/api/release")
    executable = Path(shutil.which("foundation")).resolve()
    if hashlib.sha256(executable.read_bytes()).hexdigest() == release["cliSha256"]:
        print("The execution agent already uses the verified CLI."); return
    # Only the package selected by the verified production release may be installed.
    pkg = request("https://registry.npmjs.org/%40tomato414941%2Ffoundation/" + release["cliVersion"])
    url = pkg["dist"]["tarball"]
    if not url.startswith("https://registry.npmjs.org/"): raise ValueError("Unexpected package origin.")
    with urllib.request.urlopen(url, timeout=60) as response: packed = response.read(40_000_001)
    if len(packed) > 40_000_000: raise ValueError("The CLI package is too large.")
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(packed).digest()).decode()
    if integrity != pkg["dist"]["integrity"]: raise ValueError("The CLI package failed its integrity check.")
    with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as archive:
        code = archive.extractfile("package/dist/cli.mjs").read()
        metadata = archive.extractfile("package/package.json").read()
    if hashlib.sha256(code).hexdigest() != release["cliSha256"]: raise ValueError("The CLI does not match the verified release.")
    maintenance = origin + "/api/environments/" + args.environment + "/maintenance"
    token = identity["token"]
    stopped = False
    package = executable.parent.parent / "package.json"
    previous_code, previous_metadata = executable.read_bytes(), package.read_bytes()
    try:
        state = request(maintenance, {"paused": True}, token)
        deadline = time.monotonic() + 60
        while state["active"] or state["sshSessions"]:
            if time.monotonic() >= deadline:
                print("The environment is busy; the next scheduled update will retry."); return
            time.sleep(2); state = request(maintenance, token=token)
        stopped = True
        subprocess.run(["systemctl", "--user", "stop", args.service], check=True, timeout=30)
        heartbeat = request(maintenance, token=token)["heartbeatAt"]
        replace(executable, code); replace(package, metadata)
        version = subprocess.check_output([str(executable), "--version"], text=True).strip()
        if version != release["cliVersion"]: raise RuntimeError("The installed CLI version is incorrect.")
        subprocess.run(["systemctl", "--user", "start", args.service], check=True)
        deadline = time.monotonic() + 30
        while True:
            subprocess.run(["systemctl", "--user", "is-active", "--quiet", args.service], check=True)
            if request(maintenance, token=token)["heartbeatAt"] != heartbeat: break
            if time.monotonic() >= deadline: raise RuntimeError("The updated execution agent did not reconnect.")
            time.sleep(1)
        print("Updated the execution agent to Foundation " + version + "; identity and stored data were retained.")
    except Exception:
        if stopped:
            replace(executable, previous_code); replace(package, previous_metadata)
            subprocess.run(["systemctl", "--user", "start", args.service], check=True)
        raise
    finally:
        request(maintenance, {"paused": False}, token)


if __name__ == "__main__":
    main()
