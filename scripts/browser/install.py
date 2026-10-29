import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request


configuration = json.loads(Path(__file__).with_name("browsers.json").read_text())
for name in ["chrome", "headless", "webkit"]:
    artifact = configuration[name]
    destination = Path("/opt/ms-playwright/webkit-" + artifact["revision"]) if name == "webkit" else Path("/opt/browsers")
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / "browser.zip"
        with urllib.request.urlopen(artifact["url"], timeout=120) as response, archive.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if digest != artifact["sha256"]:
            raise RuntimeError(name + " archive does not match its pinned SHA-256")
        subprocess.run(["unzip", "-q", str(archive), "-d", str(destination)], check=True)
    print(name + ": verified " + digest, flush=True)
