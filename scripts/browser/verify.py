import importlib.metadata
import json
import os
from pathlib import Path
import grp
import pwd
import re
import subprocess
import sys

from playwright.sync_api import sync_playwright


# Match artifact ownership to the caller without mounting the host's user database or home directory.
uid = int(os.environ["FOUNDATION_TEST_UID"])
gid = int(os.environ["FOUNDATION_TEST_GID"])
if uid != 0:
    try:
        grp.getgrgid(gid)
    except KeyError:
        subprocess.run(["groupadd", "--gid", str(gid), "browser-tests"], check=True)
    try:
        account = pwd.getpwuid(uid)
    except KeyError:
        subprocess.run(["useradd", "--uid", str(uid), "--gid", str(gid), "--no-create-home", "--home-dir", "/tmp/browser-home", "browser-tests"], check=True)
        account = pwd.getpwuid(uid)
    home = Path("/tmp/browser-home")
    home.mkdir(exist_ok=True)
    os.chown(home, uid, gid)
    os.initgroups(account.pw_name, gid)
    os.setgid(gid)
    os.setuid(uid)
    os.environ["HOME"] = str(home)

directory = Path(__file__).parent
configuration = json.loads((directory / "browsers.json").read_text())
if importlib.metadata.version("playwright") != configuration["playwright"]:
    raise RuntimeError("The Playwright package does not match the browser test definition")
node = subprocess.check_output(["node", "--version"], text=True).strip()
if node != configuration["node"]:
    raise RuntimeError("Node does not match the browser test definition")
if os.environ.get("FOUNDATION_TEST_CHROMIUM") != configuration["headless"]["executable"]:
    raise RuntimeError("Use the pinned Chrome Headless Shell for browser tests")

versions = {}
with sync_playwright() as playwright:
    for name in ["chrome", "headless"]:
        browser = playwright.chromium.launch(executable_path=configuration[name]["executable"], headless=True)
        try:
            versions[name] = browser.version
            if browser.version != configuration["chromiumVersion"]:
                raise RuntimeError(name + " is not the pinned security update")
        finally:
            browser.close()
    executable = Path("/opt/ms-playwright/webkit-" + configuration["webkit"]["revision"] + "/pw_run.sh")
    if os.environ.get("FOUNDATION_TEST_WEBKIT") != str(executable):
        raise RuntimeError("Use the pinned WebKit build for browser tests")
    browser = playwright.webkit.launch(executable_path=str(executable), headless=True)
    try:
        versions["webkit"] = browser.version
        expected = configuration["webkit"]
        if browser.version != expected["version"]:
            raise RuntimeError("WebKit does not match the browser test definition")
    finally:
        browser.close()
    versions["webkitEngine"] = subprocess.check_output([str(executable), "--headless", "--version"], text=True).strip()
    if not versions["webkitEngine"].startswith("WPE WebKit "):
        raise RuntimeError("Could not verify the native WebKit engine version")

packages = dict(line.split("\t", 1) for line in (directory / "packages.tsv").read_text().splitlines())
snapshot = re.search(r"/archive/debian/(\d+T\d+Z)/", Path("/etc/apt/sources.list.d/debian.sources").read_text()).group(1)
report = {
    "playwright": configuration["playwright"], "node": node, "browsers": versions,
    "webkitRevision": configuration["webkit"]["revision"], "webkitPlaywrightRevision": configuration["webkit"]["playwrightRevision"],
    "webkitUpstreamRevision": configuration["webkit"]["upstreamRevision"],
    "debianSnapshot": snapshot, "packages": packages,
}
output = Path("test-results/browser-environment.json")
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, indent=2) + "\n")
print("Browser environment verified: " + json.dumps({key: value for key, value in report.items() if key != "packages"}), flush=True)
if len(sys.argv) > 1:
    os.execvp(sys.argv[1], sys.argv[1:])
