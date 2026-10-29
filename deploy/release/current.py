import os
from pathlib import Path
import re
import subprocess
import sys


def current(commit, repository):
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("The release must identify its complete source commit.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("The release must identify its GitHub repository.")
    head = subprocess.check_output([
        "gh", "api", "repos/" + repository + "/git/ref/heads/main",
        "--header", "Cache-Control: no-cache", "--jq", ".object.sha",
    ], text=True, timeout=30).strip()
    if not re.fullmatch(r"[a-f0-9]{40}", head):
        raise RuntimeError("GitHub did not return the complete main commit.")
    if head != commit:
        print("Skipping release " + commit + "; main is now " + head + ".", flush=True)
        return False
    print("Release commit matches main: " + commit, flush=True)
    return True


def main():
    allowed = current(os.environ["GITHUB_SHA"], os.environ["GITHUB_REPOSITORY"])
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write("current=" + str(allowed).lower() + "\n")
        if not allowed:
            output.write("obsolete=true\n")
    if not allowed:
        return 0
    command = sys.argv[1:]
    if command[:1] == ["--"]:
        command = command[1:]
    if command:
        code = subprocess.run(command).returncode
        return code if code >= 0 else 128 - code
    return 0


if __name__ == "__main__":
    sys.exit(main())
