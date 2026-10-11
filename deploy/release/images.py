import re
import subprocess
import sys
import time


TRANSIENT = re.compile(
    r"toomanyrequests|too many requests|rate exceeded|rate limit|"
    r"(?:unexpected status|status code|HTTP)[^\n]*\b(?:429|500|502|503|504)\b|"
    r"connection reset|connection refused|connection timed out|i/o timeout|"
    r"TLS handshake timeout|timeout awaiting response|context deadline exceeded|"
    r"temporary failure in name resolution|service unavailable",
    re.IGNORECASE,
)


def registry_command(command, *, attempts=5, run=None, sleep=None):
    run, sleep = run or subprocess.run, sleep or time.sleep
    for attempt in range(attempts):
        result = run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = result.stdout or ""
        sys.stdout.write(output)
        sys.stdout.flush()
        if result.returncode == 0:
            return
        if attempt + 1 == attempts or not TRANSIENT.search(output):
            raise subprocess.CalledProcessError(result.returncode, command, output=output)
        seconds = min(5 * 2 ** attempt, 30)
        print(f"The registry is temporarily unavailable; retrying in {seconds}s ({attempt + 2}/{attempts}).", flush=True)
        sleep(seconds)


def pull_image(image):
    found = subprocess.run(["docker", "image", "inspect", image], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if found.returncode:
        registry_command(["docker", "pull", image])


if __name__ == "__main__":
    for image in sys.argv[1:]:
        pull_image(image)
