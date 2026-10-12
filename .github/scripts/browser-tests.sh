#!/bin/bash
set -euo pipefail

# Playwright 1.58.0 with its browsers and Ubuntu 24.04 dependencies.
image=mcr.microsoft.com/playwright/python@sha256:678457c4c323b981d8b4befc57b95366bb1bb6aa30057b1269f6b171e8d9975a
python3 deploy/release/images.py "$image"
docker run --rm --init --ipc=host --network=host \
  --volume "$PWD:/work" \
  --volume "$(command -v node):/usr/local/bin/node:ro" \
  --volume "$(command -v ssh-keygen):/usr/local/bin/ssh-keygen:ro" \
  --workdir /work \
  --env CI=true --env TEST_DATABASE_URL --env FOUNDATION_BROWSER_SHARD --env FOUNDATION_TEST_PORT \
  "$image" /bin/bash -ec '
    python3 -m pip install --break-system-packages --disable-pip-version-check playwright==1.58.0
    python3 tests/browser.py
  '
