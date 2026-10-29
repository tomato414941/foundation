FROM public.ecr.aws/docker/library/node@sha256:c8c4a7483bb04544293c82a3eecc3081c37ff5dfedcaf819d60e6e4aaad35b12

ENV DEBIAN_FRONTEND=noninteractive \
    PATH=/opt/playwright/bin:$PATH \
    PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright \
    FOUNDATION_TEST_CHROMIUM=/opt/browsers/chrome-headless-shell-linux64/chrome-headless-shell \
    PYTHONDONTWRITEBYTECODE=1 \
    XDG_CACHE_HOME=/tmp/browser-cache

# APT verifies the pinned archive's signatures before installing its CA certificates.
RUN printf '%s\n' \
      'Types: deb' \
      'URIs: http://snapshot.debian.org/archive/debian/20261029T000000Z/' \
      'Suites: trixie trixie-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      '' \
      'Types: deb' \
      'URIs: http://snapshot.debian.org/archive/debian-security/20261029T000000Z/' \
      'Suites: trixie-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' > /etc/apt/sources.list.d/debian.sources \
    && apt-get update --error-on=any \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv openssh-client unzip

COPY requirements.txt /opt/browser-tests/requirements.txt
RUN python3 -m venv /opt/playwright \
    && pip install --no-cache-dir --require-hashes -r /opt/browser-tests/requirements.txt \
    && python3 -m playwright install-deps chromium webkit

COPY browsers.json install.py /opt/browser-tests/
RUN python3 /opt/browser-tests/install.py \
    && dpkg-query -W -f='${binary:Package}\t${Version}\n' > /opt/browser-tests/packages.tsv \
    && apt-get -s upgrade | tee /opt/browser-tests/upgrade.txt \
    && grep -q '^0 upgraded, 0 newly installed' /opt/browser-tests/upgrade.txt \
    && rm -rf /var/lib/apt/lists/*

COPY verify.py /opt/browser-tests/verify.py
ENV FOUNDATION_TEST_WEBKIT=/opt/ms-playwright/webkit-2384/pw_run.sh
WORKDIR /work
ENTRYPOINT ["python3", "/opt/browser-tests/verify.py"]
CMD ["python3", "tests/browser.py"]
