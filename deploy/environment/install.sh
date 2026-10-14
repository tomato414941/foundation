#!/bin/bash
set -euo pipefail
umask 077
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl xz-utils docker.io openssh-server util-linux
node_version=24.14.0
node_archive="node-v${node_version}-linux-x64.tar.xz"
curl --fail --silent --show-error --location "https://nodejs.org/dist/v${node_version}/${node_archive}" -o "/tmp/${node_archive}"
curl --fail --silent --show-error --location "https://nodejs.org/dist/v${node_version}/SHASUMS256.txt" -o /tmp/foundation-node-shasums
awk -v archive="$node_archive" '$2 == archive' /tmp/foundation-node-shasums | (cd /tmp && sha256sum --check --strict -)
tar -xJf "/tmp/${node_archive}" -C /usr/local --strip-components=1
rm -f "/tmp/${node_archive}" /tmp/foundation-node-shasums
install -m 755 /opt/foundation-image/cli.mjs /usr/local/bin/foundation
install -m 755 /opt/foundation-image/ssh-session.sh /usr/local/bin/foundation-ssh-session
install -m 644 /opt/foundation-image/foundation-environment.service /etc/systemd/system/foundation-environment.service
install -d -m 700 /etc/foundation /data/config
install -d -m 755 /run/sshd
# The managed worker runs its own key-only listener on port 22.
systemctl disable --now ssh.service ssh.socket
systemctl mask ssh.service ssh.socket
passwd -d root
rm -f /etc/ssh/ssh_host_* /root/.ssh/authorized_keys /home/ubuntu/.ssh/authorized_keys
systemctl enable --now docker.service
docker pull "$FOUNDATION_IMAGE_FUNCTION"
foundation --version
systemctl daemon-reload
systemctl enable foundation-environment.service
rm -rf /opt/foundation-image /tmp/foundation-image.tar /var/lib/cloud/instances
rm -f /var/log/cloud-init-output.log /var/log/cloud-init.log
cloud-init clean --logs --machine-id
echo FOUNDATION_IMAGE_READY >/dev/console
