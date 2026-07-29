#!/usr/bin/env bash
# A throwaway SSH server for the tests that need the server configured.
#
# Two things the shared container cannot provide. It rekeys every 64 KB, so the
# rekey path can be exercised in seconds rather than the hour OpenSSH would
# otherwise take. And it authorises a known test key, so public key
# authentication can be confirmed end to end.
#
# Deliberately separate from the `bbssh` container on port 2222: that one is
# what the handset connects to, and reconfiguring or restarting it would
# interrupt whoever is using it.
#
# The authorised key is the RFC 8032 test vector 3 seed, which is published in
# the RFC and used in this project's crypto vectors. It is a test value in the
# most literal sense and secures nothing.
#
#   tools/rekey-server.sh          # build and start on 2223
#   tools/rekey-server.sh stop
set -euo pipefail

cd "$(dirname "$0")/.."

NAME=berryssh-rekey
IMAGE=berryssh-rekey-test
PORT=2223

export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.orbstack/run/docker.sock}"
DOCKER_CONFIG="$(mktemp -d)"; export DOCKER_CONFIG
printf '{}' > "$DOCKER_CONFIG/config.json"
trap 'rm -rf "$DOCKER_CONFIG"' EXIT

if [ "${1:-start}" = "stop" ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "stopped"
    exit 0
fi

build="$(mktemp -d)"
# Public half of the RFC 8032 test vector 3 seed.
AUTHORIZED="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPxRzY5iGKGjjaR+0AIw8FgIFu0TujMDrF3rkRVIkIAl berryssh-test-vector"

cat > "$build/Dockerfile" <<EOF
FROM bbssh-sshd:latest
RUN printf '\nRekeyLimit 64K none\n' >> /etc/ssh/sshd_config.d/00-bbssh-legacy.conf \\
 && ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q \\
 && printf '\nHostKey /etc/ssh/ssh_host_ed25519_key\n' >> /etc/ssh/sshd_config.d/00-bbssh-legacy.conf \\
 && mkdir -p /home/bb/.ssh \\
 && echo '$AUTHORIZED' > /home/bb/.ssh/authorized_keys \\
 && chown -R bb:bb /home/bb/.ssh \\
 && chmod 700 /home/bb/.ssh && chmod 600 /home/bb/.ssh/authorized_keys
EOF

echo "==> building $IMAGE"
docker build -q -t "$IMAGE" "$build" >/dev/null
rm -rf "$build"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --rm --name "$NAME" -p "$PORT:22" "$IMAGE" >/dev/null
sleep 2

echo "==> $NAME on $PORT, $(docker exec "$NAME" sshd -T | grep -i '^rekeylimit')"
echo "    spike2/against-server.sh now includes the rekey test"
