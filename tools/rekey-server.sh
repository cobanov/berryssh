#!/usr/bin/env bash
# A throwaway SSH server that asks to rekey almost immediately.
#
# OpenSSH requests a rekey after about a gigabyte or an hour. Waiting an hour is
# not a test, so this one is built with RekeyLimit at 64 KB, which makes a few
# hundred kilobytes of output force ten of them.
#
# Deliberately separate from the `bbssh` container on port 2222: that one is
# what the handset connects to, and restarting it to change its configuration
# would interrupt whoever is using it.
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
cat > "$build/Dockerfile" <<'EOF'
FROM bbssh-sshd:latest
RUN printf '\nRekeyLimit 64K none\n' >> /etc/ssh/sshd_config.d/00-bbssh-legacy.conf \
 && ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q \
 && printf '\nHostKey /etc/ssh/ssh_host_ed25519_key\n' >> /etc/ssh/sshd_config.d/00-bbssh-legacy.conf
EOF

echo "==> building $IMAGE"
docker build -q -t "$IMAGE" "$build" >/dev/null
rm -rf "$build"

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --rm --name "$NAME" -p "$PORT:22" "$IMAGE" >/dev/null
sleep 2

echo "==> $NAME on $PORT, $(docker exec "$NAME" sshd -T | grep -i '^rekeylimit')"
echo "    spike2/against-server.sh now includes the rekey test"
