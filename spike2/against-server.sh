#!/usr/bin/env bash
# Run the half of the verification that needs a real OpenSSH server.
#
# Kept apart from run.sh so that the offline vectors stay runnable with nothing
# but a compiler. This one needs servers, and tools/test-server.sh is them: an
# OpenSSH that takes a password, one that rekeys every 64 KB and takes a key,
# and the WebSocket bridge.
#
#   tools/test-server.sh && spike2/against-server.sh
set -euo pipefail

cd "$(dirname "$0")"

SERVER=berryssh-test

export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.orbstack/run/docker.sock}"
DOCKER_CONFIG="$(mktemp -d)"; export DOCKER_CONFIG
printf '{}' > "$DOCKER_CONFIG/config.json"
trap 'rm -rf "$DOCKER_CONFIG"' EXIT

if [ ! -d classes ]; then
    echo "no classes yet — run spike2/run.sh first" >&2
    exit 1
fi

if ! docker inspect -f '{{.State.Running}}' "$SERVER" 2>/dev/null | grep -q true; then
    echo "the test servers are not running — start them with tools/test-server.sh" >&2
    exit 1
fi

# Asked of the server itself, so the test compares what the handshake produced
# with what ssh-keygen prints — the same comparison a person makes on first
# contact, and one a constant in the test could not make for a fresh host key.
FINGERPRINT=$(docker exec "$SERVER" ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2)

echo "==> running against $SERVER"
# In the server's own network namespace, so its loopback is ours and nothing
# depends on how this machine publishes container ports.
docker run --rm --network "container:$SERVER" -v "$PWD:/spike2" -w /spike2 \
    eclipse-temurin:8-jdk \
    sh -c 'javac -nowarn -encoding UTF-8 -cp classes -d classes src/ServerTests.java \
           && java -cp classes ServerTests 127.0.0.1 2222 bb bbssh "$0"' "$FINGERPRINT"
