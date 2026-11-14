#!/usr/bin/env bash
# The servers spike2/against-server.sh talks to, in one throwaway container.
#
# A key exchange either convinces OpenSSH or it does not, so half of the
# verification needs a real one. This builds it from a stock image, so the
# tests run anywhere Docker does and against whatever OpenSSH is current —
# which is the point: a server that is years old proves nothing about today's.
#
# Ports, inside the container:
#
#   2222  sshd      password login for `bb`; `open` needs no authentication
#   2223  sshd      rekeys every 64 KB, and authorises the test key for `bb`
#   8090  wsbridge  the WebSocket bridge, in front of 2222 as "testserver",
#                   and of nothing at all as "down"
#
# Nothing in here is a secret. The password, the bridge key and the authorised
# key are fixtures: the key is RFC 8032's test vector 3, published in the RFC
# and used in this project's crypto vectors, and the rest are written in
# ServerTests. They guard a container that holds nothing.
#
#   tools/test-server.sh          # build and start
#   tools/test-server.sh stop
set -euo pipefail

cd "$(dirname "$0")/.."

NAME=berryssh-test
IMAGE=berryssh-test

export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.orbstack/run/docker.sock}"
DOCKER_CONFIG="$(mktemp -d)"; export DOCKER_CONFIG
printf '{}' > "$DOCKER_CONFIG/config.json"
build="$(mktemp -d)"
trap 'rm -rf "$DOCKER_CONFIG" "$build"' EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true
if [ "${1:-start}" = "stop" ]; then
    echo "stopped"
    exit 0
fi

cp tools/wsbridge.py "$build/"

cat > "$build/bridge.json" <<'JSON'
{
  "listen": 8090,
  "bind": "0.0.0.0",
  "psk": "spike2-bridge-key-not-a-secret",
  "targets": { "testserver": ["127.0.0.1", 2222], "down": ["127.0.0.1", 1] }
}
JSON

cat > "$build/sshd_config" <<'CONF'
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication yes
# With this, a user whose password is empty is let in by the `none` method —
# which is how a server that asks for nothing looks from the client's side.
PermitEmptyPasswords yes
# Offered so the tests can see that the modern exchange was chosen, not forced.
KexAlgorithms +diffie-hellman-group14-sha1
CONF

cat > "$build/start.sh" <<'SH'
#!/bin/sh
/usr/sbin/sshd -f /etc/ssh/sshd_config -p 2222 -o PidFile=/run/sshd-2222.pid \
    -o AuthorizedKeysFile=none
/usr/sbin/sshd -f /etc/ssh/sshd_config -p 2223 -o PidFile=/run/sshd-2223.pid \
    -o RekeyLimit=64K
exec python3 /wsbridge.py /bridge.json
SH

cat > "$build/Dockerfile" <<'DOCKER'
FROM alpine:3
RUN apk add --no-cache openssh-server openssh-keygen python3 \
 && ssh-keygen -q -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" \
 && adduser -D -s /bin/sh bb && echo 'bb:bbssh' | chpasswd \
 && adduser -D -s /bin/sh open && passwd -d open \
 && mkdir -p /home/bb/.ssh \
 && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPxRzY5iGKGjjaR+0AIw8FgIFu0TujMDrF3rkRVIkIAl rfc8032-test-3' \
      > /home/bb/.ssh/authorized_keys \
 && chown -R bb:bb /home/bb/.ssh && chmod 700 /home/bb/.ssh \
 && chmod 600 /home/bb/.ssh/authorized_keys
COPY sshd_config /etc/ssh/sshd_config
COPY wsbridge.py bridge.json start.sh /
CMD ["/bin/sh", "/start.sh"]
DOCKER

echo "==> building $IMAGE"
docker build -q -t "$IMAGE" "$build" >/dev/null

# No ports are published. The tests join this container's network namespace
# and reach it on its own loopback, so nothing here can collide with a port in
# use on this machine, and a login whose password is "bbssh" is never on a
# network anyone else is on.
docker run -d --rm --name "$NAME" "$IMAGE" >/dev/null

for _ in 1 2 3 4 5 6 7 8 9 10; do
    if docker exec "$NAME" sh -c 'nc -z 127.0.0.1 2222 && nc -z 127.0.0.1 2223 && nc -z 127.0.0.1 8090' 2>/dev/null; then
        break
    fi
    sleep 1
done

echo "==> $NAME: $(docker exec "$NAME" sshd -V 2>&1 | head -1)"
echo "    host key $(docker exec "$NAME" ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2)"
echo "    now run spike2/against-server.sh"
