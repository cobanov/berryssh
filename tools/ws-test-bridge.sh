#!/usr/bin/env bash
# Start the WebSocket bridge locally, so the WebSocket half of
# spike2/against-server.sh has something to talk to.
#
# Without it that test prints SKIP and passes, which is the failure mode worth
# guarding against: a test that quietly stops running is worse than one that
# fails, because nothing tells you it stopped.
#
#   tools/ws-test-bridge.sh          # foreground, Ctrl-C to stop
#   tools/ws-test-bridge.sh stop
set -euo pipefail

cd "$(dirname "$0")/.."

PORT=8090
CONFIG="${TMPDIR:-/tmp}/berryssh-ws-test.json"

if [ "${1:-start}" = "stop" ]; then
    pkill -f "wsbridge.py $CONFIG" 2>/dev/null || true
    echo "stopped"
    exit 0
fi

if lsof -nP -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1; then
    echo "something is already listening on $PORT — leaving it alone" >&2
    exit 0
fi

# Points at the same container the rest of against-server.sh uses, so the
# WebSocket path and the direct path are proved against the same server.
#
# The key is a fixture, not a secret: it is written here, committed, and
# matches the constant in ServerTests. A bridge on loopback in front of a
# throwaway container has nothing to protect — what is being tested is that the
# key is demanded at all, and that a wrong one gets nothing.
cat > "$CONFIG" <<'EOF'
{
  "listen": 8090,
  "bind": "127.0.0.1",
  "psk": "spike2-bridge-key-not-a-secret",
  "targets": {
    "testserver": ["127.0.0.1", 2222]
  }
}
EOF

echo "==> bridge on $PORT -> 127.0.0.1:2222 (target testserver, key required)"
exec python3 tools/wsbridge.py "$CONFIG"
