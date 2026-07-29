#!/usr/bin/env bash
# Run the half of the verification that needs a real OpenSSH server.
#
# Kept apart from run.sh so that the offline vectors stay runnable with no
# external anything. This one needs a server; by default the container the
# project keeps for the purpose.
#
#   spike2/against-server.sh [host] [port]
set -euo pipefail

cd "$(dirname "$0")"

HOST="${1:-127.0.0.1}"
PORT="${2:-2222}"

if [ ! -d classes ]; then
    echo "no classes yet — run spike2/run.sh first" >&2
    exit 1
fi

if ! nc -z "$HOST" "$PORT" 2>/dev/null; then
    echo "nothing listening on $HOST:$PORT" >&2
    echo "the project's test server is a container: docker start bbssh" >&2
    exit 1
fi

echo "==> compiling server tests (host JDK)"
javac -nowarn -cp classes -d classes src/ServerTests.java

echo "==> running against $HOST:$PORT"
java -cp classes ServerTests "$HOST" "$PORT"
