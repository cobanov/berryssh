#!/usr/bin/env bash
# Compile the client sources under CLDC 1.1 constraints, then run the test
# vectors on a desktop JVM.
#
# The two halves are the point: compiling at -source 1.3 against the CLDC
# bootclasspath proves the code will run on the device, while executing on a
# desktop JVM proves it is correct — without a single device round-trip.
#
# All of it happens in the JDK 8 container the build uses, so the only things
# this machine needs are Docker and the jars lib/fetch.sh downloads.
set -euo pipefail

cd "$(dirname "$0")"

export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.orbstack/run/docker.sock}"
DOCKER_CONFIG="$(mktemp -d)"; export DOCKER_CONFIG
printf '{}' > "$DOCKER_CONFIG/config.json"
trap 'rm -rf "$DOCKER_CONFIG"' EXIT

if [ ! -f ../lib/cldcapi11.jar ]; then
    echo "no API stubs yet — run lib/fetch.sh first" >&2
    exit 1
fi

rm -rf classes
mkdir -p classes

# javac's exit status is what decides each step, not the presence of some class
# file: a partial failure still leaves the earlier packages on disk, so counting
# classes would let a package that does not build on the device pass unnoticed.
# The tests are compiled without the CLDC restrictions — they are host-only,
# and use what the device's Java does not have.
docker run --rm -v "$PWD/..:/client" -w /client/spike2 eclipse-temurin:8-jdk sh -c '
    set -e
    echo "==> compiling the client under CLDC 1.1 / -source 1.3"
    if ! output=$(javac -source 1.3 -target 1.3 -nowarn -encoding UTF-8 \
            -bootclasspath ../lib/cldcapi11.jar:../lib/midpapi20.jar \
            -d classes $(find ../ssh/src -name "*.java") 2>&1); then
        echo "$output" >&2
        echo "the client did not compile under CLDC constraints" >&2
        exit 1
    fi

    echo "==> compiling the tests"
    javac -nowarn -encoding UTF-8 -cp classes -d classes \
        src/CryptoTests.java src/TransportTests.java src/TerminalTests.java

    for suite in CryptoTests TransportTests TerminalTests; do
        echo "==> $suite"
        java -cp classes "$suite"
    done
'
