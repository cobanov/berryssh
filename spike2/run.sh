#!/usr/bin/env bash
# Compile the crypto sources under CLDC 1.1 constraints, then run the test
# vectors on the host JVM.
#
# The two halves are the point: compiling at -source 1.3 against the CLDC
# bootclasspath proves the code will run on the device, while executing on the
# host proves it is correct — without a single device round-trip.
set -euo pipefail

cd "$(dirname "$0")"

export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.orbstack/run/docker.sock}"
DOCKER_CONFIG="$(mktemp -d)"; export DOCKER_CONFIG
printf '{}' > "$DOCKER_CONFIG/config.json"
trap 'rm -rf "$DOCKER_CONFIG"' EXIT

rm -rf classes
mkdir -p classes

echo "==> compiling crypto under CLDC 1.1 / -source 1.3"
docker run --rm \
    -v "$PWD/..:/client" -w /client/spike2 \
    eclipse-temurin:8-jdk \
    javac -source 1.3 -target 1.3 -nowarn \
          -bootclasspath /client/lib/cldcapi11.jar:/client/lib/midpapi20.jar \
          -d classes \
          $(cd .. && find ssh/src -name '*.java' | sed 's|^|/client/|' | tr '\n' ' ') \
    2>&1 | grep -v 'obsolete\|deprecat\|warning' || true

if [ -z "$(find classes -name '*.class' -print -quit)" ]; then
    echo "crypto did not compile under CLDC constraints" >&2
    exit 1
fi

echo "==> compiling tests (host JDK, sees the CLDC-built classes)"
javac -nowarn -cp classes -d classes src/CryptoTests.java

echo "==> running vectors on host JVM"
java -cp classes CryptoTests
