#!/usr/bin/env bash
# Build the berryssh MIDlet: javac (JDK 8, targeting 1.3) -> preverify -> jar -> jad.
#
# Compiles in a container because CLDC 1.1 wants class file version 47 and the
# host JDK cannot emit anything that old. The API stubs are microemu's
# repackaged cldcapi11/midpapi20, so no BlackBerry JDE is involved anywhere —
# and since nothing here touches a RIM API, the result needs no code signature.
#
#   ./build.sh            -> out/berryssh.jar + out/berryssh.jad
#   tools/ota_server.py out
set -euo pipefail

cd "$(dirname "$0")"

NAME=berryssh
VENDOR="berryssh"
VERSION=0.8.0
MIDLET_CLASS=berryssh.device.BerrysshMIDlet

OUT=out
JAR="$OUT/$NAME.jar"
JAD="$OUT/$NAME.jad"

# OrbStack's socket, and a throwaway docker config so the host's broken Docker
# Desktop credential helper is not consulted.
export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.orbstack/run/docker.sock}"
DOCKER_CONFIG="$(mktemp -d)"; export DOCKER_CONFIG
printf '{}' > "$DOCKER_CONFIG/config.json"
trap 'rm -rf "$DOCKER_CONFIG"' EXIT

rm -rf "$OUT" classes classes-pv
mkdir -p "$OUT" classes

echo "==> compiling (source/target 1.3)"
# javac's exit status decides this, not the presence of some class file: a
# partial failure still leaves earlier packages on disk.
if ! output=$(docker run --rm \
    -v "$PWD:/work" -v "$PWD/lib:/libs:ro" -w /work \
    eclipse-temurin:8-jdk \
    javac -source 1.3 -target 1.3 -nowarn \
          -bootclasspath /libs/cldcapi11.jar:/libs/midpapi20.jar \
          -d classes $(find ssh/src -name '*.java' | tr '\n' ' ') 2>&1); then
    echo "$output" >&2
    echo "the client did not compile under CLDC constraints" >&2
    exit 1
fi
echo "$output" | grep -v 'obsolete\|deprecat\|warning' || true

echo "==> class file version"
docker run --rm -v "$PWD:/work" -w /work eclipse-temurin:8-jdk \
    javap -verbose -cp classes "$MIDLET_CLASS" 2>/dev/null | grep -m1 'major version' || true

# CLDC's verifier needs StackMap attributes baked in ahead of time; without them
# the device rejects the suite with "907 Invalid JAR / missing stack map".
# ProGuard's -microedition mode emits them, so no native preverifier is needed.
echo "==> preverifying (CLDC StackMap)"
rm -rf classes-pv && mkdir -p classes-pv
java -cp lib/proguard.jar proguard.ProGuard \
    -injars classes -outjars classes-pv \
    -libraryjars lib/cldcapi11.jar -libraryjars lib/midpapi20.jar \
    -dontshrink -dontobfuscate -dontoptimize -microedition \
    -keep 'public class * extends javax.microedition.midlet.MIDlet' \
    > "$OUT/proguard.log" 2>&1

if [ -z "$(find classes-pv -name '*.class' -print -quit)" ]; then
    echo "preverification produced no classes; see $OUT/proguard.log" >&2
    exit 1
fi

echo "==> packaging jar"
cat > "$OUT/manifest.mf" <<EOF
MIDlet-Name: $NAME
MIDlet-Version: $VERSION
MIDlet-Vendor: $VENDOR
MIDlet-1: $NAME,,$MIDLET_CLASS
MicroEdition-Profile: MIDP-2.0
MicroEdition-Configuration: CLDC-1.1
EOF

# The font atlases ride in the jar and are loaded with getResourceAsStream.
docker run --rm -v "$PWD:/work" -w /work eclipse-temurin:8-jdk \
    jar cfm "$JAR" "$OUT/manifest.mf" -C classes-pv . -C ssh/res .

JAR_SIZE=$(stat -f%z "$JAR" 2>/dev/null || stat -c%s "$JAR")

# The descriptor must repeat the MIDlet-* attributes and state the jar's exact
# size; a mismatch is one of the ways an OTA install fails with no useful error.
cat > "$JAD" <<EOF
MIDlet-Name: $NAME
MIDlet-Version: $VERSION
MIDlet-Vendor: $VENDOR
MIDlet-1: $NAME,,$MIDLET_CLASS
MicroEdition-Profile: MIDP-2.0
MicroEdition-Configuration: CLDC-1.1
MIDlet-Jar-URL: $NAME.jar
MIDlet-Jar-Size: $JAR_SIZE
EOF

rm -f "$OUT/manifest.mf"
echo "==> built $JAR ($JAR_SIZE bytes) + $JAD"
