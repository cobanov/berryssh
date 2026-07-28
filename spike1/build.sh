#!/usr/bin/env bash
# Build the Spike 1 MIDlet: javac (JDK 8, targeting 1.3) -> jar -> jad.
#
# Compiles in a container because CLDC 1.1 wants class file version 47 and the
# host JDK 17 cannot emit anything below 51. The API stubs come from microemu's
# repackaged cldcapi11/midpapi20, so no BlackBerry JDE is involved anywhere.
#
# No RIM APIs are referenced, so the suite needs no BlackBerry code signature.
set -euo pipefail

cd "$(dirname "$0")"

NAME=Probe
VENDOR="blackberry-ssh"
VERSION=1.0.1
MIDLET_CLASS=Probe

OUT=out
JAR="$OUT/$NAME.jar"
JAD="$OUT/$NAME.jad"

# OrbStack's socket, and a throwaway docker config so the host's broken
# Docker Desktop credential helper is not consulted.
export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.orbstack/run/docker.sock}"
DOCKER_CONFIG="$(mktemp -d)"; export DOCKER_CONFIG
printf '{}' > "$DOCKER_CONFIG/config.json"
trap 'rm -rf "$DOCKER_CONFIG"' EXIT

rm -rf "$OUT" classes classes-pv
mkdir -p "$OUT" classes

echo "==> compiling (source/target 1.3)"
docker run --rm \
    -v "$PWD:/work" -v "$PWD/../lib:/libs:ro" -w /work \
    eclipse-temurin:8-jdk \
    javac -source 1.3 -target 1.3 -nowarn \
          -bootclasspath /libs/cldcapi11.jar:/libs/midpapi20.jar \
          -d classes src/*.java 2>&1 | grep -v 'obsolete\|deprecat\|^1 warning\|^2 warnings\|^3 warnings' || true

if [ -z "$(find classes -name '*.class' -print -quit)" ]; then
    echo "compile produced no classes" >&2
    exit 1
fi

echo "==> class file version"
# `grep -m1` closing the pipe early would trip pipefail, so swallow the status.
docker run --rm -v "$PWD:/work" -w /work eclipse-temurin:8-jdk \
    javap -verbose -cp classes "$MIDLET_CLASS" 2>/dev/null | grep -m1 'major version' || true

# CLDC's verifier needs StackMap attributes baked in ahead of time; without them
# the device rejects the suite with "907 Invalid JAR / missing stack map".
# ProGuard's -microedition mode emits them, so no native preverifier is needed.
echo "==> preverifying (CLDC StackMap)"
rm -rf classes-pv && mkdir -p classes-pv
java -cp ../lib/proguard.jar proguard.ProGuard \
    -injars classes -outjars classes-pv \
    -libraryjars ../lib/cldcapi11.jar -libraryjars ../lib/midpapi20.jar \
    -dontshrink -dontobfuscate -dontoptimize -microedition \
    -keep 'public class * extends javax.microedition.midlet.MIDlet' \
    > "$OUT/proguard.log" 2>&1

if [ -z "$(ls classes-pv/*.class 2>/dev/null)" ]; then
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

docker run --rm -v "$PWD:/work" -w /work eclipse-temurin:8-jdk \
    jar cfm "$JAR" "$OUT/manifest.mf" -C classes-pv .

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
