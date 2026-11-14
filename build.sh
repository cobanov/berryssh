#!/usr/bin/env bash
# Build a MIDlet: javac (JDK 8, targeting 1.3) -> preverify -> jar -> jad.
#
#   ./build.sh            the client   -> out/berryssh.jar + out/berryssh.jad
#   ./build.sh probe      the spike1 capability probe -> spike1/out/Probe.*
#
# Everything runs in a JDK 8 container, because CLDC 1.1 wants class file
# version 47 and no current JDK can emit anything that old. So the only things
# this machine needs are Docker and the jars lib/fetch.sh downloads. The API
# stubs are microemu's repackaged cldcapi11/midpapi20, so no BlackBerry JDE is
# involved anywhere — and since nothing here touches a RIM API, the result
# needs no code signature.
#
# To put a build on a handset: python3 tools/ota_server.py out
set -euo pipefail

cd "$(dirname "$0")"

case "${1:-berryssh}" in
    berryssh)
        NAME=berryssh
        MIDLET_CLASS=berryssh.device.BerrysshMIDlet
        SRC=ssh/src
        RES=ssh/res
        OUT=out
        # The version is written once, where the client announces it to the
        # server, and read from there. It used to be written here as well, and
        # the two had drifted apart by eight releases.
        VERSION=$(sed -n 's/.*SOFTWARE_VERSION = "berryssh_\([0-9][0-9.]*\)".*/\1/p' \
            "$SRC/berryssh/protocol/Transport.java")
        ;;
    probe)
        NAME=Probe
        MIDLET_CLASS=Probe
        SRC=spike1/src
        RES=
        OUT=spike1/out
        VERSION=1.0.1
        ;;
    *)
        echo "usage: $0 [berryssh|probe]" >&2
        exit 2
        ;;
esac

if [ -z "$VERSION" ]; then
    echo "could not read the version from Transport.SOFTWARE_VERSION" >&2
    exit 1
fi
if [ ! -f lib/cldcapi11.jar ] || [ ! -f lib/proguard.jar ]; then
    echo "no build jars yet — run lib/fetch.sh first" >&2
    exit 1
fi

JAR="$OUT/$NAME.jar"
JAD="$OUT/$NAME.jad"

# OrbStack's socket, and a throwaway docker config so the host's Docker Desktop
# credential helper is not consulted.
export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.orbstack/run/docker.sock}"
DOCKER_CONFIG="$(mktemp -d)"; export DOCKER_CONFIG
printf '{}' > "$DOCKER_CONFIG/config.json"
trap 'rm -rf "$DOCKER_CONFIG"' EXIT

rm -rf "$OUT"
mkdir -p "$OUT"

cat > "$OUT/manifest.mf" <<MANIFEST
MIDlet-Name: $NAME
MIDlet-Version: $VERSION
MIDlet-Vendor: berryssh
MIDlet-1: $NAME,,$MIDLET_CLASS
MicroEdition-Profile: MIDP-2.0
MicroEdition-Configuration: CLDC-1.1
MANIFEST

docker run --rm -v "$PWD:/work" -w /work \
    -e SRC="$SRC" -e RES="$RES" -e OUT="$OUT" -e JAR="$JAR" -e MIDLET_CLASS="$MIDLET_CLASS" \
    eclipse-temurin:8-jdk sh -c '
    set -e
    mkdir -p "$OUT/classes" "$OUT/classes-pv"

    echo "==> compiling (source/target 1.3)"
    # The exit status of javac decides this, not the presence of some class
    # file: a partial failure still leaves earlier packages on disk.
    if ! output=$(javac -source 1.3 -target 1.3 -nowarn -encoding UTF-8 \
            -bootclasspath lib/cldcapi11.jar:lib/midpapi20.jar \
            -d "$OUT/classes" $(find "$SRC" -name "*.java") 2>&1); then
        echo "$output" >&2
        echo "did not compile under CLDC constraints" >&2
        exit 1
    fi

    # The whole reason for the container. A class file newer than this
    # installs and is then refused by the device.
    if ! javap -verbose -cp "$OUT/classes" "$MIDLET_CLASS" | grep -q "major version: 47"; then
        echo "class files are not version 47" >&2
        exit 1
    fi

    # The verifier on the device needs StackMap attributes computed ahead of
    # time; without them it rejects the suite with "907 Invalid JAR / missing
    # stack map". ProGuard in -microedition mode emits them, so no native
    # preverifier is needed.
    echo "==> preverifying (CLDC StackMap)"
    if ! java -cp lib/proguard.jar proguard.ProGuard \
            -injars "$OUT/classes" -outjars "$OUT/classes-pv" \
            -libraryjars lib/cldcapi11.jar -libraryjars lib/midpapi20.jar \
            -dontshrink -dontobfuscate -dontoptimize -microedition \
            -keep "public class * extends javax.microedition.midlet.MIDlet" \
            > "$OUT/proguard.log" 2>&1; then
        echo "preverification failed; see $OUT/proguard.log" >&2
        exit 1
    fi

    echo "==> packaging"
    # Resources — the font atlases — ride in the jar and are loaded with
    # getResourceAsStream.
    if [ -n "$RES" ]; then
        jar cfm "$JAR" "$OUT/manifest.mf" -C "$OUT/classes-pv" . -C "$RES" .
    else
        jar cfm "$JAR" "$OUT/manifest.mf" -C "$OUT/classes-pv" .
    fi
    rm -rf "$OUT/classes" "$OUT/classes-pv"
'

JAR_SIZE=$(wc -c < "$JAR" | tr -d ' ')

# The descriptor must repeat the MIDlet-* attributes and state the exact size of
# the jar; a mismatch is one of the ways an OTA install fails with no useful
# error.
{
    cat "$OUT/manifest.mf"
    echo "MIDlet-Jar-URL: $NAME.jar"
    echo "MIDlet-Jar-Size: $JAR_SIZE"
} > "$JAD"
rm -f "$OUT/manifest.mf"

echo "==> built $JAR ($JAR_SIZE bytes) + $JAD, version $VERSION"
