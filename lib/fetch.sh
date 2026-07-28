#!/usr/bin/env bash
# Fetch the build dependencies. They are not committed: the API stubs and
# ProGuard are third-party artifacts with their own licences, and pinning them
# by URL keeps the repository to source only.
set -euo pipefail
cd "$(dirname "$0")"

fetch() {
    local url=$1 out=$2
    if [ -f "$out" ]; then
        echo "  have $out"
        return
    fi
    echo "  fetching $out"
    curl -fsSL -o "$out" "$url"
}

# MIDP 2.0 / CLDC 1.1 API stubs, from microemu (LGPL). Compile-time only.
MICROEMU=https://repo1.maven.org/maven2/org/microemu
fetch "$MICROEMU/cldcapi11/2.0.4/cldcapi11-2.0.4.jar" cldcapi11.jar
fetch "$MICROEMU/midpapi20/2.0.4/midpapi20-2.0.4.jar" midpapi20.jar

# ProGuard, used only for its -microedition preverifier (GPL-2.0).
fetch "https://repo1.maven.org/maven2/net/sf/proguard/proguard-base/6.2.2/proguard-base-6.2.2.jar" \
      proguard.jar

echo "done"
