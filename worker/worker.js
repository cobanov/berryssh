// Serves the OTA install files for the handset from the GitHub release.
//
// Two things the device needs that GitHub's release CDN does not give:
// the descriptor as text/vnd.sun.j2me.app-descriptor and the jar as
// application/java-archive, over plain HTTP (see tools/deploy.md), with an
// exact Content-Length.
//
// The descriptor is rewritten on the way through so that it can never
// disagree with the jar (#64): MIDlet-Jar-Size is taken from the jar this
// Worker would actually serve, and MIDlet-Jar-URL names the versioned jar
// (berryssh-0.8.1.jar), which is fetched from that version's release
// regardless of what RELEASE says by the time the second request arrives.
// A client that starts an install on one version finishes on it.

const RELEASE = "v0.8.1";

const REPO = "https://github.com/cobanov/berryssh/releases/download/";
const JAD_TYPE = "text/vnd.sun.j2me.app-descriptor";
const JAR_TYPE = "application/java-archive";

const PAGE = `<html><head><title>berryssh</title></head>
<body bgcolor="#0d0d10" text="#e8e8ea" link="#4a90d9" vlink="#4a90d9">
<h2>berryssh</h2>
<p>An SSH client for BlackBerry OS 7.</p>
<p><b><a href="/berryssh.jad">Install (berryssh.jad)</a></b></p>
<p>Open this on the handset's own browser, over plain HTTP.</p>
<p><a href="https://github.com/cobanov/berryssh">Source</a></p>
</body></html>`;

function reply(body, type, status = 200) {
  const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body;
  return new Response(bytes, {
    status,
    headers: {
      "content-type": type,
      "content-length": String(bytes.byteLength),
      "cache-control": "no-store",
    },
  });
}

async function release(tag, name) {
  const upstream = await fetch(REPO + tag + "/" + name, {
    redirect: "follow",
    cf: { cacheTtl: 0 },
  });
  if (!upstream.ok) return null;
  // Buffered so Content-Length is exact.
  return await upstream.arrayBuffer();
}

async function descriptor() {
  const jad = await release(RELEASE, "berryssh.jad");
  if (!jad) return null;
  const text = new TextDecoder().decode(jad);
  const version = (text.match(/^MIDlet-Version:\s*(\S+)/m) || [])[1];
  if (!version) return null;

  const jar = await release("v" + version, "berryssh.jar");
  if (!jar) return null;

  const rewritten = text
    .replace(/^MIDlet-Jar-URL:.*$/m, "MIDlet-Jar-URL: berryssh-" + version + ".jar")
    .replace(/^MIDlet-Jar-Size:.*$/m, "MIDlet-Jar-Size: " + jar.byteLength);
  return rewritten;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const name = url.pathname.replace(/^\/+/, "");

    if (name === "" || name === "index.html") {
      return reply(PAGE, "text/html; charset=utf-8");
    }

    if (name === "berryssh.jad") {
      const jad = await descriptor();
      if (!jad) return reply("upstream failed\n", "text/plain", 502);
      return reply(jad, JAD_TYPE);
    }

    // berryssh.jar is the unversioned name older descriptors point at;
    // berryssh-X.Y.Z.jar is what the rewritten descriptor asks for.
    const jarName = name.match(/^berryssh(?:-(\d+\.\d+\.\d+))?\.jar$/);
    if (jarName) {
      const tag = jarName[1] ? "v" + jarName[1] : RELEASE;
      const jar = await release(tag, "berryssh.jar");
      if (!jar) return reply("upstream failed\n", "text/plain", 502);
      return reply(jar, JAR_TYPE);
    }

    return reply("not found\n", "text/plain", 404);
  },
};
