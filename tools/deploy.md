# Serving a build to the handset

The device installs over the air from a `.jad` descriptor, and it is fussy in
two ways that produce silent failures rather than errors.

## The two MIME types

    berryssh.jad   text/vnd.sun.j2me.app-descriptor
    berryssh.jar   application/java-archive

Serve the descriptor as anything else — `text/plain`, or the
`application/octet-stream` a generic static host will guess — and the browser
displays it instead of installing it. Nothing says why.

`MIDlet-Jar-Size` in the descriptor must equal the jar's length exactly. A
mismatch is another silent install failure.

## Plain HTTP, and why it is not negotiable

An OS 7.1 browser offers TLS 1.0 at best, and its trust store is from 2011.
A current Cloudflare zone refuses TLS 1.0 and 1.1 and presents a certificate
chained to a root that did not exist when the handset shipped. Neither half can
be worked around from the device.

So the hostname must not redirect HTTP to HTTPS. Measured on this account:

| zone | plain HTTP |
| --- | --- |
| `cobanov.dev` | 301 to HTTPS — unreachable from the device |
| `cobanov.run` | 200 — usable |

`.dev` is also an HSTS-preloaded TLD, which forces HTTPS in any modern browser.
That does not bind this device, whose browser predates the preload list, so for
this purpose the Cloudflare redirect is the only obstacle — turning off
"Always Use HTTPS" for that hostname would be enough.

## What is deployed

- The artifacts are attached to a GitHub release.
- A Worker named `berryssh` fetches them and re-serves them with the MIME types
  above, buffering rather than streaming so `Content-Length` is exact.
- It is attached to `berryssh.cobanov.run` as a Workers custom domain.

To publish a new build:

```sh
./build.sh                                          # bump VERSION first
gh release create vX.Y.Z out/berryssh.jar out/berryssh.jad
```

Then point the Worker's `RELEASE` constant at the new tag. The version in the
descriptor must increase, or the device refuses the update as already
installed — and says nothing about versions when it does.
