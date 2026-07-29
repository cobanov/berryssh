# berryssh

An SSH client for BlackBerry OS 7.x, written as a plain MIDP 2.0 / CLDC 1.1
MIDlet.

It speaks `curve25519-sha256`, `ssh-ed25519`, and
`chacha20-poly1305@openssh.com` — the algorithms a current OpenSSH offers by
default, so a twenty-year-old handset can reach a modern server without that
server being weakened to meet it.

Target hardware is a BlackBerry Bold 9790: a 480×360 screen, a hardware QWERTY
keyboard, and a real terminal on it.

## Design

**No RIM APIs.** Everything is standard MIDP and CLDC. This is a deliberate
constraint, not a portability exercise: BlackBerry code signing is a runtime
check inside the device VM that fires when a module touches a protected API, and
every signature had to be issued by BlackBerry's signing authority, which no
longer exists. Code that touches no protected API needs no signature. It also
means the build needs no BlackBerry tooling at all.

**Crypto from scratch.** CLDC 1.1 has no `java.security`, no `javax.crypto`, and
no `BigInteger`, so the primitives are implemented here. The modern algorithms
make that tractable rather than harder:

| | Why it suits this hardware |
| --- | --- |
| `curve25519-sha256` | Fixed 32-byte field arithmetic instead of 2048-bit modular exponentiation, and no `BigInteger` |
| `ssh-ed25519` | Same curve arithmetic, nothing extra to carry |
| `chacha20-poly1305` | Pure 32-bit add/xor/rotate, no lookup tables; AEAD, so no separate MAC |
| `SHA-256` | Small and self-contained |

The classic 2011 SSH stack is anchored on 2048-bit modexp, which is genuinely
slow in interpreted Java on this class of CPU. Modern cryptography is the
cheaper option here, not the more expensive one.

## Building

No BlackBerry SDK is involved. Dependencies are fetched, not vendored:

```sh
lib/fetch.sh          # MIDP/CLDC API stubs and ProGuard, from Maven Central
tools/make_atlas.sh   # regenerate the font atlases (only if the charset changes)
./build.sh            # -> out/berryssh.jad + berryssh.jar
```

- **API stubs**: microemu's `cldcapi11` / `midpapi20`
- **Compiler**: JDK 8 in a container at `-source 1.3 -target 1.3`; the host JDK
  17 cannot emit class file version 47, which is what CLDC wants
- **Preverifier**: ProGuard's `-microedition` mode

### The preverification trap

A MIDlet jar that is merely compiled will install and then fail on the device:

```
907 Invalid JAR — missing stack map in startApp at label 43
```

CLDC's verifier requires `StackMap` attributes computed ahead of time. Modern
`javac` emits `StackMapTable` (the Java 6+ format) or nothing at this target, so
a preverification pass is mandatory. ProGuard's `-microedition` mode produces
them without needing a native preverifier binary.

## Installing

`tools/ota_server.py` serves a build with the MIME types the device requires — a
generic static server renders the descriptor as text instead of installing it.
Plain HTTP is deliberate: the OS 7 browser's trust store predates every
currently issued CA.

```sh
python3 tools/ota_server.py out
```

Then open the printed URL in the device's native browser, over Wi-Fi.

## Verification

`spike2/run.sh` compiles the client against the CLDC bootclasspath at
`-source 1.3`, then runs its test vectors on the host JVM. Compiling under the
device's constraints proves the code will run there; executing on the host
proves it is correct. Neither half needs the device.

```sh
spike2/run.sh
```

**Crypto**: FIPS 180-4 for SHA-256 and SHA-512, RFC 8439 §2.4.2 / §2.5.2 /
§2.8.2 for ChaCha20, Poly1305 and the AEAD construction, RFC 7748 §5.2 / §6.1
for X25519, RFC 8032 §7.1 for Ed25519 in both directions, and the DRBG
against vectors computed outside it. 49 in total.

**Transport**: RFC 4251 §5 for the wire types, RFC 4253 §6 for the packet
framing and §7.1 for algorithm negotiation, RFC 8731 §3 for the exchange hash
and RFC 4253 §7.2 for key derivation, plus base64, host key parsing, the
version exchange, the chacha20-poly1305 packet layer, UTF-8, host key trust,
saved connections and the paths that have to reject malformed input. 106 in
total. A further 39 cover the terminal: escape sequences, key dispatch,
scrollback and the character-to-glyph mapping. They run under a Turkish default locale, which is the device's own and
the setting most likely to break protocol code without raising an error
anywhere.

### Against a real server

Encodings can be proved offline; a protocol cannot. A key exchange either
convinces an OpenSSH server or it does not, so the other half of the
verification talks to one:

```sh
spike2/against-server.sh          # defaults to the project's container
```

It is a separate script so that `run.sh` needs nothing external. The container
still offers the 2011 algorithms as well as the modern ones, which is what
makes it a useful test: the negotiated set is a choice rather than the only
thing on the table.

## Measured on the device

`spike1` is a capability probe rather than a hello world. On a Bold 9790:

| | |
| --- | --- |
| Canvas | 480×360, full screen |
| Default encoding | `ISO8859_1` — so UTF-8 is converted in our own code |
| Colour | 24-bit |
| Free heap | ~357 MB — memory is not a constraint |
| MIDP monospace cell | 22×27 px, giving a 21×13 terminal |

That last row is why the terminal renders from a bitmap font atlas rather than a
system font: MIDP exposes only three font sizes and the smallest is far too
large here. An 8×14 cell gives the 60×25 terminal this screen should have.

## Layout

    lib/            dependency fetcher
    ssh/src/        the client library and the MIDlet
    spike1/         device capability probe
    ssh/res/        generated font atlases
    spike2/         test vectors, run on the host
    tools/          OTA server

## Status

- [x] MIDlet builds, installs over the air, and runs on a Bold 9790
- [x] SHA-256, SHA-512, ChaCha20, Poly1305, ChaCha20-Poly1305 AEAD
- [x] X25519 key agreement
- [x] Ed25519 signature verification, and SHA-512
- [x] SSH transport: version exchange and the binary packet protocol
- [x] A random source for key material
- [x] KEXINIT algorithm negotiation
- [x] `curve25519-sha256` key exchange, host key check and key derivation
- [x] `chacha20-poly1305@openssh.com` packet layer, and an encrypted handshake
- [x] User authentication: `none`, `password`, `publickey` with Ed25519
- [x] Channels, `pty-req`, shell — a working session against OpenSSH 9.2p1
- [x] Host key trust, stored in RMS
- [x] VT320 terminal emulation, and a bitmap font renderer
- [x] A MIDlet that connects, authenticates and runs a shell
- [x] Runs on a Bold 9790: connects, authenticates, opens a shell
- [x] Saved connections, host key confirmation, and a transport two threads can share
- [ ] Keyboard mapping confirmed against the hardware's real key codes

## Prior art

[BBSSH](https://github.com/marcparadise/bbssh) by Marc Paradise was the SSH
client for these devices, and it solved a lot of problems well. berryssh is a
separate implementation — different architecture, different algorithms — but it
borrows from BBSSH where BBSSH already got it right, and those parts are
credited in the files that use them.

What is taken, or planned to be:

- **`VT320`** — the terminal emulator, originally from
  [JTA](http://javatelnet.org/) by Matthias L. Jugel and Marcus Meissner. It has
  no platform dependencies at all, which makes it portable as-is.
- **`BitmapFont`** — the subpixel-antialiased bitmap font renderer, derived from
  Roar Lauritzsen's LCDFont. Its atlas layout and `drawRGB` approach map
  directly onto MIDP.
- **Font atlases** — no longer. The atlases that came across covered U+0020 to
  U+00FF and nothing else, which left Turkish `ğ ı ş İ` and the whole
  box-drawing range without glyphs. They are generated now, by
  `tools/make_atlas.sh`, from DejaVu Sans Mono — the continuation of the same
  Bitstream Vera family, whose licence permits redistributing what is rendered
  from it. The monospace fonts already on a Mac all cover what is needed and
  none may be used here: baking Menlo, Monaco or Courier New into a GPL project
  would redistribute a derivative of a proprietary typeface, which is what
  leaving BBSSH's Courier New atlases behind was avoiding.

A verified copy of BBSSH, including binaries that survive nowhere else, is
preserved at [cobanov/bbssh-archive](https://github.com/cobanov/bbssh-archive).

## Licence

GPL-2.0-or-later, matching BBSSH, whose code this project reuses.
