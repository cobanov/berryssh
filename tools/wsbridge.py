#!/usr/bin/env python3
"""A WebSocket-to-TCP bridge, so a client that can only speak HTTP can reach
SSH — including SSH on a machine that is only reachable over Tailscale.

The handset cannot run a VPN: being one means capturing the device's traffic,
which on BlackBerry OS 7 lives behind RIM's signed VPN framework. So the phone
never joins the tailnet. This does, and carries the phone's SSH stream in.

    wsbridge.py <config.json>

    {
      "listen": 8022,
      "bind": "127.0.0.1",
      "psk": "a long random passphrase, shared with the handset",
      "targets": {
        "pve":   ["100.76.56.16", 22],
        "ct107": ["100.110.192.73", 22]
      }
    }

**A key is required, and the targets are an allowlist.** Between them they are
the whole of this program's security model:

- Without the key, a connection learns nothing and reaches nothing. The bridge
  is on a public hostname; anyone can find it, and finding it must not be
  enough.
- Nothing outside `targets` is ever dialled, whatever is asked for, so a
  compromise here is not an open proxy into the network.

Neither is the outermost bound, and neither should be trusted as if it were.
Give this a *tagged* Tailscale identity whose grants allow only tcp:22 to the
hosts it serves, and even a bridge running attacker code reaches nothing else.
See wsbridge-install.md.

Beyond that the protection is SSH's own: the servers take keys, the client
checks the host key, so the bridge carries ciphertext it cannot read and cannot
usefully tamper with — a forged or swapped host key is refused at the far end.

Standard library only, so it runs anywhere Python does with nothing installed.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import sys
import threading
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LABEL = b"berryssh-bridge-v1"
GREETING = "BERRYSSH1"

MAX_HEADERS = 65536
MAX_FRAME = 1 << 20
MAX_LINE = 4096
NONCE_BYTES = 32

# What a target may be called: what survives an ASCII line protocol without
# quoting, and what someone can retype from a handset.
NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Long enough to make guessing over the network pointless, short enough that a
# legitimate client never notices. Applied to every failure, so the reason for
# one cannot be told from how long it took.
FAILURE_DELAY = 1.0


def read_request(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return None, None
        data += chunk
        if len(data) > MAX_HEADERS:
            return None, None
    head = data.decode("latin-1", "replace")
    lines = head.split("\r\n")
    path = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else ""
    key = None
    for line in lines[1:]:
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    return path, key


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def read_frame(conn):
    first, second = recv_exact(conn, 2)
    opcode = first & 0x0F
    masked = second & 0x80
    length = second & 0x7F
    if length == 126:
        length = struct.unpack(">H", recv_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(conn, 8))[0]
    if length > MAX_FRAME:
        raise ConnectionError("frame too large")
    mask = recv_exact(conn, 4) if masked else None
    payload = recv_exact(conn, length) if length else b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def write_frame(conn, opcode, payload):
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n < 65536:
        header += bytes([126]) + struct.pack(">H", n)
    else:
        header += bytes([127]) + struct.pack(">Q", n)
    conn.sendall(header + payload)


class Framed:
    """The frames as a byte stream, so the handshake can be read a line at a
    time and whatever follows it handed on untouched.

    The leftover matters: the client is free to put its OPEN line and the first
    bytes of SSH in one frame, and those bytes belong upstream, not on the
    floor.
    """

    def __init__(self, conn):
        self.conn = conn
        self.buffer = b""
        self.closed = False

    def _fill(self):
        while True:
            opcode, payload = read_frame(self.conn)
            if opcode == 0x8:
                self.closed = True
                return
            if opcode == 0x9:
                write_frame(self.conn, 0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in (0x0, 0x1, 0x2):
                self.buffer += payload
                return

    def read_line(self):
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_LINE:
                raise ConnectionError("line too long")
            self._fill()
            if self.closed:
                raise ConnectionError("closed during handshake")
        line, _, rest = self.buffer.partition(b"\n")
        self.buffer = rest
        return line.decode("latin-1", "replace").rstrip("\r")

    def take_pending(self):
        pending, self.buffer = self.buffer, b""
        return pending

    def write_line(self, text):
        write_frame(self.conn, 0x2, (text + "\r\n").encode("ascii"))


def authenticate(stream, psk):
    """Challenge, verify, and return the catalogue. Raises on refusal."""
    nonce = os.urandom(NONCE_BYTES)
    stream.write_line(GREETING + " " + base64.b64encode(nonce).decode())

    line = stream.read_line()
    if not line.startswith("AUTH "):
        raise PermissionError("expected AUTH")

    expected = hmac.new(psk, LABEL + nonce, hashlib.sha256).digest()
    try:
        offered = base64.b64decode(line[5:].strip(), validate=True)
    except Exception:
        raise PermissionError("malformed tag")
    # compare_digest, not ==: a comparison that stops at the first wrong byte
    # tells an attacker how much of a guess was right.
    if not hmac.compare_digest(offered, expected):
        raise PermissionError("bad key")


def serve(conn, targets, psk):
    upstream = None
    try:
        path, key = read_request(conn)
        if not key:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        accept = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()
        ).decode()
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode()
        )

        stream = Framed(conn)
        try:
            authenticate(stream, psk)
        except PermissionError:
            # Named rather than described, and slowly: someone guessing learns
            # only that they guessed wrong.
            time.sleep(FAILURE_DELAY)
            try:
                stream.write_line("ERR auth")
            except Exception:
                pass
            return

        # The catalogue is the answer to authenticating. Nobody has to know an
        # address to use this, and nobody who has not authenticated sees one.
        stream.write_line("OK " + " ".join(sorted(targets)))

        line = stream.read_line()
        if not line.startswith("OPEN "):
            stream.write_line("ERR expected OPEN")
            return
        name = line[5:].strip()
        target = targets.get(name) if NAME.match(name or "") else None
        if target is None:
            stream.write_line("ERR no such target")
            return

        upstream = socket.create_connection((target[0], target[1]), timeout=15)
        upstream.settimeout(None)
        stream.write_line("READY")

        # Anything that arrived in the same frame as OPEN is already SSH.
        pending = stream.take_pending()
        if pending:
            upstream.sendall(pending)

        def pump_up():
            try:
                while True:
                    opcode, payload = read_frame(conn)
                    if opcode == 0x8:          # close
                        break
                    if opcode == 0x9:          # ping
                        write_frame(conn, 0xA, payload)
                        continue
                    if opcode in (0x0, 0x1, 0x2) and payload:
                        upstream.sendall(payload)
            except Exception:
                pass
            finally:
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

        threading.Thread(target=pump_up, daemon=True).start()

        while True:
            data = upstream.recv(16384)
            if not data:
                break
            write_frame(conn, 0x2, data)
    except Exception:
        pass
    finally:
        for s in (upstream, conn):
            try:
                if s:
                    s.close()
            except Exception:
                pass


def main():
    config = json.load(open(sys.argv[1]))

    # Refused at startup rather than defaulted: a bridge with no key is the
    # thing this program exists to not be, and leaving a field out should not
    # be a way to get one.
    psk = config.get("psk", "")
    if len(psk) < 16:
        sys.exit("config needs a \"psk\" of at least 16 characters")

    targets = {}
    for name, value in config["targets"].items():
        if not NAME.match(name):
            sys.exit(f"target name {name!r} must match {NAME.pattern}")
        targets[name] = (value[0], int(value[1]))
    if not targets:
        sys.exit("config needs at least one target")

    listen = int(config.get("listen", 8022))
    # Bound to loopback: the only thing that should reach it is the reverse
    # proxy in front, which is what terminates the public hostname.
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config.get("bind", "127.0.0.1"), listen))
    server.listen(32)
    print(f"wsbridge on {listen}, {len(targets)} target(s)", flush=True)

    key = psk.encode("utf-8")
    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn, targets, key), daemon=True).start()


if __name__ == "__main__":
    main()
