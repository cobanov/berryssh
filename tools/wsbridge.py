#!/usr/bin/env python3
"""A WebSocket-to-TCP bridge, so a client that can only speak HTTP can reach
SSH.

The handset cannot run a VPN, and behind Cloudflare there is no raw TCP route
into the network to fall back on. HTTP is what the entrance speaks, and a
WebSocket is a TCP stream wearing an HTTP handshake — so this unwraps it and
connects onward.

    wsbridge.py <config.json>

    {
      "listen": 8022,
      "targets": {
        "/pve":   ["192.168.8.50", 22],
        "/ct100": ["192.168.8.155", 22]
      }
    }

**The targets are an allowlist and that is the whole security model.** A bridge
that connected wherever the path asked would be an open proxy into the network,
reachable by anyone who found the hostname. Nothing outside this map is dialled.

Beyond that the protection is SSH's own: the servers take keys, and the client
checks the host key, so the bridge carries ciphertext it cannot read and cannot
usefully tamper with — a forged or swapped host key is refused at the far end.

Standard library only, so it runs anywhere Python does with nothing installed.
"""
import base64
import hashlib
import json
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HEADERS = 65536
MAX_FRAME = 1 << 20


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


def serve(conn, targets):
    upstream = None
    try:
        path, key = read_request(conn)
        if not key:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        target = targets.get(path)
        if target is None:
            # Named rather than described: someone probing gets no map of what
            # else might be here.
            conn.sendall(b"HTTP/1.1 404 Not Found\r\n\r\n")
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

        upstream = socket.create_connection((target[0], target[1]), timeout=15)
        upstream.settimeout(None)

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
    targets = {k: (v[0], int(v[1])) for k, v in config["targets"].items()}
    listen = int(config.get("listen", 8022))
    # Bound to loopback: the only thing that should reach it is the reverse
    # proxy in front, which is what terminates the public hostname.
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config.get("bind", "127.0.0.1"), listen))
    server.listen(32)
    print(f"wsbridge on {listen}, {len(targets)} target(s)", flush=True)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn, targets), daemon=True).start()


if __name__ == "__main__":
    main()
