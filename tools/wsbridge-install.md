# Installing the WebSocket bridge

The client half is done and tested. This is the server half, which touches a
machine of yours and so is yours to run.

## What it does, and what it exposes

A path on an existing HTTP hostname becomes a way to reach one SSH server. The
handset connects to `ws://<host>/<path>`, the bridge unwraps the frames and
connects onward to the address that path is mapped to.

**Read this part before running it.** A path that is reachable from the
internet and lands on `sshd` is, in security terms, a port forward to that
`sshd` — with three differences, all in its favour:

- Only the addresses in `targets` can be dialled. Nothing else is reachable, no
  matter what path is requested, so it is not an open proxy into the LAN.
- No router port is opened. It rides the Cloudflare tunnel that is already
  there, so it inherits whatever rate limiting and DDoS handling that has.
- The bridge listens on loopback only. The reverse proxy in front is the only
  thing that can reach it.

What it does *not* do is add authentication of its own. The protection is
`sshd`'s: those hosts take keys and not passwords. The bridge carries ciphertext
it cannot read, and the client checks the host key, so a bridge that was
tampered with or replaced would be refused at the far end rather than silently
trusted.

If that trade is not one you want, do not install it — the handset can still
reach anything on the LAN when it is at home.

## Install

On the edge container (CT103), as root:

```sh
mkdir -p /opt/wsbridge
curl -fsSL -o /opt/wsbridge/wsbridge.py \
  https://raw.githubusercontent.com/cobanov/berryssh/main/tools/wsbridge.py
```

Write `/opt/wsbridge/config.json` with only the hosts you want reachable:

```json
{
  "listen": 8022,
  "bind": "127.0.0.1",
  "targets": {
    "/pve":   ["192.168.8.50", 22],
    "/ct100": ["192.168.8.155", 22]
  }
}
```

Write `/etc/systemd/system/wsbridge.service`:

```ini
[Unit]
Description=WebSocket to TCP bridge for berryssh
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/wsbridge/wsbridge.py /opt/wsbridge/config.json
Restart=always
RestartSec=2
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now wsbridge
```

Append to `/etc/caddy/Caddyfile` — Caddy passes WebSockets through
`reverse_proxy` without any extra configuration:

```
ssh.cobanov.run:80 {
	reverse_proxy 127.0.0.1:8022
}
```

```sh
systemctl reload caddy
```

`*.cobanov.run` already resolves through the tunnel, so no DNS step.

## Check it

From anywhere:

```sh
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Version: 13' \
  http://ssh.cobanov.run/pve
```

`101` means the bridge answered. `404` means that path is not in `targets`,
which is what a wrong or probing path should get.

## On the handset

In the connection editor set **Host** to `ssh.cobanov.run`, **Port** to `80`,
and **WebSocket path** to `/pve`. Leave the path empty for an ordinary socket.

Host and port then address the HTTP endpoint rather than the SSH server — which
one is reached is decided by the path, on the bridge.
