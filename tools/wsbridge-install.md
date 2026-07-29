# Installing the WebSocket bridge

The client half is done and tested. This is the server half, which touches
machines of yours and so is yours to run.

## What this gets you

A handset that can reach any machine on your tailnet, without running Tailscale
— which it cannot. Being a VPN means capturing the whole device's traffic, and
on BlackBerry OS 7 that lives behind RIM's signed VPN framework, which this
project cannot enter. So the phone never joins the tailnet. The bridge does,
and carries the phone's SSH stream in.

Tailscale Funnel would have avoided all of the plumbing below, and does not
work here: it listens only on 443/8443/10000 and only over TLS, and this client
has no TLS. Even with it, Funnel's certificates come from Let's Encrypt, whose
root is from 2015 while the 9790's trust store stopped being updated in 2013.

## What it exposes, and what holds it

A path on a public hostname becomes a way to reach SSH on machines you name.
Read this part before running it — the protection is three independent layers,
and the first is the one that actually bounds the damage.

**1. The Tailscale policy.** Give the bridge a tagged identity rather than your
own, and grant it only what it needs:

```json
{
  "tagOwners": { "tag:berryssh-bridge": ["autogroup:admin"],
                 "tag:phone-reachable": ["autogroup:admin"] },
  "grants": [
    { "src": ["tag:berryssh-bridge"],
      "dst": ["tag:phone-reachable"],
      "ip":  ["tcp:22"] }
  ]
}
```

Then tag the machines the phone should reach with `tag:phone-reachable`. A
bridge running attacker code still reaches nothing but port 22 on those, which
is the property worth having: the config below stops being the only thing
standing between a public path and your network.

**2. A pre-shared key.** The bridge refuses to start without one. Nothing —
not even the list of machines it serves — is disclosed before it is proved.

**3. SSH itself.** Key authentication at the far end, host key verification at
the near one. The bridge carries ciphertext it cannot read, and one that was
swapped or tampered with is refused by the handset rather than trusted.

What this does **not** do is encrypt the outer layer. `ws://` is plaintext, so
an observer on the path sees that you connected and which name you asked for.
They do not see the session: SSH already provides confidentiality, integrity
and both ends' identities. TLS here would buy metadata privacy, not security.

If that trade is not one you want, do not install it — the handset can still
reach anything on the LAN when it is at home.

## Where to run it

**Not on the machine that faces the internet.** Put it on an internal node and
have the public reverse proxy reach it over the LAN. Then a compromise of the
public box yields no tailnet identity at all. Splitting them costs one config
line and removes a whole class of bad day.

## Install

On the internal node, as root:

```sh
mkdir -p /opt/wsbridge
curl -fsSL -o /opt/wsbridge/wsbridge.py \
  https://raw.githubusercontent.com/cobanov/berryssh/main/tools/wsbridge.py
```

Join the tailnet with a tagged, **non-reusable** auth key (create it in the
admin console with Tags enabled):

```sh
tailscale up --auth-key=tskey-... --advertise-tags=tag:berryssh-bridge
```

Generate a key. Do not invent one by hand — this is the whole of layer 2:

```sh
head -c 24 /dev/urandom | base64
```

Write `/opt/wsbridge/config.json`, naming only the machines you want reachable.
The names are what the handset will show; the addresses are never sent to it.

```json
{
  "listen": 8022,
  "bind": "127.0.0.1",
  "psk": "the base64 string you just generated",
  "targets": {
    "pve":   ["100.76.56.16", 22],
    "ct107": ["100.110.192.73", 22]
  }
}
```

```sh
chmod 600 /opt/wsbridge/config.json
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

On the public node, append to `/etc/caddy/Caddyfile` — Caddy passes WebSockets
through `reverse_proxy` with no extra configuration. Point it at the internal
node's LAN address:

```
ssh.cobanov.run:80 {
	reverse_proxy 192.168.8.56:8022
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
  http://ssh.cobanov.run/
```

`101` means the bridge answered and is now waiting to be authenticated. It will
not say anything further, and will close, which is correct: `curl` does not
have the key.

## On the handset

In the connection editor:

- **Host** `ssh.cobanov.run`, **Port** `80` — the HTTP entrance, not the SSH
  server.
- **WebSocket path** `/`
- **Bridge key** — the string from `config.json`.
- **Bridge target** — open it and it asks the bridge which names it has, then
  offers them as a list. No address is ever typed into the phone.

Leave **Bridge key** empty for an ordinary WebSocket-to-TCP proxy that asks for
none; leave **WebSocket path** empty for a plain socket.

Each target gets its own host key record, stored as `pve via ssh.cobanov.run`,
so two machines behind one bridge do not look to the phone like one machine
whose key keeps changing.
