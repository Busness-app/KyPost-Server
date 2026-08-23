# Reverse proxy networking

How to put a proxy in front of KyPost so the server sees each visitor's real
address. This is referenced from `docker-compose.yml`, which keeps only a short
pointer at each setting.

## Why it matters

Every IP-keyed control depends on the peer address being the caller's: the
login, CardDAV, device and proof-of-work lockouts, the WKD rate limit, and the
address the MFA sign-in push reports.

Traffic that crosses from one Docker network to another — or that leaves and
comes back through the published port — is source-NATed on the way in, so the
peer address becomes a bridge gateway (`172.x.0.1`) that is **the same for every
caller**. All those lockouts then collapse into one shared bucket: enough
failures from anyone locks out everyone.

Put the proxy on `kypost-net` and address the container by name. Container-to-
container traffic ignores published ports, so nothing needs publishing at all.

Verify with `GET /api/status`: `clientIp` must be your own public address and
`proxyHeadersTrusted` must be `true`. Do not assume — check.

## Joining the network from another Compose project

In the proxy's own compose file:

```yaml
services:
  cloudflared:
    networks:
      kypost-net:
        ipv4_address: 10.89.0.10    # pin it: TRUSTED_PROXY_CIDRS names this
networks:
  kypost-net:
    external: true
```

Then point the proxy at `http://KyPost-Server:5866` (this network has DNS, so
the name is stable across rebuilds) and set
`TRUSTED_PROXY_CIDRS=10.89.0.10/32`.

`external: true` goes on the **proxy** side only. This Compose project creates
and owns the network, so bring KyPost up first. A proxy that starts first fails
with `network kypost-net declared as external, but could not be found` — start
it again once KyPost is up.

A proxy started with a plain `docker run` and no `--network` lands on Docker's
default bridge, not here, and reaches the server only through the published
port. If you are wiring up a proxy and every visitor's address comes out
identical, this is the first thing to check.

## Why the network is named, with an explicit subnet

A proxy in a different Compose project can join it by a name that does not
depend on this checkout's directory name, and a user-configured subnet is the
prerequisite for the pinned `ipv4_address` — Docker rejects pinned addresses on
any network it auto-configured, including the default bridge.

## Do not create it by hand

`docker network create` produces a network without Compose's labels, which
Compose refuses:

```
network kypost-net was found but has incorrect label
com.docker.compose.network set to "" (expected: "kypost-net")
```

To recover, hand it back to Compose:

```sh
docker compose down                                   # in this directory
docker network inspect kypost-net \
  -f '{{range .Containers}}{{.Name}} {{end}}'          # what is still attached
docker network disconnect -f kypost-net <each>         # or stop those containers
docker network rm kypost-net
docker compose up -d                                   # recreates it, labelled
```

Start the proxy again so it rejoins. Nothing is lost: the network holds no
state, and both addresses are pinned, so the containers come back where they
were.

## Address allocation

Keep this network to just the proxy and the server, or pin addresses high
(`.200`, `.201`). Docker allocates dynamic addresses from the low end of the
subnet, so a third container joining can be handed the address you pinned for
something else.

## Subnet collisions

If startup fails with `Pool overlaps with other one on this address space`, the
subnet is already taken. Change both:

```sh
KYPOST_SUBNET=10.90.0.0/24
KYPOST_IP=10.90.0.5
```

List what is taken:

```sh
docker network ls -q | xargs docker network inspect \
  -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'
```

The default is `10.89.0.0/24` rather than a `172.x` one deliberately. Docker
auto-allocates project networks as /16s out of `172.17.0.0/12` — 172.17, 172.18,
172.19 and up — so any `172.x` default collides once a host has enough Compose
projects, and the collision surfaces as the error above rather than as anything
mentioning this file. `10.89.0.0/24` is outside that pool. Change it if it
clashes with your own LAN or VPN routes.

## The pairing QR reads your proxy's certificate

The mobile pairing QR carries a pin for the certificate the device will be
handed, so the app can pin the registration handshake before it discloses the
pairing token and its push credentials. See
[Certificate pinning in the pairing QR](../README.md#certificate-pinning-in-the-pairing-qr).

Your proxy holds that certificate, not this server — with `cloudflared` there is
no file to mount at all, because the device validates a Cloudflare edge
certificate. So the server reads it the same way the device will: at the moment
it builds each QR, it makes a verified TLS connection to `SERVER_BASE_URL` and
takes the leaf.

**Set `SERVER_BASE_URL` to your public `https://` URL.** That is the whole
configuration, and pairing does not work without it. No URL that carries a
credential is derived from the request's `Host` header — a caller who could
steer that would be choosing which key the app pins, and where the pairing
token is sent.

If your public hostname does not resolve back to the proxy from inside the
server's network — a self-hosted proxy behind a consumer router with no NAT
hairpinning is the usual case — the probe fails and the QR simply omits the pin,
leaving pairing exactly as it was. Split-horizon DNS pointing the hostname at
the proxy's LAN address fixes it; so does `cloudflared`, whose traffic leaves to
the anycast edge and never needs to come back in.
