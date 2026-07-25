# vpnp — AWS Client VPN on macOS without breaking apple/container

Amazon's AWS VPN Client app disables `net.inet.ip.forwarding` on macOS,
which kills [apple/container](https://github.com/apple/container) networking
and local development. `vpnp` replaces it with **stock OpenVPN in
split-tunnel mode**: the endpoint pushes its routes (e.g. `10.0.0.0/16`)
onto a `utun`, the OS routing table does the split, and every tool on the
Mac reaches VPN-private IPs automatically — no proxy, no proxy env, no
per-tool config, and (validated live) no change to `net.inet.ip.forwarding`,
the default route, or your global DNS.

```
your tools ──▶ OS routing table ──┬─ pushed ranges (10.0.0.0/16) ──▶ utun (stock openvpn) ──▶ AWS VPN
                                  └─ everything else ─────────────▶ default interface

DNS: only the suffixes in config/vpn.dns → /etc/resolver/<suffix> → VPN DNS
     everything else → your normal resolvers
```

`vpnp` itself is a thin Go wrapper that adds the pieces stock
openvpn is missing for AWS Client VPN:

- **endpoint IP pinning** — AWS profiles carry `remote-random-hostname`,
  which makes stock openvpn prepend a fresh random DNS label on every
  attempt and fail; vpnp resolves once (random-prefixed) and pins the IP
- **per-domain split-DNS** — writes `/etc/resolver/<suffix>` files for the
  suffixes you list in `config/vpn.dns` on up, removes exactly those on down
- **SAML/SSO federation** — profiles with AWS's `auth-federate` sign in
  through your browser; vpnp drives the challenge/response flow that the
  AWS-forked OpenVPN normally handles (see below)
- **lifecycle** — daemonized openvpn with log/pidfile under `.run/`, clean
  status and teardown; reconnects are openvpn's own

## Prerequisites

- macOS (Apple Silicon), [Homebrew](https://brew.sh) OpenVPN ≥ 2.7
  (installed automatically by the brew formula, or `brew install openvpn`)
- Your AWS Client VPN `.ovpn` — **mutual certificate auth** (inline
  `<cert>`/`<key>`) or **SAML/SSO federation** (`auth-federate`) — see
  [config/README.md](config/README.md)

## Install with Homebrew

```sh
brew install TakiTake/tap/vpnp
cp ~/Downloads/downloaded-client-config.ovpn /opt/homebrew/etc/vpnp/config/vpn.ovpn
```

A brew-installed vpnp keeps its config and runtime state under
`/opt/homebrew/etc/vpnp/` (`config/vpn.ovpn`, `config/vpn.dns`,
`config/vpn.access`, optional `.env`, logs in `.run/`). Everything else
below is identical.

## Install from source (alternative)

Needs Go (`brew install go`). Config then lives in the clone.

```sh
git clone https://github.com/TakiTake/vpnp.git && cd vpnp
make install                                   # builds vpnp into your brew bin
cp ~/Downloads/downloaded-client-config.ovpn config/vpn.ovpn
cp .env.example .env                           # optional: set VPN_TEST_URL
```

Skeptical the invariants hold for *your* endpoint? Run the validation
script first: `sudo bash docs/validate-direct-openvpn.sh` — it connects
with stock openvpn and checks forwarding, default route, pushed routes,
and VPN DNS end to end.

## Daily usage

```sh
vpnp up        # connect (asks for your sudo password — openvpn needs root for the utun)
vpnp status    # tunnel / routes / split-DNS / forwarding-invariant health
vpnp down      # disconnect and remove the /etc/resolver entries
```

Every command documents itself in detail — behavior, files touched, file
formats, and exit codes: `vpnp help <command>`. Non-interactive callers
(scripts, AI agents) can edit `config/vpn.dns` / `config/vpn.access`
directly and run `vpnp dns -apply` / `vpnp access -apply` — no `$EDITOR`
involved; `vpnp status` exits 0 only when connected, so it doubles as a
probe.

That's it. While up, VPN-private IPs and the DNS suffixes in
`config/vpn.dns` work in **every** tool — curl, ssh, browsers, IDEs —
with zero configuration:

```sh
curl https://internal.example.corp/            # just works
ssh 10.0.12.34                                 # just works
```

Session drops are recovered by openvpn itself — silently for certificate
auth, and for SAML too (via the session token AWS pushes) until the AWS
session duration expires, at which point `vpnp up` signs in again.
`vpnp logs` follows the openvpn log if you're curious.

### SAML / SSO federation endpoints

If your `.ovpn` contains `auth-federate` (browser sign-in instead of a
client certificate), install the patched OpenVPN build once:

```sh
brew install TakiTake/tap/openvpn-aws
```

`vpnp up` then opens your browser for the IdP sign-in and connects when
it completes — no other change to the workflow. The patch only raises
OpenVPN's buffer sizes: AWS transports the multi-KB SAML response as the
OpenVPN password inside a single TLS control message, which stock
OpenVPN caps at 2 KB. It installs as a separate `openvpn-aws` binary and
never touches your stock openvpn; cert-auth profiles keep using stock.

### Split-DNS: which names resolve through the VPN

```sh
vpnp dns       # edit config/vpn.dns — re-applies immediately if the VPN is up
```

One DNS suffix per line; each becomes an `/etc/resolver/<suffix>` file
pointing at the VPN's pushed DNS server (VPC resolver), so VPN-private
names resolve to their private IPs. All other DNS never touches the VPN.
Routing needs no list at all — the endpoint's pushed routes cover it.

### Container governance: what containers may reach through the VPN

The AWS VPN Client app "solves" the Mac-as-router risk by disabling IP
forwarding entirely, breaking apple/container. vpnp keeps forwarding on
and moves the enforcement into pf instead: containers are **default-deny**
into the tunnel, and `config/vpn.access` opts in specific destinations:

```sh
vpnp access    # edit — re-applies immediately if the VPN is up
```

```
allow 10.0.0.0/16 port 443     # HTTPS anywhere in the VPC
allow 10.0.12.34 port 5432     # one database
allow any                      # ungoverned, explicit opt-in
```

The filter matches container-sourced traffic before NAT, so host traffic
is never affected, and only VPN-routed ranges are filtered — container
internet access is untouched. Other LAN devices can't ride the tunnel at
all (their sources are never NAT'd, so the VPN drops them).

### Switching endpoints

```sh
vpnp down && vpnp up -ovpn config/other-endpoint.ovpn
```

## Why not the AWS VPN Client / a proxy?

| Approach | Problem |
|---|---|
| AWS VPN Client app | sets `net.inet.ip.forwarding=0` → apple/container loses networking (macOS also defaults to 0 after reboot: `sudo sysctl -w net.inet.ip.forwarding=1` restores it) |
| VPN-in-a-container + SOCKS proxy | works, but every tool needs proxy config |
| userspace VPN + rule-routed proxy | works, but every tool needs proxy env |
| **stock openvpn split-tunnel (this)** | OS does the split; zero per-tool config; forwarding untouched (validated: `docs/validate-direct-openvpn.sh`) |

Earlier incarnations of this project implemented the two middle rows — an
apple/container OpenVPN+SOCKS stack and a userspace minivpn/gVisor proxy
with rule routing. Both worked, but a split-tunnel endpoint makes them
unnecessary complexity.

## How it works

1. `vpnp up` parses `config/vpn.ovpn`, strips `remote` /
   `remote-random-hostname` (and, for SAML profiles, `auth-federate` /
   `auth-user-pass` / `auth-retry`, which stock openvpn rejects), resolves
   the endpoint once with a random-prefixed label (bare AWS endpoint names
   often don't resolve) and pins that IP for the whole session.
2. SAML profiles only: runs `openvpn-aws` once unprivileged with password
   `ACS::35001`; the server "fails" the auth with a `CRV1:` challenge
   carrying the IdP sign-in URL. vpnp opens it in your browser, catches
   the `SAMLResponse` the IdP POSTs to `127.0.0.1:35001`, and uses
   `CRV1::<sid>::<response>` as the password for the real connection —
   to the same pinned IP, which AWS requires.
3. Runs `sudo openvpn --daemon` with the sanitized profile,
   `--dns-updown disable` (openvpn 2.7 would otherwise install the pushed
   DNS server as your **global** resolver), and log/pidfile under `.run/`.
4. Waits for `Initialization Sequence Completed`, then reads the pushed
   routes and DNS server from the log.
5. Writes `/etc/resolver/<suffix>` (nameserver = pushed VPN DNS) for each
   suffix in `config/vpn.dns` and flushes the DNS caches. The file list is
   tracked in `.run/resolver.list`.
6. Loads the container policy into the pf anchor `com.apple/vpnp`
   (evaluated by macOS's stock pf.conf — no system config touched) so
   **apple/container guests reach the VPN too, governed**: a source-NAT
   rule (their forwarded packets would otherwise enter the tunnel with the
   container's `192.168.64.x` source address, which AWS drops) plus a
   **default-deny allowlist** — containers only reach the destinations and
   ports listed in `config/vpn.access`. Host traffic and container
   internet traffic are never filtered. Override the subnet with
   `CONTAINER_NAT_SUBNET` in `.env` (`off` disables NAT and filtering).
7. `vpnp down` removes the resolver files and the pf rules, then SIGTERMs
   openvpn, which tears down its routes and the utun.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cannot resolve cvpn-endpoint-…` | The endpoint has no target network associated (AWS side) — its DNS name only exists while associated; ask your AWS admin |
| `up` times out | `vpnp logs` — cert rejected, endpoint unreachable, port blocked? `vpnp down` cleans up the half-started daemon |
| A private hostname doesn't resolve | Its suffix isn't in `config/vpn.dns` — add it: `vpnp dns` |
| A private IP doesn't connect | Is it inside the pushed routes? `vpnp status` shows them; ranges outside what the endpoint pushes need an AWS-side route |
| apple/container has no internet | Unrelated to vpnp (validated) — check `sysctl net.inet.ip.forwarding` is 1; macOS resets it to 0 on reboot and Amazon's client sets it to 0 |
| Containers resolve VPN names but connections time out | Either the destination/port isn't allowed in `config/vpn.access` (`vpnp access`), or the pf rules went stale (utun number changed after a reconnect) — `vpnp status` shows the `containers:` line; `vpnp down && vpnp up` refreshes |
| Stale `/etc/resolver` entries after a crash | `vpnp down` removes them any time, even with openvpn already dead |
| `this profile uses SAML federation…` | Install the patched build: `brew install TakiTake/tap/openvpn-aws` (stock openvpn can't carry the SAML response — see the SAML section) |
| `no SAML challenge in the openvpn output` | The endpoint didn't offer federation — wrong profile? — or it's unreachable; the captured openvpn output is printed below the error |
| Browser sign-in succeeds but `up` then fails | The one-time SAML password expired between sign-in and connect — rerun `vpnp up`; also check `vpnp logs` for AUTH_FAILED (session policy, revoked user) |
| SAML VPN drops after hours and won't reconnect | The AWS session duration expired — sign in again: `vpnp up` |

## License

[MIT](LICENSE)
