# VPN endpoint configs

Drop your AWS Client VPN configuration file(s) here, e.g. `vpn.ovpn`
(everything matching `*.ovpn` is gitignored).

Get the file from your Client VPN **self-service portal** (ask your AWS admin
for the URL), or from the AWS console: VPC → Client VPN Endpoints → Download
client configuration.

Use the file **as downloaded** — do not edit it. `vpnp up` strips the
`remote` / `remote-random-hostname` lines itself (it pins the endpoint IP
once instead) and passes everything else to openvpn verbatim.

Both AWS auth types work:

- **Mutual certificate**: the inline `<cert>`/`<key>` in the `.ovpn` are
  the credential — connects with no prompts, reconnects silently.
- **SAML / SSO federation** (`auth-federate` in the file): `vpnp up` opens
  your browser for the IdP sign-in. Needs the patched openvpn build:
  `brew install TakiTake/tap/openvpn-aws` (stock openvpn caps the TLS
  control message at 2 KB; the SAML response travels inside one as the
  password). When the AWS session duration expires, run `vpnp up` again.

Multiple endpoints: keep several files here and pick one at start:

    vpnp up -ovpn config/other-endpoint.ovpn

`vpn.dns` (created from `vpn.dns.example` on first `vpnp up`) lists the DNS
suffixes that should resolve through the VPN — edit with `vpnp dns`.
