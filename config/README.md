# VPN endpoint configs

Drop your AWS Client VPN configuration file(s) here, e.g. `vpn.ovpn`
(everything matching `*.ovpn` is gitignored).

Get the file from your Client VPN **self-service portal** (ask your AWS admin
for the URL), or from the AWS console: VPC → Client VPN Endpoints → Download
client configuration.

Use the file **as downloaded** — do not edit it. `vpnp up` strips the
`remote` / `remote-random-hostname` lines itself (it pins the endpoint IP
once instead) and passes everything else to openvpn verbatim.

The endpoint must be a **mutual-certificate** profile: the inline
`<cert>`/`<key>` in the `.ovpn` are the credential that authenticates you
(no SAML / browser sign-in).

Multiple endpoints: keep several files here and pick one at start:

    vpnp up -ovpn config/other-endpoint.ovpn

`vpn.dns` (created from `vpn.dns.example` on first `vpnp up`) lists the DNS
suffixes that should resolve through the VPN — edit with `vpnp dns`.
