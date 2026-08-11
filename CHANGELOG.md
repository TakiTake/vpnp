# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2026-08-11

### Added

- Release pipeline: pushing a `vX.Y.Z` tag now builds the arm64 macOS
  tarball on CI and publishes a GitHub Release with notes from this file
  (`.github/workflows/release.yml`), replacing the manual `make dist` +
  `gh release create` steps.
- Each release now ships a `.sha256` checksum file alongside the tarball
  (#3), so the Homebrew tap can verify its download against a published
  checksum.

## [0.2.0] - 2026-07-25

### Added

- SAML/SSO federation support for `auth-federate` profiles: `vpnp up`
  detects the AWS CRV1 challenge, opens the browser for IdP sign-in,
  receives the SAML response on `127.0.0.1:35001`, and reconnects with the
  one-time credential. Requires the patched
  `TakiTake/tap/openvpn-aws` build, since AWS transports the multi-KB SAML
  response as the OpenVPN password in a single TLS control message.

## [0.1.0] - 2026-07-25

### Added

- Initial release: AWS Client VPN on macOS without breaking
  apple/container — `vpnp up / down / status / dns / logs` around a
  Homebrew OpenVPN, with split-DNS via macOS resolvers and pf NAT rules
  that keep container traffic working.
- Container governance: default-deny allowlist for container→VPN traffic
  (`config/vpn.access`).
- Agent-friendly CLI: per-command help docs and non-interactive `-apply`.
- Homebrew support: `vpnp version`, `make dist` release tarball, and
  install docs for `brew install TakiTake/tap/vpnp`.

[Unreleased]: https://github.com/TakiTake/vpnp/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/TakiTake/vpnp/releases/tag/v0.2.1
[0.2.0]: https://github.com/TakiTake/vpnp/releases/tag/v0.2.0
[0.1.0]: https://github.com/TakiTake/vpnp/releases/tag/v0.1.0
