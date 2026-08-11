# Release process

For an agent-operational, step-by-step version of this (who does what, agent
vs. user), run `/release` — see [`.claude/skills/release/SKILL.md`](../.claude/skills/release/SKILL.md).

vpnp has no version file — the git tag is the version, baked into the binary
at build time (`-X main.version`, see the `Makefile`). A release is:

1. Add a `## [x.y.z] - YYYY-MM-DD` section to `CHANGELOG.md` (move the
   `[Unreleased]` content down, update the link-reference footer) and get
   that PR merged. Check that `scripts/release-notes.sh x.y.z` finds the
   new section *before* tagging — the release workflow runs it only after
   the tag is public, and a public tag cannot be pushed over.
2. Tag and push: `git tag vx.y.z && git push origin vx.y.z` (gated to the
   user, not something an agent can run).
3. Pushing the tag triggers [`.github/workflows/release.yml`](../.github/workflows/release.yml),
   which runs the tests, builds the `aarch64-apple-darwin` tarball via
   `make dist` (flat layout: `vpnp` binary, `.env.example`, and the
   `config/` example files — the formula installs straight from the
   extraction root), sanity-checks that the binary prints the tag as its
   version, and publishes a GitHub Release with the tarball, a `.sha256`
   checksum, and notes pulled from the matching `CHANGELOG.md` section.
4. [TakiTake/homebrew-tap](https://github.com/TakiTake/homebrew-tap) polls
   releases hourly (`update-formula.yml`) and opens a formula-bump PR with
   the new `url` and `sha256` on its own — no manual formula editing.
   Review and merge that PR. (Once the first release with a `.sha256`
   asset is out, flip vpnp's `has_sha256_asset` flag in the tap's
   `update-formula.sh` so the tap also cross-checks its download against
   the published checksum — vpnp#3.)
