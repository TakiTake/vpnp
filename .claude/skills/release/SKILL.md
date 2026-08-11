---
name: release
description: Cut and publish a new vpnp release end to end — changelog, tag, GitHub Release verification, and Homebrew tap update. Use when the user asks to cut, ship, or publish a release, or wants the next version released. Takes the new version (e.g. 0.3.0) as an argument.
---

# Cutting a vpnp release

Full narrative in [docs/release.md](../../../docs/release.md); this is the
operational, step-by-step version with who does what. Steps alternate
between the agent and the user — several publish-only actions are gated to
the user by the permission system. Don't retry a denial or work around
it — hand the exact command to the user instead.

vpnp has no version file: the tag itself is the version, baked into the
binary at build time (`-X main.version`, see the `Makefile`). So there is
no version bump to make — the release-prep PR is just the CHANGELOG
section.

## 1. (agent) Preflight and release-prep PR

- Decide `$VERSION` from this skill's argument if given, otherwise ask.
  Plain `X.Y.Z`, no `v` — the tag adds it. Pre-1.0: a breaking change
  bumps the minor, everything else the patch.
- Confirm a clean starting point: `git status` clean, latest `main`
  pulled, and `git tag -l "v$VERSION"` empty (a tag that already exists
  cannot be reused — pick the next number instead).
- In a worktree branch, edit `CHANGELOG.md`:
  - Move the `[Unreleased]` content into a new `## [$VERSION] - YYYY-MM-DD`
    section (today's date), leaving `[Unreleased]` empty. Check
    `git log v<prev>..main --oneline` for anything merged but never noted.
  - Update the link-reference footer: `[Unreleased]` compares
    `v$VERSION...HEAD`, and add the `[$VERSION]` release link.
- Preflight the extractor — this is what `release.yml` will run after the
  tag is already public, so it must pass now:
  `scripts/release-notes.sh $VERSION` prints the new section.
- Quality gates: `go test ./...`, `go vet ./...`, `gofmt -l .` empty, and
  `make dist` (local packaging dry run; its `rm -rf` may be
  classifier-blocked — if so, run the equivalent steps individually).
- Run `local-review` on the diff, fix findings, then open the PR. Every
  revision pushed after a review is an unreviewed diff — re-run before
  each push.

**Do not merge the PR.**

## 2. (user) Merge and tag

- The user merges the PR themselves — PR merges are gated for agents.
- **(agent) Before handing over the tag command**, pull latest `main` and
  re-run `scripts/release-notes.sh $VERSION` there — `release.yml` only
  runs it *after* the tag is already public, so catching a bad heading
  here avoids pushing a tag that's guaranteed to fail downstream (see
  "If the release workflow fails" below).
- Then hand over the tag command:
  ```sh
  ! git checkout main && git pull
  ! git tag v$VERSION && git push origin v$VERSION
  ```
  Tag pushes are gated too (they trigger the public release workflow) — hand
  this exact command over rather than attempting it.

## 3. (agent) Watch the release workflow and verify the artifact

- `gh run watch <run-id>` (or poll `gh run list --workflow=release.yml --limit 1`)
  until `.github/workflows/release.yml` finishes.
- `gh release view v$VERSION` — confirm both assets exist:
  `vpnp-v$VERSION-aarch64-apple-darwin.tar.gz` and its `.sha256`.
- Download both into the scratchpad and verify:
  - `shasum -a 256 -c` the tarball against its `.sha256` file — this is
    the authoritative check.
  - `tar -tzf` shows the **flat** layout (no top-level version dir — the
    formula installs straight from the extraction root, unlike pall8t):
    `./vpnp`, `./.env.example`, `./config/vpn.dns.example`,
    `./config/vpn.access.example`, `./config/README.md`.
  - The binary's magic bytes are Mach-O ARM64:
    `od -A x -t x1z -v vpnp | head -1` should start `cf fa ed fe` with
    cputype `0c 00 00 01` (`0x0100000c` = ARM64).

**If the release workflow fails** (step 3 never finds a Release, or `gh run
watch` reports a failed run): stop — do not proceed to step 4. The tag is
already public at this point; deleting and reusing it requires
`git push --delete origin v$VERSION` (gated, hand it to the user), fixing
whatever failed on `main` in a new PR, then retagging. Report the failure
and the fix needed instead of guessing.

## 4. (agent verifies, user merges) Homebrew tap bump PR

The tap updates itself: `homebrew-tap`'s `update-formula.yml` polls
releases hourly (cron `17 * * * *`) and opens a formula-bump PR when it
sees the new one — no manual formula editing.

Only proceed here once step 3 has confirmed a real Release with both assets
verified.

- To skip the up-to-hour wait, trigger the poll directly:
  `gh workflow run update-formula.yml -R TakiTake/homebrew-tap -f formula=vpnp`
  (a write to another repo — if denied, hand the command to the user).
- Watch for the bump PR (`gh pr list -R TakiTake/homebrew-tap`), then
  verify its diff: `url` points at the new release tarball, `sha256`
  matches the checksum verified in step 3.
- The user merges the tap PR — merges are gated for agents.
- Once merged, verify the live formula: fetch
  `https://raw.githubusercontent.com/TakiTake/homebrew-tap/main/Formula/vpnp.rb`
  and confirm the `url`/`sha256`.
- Sync the user's tapped clone so `brew upgrade` sees it:
  `git -C "$(brew --repository takitake/tap)" pull`.

## 5. (user, optional) Smoke test

```sh
! brew upgrade TakiTake/tap/vpnp || brew install TakiTake/tap/vpnp
! vpnp version
```

`vpnp version` should print exactly `v$VERSION`.
