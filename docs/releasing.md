# Release and Homebrew

Tag releases (`v*`) build binaries and publish release assets through `.github/workflows/release.yml`.

Homebrew tap updates are handled by `.github/workflows/homebrew-tap.yml` on tag push (`v*`).
You can also run it manually with `workflow_dispatch` and pass a tag (useful for backfills).

## One-time setup

1. Create a PAT with access to `chandika/homebrew-tap` (contents: write).
2. Add it in this repo as the Actions secret `HOMEBREW_TAP_TOKEN`.
3. Ensure `chandika/homebrew-tap` contains `Formula/mirage-proxy.rb`.

## What the Homebrew workflow updates

- `url` -> `https://github.com/chandika/mirage-proxy/archive/refs/tags/vX.Y.Z.tar.gz`
- `sha256` -> checksum of that tarball
- `version` -> `X.Y.Z` (if the formula includes a `version` line)

## Verify after release

1. Confirm the `Update Homebrew Tap` workflow completed successfully.
2. Confirm a commit landed in `chandika/homebrew-tap` touching `Formula/mirage-proxy.rb`.
3. Test install/upgrade:
   - `brew update`
   - `brew upgrade mirage-proxy`
