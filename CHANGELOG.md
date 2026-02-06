# Changelog

## v0.2.1

- Add baseline support (`--baseline`, `--write-baseline`) for CI adoption in existing repos.
- Add suppression comments (`mcp-safety-scan ignore` / `ignore-next-line`).
- Add SARIF `partialFingerprints` for more stable code scanning results.

## v0.2.0

- Scan Python and Go files by default (`.py`, `.go`).
- Add Python rules (CORS config, `exec()`, `subprocess(..., shell=True)`, `os.system()`).
- Add Go rules (CORS config, `exec.Command("sh", "-c", ...)`).

## v0.1.3

- Add `branding` metadata for GitHub Marketplace listing.

## v0.1.2

- Scan additional extensions: `.gs` (Google Apps Script), `.mts`, `.cts`.

## v0.1.1

- Fix GitHub Action to scan the target repository path (`GITHUB_WORKSPACE`), not the action repo.
- Add moving `v0` tag.

## v0.1.0

- Initial release: CLI scanner + SARIF + GitHub Action.
