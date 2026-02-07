# Changelog

## v0.3.3

- Skip common test/fixture directories by default (e.g. `test/`, `tests/`, `__tests__/`, `fixtures/`) to reduce false positives.
- Expand the MCP Security Baseline doc with concrete request body size limit examples (Express, Go net/http).

## v0.3.2

- Add request-body size limit heuristics:
  - Web-standard `await request.json()` reads
  - Python `await request.body()` / `await request.json()` reads
  - Go `io.ReadAll(r.Body)` reads
- Document `npx`/`npm i -g` installation via GitHub (no npm publish required).

## v0.3.1

- Skip common test file name patterns by default (e.g. `*.test.*`, `*.spec.*`, `*_test.go`, `test_*.py`). Use `--include-tests` / `include-tests: "true"` to include them.

## v0.3.0

- Add `--files-from` (CLI) / `files-from` (GitHub Action input) to scan only a provided newline-delimited file list (useful for PR diff scanning).

## v0.2.9

- Reduce false positives by skipping comment-only lines and block comments when scanning.

## v0.2.8

- Flag servers that explicitly bind to all interfaces (`0.0.0.0` / `::`) as a high-severity public exposure footgun.
- Add `--ignore-dir` (CLI) / `ignore-dirs` (GitHub Action input) to reduce noise from directories like `test/` and `__tests__/`.

## v0.2.7

- Flag `cors({ origin: true })` as reflected CORS origin (common Node/Express footgun).
- Flag `AllowAllOrigins: true` (gin-contrib/cors) as wildcard CORS.

## v0.2.6

- Add remediation hints ("Fix: ...") to findings in text/github/SARIF outputs to make results more actionable.
- Document a Docker-based CI integration option (no GitHub Action dependency).

## v0.2.5

- Make npm publish in the release workflow best-effort: if `NPM_TOKEN` is set but invalid/expired, skip publish with a warning instead of failing the release.

## v0.2.4

- Fix release workflow validation: GitHub Actions does not allow `secrets.*` in `if:` expressions, so the npm publish step now gates on an env var instead.

## v0.2.3

- Add Docker image publish to GHCR on releases (`ghcr.io/theodornengoy/mcp-safety-scanner:v0`).
- Make npm publish step in release workflow conditional on `NPM_TOKEN` being set.

## v0.2.2

- Prep npm publish: remove `private`, add `files` allowlist and package metadata.
- Rename npm package to `mcp-safety-scan` (CLI remains `mcp-safety-scan`).

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
