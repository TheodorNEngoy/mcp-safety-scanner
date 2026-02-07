# mcp-safety-scanner

A tiny, dependency-free CLI that scans JS/TS/Python/Go codebases for common security footguns that show up in MCP servers and other “LLM + tools” backends.

This is a heuristic scanner. It is meant to catch obvious mistakes fast (especially in early-stage prototypes) and to provide a simple “fail CI on high severity issues” gate.

## Install / Run

```bash
# via npx (no install)
npx mcp-safety-scan . --fail-on=high

# install globally
npm i -g mcp-safety-scan
mcp-safety-scan . --fail-on=high

# via Docker (no Node install)
docker run --rm -v "$PWD:/repo" ghcr.io/theodornengoy/mcp-safety-scanner:v0 /repo --format=github --fail-on=high

cd /Users/theodornengoy/Projects/mcp-safety-scanner
npm test

# scan current dir
npm run scan

# scan a target path
node ./src/cli.js /path/to/repo

# json output
node ./src/cli.js /path/to/repo --format=json

# SARIF output (for GitHub code scanning)
node ./src/cli.js /path/to/repo --format=sarif > results.sarif

# fail if >= medium findings exist
node ./src/cli.js /path/to/repo --fail-on=medium

# generate a baseline file (ignore existing findings)
node ./src/cli.js /path/to/repo --write-baseline .mcp-safety-baseline.json

# use a baseline file (only new findings remain)
node ./src/cli.js /path/to/repo --baseline .mcp-safety-baseline.json --fail-on=high

# ignore additional directories (by basename)
node ./src/cli.js /path/to/repo --ignore-dir=test --ignore-dir=__tests__

# scan only files listed in a text file (one per line, relative to the scan path)
git diff --name-only origin/main...HEAD > changed-files.txt
node ./src/cli.js . --files-from changed-files.txt
```

## Suppressions

Use comment directives sparingly (prefer fixing the underlying issue):

```js
// mcp-safety-scan ignore child-process-exec
execSync("echo hello");

// mcp-safety-scan ignore-next-line dangerous-eval
eval(userInput);
```

```py
# mcp-safety-scan ignore-next-line python-shell-exec
subprocess.run(user_input, shell=True)
```

## GitHub Action

Add this to a workflow (pin to a release tag like `v0.1.1`, or use `v0` to track the latest `v0.x`):

```yaml
name: safety-scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - uses: TheodorNEngoy/mcp-safety-scanner@v0.3.0
        with:
          path: .
          # files-from: changed-files.txt
          # baseline: .mcp-safety-baseline.json
          # ignore-dirs: test,__tests__
          fail-on: high
          format: github
```

Scan only changed files in PRs (optional, reduces noise):

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Compute changed files
        run: |
          git diff --name-only "${{ github.event.pull_request.base.sha }}" "${{ github.sha }}" > changed-files.txt
      - uses: TheodorNEngoy/mcp-safety-scanner@v0.3.0
        with:
          path: .
          files-from: changed-files.txt
          fail-on: high
          format: github
```

If you prefer not to depend on a third-party Action in your CI, you can run the scanner via Docker instead:

```yaml
      - uses: actions/checkout@v4
      - name: MCP safety scan (docker)
        run: |
          docker run --rm -v "$GITHUB_WORKSPACE:/repo" \\
            ghcr.io/theodornengoy/mcp-safety-scanner:v0 \\
            /repo --format=github --fail-on=high
```

SARIF upload (optional, requires permissions in some orgs):

```yaml
      - uses: TheodorNEngoy/mcp-safety-scanner@v0.3.0
        id: scan
        with:
          path: .
          # files-from: changed-files.txt
          # baseline: .mcp-safety-baseline.json
          # ignore-dirs: test,__tests__
          fail-on: none
          format: sarif
          sarif-output: mcp-safety.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-safety.sarif
```

## What It Flags (Initial Rules)

- Wildcard CORS (`Access-Control-Allow-Origin: *`, `cors({ origin: "*" })`)
- Reflected CORS origin (`... = req.headers.origin`)
- CORS middleware defaults (e.g. `cors()` with no origin restrictions, `CORS(app)` in Python)
- Binding to all interfaces (`0.0.0.0` / `::`) (public network exposure)
- Dangerous code execution (`eval(`, `new Function(`, Python `exec(`)
- Shell execution (Node `child_process.exec*`, Python `subprocess(..., shell=True)`, Go `exec.Command("sh", "-c", ...)`)
- Suspicious file deletion (`rmSync(` / `unlinkSync(`)
- Logging request headers (`console.log(req.headers...)`)

File types scanned: `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx`, `.mts`, `.cts`, `.gs` (Google Apps Script), `.py`, `.go`.

## Exit Codes

- `0`: No findings at or above your `--fail-on` threshold
- `1`: Findings at or above threshold found
- `2`: CLI usage error
