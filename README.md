# mcp-safety-scanner

A tiny, dependency-free CLI that scans JS/TS codebases for common security footguns that show up in MCP servers and other “LLM + tools” backends.

This is a heuristic scanner. It is meant to catch obvious mistakes fast (especially in early-stage prototypes) and to provide a simple “fail CI on high severity issues” gate.

## Install / Run

```bash
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
```

## What It Flags (Initial Rules)

- Wildcard CORS (`Access-Control-Allow-Origin: *`, `cors({ origin: "*" })`)
- Reflected CORS origin (`... = req.headers.origin`)
- Dangerous code execution (`eval(`, `new Function(`)
- Shell execution (`exec(` / `execSync(`)
- Suspicious file deletion (`rmSync(` / `unlinkSync(`)
- Logging request headers (`console.log(req.headers...)`)

## Exit Codes

- `0`: No findings at or above your `--fail-on` threshold
- `1`: Findings at or above threshold found
- `2`: CLI usage error

## GitHub Actions (Minimal)

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
      - run: node /path/to/mcp-safety-scanner/src/cli.js . --fail-on=high
```
