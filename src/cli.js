#!/usr/bin/env node

import process from "node:process";
import { parseArgs } from "node:util";

import { scanPath } from "./scanner.js";
import { severityRank } from "./rules.js";
import { formatText, summarize } from "./format.js";
import { applyBaseline, loadBaseline, writeBaseline } from "./baseline.js";

const HELP = `
Usage:
  mcp-safety-scan [path] [--format=json|text|sarif|github] [--fail-on=high|medium|low|info|none]
  mcp-safety-scan [path] --baseline=baseline.json
  mcp-safety-scan [path] --write-baseline=baseline.json

Examples:
  mcp-safety-scan .
  mcp-safety-scan /path/to/repo --format=json
  mcp-safety-scan /path/to/repo --format=sarif > results.sarif
  mcp-safety-scan /path/to/repo --format=github
  mcp-safety-scan /path/to/repo --fail-on=medium
  mcp-safety-scan /path/to/repo --write-baseline .mcp-safety-baseline.json
`.trim();

function parseFailOn(v) {
  if (!v) return "high";
  const s = String(v).toLowerCase();
  if (s === "none") return "none";
  if (s === "info" || s === "low" || s === "medium" || s === "high" || s === "critical") return s;
  return null;
}

const { values, positionals } = parseArgs({
  args: process.argv.slice(2),
  options: {
    help: { type: "boolean", short: "h" },
    format: { type: "string" },
    "fail-on": { type: "string" },
    baseline: { type: "string" },
    "write-baseline": { type: "string" },
  },
  allowPositionals: true,
});

if (values.help) {
  console.log(HELP);
  process.exitCode = 0;
  process.exit();
}

const target = positionals[0] ?? ".";
const format = (values.format ?? "text").toLowerCase();
const failOn = parseFailOn(values["fail-on"]);

if (!failOn) {
  console.error("Invalid --fail-on. Use one of: critical, high, medium, low, info, none.");
  process.exitCode = 2;
  process.exit();
}

if (format !== "text" && format !== "json" && format !== "sarif" && format !== "github") {
  console.error("Invalid --format. Use: text, json, sarif, or github.");
  process.exitCode = 2;
  process.exit();
}

const baselinePath = values.baseline ? String(values.baseline) : "";
const writeBaselinePath = values["write-baseline"] ? String(values["write-baseline"]) : "";

if (baselinePath && writeBaselinePath) {
  console.error("Invalid usage: do not combine --baseline with --write-baseline.");
  process.exitCode = 2;
  process.exit();
}

const resultRaw = await scanPath(target);

let baselineSet = null;
if (baselinePath) {
  try {
    baselineSet = await loadBaseline(baselinePath);
  } catch (e) {
    const msg = e && typeof e.message === "string" ? e.message : String(e);
    console.error(`Failed to load baseline: ${msg}`);
    process.exitCode = 2;
    process.exit();
  }
}

const result = {
  ...resultRaw,
  findings: baselineSet ? applyBaseline(resultRaw.findings, baselineSet) : resultRaw.findings,
};

if (writeBaselinePath) {
  try {
    await writeBaseline(writeBaselinePath, resultRaw);
  } catch (e) {
    const msg = e && typeof e.message === "string" ? e.message : String(e);
    console.error(`Failed to write baseline: ${msg}`);
    process.exitCode = 2;
    process.exit();
  }
}

if (format === "json") {
  const summary = summarize(result.findings);
  console.log(
    JSON.stringify(
      {
        root: result.root,
        filesScanned: result.filesScanned,
        summary,
        findings: result.findings,
      },
      null,
      2
    )
  );
} else if (format === "sarif") {
  const { formatSarif } = await import("./sarif.js");
  console.log(JSON.stringify(formatSarif(result), null, 2));
} else if (format === "github") {
  const { formatGithub } = await import("./github.js");
  console.log(formatGithub(result));
} else {
  console.log(formatText(result));
}

if (!writeBaselinePath && failOn !== "none") {
  const threshold = severityRank(failOn);
  const has = result.findings.some((f) => severityRank(f.severity) >= threshold);
  if (has) process.exitCode = 1;
}
