import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";

import { scanPath } from "../src/scanner.js";
import { formatSarif } from "../src/sarif.js";
import { formatGithub } from "../src/github.js";

test("detects wildcard and reflected CORS", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  const ruleIds = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ruleIds.has("cors-wildcard-origin"));
  assert.ok(ruleIds.has("cors-reflect-origin"));
  assert.ok(ruleIds.has("child-process-exec"));
});

test("ignores node_modules by default", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);
  assert.ok(!res.findings.some((f) => f.file.includes("node_modules")));
});

test("does not flag RegExp .exec() as child_process exec()", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  const bad = res.findings.filter((f) => f.file === "regex-exec.js" && f.ruleId === "child-process-exec");
  assert.equal(bad.length, 0);
});

test("sarif format is valid JSON and includes results", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);
  const sarif = formatSarif(res);

  assert.equal(sarif.version, "2.1.0");
  assert.ok(Array.isArray(sarif.runs));
  assert.ok(sarif.runs.length >= 1);
  assert.ok(Array.isArray(sarif.runs[0].results));
  assert.ok(sarif.runs[0].results.length >= 1);
});

test("github format produces workflow commands", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);
  const out = formatGithub(res);

  assert.ok(out.includes("::error") || out.includes("::warning") || out.includes("::notice"));
  assert.ok(out.includes("cors-wildcard-origin") || out.includes("dangerous-eval"));
});
