import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import fs from "node:fs/promises";

import { scanPath } from "../src/scanner.js";
import { formatSarif } from "../src/sarif.js";
import { formatGithub } from "../src/github.js";
import { applyBaseline, loadBaseline, writeBaseline } from "../src/baseline.js";

test("detects wildcard and reflected CORS", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  const ruleIds = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ruleIds.has("cors-credentials-any-origin"));
  assert.ok(ruleIds.has("cors-wildcard-origin"));
  assert.ok(ruleIds.has("cors-reflect-origin"));
  assert.ok(ruleIds.has("child-process-exec"));

  assert.ok(
    res.findings.some((f) => f.file === "cors-wildcard-credentials.js" && f.ruleId === "cors-credentials-any-origin")
  );
  assert.ok(
    res.findings.some(
      (f) => f.file === "python-cors-wildcard-credentials.py" && f.ruleId === "cors-credentials-any-origin"
    )
  );
  assert.ok(
    res.findings.some((f) => f.file === "go-cors-wildcard-credentials.go" && f.ruleId === "cors-credentials-any-origin")
  );

  assert.ok(res.findings.some((f) => f.file === "cors-origin-true.js" && f.ruleId === "cors-reflect-origin"));
  assert.ok(res.findings.some((f) => f.file === "go-allowall-cors.go" && f.ruleId === "cors-wildcard-origin"));
  assert.ok(res.findings.some((f) => f.file === "cors-multiline-wildcard.js" && f.ruleId === "cors-wildcard-origin"));
});

test("detects Node child_process shell:true options", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  assert.ok(
    res.findings.some((f) => f.file === "child-process-shell-true.js" && f.ruleId === "child-process-shell-true")
  );
  assert.ok(
    res.findings.some(
      (f) => f.file === "child-process-shell-true-multiline.js" && f.ruleId === "child-process-shell-true"
    )
  );
});

test("detects Node child_process spawn of shell interpreters (sh -c / cmd /c / powershell -Command)", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  assert.ok(
    res.findings.some((f) => f.file === "child-process-shell-spawn.js" && f.ruleId === "child-process-shell-spawn")
  );
});

test("detects python and go footguns", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  const ruleIds = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ruleIds.has("python-exec"));
  assert.ok(ruleIds.has("python-shell-exec"));
  assert.ok(ruleIds.has("python-request-body-no-limit"));
  assert.ok(ruleIds.has("go-shell-exec"));
  assert.ok(ruleIds.has("go-readall-request-body-no-limit"));

  assert.ok(res.findings.some((f) => f.file === "python-shell-exec-multiline.py" && f.ruleId === "python-shell-exec"));
  const multiCall = res.findings.filter((f) => f.file === "python-shell-exec-multi-call.py" && f.ruleId === "python-shell-exec");
  assert.equal(multiCall.length, 1);
  assert.equal(multiCall[0].line, 6);
  assert.ok(
    !res.findings.some((f) => f.file === "go-readall-body-maxbytes.go" && f.ruleId === "go-readall-request-body-no-limit")
  );
  assert.ok(
    !res.findings.some((f) => f.file === "go-readall-body-roundtrip.go" && f.ruleId === "go-readall-request-body-no-limit")
  );
});

test("detects public network binding (0.0.0.0 / ::)", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  const ruleIds = new Set(res.findings.map((f) => f.ruleId));
  assert.ok(ruleIds.has("bind-all-interfaces"));

  assert.ok(res.findings.some((f) => f.file === "bind-public.js" && f.ruleId === "bind-all-interfaces"));
  assert.ok(res.findings.some((f) => f.file === "bind-public.py" && f.ruleId === "bind-all-interfaces"));
  assert.ok(res.findings.some((f) => f.file === "bind-public.go" && f.ruleId === "bind-all-interfaces"));
});

test("detects web-standard Request.json() unbounded reads", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  assert.ok(res.findings.some((f) => f.file === "web-request-json.js" && f.ruleId === "web-request-json-no-limit"));
});

test("skips common test file patterns by default (use includeTests to include)", async () => {
  const fixtures = path.resolve("test/fixtures");

  const res = await scanPath(fixtures);
  assert.ok(!res.findings.some((f) => f.file === "example.test.js"));

  const res2 = await scanPath(fixtures, { includeTests: true });
  assert.ok(res2.findings.some((f) => f.file === "example.test.js" && f.ruleId === "dangerous-eval"));
});

test("supports scanning an explicit file list", async () => {
  const fixtures = path.resolve("test/fixtures");

  const res = await scanPath(fixtures, { files: ["cors-origin-true.js"] });
  assert.equal(res.filesScanned, 1);
  assert.ok(res.findings.length >= 1);
  assert.ok(res.findings.every((f) => f.file === "cors-origin-true.js"));
  assert.ok(res.findings.some((f) => f.ruleId === "cors-reflect-origin"));

  const res2 = await scanPath(fixtures, { files: ["eval.js", "ignored/eval.js"], extraIgnoreDirs: ["ignored"] });
  assert.equal(res2.filesScanned, 1);
  assert.ok(res2.findings.some((f) => f.file === "eval.js"));
  assert.ok(!res2.findings.some((f) => String(f.file).split(/[\\\\/]/)[0] === "ignored"));
});

test("supports extra ignore dirs", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures, { extraIgnoreDirs: ["ignored"] });
  assert.ok(!res.findings.some((f) => String(f.file).split(/[\\\\/]/)[0] === "ignored"));
});

test("ignores node_modules by default", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);
  assert.ok(!res.findings.some((f) => f.file.includes("node_modules")));
});

test("ignores .venv and vendor by default", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);
  assert.ok(!res.findings.some((f) => f.file.includes(".venv")));
  assert.ok(!res.findings.some((f) => f.file.includes("vendor")));
});

test("does not flag RegExp .exec() as child_process exec()", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  const bad = res.findings.filter((f) => f.file === "regex-exec.js" && f.ruleId === "child-process-exec");
  assert.equal(bad.length, 0);
});

test("supports suppression comments", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  const suppressed = res.findings.filter((f) => f.file === "suppressed-eval.js" && f.ruleId === "dangerous-eval");
  assert.equal(suppressed.length, 0);

  const stillDetected = res.findings.filter((f) => f.file === "eval.js" && f.ruleId === "dangerous-eval");
  assert.ok(stillDetected.length >= 1);
});

test("baseline filters known findings", async () => {
  const fixtures = path.resolve("test/fixtures");
  const res = await scanPath(fixtures);

  const baselinePath = path.resolve("test/tmp-baseline.json");
  try {
    const baseline = await writeBaseline(baselinePath, res);
    const set = await loadBaseline(baselinePath);
    const filtered = applyBaseline(res.findings, set);
    assert.equal(filtered.length, 0);

    // Baselines should be stable and deduplicated by fingerprint.
    const uniq = new Set(baseline.entries.map((e) => e.fingerprint));
    assert.equal(uniq.size, baseline.entries.length);
    assert.equal(baseline.fingerprints.length, baseline.entries.length);
  } finally {
    await fs.unlink(baselinePath).catch(() => {});
  }
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
