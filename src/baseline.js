import crypto from "node:crypto";
import { promises as fs } from "node:fs";

export function findingFingerprint(f) {
  const h = crypto.createHash("sha256");
  h.update(String(f?.ruleId ?? ""));
  h.update("\n");
  h.update(String(f?.file ?? ""));
  h.update("\n");
  h.update(String(f?.excerpt ?? ""));
  return h.digest("hex");
}

export function applyBaseline(findings, baselineFingerprints) {
  if (!baselineFingerprints) return findings ?? [];
  const set = baselineFingerprints instanceof Set ? baselineFingerprints : new Set(baselineFingerprints);
  return (findings ?? []).filter((f) => !set.has(findingFingerprint(f)));
}

export async function loadBaseline(filePath) {
  const raw = await fs.readFile(filePath, "utf8");
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    const msg = e && typeof e.message === "string" ? e.message : String(e);
    throw new Error(`Invalid baseline JSON: ${msg}`);
  }
  const fps = data?.fingerprints;
  if (!Array.isArray(fps)) {
    throw new Error("Invalid baseline file: expected { fingerprints: string[] }");
  }
  return new Set(fps.map((s) => String(s)));
}

export async function writeBaseline(filePath, { findings } = {}) {
  // Deduplicate entries by fingerprint to avoid bloated baselines when identical
  // excerpts occur multiple times in the same file (common for repeated patterns).
  const entryByFingerprint = new Map();
  for (const f of findings ?? []) {
    const fingerprint = findingFingerprint(f);
    if (entryByFingerprint.has(fingerprint)) continue;
    entryByFingerprint.set(fingerprint, {
      fingerprint,
      ruleId: f.ruleId,
      severity: f.severity,
      file: f.file,
      excerpt: f.excerpt ?? "",
      context: f.context ?? "",
    });
  }

  const fingerprints = Array.from(entryByFingerprint.keys()).sort();
  const entries = fingerprints.map((fp) => entryByFingerprint.get(fp));

  const out = {
    version: 1,
    tool: "mcp-safety-scanner",
    generatedAt: new Date().toISOString(),
    fingerprints,
    entries,
  };

  await fs.writeFile(filePath, JSON.stringify(out, null, 2) + "\n", "utf8");
  return out;
}
