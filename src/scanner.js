import { promises as fs } from "node:fs";
import path from "node:path";

import { RULES, severityRank, DEFAULT_SCAN_EXTS } from "./rules.js";
import { collectCandidateFiles, DEFAULT_IGNORE_DIRS } from "./walk.js";

const DEFAULT_MAX_FILE_BYTES = 1_000_000; // avoid scanning huge bundles

function parseSuppressionDirective(line) {
  // Examples:
  //   // mcp-safety-scan ignore child-process-exec
  //   # mcp-safety-scan ignore-next-line python-shell-exec
  //   // mcp-safety-scan ignore
  if (!line || !line.includes("mcp-safety-scan")) return null;
  const m = line.match(/\bmcp-safety-scan\b\s*(?::\s*)?(ignore-next-line|ignore)\b\s*(.*)$/i);
  if (!m) return null;
  const cmd = String(m[1] ?? "").toLowerCase();
  const rest = String(m[2] ?? "").trim();
  const idsRaw = rest ? rest.split(/[,\s]+/).filter(Boolean) : ["*"];
  const ids = idsRaw
    .map((s) => s.replace(/[^a-z0-9_*.-]/gi, "").toLowerCase())
    .filter(Boolean);
  return { cmd, ids: ids.length ? ids : ["*"] };
}

function suppressionIdsMatch(ids, ruleId) {
  const rid = String(ruleId ?? "").toLowerCase();
  return ids.includes("*") || ids.includes("all") || ids.includes(rid);
}

function isLineSuppressedForRule(lines, i, ruleId) {
  const line = lines[i] ?? "";
  const prev = i > 0 ? lines[i - 1] : "";

  const dSame = parseSuppressionDirective(line);
  if (dSame && dSame.cmd === "ignore" && suppressionIdsMatch(dSame.ids, ruleId)) return true;

  const dPrev = parseSuppressionDirective(prev);
  if (dPrev && dPrev.cmd === "ignore-next-line" && suppressionIdsMatch(dPrev.ids, ruleId)) return true;

  return false;
}

function isProbablyBinary(buf) {
  // Fast check: presence of NUL suggests binary.
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function ruleAppliesToFile(rule, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return !rule.exts || rule.exts.includes(ext);
}

function isTestFile({ root, fileAbs }) {
  const rel = path.relative(root, fileAbs);
  const parts = rel.split(/[\\/]+/).filter(Boolean);
  if (!parts.length) return false;
  if (parts[0] === "..") return false; // outside root

  // If the file lives under a known test/fixture directory, treat it as a test
  // file for noise reduction (unless --include-tests is set).
  //
  // This intentionally uses *relative* paths so scanning subdirectories like
  // "test/fixtures" still works as expected.
  const testDirs = new Set(["test", "tests", "__tests__", "__mocks__", "fixtures", "__fixtures__"]);
  for (let i = 0; i < parts.length - 1; i++) {
    if (testDirs.has(String(parts[i]).toLowerCase())) return true;
  }

  const base = String(parts[parts.length - 1]).toLowerCase();
  if (base.endsWith("_test.go")) return true;
  if (base.startsWith("test_") && base.endsWith(".py")) return true;
  if (base.endsWith("_test.py")) return true;
  if (base.includes(".test.")) return true;
  if (base.includes(".spec.")) return true;
  return false;
}

function isInIgnoredDir({ root, fileAbs, ignoreDirs }) {
  const rel = path.relative(root, fileAbs);
  const parts = rel.split(/[\\/]+/).filter(Boolean);
  if (!parts.length) return false;

  // If the file is outside the root, don't apply ignore-dirs heuristics.
  if (parts[0] === "..") return false;

  // Ignore based on any directory segment basename (not the file itself).
  for (let i = 0; i < parts.length - 1; i++) {
    if (ignoreDirs.has(parts[i])) return true;
  }
  return false;
}

function normalizeFileList({ root, files, exts, ignoreDirs }) {
  if (!files || !files.length) return [];

  const out = [];
  const seen = new Set();

  for (const raw of files) {
    const s = String(raw ?? "").trim();
    if (!s) continue;
    if (s.startsWith("#")) continue;

    const abs = path.isAbsolute(s) ? path.resolve(s) : path.resolve(root, s);
    if (seen.has(abs)) continue;
    seen.add(abs);

    const ext = path.extname(abs).toLowerCase();
    if (exts && !exts.includes(ext)) continue;

    if (ignoreDirs && isInIgnoredDir({ root, fileAbs: abs, ignoreDirs })) continue;

    out.push(abs);
  }

  return out;
}

function buildMultilineChunk(lines, start, windowSize) {
  // Build a short chunk for multi-line heuristics while stripping obvious
  // comment-only lines to avoid matching patterns inside comments.
  const end = Math.min(lines.length, start + windowSize);
  const out = [];
  let inBlockComment = false;

  for (let i = start; i < end; i++) {
    const line = lines[i] ?? "";
    const trimmed = line.trimStart();

    if (inBlockComment) {
      if (trimmed.includes("*/")) inBlockComment = false;
      out.push("");
      continue;
    }

    if (trimmed.startsWith("/*")) {
      if (!trimmed.includes("*/")) inBlockComment = true;
      out.push("");
      continue;
    }

    if (trimmed.startsWith("//") || trimmed.startsWith("#")) {
      out.push("");
      continue;
    }

    out.push(line);
  }

  return out.join("\n");
}

function buildContextSnippet(chunk, maxLen = 240) {
  if (!chunk) return "";
  const s = String(chunk)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
  if (!s) return "";
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

function isExcludedByLookback(lines, i, rule) {
  const patterns = Array.isArray(rule.excludeLookbackPatterns) ? rule.excludeLookbackPatterns : [];
  if (!patterns.length) return false;

  const nRaw = Number(rule.excludeLookbackLines);
  if (!Number.isFinite(nRaw) || nRaw <= 0) return false;
  const n = Math.max(1, Math.min(200, nRaw));

  const start = Math.max(0, i - n);
  const chunk = lines.slice(start, i).join("\n");
  if (!chunk) return false;

  for (const re of patterns) {
    if (chunk.search(re) !== -1) return true;
  }
  return false;
}

function scanTextByLines({ root, relPath, text, rule }) {
  const findings = [];
  const lines = text.split(/\r?\n/);
  let inBlockComment = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Reduce obvious false positives from docs/comments.
    // This is heuristic and intentionally simple (line-based scanner).
    const trimmed = line.trimStart();
    if (inBlockComment) {
      if (trimmed.includes("*/")) inBlockComment = false;
      continue;
    }
    if (trimmed.startsWith("/*")) {
      if (!trimmed.includes("*/")) inBlockComment = true;
      continue;
    }
    if (trimmed.startsWith("//") || trimmed.startsWith("#")) continue;

    if (isLineSuppressedForRule(lines, i, rule.id)) continue;

    const multilineWindow = rule.multiline ? Math.max(2, Math.min(50, Number(rule.multilineWindow) || 10)) : 1;
    const haystack = rule.multiline ? buildMultilineChunk(lines, i, multilineWindow) : line;
    const maxStart = rule.multiline ? line.length : Infinity;

    for (const re of rule.patterns) {
      const idx = haystack.search(re);
      if (idx === -1) continue;
      // Avoid duplicate multi-line matches by only reporting matches that start
      // on the current line. (We'll scan subsequent lines too.)
      if (idx > maxStart) continue;
      if (isExcludedByLookback(lines, i, rule)) break;
      const excerpt = line.trim().slice(0, 240);
      const context = rule.multiline ? buildContextSnippet(haystack) : "";
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        help: rule.help || "",
        file: relPath,
        line: i + 1,
        column: idx + 1,
        excerpt,
        context: context || undefined,
      });
      break;
    }
  }

  return findings;
}

export async function scanPath(
  targetPath,
  {
    exts = DEFAULT_SCAN_EXTS,
    maxFileBytes = DEFAULT_MAX_FILE_BYTES,
    extraIgnoreDirs = null,
    files = null,
    includeTests = false,
  } = {}
) {
  const root = path.resolve(targetPath);
  const ignoreDirs =
    extraIgnoreDirs && extraIgnoreDirs.length
      ? new Set([...DEFAULT_IGNORE_DIRS, ...extraIgnoreDirs.map((s) => String(s))])
      : DEFAULT_IGNORE_DIRS;

  const candidates =
    Array.isArray(files)
      ? normalizeFileList({ root, files, exts, ignoreDirs })
      : await collectCandidateFiles(root, { exts, extraIgnoreDirs });
  const candidateFiles = includeTests ? candidates : candidates.filter((p) => !isTestFile({ root, fileAbs: p }));
  const findings = [];

  for (const fileAbs of candidateFiles) {
    let st;
    try {
      st = await fs.stat(fileAbs);
    } catch {
      continue;
    }
    if (!st.isFile()) continue;
    if (st.size > maxFileBytes) continue;

    let buf;
    try {
      buf = await fs.readFile(fileAbs);
    } catch {
      continue;
    }
    if (isProbablyBinary(buf)) continue;

    const text = buf.toString("utf8");
    const relPath = path.relative(root, fileAbs) || path.basename(fileAbs);

    for (const rule of RULES) {
      if (!ruleAppliesToFile(rule, fileAbs)) continue;
      findings.push(...scanTextByLines({ root, relPath, text, rule }));
    }
  }

  findings.sort((a, b) => {
    const ds = severityRank(b.severity) - severityRank(a.severity);
    if (ds) return ds;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return (a.line ?? 0) - (b.line ?? 0);
  });

  return { root, filesScanned: candidateFiles.length, findings };
}
