import { promises as fs } from "node:fs";
import path from "node:path";

import { RULES, severityRank, DEFAULT_SCAN_EXTS } from "./rules.js";
import { collectCandidateFiles } from "./walk.js";

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

function scanTextByLines({ root, relPath, text, rule }) {
  const findings = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isLineSuppressedForRule(lines, i, rule.id)) continue;
    for (const re of rule.patterns) {
      const idx = line.search(re);
      if (idx === -1) continue;
      const excerpt = line.trim().slice(0, 240);
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        file: relPath,
        line: i + 1,
        column: idx + 1,
        excerpt,
      });
      break;
    }
  }

  return findings;
}

export async function scanPath(targetPath, { exts = DEFAULT_SCAN_EXTS, maxFileBytes = DEFAULT_MAX_FILE_BYTES } = {}) {
  const root = path.resolve(targetPath);
  const files = await collectCandidateFiles(root, { exts });
  const findings = [];

  for (const fileAbs of files) {
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

  return { root, filesScanned: files.length, findings };
}
