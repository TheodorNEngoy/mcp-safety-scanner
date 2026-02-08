import { SEVERITY_ORDER } from "./rules.js";

export function summarize(findings) {
  const counts = Object.fromEntries(Object.keys(SEVERITY_ORDER).map((k) => [k, 0]));
  for (const f of findings) {
    const sev = f?.severity;
    if (typeof counts[sev] === "number") counts[sev] += 1;
  }
  const total = findings.length;
  return { total, counts };
}

export function formatText({ root, filesScanned, findings }) {
  const { total, counts } = summarize(findings);
  const parts = [];
  parts.push(`mcp-safety-scanner: ${total} finding${total === 1 ? "" : "s"} (scanned ${filesScanned} file${filesScanned === 1 ? "" : "s"})`);
  parts.push(
    `severity counts: critical=${counts.critical}, high=${counts.high}, medium=${counts.medium}, low=${counts.low}, info=${counts.info}`
  );

  for (const f of findings) {
    const loc = `${f.file}:${f.line}:${f.column}`;
    parts.push(`[${f.severity}] ${f.ruleId} ${f.title}`);
    parts.push(`  ${loc}`);
    const snippet = f.context || f.excerpt;
    if (snippet) parts.push(`  ${snippet}`);
    if (f.help) parts.push(`  help: ${String(f.help).trim()}`);
  }

  return parts.join("\n");
}
