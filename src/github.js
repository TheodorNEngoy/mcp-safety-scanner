import { severityRank } from "./rules.js";

function escapeWorkflowCommandValue(s) {
  // https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions
  return String(s ?? "")
    .replaceAll("%", "%25")
    .replaceAll("\r", "%0D")
    .replaceAll("\n", "%0A");
}

function commandForSeverity(sev) {
  const r = severityRank(sev);
  if (r >= severityRank("high")) return "error";
  if (r >= severityRank("medium")) return "warning";
  return "notice";
}

export function formatGithub({ findings }) {
  const lines = [];
  for (const f of findings ?? []) {
    const cmd = commandForSeverity(f.severity);
    const file = f.file ?? "";
    const line = Number.isFinite(f.line) ? f.line : "";
    const col = Number.isFinite(f.column) ? f.column : "";

    const props = [];
    if (file) props.push(`file=${escapeWorkflowCommandValue(file)}`);
    if (line) props.push(`line=${line}`);
    if (col) props.push(`col=${col}`);

    const title = `${f.ruleId} ${f.title}`;
    const msg = f.excerpt ? `${title}: ${f.excerpt}` : title;

    const prefix = props.length ? `::${cmd} ${props.join(",")}::` : `::${cmd}::`;
    lines.push(`${prefix}${escapeWorkflowCommandValue(msg)}`);
  }

  return lines.join("\n");
}
