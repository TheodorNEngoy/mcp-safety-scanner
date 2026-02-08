import path from "node:path";

import { RULES, severityRank } from "./rules.js";
import { findingFingerprint } from "./baseline.js";

function sarifLevelForSeverity(sev) {
  // SARIF levels: none | note | warning | error.
  // Map medium+ to warning/error; treat critical/high as error.
  const r = severityRank(sev);
  if (r >= severityRank("high")) return "error";
  if (r >= severityRank("medium")) return "warning";
  if (r >= severityRank("low")) return "note";
  return "note";
}

function buildRuleIndex() {
  const map = new Map();
  for (const r of RULES) map.set(r.id, r);
  return map;
}

export function formatSarif({ root, findings }) {
  const rootAbs = path.resolve(root);
  const ruleIndex = buildRuleIndex();

  const sarifRules = RULES.map((r) => ({
    id: r.id,
    name: r.title,
    shortDescription: { text: r.title },
    fullDescription: { text: r.description },
    help: r.help ? { text: r.help } : undefined,
    helpUri: "https://github.com/TheodorNEngoy/mcp-safety-scanner/blob/main/docs/MCP_SECURITY_BASELINE.md",
    properties: { severity: r.severity },
  }));

  const results = (findings ?? []).map((f) => {
    const r = ruleIndex.get(f.ruleId);
    const level = sarifLevelForSeverity(f.severity);
    const snippet = f.context || f.excerpt;

    const artifactLocation = {
      uri: f.file,
    };

    const region =
      Number.isFinite(f.line) && Number.isFinite(f.column)
        ? { startLine: f.line, startColumn: f.column }
        : undefined;

    return {
      ruleId: f.ruleId,
      level,
      message: {
        text: `${f.title}${snippet ? `: ${snippet}` : ""}`,
      },
      partialFingerprints: {
        "mcp-safety-scan/v1": findingFingerprint(f),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation,
            region,
          },
        },
      ],
      properties: {
        severity: f.severity,
        title: f.title,
        ruleDescription: r?.description ?? "",
      },
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-safety-scanner",
            informationUri: "https://github.com/TheodorNEngoy/mcp-safety-scanner",
            rules: sarifRules,
          },
        },
        originalUriBaseIds: {
          ROOT: {
            uri: rootAbs.endsWith(path.sep) ? rootAbs : rootAbs + path.sep,
          },
        },
        results,
      },
    ],
  };
}
