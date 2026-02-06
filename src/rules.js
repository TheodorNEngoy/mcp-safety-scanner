export const SEVERITY_ORDER = Object.freeze({
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

export function severityRank(sev) {
  return SEVERITY_ORDER[sev] ?? -1;
}

const JS_TS_EXTS = Object.freeze([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts", ".gs"]);

function rule({ id, severity, title, description, exts = JS_TS_EXTS, patterns }) {
  return Object.freeze({ id, severity, title, description, exts, patterns });
}

// Each pattern is line-based and should be fairly specific to reduce noise.
export const RULES = Object.freeze([
  rule({
    id: "cors-wildcard-origin",
    severity: "high",
    title: "Wildcard CORS origin",
    description:
      "Allowing any origin enables cross-site requests. For MCP/tool servers, prefer an allowlist (e.g. chatgpt.com) and do not combine wildcard origin with credentials.",
    patterns: [
      /Access-Control-Allow-Origin[^\n]*["']\*["']/i,
      /setHeader\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']\s*\)/i,
      /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*["']\*["']/i,
    ],
  }),

  rule({
    id: "cors-reflect-origin",
    severity: "high",
    title: "Reflected CORS origin",
    description:
      "Reflecting the request Origin header without validation effectively allows any website to call your server. Use an explicit allowlist check.",
    patterns: [
      /Access-Control-Allow-Origin[^\n]*(req\.headers\.origin|request\.headers\.origin)/i,
      /setHeader\(\s*["']Access-Control-Allow-Origin["'][^\n]*(req\.headers\.origin|request\.headers\.origin)/i,
    ],
  }),

  rule({
    id: "cors-unconfigured-middleware",
    severity: "medium",
    title: "cors() used without origin restrictions",
    description:
      "Using `cors()` with default settings is often broader than intended. Configure `origin` explicitly (allowlist) for servers that accept authenticated requests.",
    patterns: [
      /\buse\s*\(\s*cors\s*\(\s*\)\s*\)/,
      /\bapp\.use\s*\(\s*cors\s*\(\s*\)\s*\)/,
    ],
  }),

  rule({
    id: "dangerous-eval",
    severity: "critical",
    title: "Dynamic code execution (eval / new Function)",
    description:
      "`eval()` / `new Function()` can turn untrusted input into code execution. Avoid entirely in networked services.",
    patterns: [/\beval\s*\(/, /\bnew\s+Function\s*\(/],
  }),

  rule({
    id: "child-process-exec",
    severity: "high",
    title: "Shell execution (child_process exec/execSync)",
    description:
      "`exec()`/`execSync()` invokes a shell and is easy to misuse with untrusted input. Prefer safe APIs or strict allowlists + argument arrays (`spawn`) when absolutely required.",
    patterns: [
      // ESM named imports
      /\bimport\s*\{[^}]*\bexecSync\b[^}]*\}\s*from\s*["'](?:node:)?child_process["']/,
      /\bimport\s*\{[^}]*\bexec\b[^}]*\}\s*from\s*["'](?:node:)?child_process["']/,

      // CJS require() direct member access
      /\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*execSync\s*\(/,
      /\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*exec\s*\(/,

      // CJS destructuring require()
      /\{\s*[^}]*\bexecSync\b[^}]*\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/,
      /\{\s*[^}]*\bexec\b[^}]*\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/,

      // Common namespace name
      /\bchild_process\s*\.\s*execSync\s*\(/,
      /\bchild_process\s*\.\s*exec\s*\(/,
    ],
  }),

  rule({
    id: "file-delete-apis",
    severity: "medium",
    title: "File delete APIs used (rm/unlink)",
    description:
      "Deletion APIs are fine in trusted code, but become dangerous when parameters can be influenced by requests. Ensure strict path allowlists and never pass user input directly.",
    patterns: [/\brmSync\s*\(/, /\bunlinkSync\s*\(/, /\brm\s*\(/, /\bunlink\s*\(/],
  }),

  rule({
    id: "log-request-headers",
    severity: "low",
    title: "Request headers logged",
    description:
      "Logging request headers can leak credentials (Authorization, cookies). Redact sensitive headers before logging.",
    patterns: [/\bconsole\.(log|info|debug)\s*\(\s*req\.headers\b/, /\bconsole\.(log|info|debug)\s*\(\s*request\.headers\b/],
  }),

  rule({
    id: "express-json-no-limit",
    severity: "medium",
    title: "Express JSON parser without explicit size limit",
    description:
      "`express.json()` defaults may be too large/surprising for tool endpoints. Set an explicit `limit` to reduce DoS risk.",
    patterns: [/\bexpress\.json\s*\(\s*\)\s*/, /\bbodyParser\.json\s*\(\s*\)\s*/],
  }),
]);

export const DEFAULT_SCAN_EXTS = JS_TS_EXTS;
