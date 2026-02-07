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
const PY_EXTS = Object.freeze([".py"]);
const GO_EXTS = Object.freeze([".go"]);

const EVAL_EXTS = Object.freeze([...JS_TS_EXTS, ...PY_EXTS]);

function rule({ id, severity, title, description, help = "", exts = JS_TS_EXTS, patterns }) {
  return Object.freeze({ id, severity, title, description, help, exts, patterns });
}

// Each pattern is line-based and should be fairly specific to reduce noise.
export const RULES = Object.freeze([
  rule({
    id: "cors-wildcard-origin",
    severity: "high",
    title: "Wildcard CORS origin",
    description:
      "Allowing any origin enables cross-site requests. For MCP/tool servers, prefer an allowlist (e.g. chatgpt.com) and do not combine wildcard origin with credentials.",
    help: "Fix: replace '*' with an explicit origin allowlist (e.g. https://chatgpt.com, https://chat.openai.com).",
    exts: null,
    patterns: [
      /Access-Control-Allow-Origin[^\n]*["']\*["']/i,
      /setHeader\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']\s*\)/i,
      /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*["']\*["']/i,

      // Python (FastAPI/Starlette)
      /\ballow_origins\s*=\s*\[\s*["']\*\s*["']\s*\]/i,
      /\ballow_origin_regex\s*=\s*r?["']\.\*["']/i,

      // Go (gin-contrib/cors, rs/cors, echo, etc.)
      /\bAllowOrigins\s*:\s*\[\]string\s*\{[^}]*["']\*["'][^}]*\}/,
      /\bAllowedOrigins\s*:\s*\[\]string\s*\{[^}]*["']\*["'][^}]*\}/,
    ],
  }),

  rule({
    id: "cors-reflect-origin",
    severity: "high",
    title: "Reflected CORS origin",
    description:
      "Reflecting the request Origin header without validation effectively allows any website to call your server. Use an explicit allowlist check.",
    help: "Fix: only echo Origin after allowlist validation; otherwise omit Access-Control-Allow-Origin.",
    exts: null,
    patterns: [
      /Access-Control-Allow-Origin[^\n]*(req\.headers\.origin|request\.headers\.origin)/i,
      /setHeader\(\s*["']Access-Control-Allow-Origin["'][^\n]*(req\.headers\.origin|request\.headers\.origin)/i,

      // Python (Flask/FastAPI/etc.)
      /Access-Control-Allow-Origin[^\n]*(headers\.get\(\s*["']origin["']\s*\)|headers\[\s*["']origin["']\s*\])/i,

      // Go net/http and common frameworks.
      /Access-Control-Allow-Origin[^\n]*(Header\(\)\.Get\(\s*["']Origin["']\s*\)|Header\.Get\(\s*["']Origin["']\s*\))/i,
    ],
  }),

  rule({
    id: "cors-unconfigured-middleware",
    severity: "medium",
    title: "CORS middleware used without origin restrictions",
    description:
      "Using CORS middleware with default settings is often broader than intended. Configure allowed origins explicitly (allowlist) for servers that accept authenticated requests.",
    help: "Fix: configure CORS with explicit allowed origins (allowlist). Avoid default cors()/CORS(app).",
    exts: null,
    patterns: [
      /\buse\s*\(\s*cors\s*\(\s*\)\s*\)/,
      /\bapp\.use\s*\(\s*cors\s*\(\s*\)\s*\)/,

      // Python (flask-cors)
      /\bCORS\s*\(\s*app\s*\)/,
    ],
  }),

  rule({
    id: "dangerous-eval",
    severity: "critical",
    title: "Dynamic code execution (eval / new Function)",
    description:
      "`eval()` / `new Function()` can turn untrusted input into code execution. Avoid entirely in networked services.",
    help: "Fix: remove eval/new Function; replace with safe parsing/dispatch (no dynamic code).",
    exts: EVAL_EXTS,
    patterns: [/\beval\s*\(/, /\bnew\s+Function\s*\(/],
  }),

  rule({
    id: "child-process-exec",
    severity: "high",
    title: "Shell execution (child_process exec/execSync)",
    description:
      "`exec()`/`execSync()` invokes a shell and is easy to misuse with untrusted input. Prefer safe APIs or strict allowlists + argument arrays (`spawn`) when absolutely required.",
    help: "Fix: avoid exec/execSync; prefer spawn(command, argv) with a strict allowlist.",
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
    help: "Fix: never pass user input to rm/unlink. Enforce allowlisted directories + safe path joins.",
    patterns: [/\brmSync\s*\(/, /\bunlinkSync\s*\(/, /\brm\s*\(/, /\bunlink\s*\(/],
  }),

  rule({
    id: "log-request-headers",
    severity: "low",
    title: "Request headers logged",
    description:
      "Logging request headers can leak credentials (Authorization, cookies). Redact sensitive headers before logging.",
    help: "Fix: redact Authorization/Cookie before logging; log only the fields you need.",
    patterns: [/\bconsole\.(log|info|debug)\s*\(\s*req\.headers\b/, /\bconsole\.(log|info|debug)\s*\(\s*request\.headers\b/],
  }),

  rule({
    id: "express-json-no-limit",
    severity: "medium",
    title: "Express JSON parser without explicit size limit",
    description:
      "`express.json()` defaults may be too large/surprising for tool endpoints. Set an explicit `limit` to reduce DoS risk.",
    help: "Fix: set an explicit size limit, e.g. express.json({ limit: '200kb' }).",
    patterns: [/\bexpress\.json\s*\(\s*\)\s*/, /\bbodyParser\.json\s*\(\s*\)\s*/],
  }),

  rule({
    id: "python-exec",
    severity: "critical",
    title: "Dynamic code execution (Python exec)",
    description: "`exec()` turns strings into code. Avoid entirely in networked services and tool backends.",
    help: "Fix: remove exec(); replace with safe parsing/dispatch (no dynamic code).",
    exts: PY_EXTS,
    patterns: [/(?<![\w.])exec\s*\(/],
  }),

  rule({
    id: "python-shell-exec",
    severity: "high",
    title: "Shell execution (Python subprocess shell=True / os.system)",
    description:
      "Shell execution is easy to misuse with untrusted input. Avoid `shell=True` and `os.system()`; prefer argument arrays and strict allowlists when absolutely required.",
    help: "Fix: avoid shell=True/os.system(); use subprocess.run([cmd, ...], shell=False) + allowlists.",
    exts: PY_EXTS,
    patterns: [
      /\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\([^\n]*\bshell\s*=\s*True\b/,
      /\bPopen\s*\([^\n]*\bshell\s*=\s*True\b/,
      /\bos\.system\s*\(/,
    ],
  }),

  rule({
    id: "go-shell-exec",
    severity: "high",
    title: "Shell execution via os/exec (sh -c / cmd /c / powershell)",
    description:
      "Invoking a shell (`sh -c`, `cmd /c`, etc.) is easy to misuse with untrusted input. Prefer direct argument arrays and strict allowlists when absolutely required.",
    help: "Fix: avoid sh -c/cmd /c; use exec.Command(name, args...) with allowlisted names/args.",
    exts: GO_EXTS,
    patterns: [
      /\bexec\.Command\s*\(\s*"(?:sh|bash|zsh)"\s*,\s*"-c"\s*[,)]/,
      /\bexec\.CommandContext\s*\(\s*[^,]+,\s*"(?:sh|bash|zsh)"\s*,\s*"-c"\s*[,)]/,
      /\bexec\.Command\s*\(\s*"(?:cmd|cmd\.exe)"\s*,\s*"(?:\/c|\/C)"\s*[,)]/,
      /\bexec\.CommandContext\s*\(\s*[^,]+,\s*"(?:cmd|cmd\.exe)"\s*,\s*"(?:\/c|\/C)"\s*[,)]/,
      /\bexec\.Command\s*\(\s*"(?:powershell|powershell\.exe)"\s*,\s*"-Command"\s*[,)]/,
      /\bexec\.CommandContext\s*\(\s*[^,]+,\s*"(?:powershell|powershell\.exe)"\s*,\s*"-Command"\s*[,)]/,
    ],
  }),
]);

export const DEFAULT_SCAN_EXTS = Object.freeze([...JS_TS_EXTS, ...PY_EXTS, ...GO_EXTS]);
