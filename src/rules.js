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

function rule({
  id,
  severity,
  title,
  description,
  help = "",
  exts = JS_TS_EXTS,
  patterns,
  multiline = false,
  multilineWindow = 10,
  excludeLookbackPatterns = null,
  excludeLookbackLines = 0,
}) {
  return Object.freeze({
    id,
    severity,
    title,
    description,
    help,
    exts,
    patterns,
    multiline: Boolean(multiline),
    multilineWindow: Number(multilineWindow),
    excludeLookbackPatterns: Array.isArray(excludeLookbackPatterns) ? excludeLookbackPatterns : [],
    excludeLookbackLines: Number(excludeLookbackLines),
  });
}

// Each pattern is line-based or small-window multi-line and should be fairly specific to reduce noise.
export const RULES = Object.freeze([
  rule({
    id: "cors-credentials-any-origin",
    severity: "critical",
    title: "Credentialed CORS with any-origin policy",
    description:
      "Allowing credentials while allowing any origin (wildcard '*' or reflecting Origin) allows any website to make authenticated requests and read responses. This is a common CSRF/exfiltration footgun for MCP/tool servers.",
    help: "Fix: do not use credentials with wildcard/reflected origins. Validate Origin against an explicit allowlist and only enable credentials if required.",
    exts: null,
    multiline: true,
    multilineWindow: 15,
    patterns: [
      // Node: cors({ origin: '*', credentials: true }) or cors({ origin: true, credentials: true })
      /\bcors\s*\(\s*\{(?=[\s\S]{0,400}\borigin\s*:\s*["']\*["'])(?=[\s\S]{0,400}\bcredentials\s*:\s*true\b)[\s\S]{0,400}\}\s*\)/i,
      /\bcors\s*\(\s*\{(?=[\s\S]{0,400}\borigin\s*:\s*true\b)(?=[\s\S]{0,400}\bcredentials\s*:\s*true\b)[\s\S]{0,400}\}\s*\)/i,

      // Python: Starlette/FastAPI allow_origins=["*"] + allow_credentials=True
      /\badd_middleware\s*\(\s*CORSMiddleware\s*,(?=[\s\S]{0,600}\ballow_origins\s*=\s*\[[^\]]*["']\*["'][^\]]*\])(?=[\s\S]{0,600}\ballow_credentials\s*=\s*True\b)[\s\S]{0,600}\)/,
      /\bCORSMiddleware\s*\(\s*(?=[\s\S]{0,600}\ballow_origins\s*=\s*\[[^\]]*["']\*["'][^\]]*\])(?=[\s\S]{0,600}\ballow_credentials\s*=\s*True\b)[\s\S]{0,600}\)/,
      /\badd_middleware\s*\(\s*CORSMiddleware\s*,(?=[\s\S]{0,600}\ballow_origins\s*=\s*["']\*["'])(?=[\s\S]{0,600}\ballow_credentials\s*=\s*True\b)[\s\S]{0,600}\)/,
      /\bCORSMiddleware\s*\(\s*(?=[\s\S]{0,600}\ballow_origins\s*=\s*["']\*["'])(?=[\s\S]{0,600}\ballow_credentials\s*=\s*True\b)[\s\S]{0,600}\)/,

      // Go: rs/cors or gin-contrib/cors wildcard + AllowCredentials
      /\bcors\.Options\s*\{(?=[\s\S]{0,500}\bAllowedOrigins\s*:\s*\[\]string\s*\{[^}]*["']\*["'][^}]*\})(?=[\s\S]{0,500}\bAllowCredentials\s*:\s*true\b)[\s\S]{0,500}\}/,
      /\bcors\.Config\s*\{(?=[\s\S]{0,500}\bAllowAllOrigins\s*:\s*true\b)(?=[\s\S]{0,500}\bAllowCredentials\s*:\s*true\b)[\s\S]{0,500}\}/,
      /\bcors\.Config\s*\{(?=[\s\S]{0,500}\bAllowOrigins\s*:\s*\[\]string\s*\{[^}]*["']\*["'][^}]*\})(?=[\s\S]{0,500}\bAllowCredentials\s*:\s*true\b)[\s\S]{0,500}\}/,

      // Manual headers: wildcard/reflected origin + allow-credentials
      /Access-Control-Allow-Origin[^\n]*["']\*["'][\s\S]{0,400}Access-Control-Allow-Credentials[^\n]*(?:true|["']true["'])/i,
      /Access-Control-Allow-Credentials[^\n]*(?:true|["']true["'])[\s\S]{0,400}Access-Control-Allow-Origin[^\n]*["']\*["']/i,
      /Access-Control-Allow-Origin[^\n]*(?:req\.headers\.origin|request\.headers\.origin)[\s\S]{0,400}Access-Control-Allow-Credentials[^\n]*(?:true|["']true["'])/i,
      /Access-Control-Allow-Credentials[^\n]*(?:true|["']true["'])[\s\S]{0,400}Access-Control-Allow-Origin[^\n]*(?:req\.headers\.origin|request\.headers\.origin)/i,
    ],
  }),

  rule({
    id: "cors-wildcard-origin",
    severity: "high",
    title: "Wildcard CORS origin",
    description:
      "Allowing any origin enables cross-site requests. For MCP/tool servers, prefer an allowlist (e.g. chatgpt.com) and do not combine wildcard origin with credentials.",
    help: "Fix: replace '*' with an explicit origin allowlist (e.g. https://chatgpt.com, https://chat.openai.com).",
    exts: null,
    multiline: true,
    patterns: [
      /Access-Control-Allow-Origin[^\n]*["']\*["']/i,
      /setHeader\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']\s*\)/i,
      /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*["']\*["']/i,

      // Python (FastAPI/Starlette)
      /\ballow_origins\s*=\s*\[\s*["']\*\s*["']\s*\]/i,
      /\ballow_origins\s*=\s*["']\*["']/i,
      /\ballow_origin_regex\s*=\s*r?["']\.\*["']/i,

      // Go (gin-contrib/cors, rs/cors, echo, etc.)
      /\bAllowOrigins\s*:\s*\[\]string\s*\{[^}]*["']\*["'][^}]*\}/,
      /\bAllowedOrigins\s*:\s*\[\]string\s*\{[^}]*["']\*["'][^}]*\}/,
      /\bAllowAllOrigins\s*:\s*true\b/,
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
    multiline: true,
    patterns: [
      /Access-Control-Allow-Origin[^\n]*(req\.headers\.origin|request\.headers\.origin)/i,
      /setHeader\(\s*["']Access-Control-Allow-Origin["'][^\n]*(req\.headers\.origin|request\.headers\.origin)/i,

      // Node cors() package
      /\bcors\s*\(\s*\{[^}]*\borigin\s*:\s*true\b/i,

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
    id: "bind-all-interfaces",
    severity: "high",
    title: "Server binds to all interfaces (0.0.0.0 / ::)",
    description:
      "Binding to 0.0.0.0/:: exposes the server to the network. For MCP/tool servers, prefer binding to localhost by default and making public binding an explicit opt-in.",
    help: "Fix: default to 127.0.0.1/localhost; require an explicit env var/flag to bind to 0.0.0.0/::.",
    exts: null,
    multiline: true,
    patterns: [
      // JS/TS (Node/Express/Hono/Deno)
      /\blisten\s*\([^)]*["']0\.0\.0\.0["']/,
      /\blisten\s*\([^)]*["']::["']/,
      /\b(hostname|host)\s*:\s*["']0\.0\.0\.0["']/,
      /\b(hostname|host)\s*:\s*["']::["']/,

      // Python (uvicorn/FastAPI/Flask)
      /\bhost\s*=\s*["']0\.0\.0\.0["']/,
      /\bhost\s*=\s*["']::["']/,
      /\b--host\s+0\.0\.0\.0\b/,
      /\b--host\s+::\b/,

      // Go (net/http, net.Listen)
      /\bListenAndServe(?:TLS)?\s*\(\s*["']0\.0\.0\.0:/,
      /\bListenAndServe(?:TLS)?\s*\(\s*["']\[\:\:\]/,
      // Empty host binds to all interfaces (e.g. ":8080").
      /\bListenAndServe(?:TLS)?\s*\(\s*["']:\d+/,
      /\bnet\.Listen\s*\([^)]*["']0\.0\.0\.0:/,
      /\bnet\.Listen\s*\([^)]*["']\[\:\:\]/,
      /\bnet\.Listen\s*\([^)]*["']:\d+/,
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
    id: "child-process-shell-true",
    severity: "high",
    title: "Shell execution via spawn/execFile with shell: true",
    description:
      "The `shell: true` option executes via a shell, which is easy to misuse with untrusted input. Prefer direct argument arrays (no shell) and strict allowlists when absolutely required.",
    help: "Fix: avoid `shell: true`; use spawn/execFile with shell disabled (default) + strict allowlists for command names/args.",
    multiline: true,
    patterns: [
      /\bspawnSync\s*\((?:(?!\n\s*(?:spawnSync|spawn|execFileSync|execFile)\b)[\s\S]){0,400}\bshell\s*:\s*true\b/i,
      /\bspawn\s*\((?:(?!\n\s*(?:spawnSync|spawn|execFileSync|execFile)\b)[\s\S]){0,400}\bshell\s*:\s*true\b/i,
      /\bexecFileSync\s*\((?:(?!\n\s*(?:spawnSync|spawn|execFileSync|execFile)\b)[\s\S]){0,400}\bshell\s*:\s*true\b/i,
      /\bexecFile\s*\((?:(?!\n\s*(?:spawnSync|spawn|execFileSync|execFile)\b)[\s\S]){0,400}\bshell\s*:\s*true\b/i,
    ],
  }),

  rule({
    id: "child-process-shell-spawn",
    severity: "high",
    title: "Shell execution via spawn/execFile (sh -c / cmd /c / powershell -Command)",
    description:
      "Spawning a shell interpreter (`sh -c`, `cmd /c`, `powershell -Command`) is easy to misuse with untrusted input. Prefer running a specific binary with an argument array, and enforce strict allowlists when absolutely required.",
    help: "Fix: avoid `sh -c` / `cmd /c` / `powershell -Command`; run commands directly with argv arrays + strict allowlists.",
    multiline: true,
    patterns: [
      /\b(?:spawnSync|spawn|execFileSync|execFile)\s*\(\s*["'](?:sh|bash|zsh)["']\s*,\s*\[\s*["']-c["']/,
      /\b(?:spawnSync|spawn|execFileSync|execFile)\s*\(\s*["'](?:cmd|cmd\.exe)["']\s*,\s*\[\s*["'](?:\/c|\/C)["']/,
      /\b(?:spawnSync|spawn|execFileSync|execFile)\s*\(\s*["'](?:powershell|powershell\.exe|pwsh|pwsh\.exe)["']\s*,\s*\[\s*["']-Command["']/,
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
    id: "web-request-json-no-limit",
    severity: "medium",
    title: "Web-standard Request.json() without explicit size limit",
    description:
      "`Request.json()` reads the full request body into memory. For networked MCP/tool servers, enforce a max request size (check Content-Length and/or stream with a byte limit) and return 413 when exceeded.",
    help: "Fix: enforce a request body size limit before calling Request.json(); return 413 Payload Too Large when exceeded.",
    patterns: [/\bawait\s+(?:req|request)\.json\s*\(\s*\)/],
  }),

  rule({
    id: "python-request-body-no-limit",
    severity: "medium",
    title: "Python request.body()/request.json() without explicit size limit",
    description:
      "`await request.body()` / `await request.json()` reads the full request body into memory. For networked MCP/tool servers, enforce a max request size (check Content-Length and/or stream with a byte limit) and return 413 when exceeded.",
    help: "Fix: enforce a request body size limit before reading/parsing; return 413 Payload Too Large when exceeded.",
    exts: PY_EXTS,
    patterns: [/\bawait\s+(?:req|request)\.(?:body|json)\s*\(\s*\)/],
  }),

  rule({
    id: "go-readall-request-body-no-limit",
    severity: "medium",
    title: "Go io.ReadAll(request.Body) without explicit size limit",
    description:
      "`io.ReadAll(r.Body)` reads the entire request body into memory. Use `http.MaxBytesReader` (net/http) or a streaming/limit approach to enforce a maximum request size and return 413 when exceeded.",
    help: "Fix: enforce a max body size (e.g. http.MaxBytesReader) before io.ReadAll; return 413 Payload Too Large when exceeded.",
    exts: GO_EXTS,
    // Avoid flagging common safe patterns where the handler has already wrapped
    // the request body with a size-limited reader.
    excludeLookbackLines: 40,
    excludeLookbackPatterns: [/\bMaxBytesReader\s*\(/, /\bMaxBytesHandler\s*\(/, /\bRoundTrip\s*\(/],
    patterns: [
      /\b(?:io|ioutil)\.ReadAll\s*\(\s*(?:r|req|request)\.Body\s*\)/,
      /\b(?:io|ioutil)\.ReadAll\s*\(\s*c\.Request\.Body\s*\)/,
      /\b(?:io|ioutil)\.ReadAll\s*\(\s*c\.Request\(\)\.Body\s*\)/,
    ],
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
    multiline: true,
    patterns: [
      /\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\((?:(?!\n\s*(?:subprocess\.|Popen\b))[\s\S]){0,400}\bshell\s*=\s*True\b/,
      /\bPopen\s*\((?:(?!\n\s*(?:subprocess\.|Popen\b))[\s\S]){0,400}\bshell\s*=\s*True\b/,
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
    multiline: true,
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
