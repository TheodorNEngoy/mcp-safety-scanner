# MCP Security Baseline (Practical)

This is a short checklist you can apply to MCP servers and other “LLM + tools” backends.

## 1) Treat The Browser As Hostile

- Do not use wildcard CORS (`Access-Control-Allow-Origin: *`) on authenticated endpoints.
- Do not reflect `Origin` without allowlist validation.
- If you must allow browsers, use an explicit allowlist (typically `https://chatgpt.com` and `https://chat.openai.com`, plus your own app domains), and send `Vary: Origin`.
- Avoid cookies for auth unless you also implement CSRF protections.

## 2) Constrain Capabilities (Principle Of Least Privilege)

- Keep tool surface area small.
- Don’t expose file system / shell tools unless absolutely required.
- For any tool that can mutate data, add:
  - strict input schema validation
  - rate limits
  - size limits
  - auditing (who did what, when)

## 3) Bound Resource Use

- Set maximum request body size for all endpoints (avoid unbounded body buffering).
- Put timeouts on outbound requests.
- Put upper bounds on:
  - stored records (feed posts, logs, sessions)
  - per-user actions per minute
  - per-request computation (loops, pagination)

### Request Body Size: Practical Examples

- Express: set a limit on the JSON parser.

  ```ts
  app.use(express.json({ limit: 1_000_000 })); // 1MB
  ```

- Hono (web-standard runtimes): reject oversized JSON before parsing, and stream-read with a byte limit.

- Go (net/http): enforce a limit before reading/parsing.

  ```go
  r.Body = http.MaxBytesReader(w, r.Body, 1_000_000) // 1MB
  data, err := io.ReadAll(r.Body)
  if err != nil { /* map *http.MaxBytesError to 413 */ }
  ```

- If you can’t easily change your upstream server, consider placing a small guard/proxy in front of it that enforces:
  - CORS allowlist
  - request body size limits
  - rate limits / concurrency bounds

## 4) Don’t Leak Secrets Into Logs

- Never log full request headers by default.
- Redact `Authorization`, cookies, session tokens, and any API keys.
- Prefer structured logs with explicit fields.

## 5) Make “Unsafe By Default” Patterns Hard To Introduce

- Add a CI gate that fails on high-severity footguns (`mcp-safety-scanner --fail-on=high`).
- Require code review for tool additions/changes.
- Maintain a short threat model doc:
  - what can the tool do?
  - what inputs can be attacker-controlled?
  - what are the worst-case impacts?
