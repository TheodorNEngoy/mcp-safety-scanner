# MCP Security Baseline (Practical)

This is a short checklist you can apply to MCP servers and other “LLM + tools” backends.

## 1) Treat The Browser As Hostile

- Do not use wildcard CORS (`Access-Control-Allow-Origin: *`) on authenticated endpoints.
- Do not reflect `Origin` without allowlist validation.
- If you must allow browsers, use an explicit allowlist (typically `https://chatgpt.com` and `https://chat.openai.com`, plus your own app domains).
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

- Set maximum request body size for all endpoints.
- Put timeouts on outbound requests.
- Put upper bounds on:
  - stored records (feed posts, logs, sessions)
  - per-user actions per minute
  - per-request computation (loops, pagination)

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

