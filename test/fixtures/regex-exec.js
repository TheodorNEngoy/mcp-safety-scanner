export function safeRegexUse() {
  const m = /hello\s+(\w+)/.exec("hello world");
  return m?.[1] ?? null;
}

