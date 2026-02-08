export function ok() {
  const prompt = `
You are an AI assistant.

Do not do these things:
  eval(userInput)
  new Function("return 1")
  globalThis.eval(userInput)
`;

  return prompt;
}

