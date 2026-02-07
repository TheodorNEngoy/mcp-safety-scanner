export function bad(userInput) {
  // This should be detected only when --include-tests is enabled.
  return eval(userInput);
}

