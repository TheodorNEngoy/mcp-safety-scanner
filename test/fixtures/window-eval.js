export function bad(userInput) {
  // This should be flagged.
  return window.eval(userInput);
}

