export function bad(userInput) {
  // This should be flagged.
  return eval(userInput);
}

