export function ok() {
  const msg1 = "Please do not use eval(userInput) in production.";
  const msg2 = 'Avoid new Function("return 1") and similar patterns.';
  const msg3 = "Example only: app.use(cors())";
  const msg4 = "Example only: await request.json()";
  return { msg1, msg2, msg3, msg4 };
}

