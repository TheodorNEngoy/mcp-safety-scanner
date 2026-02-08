import { spawn } from "node:child_process";

export function doNotRunInProd() {
  // shell: true executes via a shell, which is easy to misuse with untrusted input.
  return spawn("echo", ["hello"], { shell: true });
}

