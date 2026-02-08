import { spawn } from "node:child_process";

export function doNotRunInProd() {
  // Multi-line options object: scanner should still flag shell execution.
  return spawn(
    "echo",
    ["hello"],
    {
      shell: true,
    },
  );
}

