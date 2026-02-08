import { spawn } from "node:child_process";

export function doNotRunInProd() {
  return spawn("sh", ["-c", "echo hello"]);
}

