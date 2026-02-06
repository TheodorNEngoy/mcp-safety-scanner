import { execSync } from "node:child_process";

export function doNotRunInProd() {
  return execSync("echo hello").toString("utf8");
}

