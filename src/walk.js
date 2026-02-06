import { promises as fs } from "node:fs";
import path from "node:path";

const DEFAULT_IGNORE_DIRS = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "out",
  "coverage",
  ".next",
  ".turbo",
  ".cache",
]);

export async function collectCandidateFiles(rootPath, { exts, ignoreDirs = DEFAULT_IGNORE_DIRS, maxFiles = 50_000 } = {}) {
  const out = [];
  const rootAbs = path.resolve(rootPath);

  async function walk(p) {
    if (out.length >= maxFiles) return;

    let st;
    try {
      st = await fs.stat(p);
    } catch {
      return;
    }

    if (st.isFile()) {
      const ext = path.extname(p).toLowerCase();
      if (exts && !exts.includes(ext)) return;
      out.push(p);
      return;
    }

    if (!st.isDirectory()) return;

    const base = path.basename(p);
    if (ignoreDirs.has(base)) return;

    let entries;
    try {
      entries = await fs.readdir(p, { withFileTypes: true });
    } catch {
      return;
    }

    for (const ent of entries) {
      if (out.length >= maxFiles) return;
      const child = path.join(p, ent.name);
      if (ent.isDirectory()) {
        await walk(child);
      } else if (ent.isFile()) {
        const ext = path.extname(ent.name).toLowerCase();
        if (exts && !exts.includes(ext)) continue;
        out.push(child);
      }
    }
  }

  await walk(rootAbs);
  return out;
}

