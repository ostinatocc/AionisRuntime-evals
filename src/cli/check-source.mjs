#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function collect(directory) {
  let entries;
  try { entries = readdirSync(directory, { withFileTypes: true }); } catch { return []; }
  return entries.flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return collect(absolute);
    return entry.isFile() && entry.name.endsWith(".mjs") ? [absolute] : [];
  });
}

const files = [path.join(root, "src"), path.join(root, "test")]
  .flatMap(collect)
  .sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));

if (files.length === 0) throw new Error("aionis_eval_source_closure_empty");
for (const file of files) {
  const checked = spawnSync(process.execPath, ["--check", file], {
    cwd: root,
    encoding: "utf8",
  });
  if (checked.status !== 0) {
    process.stderr.write(checked.stdout ?? "");
    process.stderr.write(checked.stderr ?? "");
    process.exit(checked.status ?? 1);
  }
}
process.stdout.write(`${JSON.stringify({
  schema_version: "aionis_eval_syntax_check_v1",
  file_count: files.length,
})}\n`);
