#!/usr/bin/env node
/**
 * lockfile-lint-style check for package-lock.json (lockfileVersion 2/3):
 *  - every resolved URL uses https and an allowlisted registry host
 *  - every non-link, non-workspace package has an integrity hash (sha512)
 *  - no git / file / http dependencies
 * Usage: node scripts/lockfile-lint.mjs [path/to/package-lock.json]
 */
import { readFileSync } from "node:fs";

const ALLOWED_HOSTS = new Set(["registry.npmjs.org"]);
const file = process.argv[2] ?? "package-lock.json";
const lock = JSON.parse(readFileSync(file, "utf8"));
const problems = [];

if (!(lock.lockfileVersion === 2 || lock.lockfileVersion === 3)) problems.push(`unsupported lockfileVersion ${lock.lockfileVersion}`);

for (const [name, pkg] of Object.entries(lock.packages ?? {})) {
  if (name === "") continue; // root
  if (pkg.link || (pkg.resolved === undefined && pkg.version && !name.includes("node_modules"))) continue; // workspace entries
  if (!pkg.resolved) {
    if (!name.includes("node_modules")) continue;
    problems.push(`${name}: missing resolved URL`);
    continue;
  }
  let url;
  try {
    url = new URL(pkg.resolved);
  } catch {
    problems.push(`${name}: unparsable resolved '${pkg.resolved}'`);
    continue;
  }
  if (url.protocol !== "https:") problems.push(`${name}: non-https resolved '${pkg.resolved}'`);
  if (!ALLOWED_HOSTS.has(url.hostname)) problems.push(`${name}: host '${url.hostname}' not in allowlist`);
  if (!pkg.integrity || !pkg.integrity.startsWith("sha512-")) problems.push(`${name}: missing or weak integrity`);
}

if (problems.length) {
  console.error(`lockfile-lint: ${problems.length} problem(s) in ${file}`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`lockfile-lint: ${file} ok (${Object.keys(lock.packages ?? {}).length - 1} entries)`);
