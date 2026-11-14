#!/usr/bin/env node
/** Fails when a dependency in the given package dirs uses a range (^, ~, *, >, x, latest) instead of an exact version. */
import { readFileSync } from "node:fs";
import { join } from "node:path";

const dirs = process.argv.slice(2);
if (!dirs.length) { console.error("usage: check-pinned.mjs <pkgdir>..."); process.exit(2); }
const exact = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
let bad = 0;
for (const dir of dirs) {
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  for (const field of ["dependencies", "optionalDependencies"]) {
    for (const [name, range] of Object.entries(pkg[field] ?? {})) {
      if (name.startsWith("@signhold/")) continue; // workspace packages
      if (!exact.test(range)) { console.error(`${pkg.name}: ${name}@${range} is not pinned`); bad++; }
    }
  }
}
if (bad) process.exit(1);
console.log(`check-pinned: all dependencies pinned in ${dirs.join(", ")}`);
