#!/usr/bin/env node
/**
 * Re-runs `npm audit --omit=dev --json` (production dependency graph) and fails unless every high/critical advisory is
 * listed in .audit-exceptions.json with an unexpired `until` date and a
 * justification. Exceptions are for findings with no upstream fix; they must be
 * reviewed before their expiry.
 */
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

const LEVELS = new Set(["high", "critical"]);
const exceptions = JSON.parse(readFileSync(".audit-exceptions.json", "utf8"));
const today = new Date().toISOString().slice(0, 10);

let report;
try {
  report = JSON.parse(execSync("npm audit --omit=dev --json", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
} catch (err) {
  // npm audit exits non-zero when vulnerabilities exist; the JSON is still on stdout.
  report = JSON.parse(err.stdout);
}

const unexcused = [];
const seen = new Set();
for (const vuln of Object.values(report.vulnerabilities ?? {})) {
  if (!LEVELS.has(vuln.severity)) continue;
  for (const via of vuln.via) {
    if (typeof via !== "object") continue; // transitive pointer to another package
    const id = via.url?.split("/").pop();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const ex = exceptions.find((e) => e.id === id);
    if (!ex) unexcused.push(`${id} (${via.name}, ${via.severity}): no exception`);
    else if (ex.until < today) unexcused.push(`${id} (${via.name}): exception expired ${ex.until}`);
    else if (!ex.justification) unexcused.push(`${id}: exception has no justification`);
    else console.log(`audit: ${id} (${via.name}) excused until ${ex.until}: ${ex.justification}`);
  }
}
if (unexcused.length) {
  console.error("audit: unexcused high/critical advisories:");
  for (const u of unexcused) console.error(`  - ${u}`);
  process.exit(1);
}
console.log("audit: no unexcused high/critical advisories");
