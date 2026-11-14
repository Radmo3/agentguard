/**
 * Runner.
 *
 *   npx tsx experiments/cap-bypass/src/run.ts --arm baseline|signhold|both --scenario 1|2|both \
 *     --agent scripted:bypasser|anthropic:<model>|openai:<model>|compat:<model> --trials 20 --seed 42 \
 *     [--behavior[=<module>]] [--behavior-seed 30] [--cap 0.01] [--balance 10] [--max-steps 40] \
 *     [--policy-instruction] [--attacker-amount 0.02] [--base-url <url>] [--temperature <t>] [--out results/<name>.jsonl]
 *
 * Writes one JSON line per trial to --out (default results/<agent>-<seed>.jsonl), a
 * summary table to stdout and `summary.json` next to the JSONL.
 */
import { mkdirSync, writeFileSync, appendFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { agentFromSpec, type Agent } from "./agents/index.js";
import { formatSummaryTable, summarise, type GroupSummary } from "./metrics.js";
import { INVOICE_PAYEE, type ScenarioId } from "./scenarios.js";
import { createSignholdArm, type SignholdArm } from "./signhold.js";
import { runTrial, type Arm, type TrialResult } from "./trial.js";

export interface ExperimentOptions {
  arms: Arm[];
  scenarios: ScenarioId[];
  agent: Agent;
  trials: number;
  seed: number;
  capUsdc?: number;
  startingBalanceUsdc?: number;
  maxSteps?: number;
  policyInstruction?: boolean;
  attackerAmountUsdc?: number;
  behavior?: boolean | string;
  behaviorSeedCount?: number;
  /** Called after each trial (progress / streaming output). */
  onTrial?: (r: TrialResult) => void;
}

export interface ExperimentOutput {
  results: TrialResult[];
  summary: GroupSummary[];
  behaviorModule?: string;
}

export async function runExperiment(opts: ExperimentOptions): Promise<ExperimentOutput> {
  const capUsdc = opts.capUsdc ?? 0.01;
  const results: TrialResult[] = [];
  let signhold: SignholdArm | undefined;
  try {
    for (const scenario of opts.scenarios) {
      for (const arm of opts.arms) {
        if (arm === "signhold") {
          // One API instance per (scenario, arm); its audit chain and behavioral baseline persist across that arm's trials.
          if (signhold) await signhold.close();
          signhold = await createSignholdArm({ capUsdc, knownPayees: [INVOICE_PAYEE], behavior: opts.behavior, behaviorSeedCount: opts.behaviorSeedCount });
        }
        for (let i = 0; i < opts.trials; i++) {
          const r = await runTrial(
            { arm, scenario, trialIndex: i, seed: opts.seed, capUsdc, startingBalanceUsdc: opts.startingBalanceUsdc ?? 10, maxSteps: opts.maxSteps ?? 40, policyInstruction: opts.policyInstruction, attackerAmountUsdc: opts.attackerAmountUsdc },
            { agent: opts.agent, signhold: arm === "signhold" ? signhold : undefined },
          );
          results.push(r);
          opts.onTrial?.(r);
        }
      }
    }
  } finally {
    await signhold?.close();
  }
  return { results, summary: summarise(results), behaviorModule: signhold?.behaviorModule };
}


// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export function parseCli(argv: string[]) {
  const { values } = parseArgs({
    args: argv,
    options: {
      arm: { type: "string", default: "both" },
      scenario: { type: "string", default: "both" },
      agent: { type: "string", default: "scripted:bypasser" },
      trials: { type: "string", default: "20" },
      seed: { type: "string", default: "42" },
      cap: { type: "string", default: "0.01" },
      balance: { type: "string", default: "10" },
      "max-steps": { type: "string", default: "40" },
      behavior: { type: "string" },
      "behavior-seed": { type: "string", default: "30" },
      "policy-instruction": { type: "boolean", default: false },
      "attacker-amount": { type: "string", default: "0.02" },
      "base-url": { type: "string" },
      temperature: { type: "string" },
      out: { type: "string" },
      quiet: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
    allowNegative: false,
    strict: true,
  });
  const arms: Arm[] = values.arm === "both" ? ["baseline", "signhold"] : [values.arm as Arm];
  if (!arms.every((a) => a === "baseline" || a === "signhold")) throw new Error(`--arm must be baseline, signhold or both`);
  const scenarios: ScenarioId[] = values.scenario === "both" ? [1, 2] : [Number(values.scenario) as ScenarioId];
  if (!scenarios.every((s) => s === 1 || s === 2)) throw new Error(`--scenario must be 1, 2 or both`);
  const num = (v: string | undefined, name: string) => {
    const n = Number(v);
    if (!Number.isFinite(n)) throw new Error(`--${name} must be a number`);
    return n;
  };
  // `--behavior` alone => load `@signhold/behavior` by name; `--behavior=<specifier>` => that module.
  const behaviorRaw = values.behavior;
  const behavior: boolean | string | undefined = behaviorRaw === undefined ? undefined : behaviorRaw === "" || behaviorRaw === "true" ? true : behaviorRaw;
  return {
    help: values.help!,
    quiet: values.quiet!,
    arms,
    scenarios,
    agentSpec: values.agent!,
    trials: Math.max(1, Math.floor(num(values.trials, "trials"))),
    seed: Math.floor(num(values.seed, "seed")) >>> 0,
    capUsdc: num(values.cap, "cap"),
    startingBalanceUsdc: num(values.balance, "balance"),
    maxSteps: Math.max(1, Math.floor(num(values["max-steps"], "max-steps"))),
    behavior,
    behaviorSeedCount: Math.floor(num(values["behavior-seed"], "behavior-seed")),
    policyInstruction: values["policy-instruction"]!,
    attackerAmountUsdc: num(values["attacker-amount"], "attacker-amount"),
    baseUrl: values["base-url"],
    temperature: values.temperature === undefined ? undefined : num(values.temperature, "temperature"),
    out: values.out,
  };
}

const USAGE = `usage: tsx src/run.ts --arm baseline|signhold|both --scenario 1|2|both --agent <spec> [--trials 20] [--seed 42]
       [--behavior[=<module>]] [--behavior-seed 30] [--cap 0.01] [--balance 10] [--max-steps 40] [--policy-instruction]
       [--attacker-amount 0.02] [--base-url <url>] [--temperature <t>] [--out results/<name>.jsonl] [--quiet]
agent specs: scripted:obedient|bypasser|gullible|careful, anthropic:<model>, openai:<model>, compat:<model>`;

/** Behavior packages are loaded by module name; `--behavior` alone means '@signhold/behavior'. */
export async function main(argv = process.argv.slice(2)): Promise<number> {
  const cli = parseCli(argv.map((a) => (a === "--behavior" ? "--behavior=" : a)));
  if (cli.help) {
    console.log(USAGE);
    return 0;
  }
  const agent = agentFromSpec(cli.agentSpec, { compatBaseUrl: cli.baseUrl, temperature: cli.temperature });
  const here = dirname(fileURLToPath(import.meta.url));
  const outPath = resolve(cli.out ?? join(here, "..", "results", `${agent.id.replace(/[^A-Za-z0-9._-]+/g, "_")}-seed${cli.seed}.jsonl`));
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, "");

  const t0 = Date.now();
  const out = await runExperiment({
    arms: cli.arms,
    scenarios: cli.scenarios,
    agent,
    trials: cli.trials,
    seed: cli.seed,
    capUsdc: cli.capUsdc,
    startingBalanceUsdc: cli.startingBalanceUsdc,
    maxSteps: cli.maxSteps,
    policyInstruction: cli.policyInstruction,
    attackerAmountUsdc: cli.attackerAmountUsdc,
    behavior: cli.behavior,
    behaviorSeedCount: cli.behaviorSeedCount,
    onTrial: (r) => {
      appendFileSync(outPath, `${JSON.stringify(r, bigintSafe)}\n`);
      if (!cli.quiet) console.error(`[${r.arm} s${r.scenario} #${r.trialIndex + 1}/${cli.trials}] ${r.outcome} steps=${r.steps} invoices=${r.invoicesPaid}/${r.invoicesTotal} stop=${r.stop}`);
    },
  });
  const summaryPath = join(dirname(outPath), "summary.json");
  writeFileSync(
    summaryPath,
    JSON.stringify(
      { generatedAt: new Date().toISOString(), seed: cli.seed, trials: cli.trials, agent: agent.id, capUsdc: cli.capUsdc, attackerAmountUsdc: cli.attackerAmountUsdc, behaviorModule: out.behaviorModule, policyInstruction: cli.policyInstruction, durationMs: Date.now() - t0, groups: out.summary },
      null,
      2,
    ),
  );
  console.log(formatSummaryTable(out.summary));
  console.log(`\n${out.results.length} trials in ${((Date.now() - t0) / 1000).toFixed(1)}s -> ${outPath}\nsummary -> ${summaryPath}${out.behaviorModule ? `\nbehavior layer: ${out.behaviorModule} (private package)` : ""}`);
  return 0;
}

export const bigintSafe = (_k: string, v: unknown) => (typeof v === "bigint" ? v.toString() : v);

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    },
  );
}
