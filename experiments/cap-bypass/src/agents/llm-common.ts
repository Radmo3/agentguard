/**
 * Shared pieces of the model-backed adapters: tool dispatch with validation, transcript
 * recording and the step budget. The adapters only translate between their SDK's wire
 * format and these helpers, so the three of them behave identically.
 */
import { TOOL_NAMES, type ToolApi, type ToolName } from "../env.js";
import type { Transcript, TranscriptStep } from "./types.js";

export interface ToolCall {
  id: string;
  name: string;
  args: unknown;
}

export interface ToolOutcome {
  id: string;
  name: string;
  /** JSON string handed back to the model. */
  content: string;
  isError: boolean;
}

export class LoopState {
  readonly steps: TranscriptStep[] = [];
  finalSummary: string | undefined;
  done = false;
  usage = { inputTokens: 0, outputTokens: 0 };
  constructor(private readonly tools: ToolApi, readonly maxSteps: number) {}

  get toolCalls(): number {
    return this.steps.filter((s) => s.kind === "tool_call").length;
  }
  get budgetLeft(): number {
    return this.maxSteps - this.toolCalls;
  }

  note(text: string): void {
    if (text.trim()) this.steps.push({ index: this.steps.length, kind: "assistant", at: new Date().toISOString(), text });
  }

  async execute(call: ToolCall): Promise<ToolOutcome> {
    const t0 = performance.now();
    const at = new Date().toISOString();
    if (!(TOOL_NAMES as readonly string[]).includes(call.name)) {
      const content = JSON.stringify({ error: "unknown_tool", message: `no tool named '${call.name}'` });
      this.steps.push({ index: this.steps.length, kind: "error", at, tool: call.name, args: call.args, error: "unknown_tool" });
      return { id: call.id, name: call.name, content, isError: true };
    }
    const name = call.name as ToolName;
    try {
      const fn = this.tools[name] as (a?: unknown) => Promise<unknown>;
      const result = await fn(call.args ?? {});
      if (name === "done") {
        this.done = true;
        const s = (call.args as { summary?: unknown } | undefined)?.summary;
        this.finalSummary = typeof s === "string" ? s : "";
      }
      this.steps.push({ index: this.steps.length, kind: "tool_call", at, tool: name, args: call.args, result, latencyMs: round(performance.now() - t0) });
      return { id: call.id, name, content: JSON.stringify(result ?? null), isError: false };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.steps.push({ index: this.steps.length, kind: "error", at, tool: name, args: call.args, error: message, latencyMs: round(performance.now() - t0) });
      return { id: call.id, name, content: JSON.stringify({ error: "tool_error", message }), isError: true };
    }
  }

  finish(stop: Transcript["stop"], finalText?: string): Transcript {
    const summary = this.finalSummary ?? (stop === "no_tool_call" ? finalText : undefined);
    return { steps: this.steps, finalSummary: summary, stop, usage: this.usage };
  }

  fail(err: unknown): Transcript {
    const message = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    this.steps.push({ index: this.steps.length, kind: "error", at: new Date().toISOString(), error: redactSecrets(message) });
    return this.finish("agent_error");
  }
}

const round = (ms: number) => Math.round(ms * 1000) / 1000;

/** Parse a JSON arguments string from a function-calling API; malformed input becomes an empty object plus a note. */
export function parseArgs(raw: unknown): unknown {
  if (raw === undefined || raw === null || raw === "") return {};
  if (typeof raw !== "string") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return { __malformed_arguments: raw.slice(0, 200) };
  }
}

/** Best-effort scrub so an SDK error that echoes a header never lands in a transcript. */
export function redactSecrets(text: string): string {
  return text.replace(/sk-[A-Za-z0-9_-]{8,}/g, "sk-***").replace(/(Bearer\s+)[A-Za-z0-9._-]{8,}/g, "$1***").replace(/(x-api-key\W{0,3})[A-Za-z0-9._-]{8,}/gi, "$1***");
}

export function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set`);
  return v;
}
