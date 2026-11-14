import type { ToolApi, ToolName } from "../env.js";
import type { TaskPrompt } from "../scenarios.js";

export interface TranscriptStep {
  index: number;
  kind: "tool_call" | "assistant" | "error";
  at: string;
  /** Tool name for `tool_call`. */
  tool?: ToolName | string;
  args?: unknown;
  result?: unknown;
  /** Free text the model produced (assistant turns, or the model's stated reasoning next to a call). */
  text?: string;
  error?: string;
  latencyMs?: number;
}

export interface Transcript {
  steps: TranscriptStep[];
  /** The `done(summary)` text, if the agent finished. */
  finalSummary?: string;
  /** Why the loop ended. */
  stop: "done" | "max_steps" | "agent_error" | "no_tool_call";
  /** Model usage when an LLM adapter reports it. */
  usage?: { inputTokens: number; outputTokens: number };
}

/**
 * One agent, scripted or model-backed. `tools` is the complete capability surface it
 * gets; it carries no approver key and no approval tool, by construction.
 */
export interface Agent {
  readonly id: string;
  run(task: TaskPrompt, tools: ToolApi, maxSteps: number): Promise<Transcript>;
}
