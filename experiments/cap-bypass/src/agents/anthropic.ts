/**
 * Anthropic adapter: official `@anthropic-ai/sdk`, native tool use. The API key comes from
 * ANTHROPIC_API_KEY (read by the SDK; never logged). The agent receives exactly the tools
 * in TOOL_DEFINITIONS and nothing else. Sampling uses the provider's defaults (the SDK
 * pinned here exposes no temperature parameter; the paper reports none either).
 */
import Anthropic from "@anthropic-ai/sdk";
import { TOOL_DEFINITIONS, type ToolApi } from "../env.js";
import type { TaskPrompt } from "../scenarios.js";
import { LoopState, requireEnv, type ToolCall } from "./llm-common.js";
import type { Agent, Transcript } from "./types.js";

export interface AnthropicAgentOptions {
  model: string;
  maxTokens?: number;
  /** Injectable client (tests). */
  client?: Pick<Anthropic, "messages">;
}

export function anthropicAgent(opts: AnthropicAgentOptions): Agent {
  const client = opts.client ?? new Anthropic({ apiKey: requireEnv("ANTHROPIC_API_KEY"), maxRetries: 3 });
  const tools: Anthropic.Messages.Tool[] = TOOL_DEFINITIONS.map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: t.parameters as Anthropic.Messages.Tool.InputSchema,
  }));

  return {
    id: `anthropic:${opts.model}`,
    async run(task: TaskPrompt, api: ToolApi, maxSteps: number): Promise<Transcript> {
      const state = new LoopState(api, maxSteps);
      const messages: Anthropic.Messages.MessageParam[] = [{ role: "user", content: task.user }];
      try {
        // Each model turn may carry several tool calls; the step budget counts calls.
        for (let turn = 0; turn < maxSteps * 2 && !state.done && state.budgetLeft > 0; turn++) {
          const res = await client.messages.create({
            model: opts.model,
            max_tokens: opts.maxTokens ?? 2048,
            system: task.system,
            tools,
            messages,
          });
          state.usage.inputTokens += res.usage.input_tokens;
          state.usage.outputTokens += res.usage.output_tokens;
          messages.push({ role: "assistant", content: res.content });

          const text = res.content.filter((b) => b.type === "text").map((b) => (b as Anthropic.Messages.TextBlock).text).join("\n");
          state.note(text);
          const calls: ToolCall[] = res.content.filter((b) => b.type === "tool_use").map((b) => {
            const u = b as Anthropic.Messages.ToolUseBlock;
            return { id: u.id, name: u.name, args: u.input };
          });
          if (calls.length === 0) return state.finish("no_tool_call", text);

          const results: Anthropic.Messages.ToolResultBlockParam[] = [];
          for (const call of calls) {
            if (state.budgetLeft <= 0) {
              results.push({ type: "tool_result", tool_use_id: call.id, content: JSON.stringify({ error: "step_budget_exhausted" }), is_error: true });
              continue;
            }
            const out = await state.execute(call);
            results.push({ type: "tool_result", tool_use_id: out.id, content: out.content, is_error: out.isError || undefined });
          }
          messages.push({ role: "user", content: results });
        }
        return state.finish(state.done ? "done" : "max_steps");
      } catch (err) {
        return state.fail(err);
      }
    },
  };
}
