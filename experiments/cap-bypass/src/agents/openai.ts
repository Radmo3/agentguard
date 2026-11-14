/**
 * OpenAI adapter (`openai` SDK, chat completions with function calling) and the
 * OpenAI-compatible adapter for any other provider or local model (same SDK pointed at
 * a different base URL). Keys come from OPENAI_API_KEY / COMPAT_API_KEY and are never logged.
 */
import OpenAI from "openai";
import { TOOL_DEFINITIONS, type ToolApi } from "../env.js";
import type { TaskPrompt } from "../scenarios.js";
import { LoopState, parseArgs, requireEnv, type ToolCall } from "./llm-common.js";
import type { Agent, Transcript } from "./types.js";

export interface OpenAIAgentOptions {
  model: string;
  /** Prefix for the agent id (`openai` or `compat`). */
  provider?: string;
  baseURL?: string;
  apiKey?: string;
  temperature?: number;
  maxTokens?: number;
  /** Injectable client (tests). */
  client?: Pick<OpenAI, "chat">;
}

export function openaiAgent(opts: OpenAIAgentOptions): Agent {
  const provider = opts.provider ?? "openai";
  const client =
    opts.client ??
    new OpenAI({
      apiKey: opts.apiKey ?? (provider === "openai" ? requireEnv("OPENAI_API_KEY") : (process.env.COMPAT_API_KEY ?? process.env.OPENAI_API_KEY ?? "not-needed")),
      baseURL: opts.baseURL,
      maxRetries: 3,
    });
  const tools: OpenAI.Chat.Completions.ChatCompletionTool[] = TOOL_DEFINITIONS.map((t) => ({
    type: "function",
    function: { name: t.name, description: t.description, parameters: t.parameters },
  }));

  return {
    id: `${provider}:${opts.model}`,
    async run(task: TaskPrompt, api: ToolApi, maxSteps: number): Promise<Transcript> {
      const state = new LoopState(api, maxSteps);
      const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
        { role: "system", content: task.system },
        { role: "user", content: task.user },
      ];
      try {
        for (let turn = 0; turn < maxSteps * 2 && !state.done && state.budgetLeft > 0; turn++) {
          const res = await client.chat.completions.create({
            model: opts.model,
            messages,
            tools,
            temperature: opts.temperature,
            max_completion_tokens: opts.maxTokens,
          });
          state.usage.inputTokens += res.usage?.prompt_tokens ?? 0;
          state.usage.outputTokens += res.usage?.completion_tokens ?? 0;
          const msg = res.choices[0]?.message;
          if (!msg) return state.finish("no_tool_call", "");
          messages.push({ role: "assistant", content: msg.content ?? null, tool_calls: msg.tool_calls?.length ? msg.tool_calls : undefined });
          state.note(msg.content ?? "");

          const calls: ToolCall[] = (msg.tool_calls ?? [])
            .filter((c): c is OpenAI.Chat.Completions.ChatCompletionMessageFunctionToolCall => c.type === "function")
            .map((c) => ({ id: c.id, name: c.function.name, args: parseArgs(c.function.arguments) }));
          if (calls.length === 0) return state.finish("no_tool_call", msg.content ?? "");

          for (const call of calls) {
            if (state.budgetLeft <= 0) {
              messages.push({ role: "tool", tool_call_id: call.id, content: JSON.stringify({ error: "step_budget_exhausted" }) });
              continue;
            }
            const out = await state.execute(call);
            messages.push({ role: "tool", tool_call_id: out.id, content: out.content });
          }
        }
        return state.finish(state.done ? "done" : "max_steps");
      } catch (err) {
        return state.fail(err);
      }
    },
  };
}

/** Any OpenAI-compatible endpoint (vLLM, Ollama, OpenRouter, Together, ...). */
export function compatAgent(opts: { model: string; baseURL: string; apiKey?: string; temperature?: number; client?: Pick<OpenAI, "chat"> }): Agent {
  return openaiAgent({ ...opts, provider: "compat" });
}
