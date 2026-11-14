/**
 * Model adapters against fake SDK clients (no network): the tool loop, step budget,
 * unknown-tool handling, error redaction, and that no adapter can see or call anything
 * but the agent tool surface.
 */
import { describe, expect, it } from "vitest";
import { anthropicAgent } from "../src/agents/anthropic.js";
import { compatAgent, openaiAgent } from "../src/agents/openai.js";
import { agentFromSpec } from "../src/agents/index.js";
import { LoopState, parseArgs, redactSecrets } from "../src/agents/llm-common.js";
import { AGENT_WALLET, Inbox, Ledger, Wallet, makeToolApi, toUnits, TOOL_DEFINITIONS } from "../src/env.js";
import { mulberry32 } from "../src/rng.js";
import { INVOICE_TASK, SYSTEM_PROMPT } from "../src/scenarios.js";

const PAYEE = "0xe66c0000000000000000000000000000000098ca";
const task = { system: SYSTEM_PROMPT, user: INVOICE_TASK };

function tools() {
  const ledger = new Ledger({ [AGENT_WALLET]: toUnits(10) });
  const inbox = new Inbox([{ fromName: "Finance (ops)", from: "f@x", subject: "INV-1 (due today) — 0.01 USDC", body: `Invoice INV-1: 0.01 USDC to ${PAYEE}.`, receivedAt: "t" }]);
  const wallet = new Wallet({ ledger, inbox, rng: mulberry32(1), ownerName: "o", ownerEmail: "o@x", executor: async (req) => ({ ok: true, txHash: ledger.transfer(AGENT_WALLET, req.to, req.amountUnits).txHash }) });
  return { api: makeToolApi(wallet, inbox, () => {}), wallet };
}

/** Scripted Anthropic-shaped responses: each call returns the next canned message. */
function fakeAnthropic(script: Array<Array<Record<string, unknown>>>) {
  const seen: unknown[] = [];
  let i = 0;
  return {
    seen,
    client: {
      messages: {
        create: async (params: unknown) => {
          seen.push(params);
          const content = script[Math.min(i++, script.length - 1)]!;
          return { content, usage: { input_tokens: 10, output_tokens: 5 }, stop_reason: content.some((b) => b.type === "tool_use") ? "tool_use" : "end_turn" };
        },
      },
    } as never,
  };
}

function fakeOpenAI(script: Array<{ content?: string | null; tool_calls?: Array<{ id: string; name: string; arguments: string }> }>) {
  const seen: unknown[] = [];
  let i = 0;
  return {
    seen,
    client: {
      chat: {
        completions: {
          create: async (params: unknown) => {
            seen.push(params);
            const m = script[Math.min(i++, script.length - 1)]!;
            return {
              choices: [{ message: { role: "assistant", content: m.content ?? null, tool_calls: m.tool_calls?.map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: c.arguments } })) } }],
              usage: { prompt_tokens: 7, completion_tokens: 3 },
            };
          },
        },
      },
    } as never,
  };
}

describe("anthropic adapter", () => {
  it("runs a native tool-use loop: read inbox -> pay -> done, and records the transcript", async () => {
    const { client, seen } = fakeAnthropic([
      [{ type: "text", text: "Checking the inbox." }, { type: "tool_use", id: "t1", name: "read_inbox", input: {} }],
      [{ type: "tool_use", id: "t2", name: "pay", input: { to: PAYEE, amountUsdc: 0.01, memo: "INV-1" } }],
      [{ type: "tool_use", id: "t3", name: "done", input: { summary: "Paid INV-1." } }],
    ]);
    const { api, wallet } = tools();
    const t = await anthropicAgent({ model: "test-model", client }).run(task, api, 40);
    expect(t.stop).toBe("done");
    expect(t.finalSummary).toBe("Paid INV-1.");
    expect(t.steps.filter((s) => s.kind === "tool_call").map((s) => s.tool)).toEqual(["read_inbox", "pay", "done"]);
    expect(t.steps[0]).toMatchObject({ kind: "assistant", text: "Checking the inbox." });
    expect(wallet.balanceUsdc()).toBeCloseTo(9.99, 6);
    expect(t.usage).toEqual({ inputTokens: 30, outputTokens: 15 });
    // The request carried exactly our tool definitions and the paper-style prompts; nothing else.
    const first = seen[0] as { tools: Array<{ name: string }>; system: string; messages: Array<{ role: string }> };
    expect(first.tools.map((x) => x.name).sort()).toEqual(TOOL_DEFINITIONS.map((x) => x.name).sort());
    expect(first.system).toBe(SYSTEM_PROMPT);
    expect(first.messages[0]).toMatchObject({ role: "user", content: INVOICE_TASK });
    // Tool results went back as tool_result blocks.
    const second = seen[1] as { messages: Array<{ role: string; content: unknown }> };
    expect(second.messages.at(-1)).toMatchObject({ role: "user" });
    expect(JSON.stringify(second.messages.at(-1))).toContain('"type":"tool_result"');
  });

  it("stops with no_tool_call when the model answers in prose, keeping the text as the summary", async () => {
    const { client } = fakeAnthropic([[{ type: "text", text: "I need your approval before paying anything." }]]);
    const t = await anthropicAgent({ model: "m", client }).run(task, tools().api, 40);
    expect(t.stop).toBe("no_tool_call");
    expect(t.finalSummary).toMatch(/approval/);
  });

  it("enforces the step budget and reports unknown tools as errors instead of executing anything", async () => {
    const { client } = fakeAnthropic([
      [{ type: "tool_use", id: "x", name: "approve_escalation", input: { auditId: "abc" } }],
      [{ type: "tool_use", id: "y", name: "read_inbox", input: {} }],
    ]);
    const t = await anthropicAgent({ model: "m", client }).run(task, tools().api, 2);
    expect(t.steps.find((s) => s.kind === "error")).toMatchObject({ tool: "approve_escalation", error: "unknown_tool" });
    expect(t.stop).toBe("max_steps");
    expect(t.steps.filter((s) => s.kind === "tool_call").length).toBeLessThanOrEqual(2);
  });

  it("turns SDK failures into agent_error transcripts with secrets redacted", async () => {
    const client = { messages: { create: async () => { throw new Error("401 invalid x-api-key: sk-ant-SECRETSECRETSECRET"); } } } as never;
    const t = await anthropicAgent({ model: "m", client }).run(task, tools().api, 5);
    expect(t.stop).toBe("agent_error");
    expect(JSON.stringify(t)).not.toContain("SECRETSECRET");
  });
});

describe("openai / compat adapters", () => {
  it("runs a function-calling loop with JSON string arguments", async () => {
    const { client, seen } = fakeOpenAI([
      { content: "Reading mail.", tool_calls: [{ id: "c1", name: "read_inbox", arguments: "{}" }] },
      { tool_calls: [{ id: "c2", name: "pay", arguments: JSON.stringify({ to: PAYEE, amountUsdc: 0.01 }) }] },
      { tool_calls: [{ id: "c3", name: "done", arguments: JSON.stringify({ summary: "ok" }) }] },
    ]);
    const { api, wallet } = tools();
    const t = await openaiAgent({ model: "gpt-test", client }).run(task, api, 40);
    expect(t.stop).toBe("done");
    expect(wallet.balanceUsdc()).toBeCloseTo(9.99, 6);
    const first = seen[0] as { tools: Array<{ type: string; function: { name: string } }>; messages: Array<{ role: string; content: string }> };
    expect(first.tools.every((x) => x.type === "function")).toBe(true);
    expect(first.tools.map((x) => x.function.name).sort()).toEqual(TOOL_DEFINITIONS.map((x) => x.name).sort());
    expect(first.messages[0]).toEqual({ role: "system", content: SYSTEM_PROMPT });
    const second = seen[1] as { messages: Array<{ role: string; tool_call_id?: string }> };
    expect(second.messages.some((m) => m.role === "tool" && m.tool_call_id === "c1")).toBe(true);
  });

  it("survives malformed JSON arguments and prose-only answers", async () => {
    const { client } = fakeOpenAI([{ tool_calls: [{ id: "c1", name: "pay", arguments: "{not json" }] }, { content: "Done, nothing to pay." }]);
    const t = await openaiAgent({ model: "m", client }).run(task, tools().api, 10);
    expect(t.steps.find((s) => s.tool === "pay")!.result).toMatchObject({ ok: false, error: "invalid_address" });
    expect(t.stop).toBe("no_tool_call");
    expect(parseArgs("{bad")).toMatchObject({ __malformed_arguments: "{bad" });
    expect(parseArgs(undefined)).toEqual({});
  });

  it("compat is the same loop with a different id prefix", async () => {
    const { client } = fakeOpenAI([{ content: "hi" }]);
    const a = compatAgent({ model: "local-7b", baseURL: "http://127.0.0.1:1/v1", client });
    expect(a.id).toBe("compat:local-7b");
    expect((await a.run(task, tools().api, 3)).stop).toBe("no_tool_call");
  });
});

describe("agent specs and hygiene", () => {
  it("parses specs and rejects malformed ones", () => {
    expect(agentFromSpec("scripted:obedient").id).toBe("scripted:obedient");
    expect(() => agentFromSpec("scripted:nope")).toThrow(/unknown scripted agent/);
    expect(() => agentFromSpec("nonsense")).toThrow(/provider:name/);
    expect(() => agentFromSpec("martian:x")).toThrow(/unknown agent provider/);
    const saved = { a: process.env.ANTHROPIC_API_KEY, o: process.env.OPENAI_API_KEY, c: process.env.COMPAT_BASE_URL };
    try {
      delete process.env.ANTHROPIC_API_KEY;
      delete process.env.OPENAI_API_KEY;
      delete process.env.COMPAT_BASE_URL;
      expect(() => agentFromSpec("anthropic:claude-x")).toThrow(/ANTHROPIC_API_KEY/);
      expect(() => agentFromSpec("openai:gpt-x")).toThrow(/OPENAI_API_KEY/);
      expect(() => agentFromSpec("compat:llama")).toThrow(/base-url|COMPAT_BASE_URL/);
    } finally {
      if (saved.a) process.env.ANTHROPIC_API_KEY = saved.a;
      if (saved.o) process.env.OPENAI_API_KEY = saved.o;
      if (saved.c) process.env.COMPAT_BASE_URL = saved.c;
    }
  });

  it("redacts bearer tokens and key-shaped strings", () => {
    expect(redactSecrets("Authorization: Bearer abcdefghijklmnop")).toBe("Authorization: Bearer ***");
    expect(redactSecrets("x-api-key: sk-proj-abcdefghijkl")).not.toContain("abcdefghijkl");
  });

  it("LoopState exposes only the six tools (an injected 'approve' is unknown_tool)", async () => {
    const state = new LoopState(tools().api, 5);
    const out = await state.execute({ id: "1", name: "approve", args: {} });
    expect(out.isError).toBe(true);
    expect(JSON.parse(out.content)).toMatchObject({ error: "unknown_tool" });
    expect(state.toolCalls).toBe(0);
  });
});
