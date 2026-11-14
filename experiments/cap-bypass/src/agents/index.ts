import { anthropicAgent } from "./anthropic.js";
import { compatAgent, openaiAgent } from "./openai.js";
import { SCRIPTED_KINDS, scriptedAgent, type ScriptedKind } from "./scripted.js";
import type { Agent } from "./types.js";

export type { Agent, Transcript, TranscriptStep } from "./types.js";
export { scriptedAgent, SCRIPTED_KINDS, type ScriptedKind } from "./scripted.js";
export { anthropicAgent } from "./anthropic.js";
export { openaiAgent, compatAgent } from "./openai.js";

export interface AgentSpecOptions {
  /** Base URL for `compat:` agents (also COMPAT_BASE_URL). */
  compatBaseUrl?: string;
  temperature?: number;
}

/**
 * Parse `--agent` specs: `scripted:<kind>`, `anthropic:<model>`, `openai:<model>`,
 * `compat:<model>` (needs a base URL). The SDK clients read their keys from the
 * environment; nothing here receives or logs them.
 */
export function agentFromSpec(spec: string, opts: AgentSpecOptions = {}): Agent {
  const i = spec.indexOf(":");
  if (i <= 0) throw new Error(`invalid --agent '${spec}': expected provider:name`);
  const provider = spec.slice(0, i);
  const name = spec.slice(i + 1);
  if (!name) throw new Error(`invalid --agent '${spec}': missing model/kind`);
  switch (provider) {
    case "scripted":
      if (!(SCRIPTED_KINDS as readonly string[]).includes(name)) throw new Error(`unknown scripted agent '${name}' (one of ${SCRIPTED_KINDS.join(", ")})`);
      return scriptedAgent(name as ScriptedKind);
    case "anthropic":
      return anthropicAgent({ model: name });
    case "openai":
      return openaiAgent({ model: name, temperature: opts.temperature });
    case "compat": {
      const baseURL = opts.compatBaseUrl ?? process.env.COMPAT_BASE_URL;
      if (!baseURL) throw new Error("compat:<model> needs --base-url or COMPAT_BASE_URL");
      return compatAgent({ model: name, baseURL, temperature: opts.temperature });
    }
    default:
      throw new Error(`unknown agent provider '${provider}' (scripted | anthropic | openai | compat)`);
  }
}
