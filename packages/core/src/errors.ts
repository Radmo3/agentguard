export class AgentGuardError extends Error {
  constructor(message: string, public readonly code: string, public readonly cause?: unknown) {
    super(message);
    this.name = "AgentGuardError";
  }
}
export class SimulationError extends AgentGuardError {
  constructor(message: string, cause?: unknown) { super(message, "simulation_error", cause); }
}
export class PolicyError extends AgentGuardError {
  constructor(message: string, cause?: unknown) { super(message, "policy_error", cause); }
}
