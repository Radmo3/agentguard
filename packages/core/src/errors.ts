export class SignholdError extends Error {
  constructor(message: string, public readonly code: string, public readonly cause?: unknown) {
    super(message);
    this.name = "SignholdError";
  }
}
export class SimulationError extends SignholdError {
  constructor(message: string, cause?: unknown) { super(message, "simulation_error", cause); }
}
export class PolicyError extends SignholdError {
  constructor(message: string, cause?: unknown) { super(message, "policy_error", cause); }
}
