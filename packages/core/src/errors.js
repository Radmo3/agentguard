export class AgentGuardError extends Error {
    code;
    cause;
    constructor(message, code, cause) {
        super(message);
        this.code = code;
        this.cause = cause;
        this.name = "AgentGuardError";
    }
}
export class SimulationError extends AgentGuardError {
    constructor(message, cause) { super(message, "simulation_error", cause); }
}
export class PolicyError extends AgentGuardError {
    constructor(message, cause) { super(message, "policy_error", cause); }
}
//# sourceMappingURL=errors.js.map