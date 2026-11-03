export declare class AgentGuardError extends Error {
    readonly code: string;
    readonly cause?: unknown | undefined;
    constructor(message: string, code: string, cause?: unknown | undefined);
}
export declare class SimulationError extends AgentGuardError {
    constructor(message: string, cause?: unknown);
}
export declare class PolicyError extends AgentGuardError {
    constructor(message: string, cause?: unknown);
}
