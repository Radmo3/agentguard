import type { ChainAdapter, SimulationResult, TransactionIntent } from "@signhold/core";

export interface CircuitBreakerOptions {
  /** Consecutive failures that open the circuit. Default 5. */
  failureThreshold?: number;
  /** How long the circuit stays open before a single trial call is allowed. Default 30s. */
  resetTimeoutMs?: number;
  /** Per-call timeout; a timeout counts as a failure. Default 15s. 0 disables. */
  callTimeoutMs?: number;
  now?: () => number;
  onStateChange?: (state: CircuitState, chain: string) => void;
}

export type CircuitState = "closed" | "open" | "half_open";

export class AdapterUnavailableError extends Error {
  readonly code = "adapter_unavailable";
  constructor(chain: string, public readonly state: CircuitState, public readonly retryAfterMs: number) {
    super(`adapter for chain '${chain}' is unavailable (circuit ${state})`);
    this.name = "AdapterUnavailableError";
  }
}

export class AdapterTimeoutError extends Error {
  readonly code = "adapter_timeout";
  constructor(chain: string, timeoutMs: number) {
    super(`adapter for chain '${chain}' did not respond within ${timeoutMs}ms`);
    this.name = "AdapterTimeoutError";
  }
}

/**
 * Wraps a ChainAdapter with a circuit breaker. When open, `simulate` rejects
 * immediately with AdapterUnavailableError, which the server turns into an
 * `escalate` verdict with reason `adapter_unavailable` (fail closed).
 */
export class CircuitBreakerAdapter implements ChainAdapter {
  readonly chain: ChainAdapter["chain"];
  private failures = 0;
  private state: CircuitState = "closed";
  private openedAt = 0;
  private trialInFlight = false;
  private readonly threshold: number;
  private readonly resetTimeoutMs: number;
  private readonly callTimeoutMs: number;
  private readonly now: () => number;

  constructor(
    private readonly inner: ChainAdapter,
    private readonly opts: CircuitBreakerOptions = {},
  ) {
    this.chain = inner.chain;
    this.threshold = Math.max(1, opts.failureThreshold ?? 5);
    this.resetTimeoutMs = opts.resetTimeoutMs ?? 30_000;
    this.callTimeoutMs = opts.callTimeoutMs ?? 15_000;
    this.now = opts.now ?? Date.now;
  }

  get currentState(): CircuitState {
    return this.state;
  }

  get consecutiveFailures(): number {
    return this.failures;
  }

  async simulate(intent: TransactionIntent): Promise<SimulationResult> {
    const t = this.now();
    if (this.state === "open") {
      if (t - this.openedAt >= this.resetTimeoutMs) {
        this.transition("half_open");
      } else {
        throw new AdapterUnavailableError(this.chain, "open", this.resetTimeoutMs - (t - this.openedAt));
      }
    }
    if (this.state === "half_open") {
      if (this.trialInFlight) throw new AdapterUnavailableError(this.chain, "half_open", this.resetTimeoutMs);
      this.trialInFlight = true;
    }
    try {
      const result = await this.withTimeout(this.inner.simulate(intent));
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    } finally {
      this.trialInFlight = false;
    }
  }

  private withTimeout<T>(p: Promise<T>): Promise<T> {
    if (this.callTimeoutMs <= 0) return p;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => reject(new AdapterTimeoutError(this.chain, this.callTimeoutMs)), this.callTimeoutMs);
      p.then(
        (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        (e) => {
          clearTimeout(timer);
          reject(e);
        },
      );
    });
  }

  private onSuccess(): void {
    this.failures = 0;
    if (this.state !== "closed") this.transition("closed");
  }

  private onFailure(): void {
    this.failures++;
    if (this.state === "half_open" || this.failures >= this.threshold) {
      this.openedAt = this.now();
      if (this.state !== "open") this.transition("open");
      else this.openedAt = this.now();
    }
  }

  private transition(next: CircuitState): void {
    this.state = next;
    if (next === "open") this.openedAt = this.now();
    this.opts.onStateChange?.(next, this.chain);
  }
}
