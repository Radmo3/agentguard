import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { InMemoryAuditStore } from "../src/audit.js";
import { createRedactingLogger, redactObject } from "../src/logger.js";
import { createServer } from "../src/server.js";
import type { ServerOptions } from "../src/types.js";
import { FakeAdapter, FakeEngine, requestBody, testPolicy } from "./fakes.js";

function capture() {
  const lines: string[] = [];
  return { lines, stream: { write: (s: string) => void lines.push(s) } };
}

async function build(opts: Partial<ServerOptions> = {}) {
  const app = await createServer({
    engine: new FakeEngine(),
    adapters: { evm: new FakeAdapter("evm") },
    policies: new Map([[testPolicy.id, testPolicy]]),
    audit: new InMemoryAuditStore(),
    logger: false,
    rateLimit: false,
    env: "test",
    ...opts,
  });
  return app;
}

describe("redacting logger", () => {
  it("redacts listed keys at any depth for info+ but not at debug", () => {
    const { lines, stream } = capture();
    const log = createRedactingLogger({ level: "debug", stream, redactKeys: ["custom"] });
    const payload = { apiKey: "K1", nested: { data: "0xdead", deeper: [{ raw: "RAW", "x-api-key": "K2" }] }, metadata: { a: 1 }, custom: "C", keep: "visible", err: Object.assign(new Error("m"), { token: "T" }) };
    log.info(payload, "info line");
    log.warn(payload, "warn line");
    log.error(payload, "error line");
    log.debug(payload, "debug line");
    const [info, warn, error, debug] = lines;
    for (const l of [info, warn, error]) {
      for (const s of ["K1", "0xdead", "RAW", "K2", '"a":1', '"custom":"C"', '"token":"T"']) expect(l).not.toContain(s);
      expect(l).toContain("[REDACTED]");
      expect(l).toContain("visible");
    }
    expect(debug).toContain("0xdead");
    expect(debug).toContain("K1");
    // the original object is not mutated
    expect(payload.apiKey).toBe("K1");
  });

  it("handles cycles and depth without throwing", () => {
    const o: Record<string, unknown> = { a: 1 };
    o.self = o;
    expect(() => redactObject(o, new Set())).not.toThrow();
    let deep: Record<string, unknown> = {};
    const root = deep;
    for (let i = 0; i < 30; i++) deep = deep.n = {} as Record<string, unknown>;
    expect(JSON.stringify(redactObject(root, new Set()))).toContain("[TRUNCATED]");
  });
});

describe("secret & log hygiene (server)", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("never logs api keys, calldata, raw tx or metadata at info level", async () => {
    const { lines, stream } = capture();
    app = await build({ logger: { level: "info", stream }, apiKeys: ["SUPERSECRETKEY"] });
    const body = requestBody({ intent: { ...requestBody().intent, data: "0xdeadbeef", metadata: { memo: "PRIVATE_MEMO" } } });
    await app.inject({ method: "POST", url: "/v1/check", payload: body, headers: { "x-api-key": "SUPERSECRETKEY" } });
    const text = lines.join("");
    expect(text).toContain("check decided");
    for (const s of ["SUPERSECRETKEY", "0xdeadbeef", "PRIVATE_MEMO"]) expect(text).not.toContain(s);
    expect(text).toContain("key-"); // identity is logged instead
  });

  it("redacts even when a thrown error carries secrets, at error level", async () => {
    const { lines, stream } = capture();
    const evm = new FakeAdapter("evm", async () => { throw Object.assign(new Error("rpc"), { apiKey: "LEAK", data: "0xLEAK" }); });
    app = await build({ logger: { level: "info", stream }, adapters: { evm } });
    await app.inject({ method: "POST", url: "/v1/check", payload: requestBody() });
    expect(lines.join("")).toContain("adapter threw");
    expect(lines.join("")).not.toContain("LEAK");
  });

  it("returns a generic 500 body with a correlation id, never the error message", async () => {
    const { lines, stream } = capture();
    app = await build({ logger: { level: "error", stream } });
    app.get("/boom", async () => { throw new Error("database password is hunter2"); });
    const res = await app.inject({ method: "GET", url: "/boom" });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: "internal_error", message: "internal server error", requestId: expect.any(String) });
    expect(res.json().requestId).toBe(res.headers["x-request-id"]);
    expect(JSON.stringify(res.json())).not.toContain("hunter2");
    expect(lines.join("")).toContain("hunter2"); // operators still get it server-side
    expect(lines.join("")).toContain(res.json().requestId);
  });

  it("does not echo policy ids or route details in 404s", async () => {
    app = await build();
    const res = await app.inject({ method: "POST", url: "/v1/check", payload: requestBody({ policyId: "<script>" }) });
    expect(res.statusCode).toBe(404);
    expect(JSON.stringify(res.json())).not.toContain("<script>");
    const nf = await app.inject({ method: "GET", url: "/<script>" });
    expect(nf.statusCode).toBe(404);
    expect(JSON.stringify(nf.json())).not.toContain("<script>");
  });
});

describe("security headers & misc", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());

  it("sets hardening headers, no x-powered-by, no CORS by default", async () => {
    app = await build();
    const res = await app.inject({ method: "GET", url: "/healthz", headers: { origin: "https://evil.example" } });
    expect(res.headers["x-powered-by"]).toBeUndefined();
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["content-security-policy"]).toContain("default-src 'none'");
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
    expect(res.headers["content-type"]).toContain("application/json");
    expect((await app.inject({ method: "OPTIONS", url: "/v1/check" })).statusCode).toBe(404);
  });

  it("emits CORS headers only for configured origins", async () => {
    app = await build({ cors: { origins: ["https://ops.example"] } });
    const ok = await app.inject({ method: "OPTIONS", url: "/v1/check", headers: { origin: "https://ops.example" } });
    expect(ok.statusCode).toBe(204);
    expect(ok.headers["access-control-allow-origin"]).toBe("https://ops.example");
    expect(ok.headers["vary"]).toContain("origin");
    const no = await app.inject({ method: "GET", url: "/healthz", headers: { origin: "https://evil.example" } });
    expect(no.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("ignores client-supplied request ids and x-forwarded-for unless trustProxy is set", async () => {
    app = await build();
    const res = await app.inject({ method: "GET", url: "/healthz", headers: { "request-id": "attacker", "x-request-id": "attacker" } });
    expect(res.headers["x-request-id"]).not.toBe("attacker");
    await app.close();

    const seen: string[] = [];
    app = await build({ trustProxy: false });
    app.get("/ip", async (req) => { seen.push(req.ip); return {}; });
    await app.inject({ method: "GET", url: "/ip", headers: { "x-forwarded-for": "9.9.9.9" }, remoteAddress: "127.0.0.1" });
    expect(seen[0]).toBe("127.0.0.1");
    await app.close();

    app = await build({ trustProxy: true });
    app.get("/ip", async (req) => { seen.push(req.ip); return {}; });
    await app.inject({ method: "GET", url: "/ip", headers: { "x-forwarded-for": "9.9.9.9" }, remoteAddress: "127.0.0.1" });
    expect(seen[1]).toBe("9.9.9.9");
  });

  it("graceful shutdown drains in-flight requests and refuses new ones", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const evm = new FakeAdapter("evm", async () => { await gate; return (await new FakeAdapter("evm").simulate(requestBody().intent as never)); });
    app = await build({ adapters: { evm }, shutdownGraceMs: 2000 });
    await app.listen({ port: 0, host: "127.0.0.1" });
    const addr = app.server.address() as { port: number };
    const url = `http://127.0.0.1:${addr.port}`;

    const inflight = fetch(`${url}/v1/check`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(requestBody()) });
    await new Promise((r) => setTimeout(r, 50)); // let the request reach the adapter
    const closing = app.close();
    await new Promise((r) => setTimeout(r, 50));
    // New requests during shutdown are refused (503) or connection-refused once the listener is gone.
    const late = await fetch(`${url}/healthz`).then((r) => r.status).catch(() => 503);
    expect(late).toBe(503);
    release();
    const res = await inflight;
    expect(res.status).toBe(200);
    expect((await res.json()).decision.verdict).toBe("allow");
    await closing;
  });
});
