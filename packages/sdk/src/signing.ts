/**
 * HMAC request signing, compatible with the AgentGuard API's
 * `x-agentguard-signature` verification. Uses WebCrypto only so it runs in
 * Node 22, Deno, Bun and browsers.
 *
 * Base string:  "v1\n<timestamp-ms>\n<nonce>\n<METHOD>\n<path?query>\n<sha256hex(body)>"
 * HMAC key:     sha256(secret) (raw 32 bytes)
 * Header value: "v1=<hex hmac-sha256>"
 */
export interface SignRequestInput {
  secret: string;
  method: string;
  /** Path including query string, e.g. "/v1/check". */
  path: string;
  body: string;
  /** Override for tests. */
  timestamp?: string;
  nonce?: string;
}

export interface SignedHeaders {
  signature: string;
  timestamp: string;
  nonce: string;
}

export type RequestSigner = (input: SignRequestInput) => Promise<SignedHeaders>;

const SIGNATURE_VERSION = "v1";
const enc = new TextEncoder();

function hex(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  for (const b of u8) out += b.toString(16).padStart(2, "0");
  return out;
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error("WebCrypto (crypto.subtle) is not available in this runtime");
  return s;
}

export async function sha256Hex(data: string): Promise<string> {
  return hex(await subtle().digest("SHA-256", enc.encode(data)));
}

export async function signatureBaseString(input: Pick<SignRequestInput, "method" | "path" | "body"> & { timestamp: string; nonce: string }): Promise<string> {
  return [SIGNATURE_VERSION, input.timestamp, input.nonce, input.method.toUpperCase(), input.path, await sha256Hex(input.body)].join("\n");
}

function randomNonce(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return hex(bytes);
}

export const signRequest: RequestSigner = async (input) => {
  const timestamp = input.timestamp ?? String(Date.now());
  const nonce = input.nonce ?? randomNonce();
  const keyMaterial = await subtle().digest("SHA-256", enc.encode(input.secret));
  const key = await subtle().importKey("raw", keyMaterial, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const base = await signatureBaseString({ method: input.method, path: input.path, body: input.body, timestamp, nonce });
  const mac = await subtle().sign("HMAC", key, enc.encode(base));
  return { signature: `${SIGNATURE_VERSION}=${hex(mac)}`, timestamp, nonce };
};
