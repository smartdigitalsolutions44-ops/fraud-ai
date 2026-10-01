import "server-only";

import { createHash, createPrivateKey, createPublicKey, randomUUID, sign } from "node:crypto";
import { readFileSync } from "node:fs";

/**
 * A fraud-ai operator assertion (fraud_ai/trust/operators.py): an EdDSA (Ed25519) JWT with
 * iss=sub=operator, aud, iat/nbf/exp, a single-use jti, act (action), tgt (target) and bnd
 * (binding). The header `kid` is "ed25519:" + the first 16 hex characters of SHA-256 over the
 * raw 32-byte public key.
 *
 * DEMO MODE ONLY. Outside the demo the console never holds an operator key: analysts sign
 * their own assertion (`fraud-ai operators assert`) and paste it for that one action.
 */
function b64url(data: Buffer | string): string {
  return Buffer.from(data).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

export function keyIdFromPem(pem: string): string {
  const spki = createPublicKey(createPrivateKey(pem)).export({ format: "der", type: "spki" });
  const raw = spki.subarray(spki.length - 32);
  return "ed25519:" + createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

export interface AssertionRequest {
  keyFile: string;
  operatorId: string;
  action: string;
  target: string;
  binding: Record<string, string>;
  audience: string;
  lifetimeSeconds?: number;
  now?: Date;
}

export function createAssertion(req: AssertionRequest): string {
  const pem = readFileSync(req.keyFile, "utf8");
  const key = createPrivateKey(pem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("operator key must be Ed25519");
  const iat = Math.floor((req.now ?? new Date()).getTime() / 1000);
  const header = { alg: "EdDSA", kid: keyIdFromPem(pem), typ: "JWT" };
  const claims = {
    iss: req.operatorId,
    sub: req.operatorId,
    aud: req.audience,
    iat,
    nbf: iat,
    exp: iat + (req.lifetimeSeconds ?? 120),
    jti: randomUUID().replace(/-/g, ""),
    act: req.action,
    tgt: req.target.slice(0, 200),
    bnd: req.binding,
  };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = sign(null, Buffer.from(input), key);
  return `${input}.${b64url(signature)}`;
}
