/**
 * Demo operator assertions (EdDSA JWT) signed by the console server. Verified here with
 * node:crypto, and — when the Python package is importable — by the service's own verifier.
 */
import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { createAssertion, keyIdFromPem } from "@/lib/server/assertion";

function tempKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const dir = mkdtempSync(path.join(tmpdir(), "sentinel-test-"));
  const file = path.join(dir, "operator.pem");
  writeFileSync(file, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  const publicPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  return { file, publicPem, dir };
}

const b64 = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString("utf8")) as Record<string, unknown>;

describe("operator assertion", () => {
  it("is a well-formed, correctly signed EdDSA JWT bound to action, target and resolution", () => {
    const key = tempKey();
    const token = createAssertion({
      keyFile: key.file,
      operatorId: "rita",
      action: "review.resolve",
      target: "3f0c2c1e-0000-4000-8000-000000000001",
      binding: { resolution: "fraud" },
      audience: "fraud-ai-admin",
    });
    const [h, c, sig] = token.split(".");
    const header = b64(h!);
    const claims = b64(c!);
    expect(header).toMatchObject({ alg: "EdDSA", typ: "JWT" });
    const raw = createPublicKey(key.publicPem).export({ format: "der", type: "spki" }).subarray(-32);
    expect(header.kid).toBe(`ed25519:${createHash("sha256").update(raw).digest("hex").slice(0, 16)}`);
    expect(keyIdFromPem(readFileSync(key.file, "utf8"))).toBe(header.kid);
    expect(claims).toMatchObject({ iss: "rita", sub: "rita", aud: "fraud-ai-admin", act: "review.resolve", bnd: { resolution: "fraud" } });
    expect(claims.tgt).toBe("3f0c2c1e-0000-4000-8000-000000000001");
    expect(Number(claims.exp) - Number(claims.iat)).toBe(120);
    expect(typeof claims.jti).toBe("string");
    expect(verify(null, Buffer.from(`${h}.${c}`), key.publicPem, Buffer.from(sig!, "base64url"))).toBe(true);
  });

  it("uses a fresh jti every time (assertions are single-use)", () => {
    const key = tempKey();
    const make = () => createAssertion({ keyFile: key.file, operatorId: "rita", action: "review.resolve", target: "t", binding: { resolution: "legitimate" }, audience: "a" });
    expect(b64(make().split(".")[1]!).jti).not.toBe(b64(make().split(".")[1]!).jti);
  });

  const python = spawnSync("python3", ["-c", "import fraud_ai.trust.operators"], { cwd: path.resolve(__dirname, "../.."), encoding: "utf8" });
  it.skipIf(python.status !== 0)("is accepted by the service's own Python verifier", () => {
    const key = tempKey();
    const target = "3f0c2c1e-0000-4000-8000-000000000002";
    const token = createAssertion({ keyFile: key.file, operatorId: "rita", action: "review.resolve", target, binding: { resolution: "legitimate" }, audience: "fraud-ai-admin" });
    const registry = path.join(key.dir, "operators.json");
    const raw = createPublicKey(key.publicPem).export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
    writeFileSync(registry, JSON.stringify({ version: 1, operators: [{ id: "rita", roles: ["reviewer"], public_keys: [raw] }] }));
    const script = `
import sys
from fraud_ai.trust.operators import OperatorRegistry, verify_assertion
reg = OperatorRegistry.parse(open(sys.argv[1]).read())
v = verify_assertion(sys.argv[2], reg, audience="fraud-ai-admin", action="review.resolve", target=sys.argv[3], binding={"resolution": "legitimate"})
print("verified")
`;
    const r = spawnSync("python3", ["-c", script, registry, token, target], { cwd: path.resolve(__dirname, "../.."), encoding: "utf8" });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    // and a different binding is refused
    const bad = spawnSync("python3", ["-c", script.replace('"legitimate"}', '"fraud"}'), registry, token, target], { cwd: path.resolve(__dirname, "../.."), encoding: "utf8" });
    expect(bad.status).not.toBe(0);
  });
});
