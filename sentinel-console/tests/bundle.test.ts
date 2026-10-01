// @vitest-environment node
/** After `npm run build`: nothing server-only may reach the browser bundle. */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const STATIC = path.join(__dirname, "..", ".next", "static");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = path.join(dir, f);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

describe.skipIf(!existsSync(STATIC))("client bundle", () => {
  it("contains no credential, signing code, key path or server configuration", () => {
    const text = files(STATIC)
      .filter((f) => f.endsWith(".js"))
      .map((f) => readFileSync(f, "utf8"))
      .join("\n");
    expect(text.length).toBeGreaterThan(1000);
    for (const forbidden of [
      /FRAUD_API_CREDENTIAL/,
      /FRAUD_API_SIGNING_SECRET/,
      /SENTINEL_OPERATOR_KEY_FILE/,
      /SENTINEL_DEMO_CONTROL_TOKEN/,
      /X-Fraud-Signature/,
      /createHmac/,
      /BEGIN [A-Z ]*PRIVATE KEY/,
      /fak_[A-Za-z0-9]{6,}/,
    ]) {
      expect(text).not.toMatch(forbidden);
    }
  });
});
