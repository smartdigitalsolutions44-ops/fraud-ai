import "server-only";

import { createHash, createHmac } from "node:crypto";

/**
 * fraud-ai request signature v2, byte-for-byte compatible with
 * fraud_ai/service/signatures.py (tested against the Python implementation):
 *
 *   canonical = "fraud-ai-v2" \n METHOD \n CANONICAL_TARGET \n TIMESTAMP \n hex(SHA256(body))
 *   X-Fraud-Signature: v2=<hex HMAC-SHA256(secret, canonical)>
 */
const UNRESERVED = /[A-Za-z0-9\-._~]/;

function encode(value: string, keepSlash: boolean): string {
  let out = "";
  for (const byte of Buffer.from(value, "utf8")) {
    const ch = String.fromCharCode(byte);
    if (byte < 0x80 && (UNRESERVED.test(ch) || (keepSlash && ch === "/"))) out += ch;
    else out += "%" + byte.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

function decode(value: string, plusIsSpace: boolean): string {
  const text = plusIsSpace ? value.replace(/\+/g, " ") : value;
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const hex = text.slice(i + 1, i + 3);
    if (ch === "%" && /^[0-9A-Fa-f]{2}$/.test(hex)) {
      bytes.push(parseInt(hex, 16));
      i += 2;
    } else {
      bytes.push(...Buffer.from(ch, "utf8"));
    }
  }
  return Buffer.from(bytes).toString("utf8");
}

/** Python's urllib.parse.parse_qsl(query, keep_blank_values=True). */
export function parseQsl(query: string): Array<[string, string]> {
  const pairs: Array<[string, string]> = [];
  for (const piece of query.split("&")) {
    if (!piece) continue;
    const at = piece.indexOf("=");
    const name = at === -1 ? piece : piece.slice(0, at);
    const value = at === -1 ? "" : piece.slice(at + 1);
    pairs.push([decode(name, true), decode(value, true)]);
  }
  return pairs;
}

function compare(a: string, b: string): number {
  // Code-point order, like Python's str comparison.
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

export function canonicalTarget(path: string, query = ""): string {
  const canonicalPath = encode(decode(path, false), true) || "/";
  const pairs = parseQsl(query).sort((p, q) => compare(p[0], q[0]) || compare(p[1], q[1]));
  if (pairs.length === 0) return canonicalPath;
  return canonicalPath + "?" + pairs.map(([k, v]) => `${encode(k, false)}=${encode(v, false)}`).join("&");
}

export function canonicalV2(method: string, path: string, query: string, timestamp: number, body: Buffer): string {
  return [
    "fraud-ai-v2",
    method.toUpperCase(),
    canonicalTarget(path, query),
    String(timestamp),
    createHash("sha256").update(body).digest("hex"),
  ].join("\n");
}

export function signV2(secret: string, method: string, path: string, timestamp: number, body: Buffer, query = ""): string {
  return "v2=" + createHmac("sha256", secret).update(canonicalV2(method, path, query, timestamp, body)).digest("hex");
}

/**
 * The service stores every accepted signature and refuses a replay. Two identical requests
 * in the same second would produce the same signature, so each gets its own timestamp
 * (never in the future, always inside the service's freshness window).
 */
export class TimestampAllocator {
  private used = new Map<string, Set<number>>();
  constructor(private readonly windowSeconds = 120) {}

  next(key: string, nowSeconds = Math.floor(Date.now() / 1000)): number {
    let set = this.used.get(key);
    if (!set) {
      set = new Set();
      this.used.set(key, set);
    }
    for (const ts of set) if (ts < nowSeconds - this.windowSeconds) set.delete(ts);
    for (let ts = nowSeconds; ts > nowSeconds - this.windowSeconds; ts--) {
      if (!set.has(ts)) {
        set.add(ts);
        return ts;
      }
    }
    throw new Error("too many identical requests in the signature window");
  }
}
