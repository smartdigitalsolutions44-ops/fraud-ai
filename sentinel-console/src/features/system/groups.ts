import type { CheckState } from "@/lib/domain";
import { ApiError } from "@/lib/api/client";
import type { ReadyT, SessionT, SystemT } from "@/lib/api/schemas";

/**
 * Stage 14: system health in seven operational groups, derived ONLY from what the service
 * reports (/v1/ready, /v1/analyst/system) and from the console's own /api/session. The
 * start-up sequence and the System page both use this, so the two can never disagree.
 *
 * A group with no answer yet is CHECKING; one whose source failed is OFFLINE; anything the
 * service did not confirm is never shown as ONLINE.
 */
export type GroupId = "service" | "trust" | "data" | "models" | "policy" | "audit" | "analyst";

export interface HealthGroup {
  id: GroupId;
  /** The System page heading. */
  title: string;
  /** The start-up line: what the console is doing while this group is checked. */
  action: string;
  state: CheckState;
  /** Why it is in that state: what the service reported, in a few words. */
  cause: string;
}

interface Inputs {
  session?: SessionT;
  sessionError?: unknown;
  ready?: ReadyT;
  readyError?: unknown;
  system?: SystemT;
  systemError?: unknown;
}

function denied(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.kind === "forbidden") return "permission denied: the console key lacks the analyst:read scope";
    if (err.kind === "unauthorised") return "the console's API credential was rejected";
    if (err.kind === "rate_limited") return "rate limited by the service; retrying";
    if (err.code === "BACKEND_NOT_CONFIGURED") return "the console has no API credential configured";
    if (err.kind === "timeout") return "the service did not answer in time";
    return "the fraud service is unreachable";
  }
  return "the fraud service is unreachable";
}

function service(i: Inputs): HealthGroup {
  const g = { id: "service" as const, title: "Service", action: "Contacting fraud service" };
  if (i.readyError !== undefined && !i.ready) return { ...g, state: "offline", cause: denied(i.readyError) };
  if (!i.ready) return { ...g, state: "checking", cause: "waiting for /v1/ready" };
  const failing = Object.entries(i.ready.checks).filter(([, v]) => v !== "ok" && v !== "not_required");
  const env = i.system ? ` · ${i.system.environment}` : "";
  if (i.ready.status === "ready") return { ...g, state: "online", cause: `${i.ready.api_version} ready${env}` };
  return { ...g, state: "degraded", cause: `not ready: ${failing.map(([k, v]) => `${k} ${v}`).join(", ") || "unknown"}` };
}

function data(i: Inputs): HealthGroup {
  const g = { id: "data" as const, title: "Data", action: "Connecting data plane" };
  if (i.readyError !== undefined && !i.ready) return { ...g, state: "offline", cause: denied(i.readyError) };
  if (!i.ready) return { ...g, state: "checking", cause: "database and shared state" };
  const c = i.ready.checks;
  if (c.database !== "ok") return { ...g, state: "offline", cause: `database ${c.database ?? "not reported"}` };
  const parts = ["database connected"];
  let state: CheckState = "online";
  if (c.migrations === "ok") parts.push("schema at migration head");
  else {
    state = "degraded";
    const m = i.system?.migrations;
    parts.push(`migrations ${c.migrations ?? "not reported"}${m ? ` (${m.current ?? "?"} of ${m.head ?? "?"})` : ""}`);
  }
  if (c.shared_state === "ok") parts.push("Redis shared state reachable");
  else if (c.shared_state === "not_required") parts.push("Redis not used (in-memory, single process)");
  else {
    state = "degraded";
    parts.push(`Redis ${c.shared_state ?? "not reported"}: rate limits and replay checks are not shared`);
  }
  return { ...g, state, cause: parts.join(" · ") };
}

function models(i: Inputs): HealthGroup {
  const g = { id: "models" as const, title: "Models", action: "Verifying model signatures" };
  if (i.systemError !== undefined && !i.system) return { ...g, state: "offline", cause: denied(i.systemError) };
  if (!i.system || !i.ready) return { ...g, state: "checking", cause: "reading the model registry" };
  const all = i.system.models;
  const primary = all.find((m) => m.role === "primary");
  if (!primary || !primary.registered) return { ...g, state: "offline", cause: "primary model not registered" };
  if (i.ready.checks.primary_model !== "ok") return { ...g, state: "offline", cause: `primary model ${i.ready.checks.primary_model ?? "not loaded"} (signature or artefact refused at readiness)` };
  const mismatch = all.find((m) => m.signature?.present && !m.signature.matches_artifact);
  if (mismatch) return { ...g, state: "offline", cause: `${mismatch.ref}: signature does not match the artefact` };
  const required = i.system.security.model_signatures_required;
  const unsigned = all.filter((m) => m.registered && !m.signature?.present);
  if (unsigned.length) {
    const primaryUnsigned = unsigned.includes(primary);
    return { ...g, state: primaryUnsigned && required ? "offline" : "degraded", cause: `${unsigned.map((m) => m.ref).join(", ")} unsigned` };
  }
  if (!required) return { ...g, state: "degraded", cause: "models signed, but signatures are not enforced in this profile" };
  const key = primary.signature?.key_id;
  return { ...g, state: "online", cause: `${all.length} model${all.length === 1 ? "" : "s"} signed and verified${key ? ` · key ${key}` : ""}` };
}

function policy(i: Inputs): HealthGroup {
  const g = { id: "policy" as const, title: "Policy", action: "Loading risk policy" };
  if (i.readyError !== undefined && !i.ready) return { ...g, state: "offline", cause: denied(i.readyError) };
  if (!i.ready) return { ...g, state: "checking", cause: "reading the active deployment" };
  if (i.ready.checks.active_policy !== "ok") return { ...g, state: "offline", cause: `no active policy (${i.ready.checks.active_policy ?? "not reported"})` };
  const p = i.system?.policy;
  if (!p) return { ...g, state: i.systemError !== undefined ? "online" : "checking", cause: "a policy is active" };
  const shadows = p.shadow_policies.length ? ` · ${p.shadow_policies.length} shadow` : "";
  return { ...g, state: "online", cause: `${p.policy_version} active · deployment #${p.deployment_sequence ?? "?"}${shadows}` };
}

function trust(i: Inputs): HealthGroup {
  const g = { id: "trust" as const, title: "Trust", action: "Verifying trust chain" };
  if (i.systemError !== undefined && !i.system) return { ...g, state: "offline", cause: denied(i.systemError) };
  if (!i.system) return { ...g, state: "checking", cause: "authenticating the console's signed request" };
  const s = i.system.security;
  const off: string[] = [];
  if (!s.request_signatures_required) off.push("request signatures not required");
  else if (s.signature_min_version !== "v2") off.push(`signature minimum ${s.signature_min_version}`);
  if (!s.operator_auth_required) off.push("operator authentication off");
  if (!s.model_signatures_required) off.push("model signatures not enforced");
  if (off.length) return { ...g, state: "degraded", cause: `${off.join(" · ")} (${i.system.environment} profile)` };
  return { ...g, state: "online", cause: `signed ${s.signature_min_version} requests accepted · operator authentication on · keys: ${s.key_provider}` };
}

function audit(i: Inputs): HealthGroup {
  const g = { id: "audit" as const, title: "Audit", action: "Checking audit chain" };
  if (i.systemError !== undefined && !i.system) return { ...g, state: "offline", cause: denied(i.systemError) };
  if (!i.system) return { ...g, state: "checking", cause: "verifying the hash chain" };
  const { chain, anchor, anchor_max_age_minutes } = i.system.audit;
  if (chain.verified === false) return { ...g, state: "offline", cause: `hash chain broken: ${chain.reason ?? "verification failed"}` };
  if (chain.verified === null) return { ...g, state: "degraded", cause: chain.reason ?? "chain not verified by this view" };
  if (!anchor) return { ...g, state: "degraded", cause: `${chain.events} events verified · no external anchor yet` };
  if (anchor.age_minutes > anchor_max_age_minutes) {
    return { ...g, state: "degraded", cause: `${chain.events} events verified · last anchor ${Math.round(anchor.age_minutes)} min old (max ${anchor_max_age_minutes})` };
  }
  return { ...g, state: "online", cause: `${chain.events} events verified · anchor #${anchor.anchor_number}` };
}

function analyst(i: Inputs): HealthGroup {
  const g = { id: "analyst" as const, title: "Analyst layer", action: "Initializing analyst console" };
  if (i.sessionError !== undefined && !i.session) return { ...g, state: "offline", cause: "the console server is unreachable" };
  if (i.session && !i.session.backend_configured) return { ...g, state: "offline", cause: "the console has no API credential configured" };
  if (i.systemError !== undefined && !i.system) return { ...g, state: "offline", cause: denied(i.systemError) };
  if (!i.system || !i.session) return { ...g, state: "checking", cause: "opening the analyst session" };
  const llm = i.system.llm;
  if (!llm.available) return { ...g, state: "degraded", cause: "analyst assistance unavailable (case review and decisions unaffected)" };
  const assist = llm.reference_template ? "assistance: reference template (not a language model)" : `assistance: ${llm.runtime ?? "local model"}${llm.model ? ` ${llm.model}` : ""}`;
  const who = i.session.operator.mode === "demo_key" ? `demo reviewer ${i.session.operator.operator_id ?? ""}`.trim() : "per-analyst signed assertions";
  return { ...g, state: "online", cause: `analyst:read granted · ${who} · ${assist}` };
}

/** In start-up order: the service first, then what the analyst depends on. When the
 * service itself does not answer, every group that depends on it is OFFLINE with that cause:
 * nothing is shown as healthy from an answer that is no longer current. */
export function deriveGroups(i: Inputs): HealthGroup[] {
  const groups = [service(i), trust(i), data(i), models(i), policy(i), audit(i), analyst(i)];
  if (i.readyError === undefined || i.ready) return groups;
  const cause = denied(i.readyError);
  return groups.map((g) => (g.state === "offline" ? g : { ...g, state: "offline" as const, cause }));
}

export type Overall = "checking" | "operational" | "degraded" | "offline";

const CORE: GroupId[] = ["service", "data", "models", "policy", "analyst"];

export function overallOf(groups: HealthGroup[]): Overall {
  if (groups.some((g) => g.state === "checking")) return "checking";
  if (groups.some((g) => CORE.includes(g.id) && g.state === "offline")) return "offline";
  if (groups.some((g) => g.state === "offline" || g.state === "degraded")) return "degraded";
  return "operational";
}
