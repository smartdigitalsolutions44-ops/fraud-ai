import type { CheckState } from "@/lib/domain";
import { ApiError } from "@/lib/api/client";
import type { ReadyT, SessionT, SystemT } from "@/lib/api/schemas";

export interface StartupCheck {
  id: string;
  label: string;
  state: CheckState;
  detail: string;
}

interface Inputs {
  session?: SessionT;
  sessionError?: unknown;
  ready?: ReadyT;
  readyError?: unknown;
  system?: SystemT;
  systemError?: unknown;
}

/**
 * The start-up checks, derived only from what the service reports (/v1/ready and
 * /v1/analyst/system). A check with no answer yet is CHECKING; a check whose source failed
 * is OFFLINE. Nothing is ever assumed to be fine.
 */
export function deriveChecks(i: Inputs): StartupCheck[] {
  const readyCheck = (name: string) => i.ready?.checks[name];
  const readyDown = i.readyError !== undefined && !i.ready;
  const fromReady = (id: string, label: string, name: string, okDetail: string): StartupCheck => {
    if (readyDown) return { id, label, state: "offline", detail: "readiness endpoint unreachable" };
    const v = readyCheck(name);
    if (v === undefined) return { id, label, state: "checking", detail: "waiting for /v1/ready" };
    if (v === "ok") return { id, label, state: "online", detail: okDetail };
    if (v === "not_required") return { id, label, state: "not_used", detail: "not required in this profile" };
    if (v === "outdated") return { id, label, state: "degraded", detail: "schema migrations are not at head" };
    return { id, label, state: "offline", detail: `readiness: ${v}` };
  };

  const db = fromReady("database", "Database link", "database", "connected");
  if (db.state === "online" && readyCheck("migrations") && readyCheck("migrations") !== "ok") {
    db.state = "degraded";
    db.detail = `migrations: ${readyCheck("migrations")}`;
  }

  const shared = fromReady("shared_state", "Redis shared state", "shared_state", "reachable");
  if (shared.state === "not_used") shared.detail = "in-memory state (single process); Redis not configured";
  if (i.system && shared.state === "online") shared.detail = `backend: ${i.system.security.state_backend}`;

  const policy = fromReady("policy", "Risk policy", "active_policy", "active");
  if (policy.state === "online" && i.system?.policy) policy.detail = `${i.system.policy.policy_version} active`;

  const model = fromReady("model", "Primary model", "primary_model", "loaded and verified");
  if (model.state === "online" && i.system?.policy) model.detail = `${i.system.policy.primary_model} loaded`;

  const signatures = modelSignatures(i);
  const audit = auditChain(i);
  const analyst = analystService(i);
  return [db, shared, policy, model, signatures, audit, analyst];
}

function unreachable(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.kind === "forbidden") return "permission denied (analyst:read scope missing)";
    if (err.kind === "unauthorised") return "console credential rejected";
    if (err.code === "BACKEND_NOT_CONFIGURED") return "console has no API credential configured";
    return `${err.code.toLowerCase()}`;
  }
  return "unreachable";
}

function modelSignatures(i: Inputs): StartupCheck {
  const base = { id: "signatures", label: "Model signatures" };
  if (i.systemError !== undefined && !i.system) return { ...base, state: "offline", detail: unreachable(i.systemError) };
  if (!i.system) return { ...base, state: "checking", detail: "reading model registry" };
  const primary = i.system.models.find((m) => m.role === "primary");
  if (!primary || !primary.registered) return { ...base, state: "offline", detail: "primary model not registered" };
  const sig = primary.signature;
  if (sig?.present && sig.matches_artifact) {
    const required = i.system.security.model_signatures_required;
    return {
      ...base,
      state: required ? "online" : "degraded",
      detail: required ? `verified · key ${sig.key_id ?? "?"}` : "signed, but signatures are not required in this profile",
    };
  }
  if (sig?.present && !sig.matches_artifact) return { ...base, state: "offline", detail: "signature does not match the artefact" };
  return {
    ...base,
    state: i.system.security.model_signatures_required ? "offline" : "degraded",
    detail: "primary model is unsigned",
  };
}

function auditChain(i: Inputs): StartupCheck {
  const base = { id: "audit", label: "Audit chain" };
  if (i.systemError !== undefined && !i.system) return { ...base, state: "offline", detail: unreachable(i.systemError) };
  if (!i.system) return { ...base, state: "checking", detail: "verifying hash chain" };
  const { chain, anchor, anchor_max_age_minutes } = i.system.audit;
  if (chain.verified === false) return { ...base, state: "offline", detail: `chain broken: ${chain.reason ?? "verification failed"}` };
  if (chain.verified === null) return { ...base, state: "degraded", detail: chain.reason ?? "not verified by the console view" };
  if (!anchor) return { ...base, state: "degraded", detail: `${chain.events} events verified · no external anchor yet` };
  if (anchor.age_minutes > anchor_max_age_minutes) {
    return { ...base, state: "degraded", detail: `${chain.events} events verified · anchor ${Math.round(anchor.age_minutes)} min old` };
  }
  return { ...base, state: "online", detail: `${chain.events} events verified · anchor #${anchor.anchor_number}` };
}

function analystService(i: Inputs): StartupCheck {
  const base = { id: "analyst", label: "Analyst service" };
  if (i.sessionError !== undefined && !i.session) return { ...base, state: "offline", detail: "console server unreachable" };
  if (i.session && !i.session.backend_configured) return { ...base, state: "offline", detail: "console has no API credential configured" };
  if (i.systemError !== undefined && !i.system) return { ...base, state: "offline", detail: unreachable(i.systemError) };
  if (!i.system || !i.session) return { ...base, state: "checking", detail: "authenticating console" };
  return { ...base, state: "online", detail: `${i.system.api_version} · signed ${i.system.security.signature_min_version} requests` };
}

export type Overall = "checking" | "operational" | "degraded" | "offline";

export function overall(checks: StartupCheck[]): Overall {
  if (checks.some((c) => c.state === "checking")) return "checking";
  const core = checks.filter((c) => ["database", "policy", "model", "analyst"].includes(c.id));
  if (core.some((c) => c.state === "offline")) return "offline";
  if (checks.some((c) => c.state === "offline" || c.state === "degraded")) return "degraded";
  return "operational";
}
