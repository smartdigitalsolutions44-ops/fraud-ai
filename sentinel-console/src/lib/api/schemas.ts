import { z } from "zod";

/**
 * Runtime schemas for every fraud-ai response the console reads. A response that does not
 * match is rejected (ApiError code SCHEMA_MISMATCH) instead of being rendered on a guess.
 * Unknown extra fields are dropped; required fields must be present with the right type.
 */
const iso = z.string().min(10);
const uuid = z.string().uuid();
const nullableIso = iso.nullable();

export const Health = z.object({ status: z.literal("ok"), api_version: z.string() });
export const Ready = z.object({
  status: z.enum(["ready", "not_ready"]),
  api_version: z.string(),
  checks: z.record(z.string(), z.string()),
});

export const Session = z.object({
  console_version: z.string(),
  environment: z.string(),
  demo_mode: z.boolean(),
  backend_configured: z.boolean(),
  demo_reset_available: z.boolean(),
  operator: z.object({
    mode: z.enum(["demo_key", "assertion"]),
    operator_id: z.string().nullable(),
    note: z.string(),
  }),
  audience: z.string(),
  problems: z.array(z.string()),
});

export const Authentication = z.object({
  attempts: z.number().int(),
  latest_result: z.string().nullable(),
  method: z.string().nullable(),
  completed: z.boolean(),
  followup_assessment_id: z.string().nullable().optional(),
});

export const ReviewStatus = z.object({
  review_id: uuid,
  status: z.string(),
  priority: z.number().int(),
  outcome: z.string().nullable(),
});

export const FeedItem = z.object({
  assessment_id: uuid,
  event_id: uuid,
  event_type: z.string().nullable(),
  assessment_version: z.number().int(),
  mode: z.string(),
  assessed_at: iso,
  event_time: nullableIso,
  decision: z.string(),
  risk_level: z.string(),
  reason_codes: z.array(z.string()),
  policy_version: z.string(),
  model_version: z.string().nullable(),
  fallback_used: z.boolean(),
  latency_ms: z.number().nullable(),
  review: ReviewStatus.nullable(),
  authentication: Authentication,
});
export const Feed = z.object({ api_version: z.string(), generated_at: iso, items: z.array(FeedItem) });

export const QueueItem = z.object({
  review_id: uuid,
  assessment_id: uuid,
  event_id: uuid,
  priority: z.number().int(),
  status: z.string(),
  outcome: z.string().nullable(),
  reason_codes: z.array(z.string()),
  created_at: iso,
  reviewed_at: nullableIso,
  event_type: z.string().nullable(),
  decision: z.string(),
  risk_level: z.string(),
  policy_version: z.string(),
  model_version: z.string().nullable(),
  fallback_used: z.boolean(),
  authentication: Authentication,
});
export const Queue = z.object({ api_version: z.string(), generated_at: iso, items: z.array(QueueItem) });

export const AssessmentView = z.object({
  assessment_id: uuid,
  event_id: uuid,
  assessment_version: z.number().int(),
  supersedes_assessment_id: z.string().nullable(),
  latest_assessment_id: uuid,
  mode: z.string(),
  decision: z.string(),
  risk_level: z.string(),
  reason_codes: z.array(z.string()),
  action_type: z.string().nullable(),
  policy_version: z.string(),
  model_version: z.string().nullable(),
  fallback_used: z.boolean(),
  assessed_at: iso,
  step_up_required: z.boolean(),
  review_required: z.boolean(),
  review: ReviewStatus.nullable(),
  authentication: Authentication,
});

const Scalar = z.union([z.string(), z.number(), z.boolean(), z.null()]);

export const ModelEntry = z.object({
  role: z.string(),
  status: z.string(),
  model: z.string().nullable().optional(),
  raw_score: z.number().nullable().optional(),
  calibrated_score: z.number().nullable().optional(),
  threshold: z.number().nullable().optional(),
  flagged: z.boolean().nullable(),
  agrees_with_active: z.boolean().nullable().optional(),
});

export const Finding = z.object({ statement: z.string(), evidence_ids: z.array(z.string()) });
export const Explanation = z.object({
  summary: Finding,
  risk_factors: z.array(Finding).default([]),
  protective_factors: z.array(Finding).default([]),
  model_disagreement: z.array(Finding).default([]),
  temporal_findings: z.array(Finding).default([]),
  uncertainties: z.array(Finding).default([]),
  recommended_review_questions: z
    .array(z.object({ question: z.string(), evidence_ids: z.array(z.string()).default([]) }))
    .default([]),
});

export const TimelineItem = z.object({
  event_id: uuid,
  event_type: z.string(),
  occurred_at: iso,
  is_case_event: z.boolean(),
  after_decision: z.boolean(),
  source: z.string().nullable().optional(),
  new_device: z.boolean().optional(),
  login: z.object({ outcome: z.string(), auth_method: z.string().nullable(), mfa_used: z.boolean().nullable() }).optional(),
  transaction: z
    .object({
      amount_minor: z.number(),
      currency: z.string(),
      channel: z.string().nullable(),
      merchant_category: z.string().nullable(),
      status: z.string().nullable(),
    })
    .optional(),
  network: z
    .object({
      country: z.string().nullable(),
      network_type: z.string().nullable(),
      vpn: z.boolean().nullable(),
      proxy: z.boolean().nullable(),
      tor: z.boolean().nullable(),
      datacenter: z.boolean().nullable(),
      mobile: z.boolean().nullable(),
    })
    .optional(),
  security_event: z.string().optional(),
});

export const Case = z.object({
  api_version: z.string(),
  generated_at: iso,
  assessment: AssessmentView,
  versions: z.array(
    z.object({
      assessment_id: uuid,
      assessment_version: z.number().int(),
      mode: z.string(),
      decision: z.string(),
      reason_codes: z.array(z.string()),
      assessed_at: iso,
    }),
  ),
  review: z
    .object({
      review_id: uuid,
      status: z.string(),
      priority: z.number().int(),
      outcome: z.string().nullable(),
      assessment_id: uuid,
      reason_codes: z.array(z.string()),
      created_at: iso,
      reviewed_at: nullableIso,
      outcomes: z.array(
        z.object({ resolution: z.string(), note: z.string().nullable(), reviewer: z.string().nullable(), created_at: iso }),
      ),
    })
    .nullable(),
  reasons: z.array(z.object({ code: z.string(), description: z.string().nullable() })),
  rules: z.array(
    z.object({
      rule_id: z.string().nullable(),
      reason_code: z.string().nullable(),
      description: z.string().nullable(),
      severity: z.string().nullable(),
      matched: z.boolean().nullable(),
      evaluated: z.boolean().nullable(),
      evidence: z.record(z.string(), Scalar),
      missing: z.array(z.string()),
    }),
  ),
  models: z.object({
    entries: z.array(ModelEntry),
    flagged: z.number().int(),
    rated: z.number().int(),
    disagreement: z.boolean(),
    shadow_policies: z.array(
      z.object({
        policy_version: z.string().nullable(),
        decision: z.string().nullable(),
        risk_level: z.string().nullable(),
        agrees: z.boolean().nullable(),
      }),
    ),
    note: z.string(),
  }),
  indicators: z.array(
    z.object({
      name: z.string(),
      group: z.enum(["device", "network", "behaviour"]),
      label: z.string(),
      value: Scalar,
      missing: z.string().nullable().optional(),
      as_of: nullableIso,
      feature_version: z.string(),
    }),
  ),
  timeline: z.array(TimelineItem),
  step_up: z.object({
    attempts: z.array(
      z.object({
        attempt_number: z.number().int(),
        method: z.string(),
        result: z.string(),
        failure_reason: z.string().nullable(),
        created_at: iso,
        followup_assessment_id: z.string().nullable(),
      }),
    ),
    payment_requests: z.array(
      z.object({
        provider: z.string(),
        status: z.string(),
        attempt_number: z.number().int(),
        created_at: iso,
        completed_at: nullableIso,
      }),
    ),
  }),
  activity: z.array(
    z.object({
      at: nullableIso,
      kind: z.string(),
      source: z.string(),
      summary: z.string(),
      sequence: z.number().int().optional(),
    }),
  ),
  investigation: z
    .object({
      investigation_id: uuid,
      explanation_version: z.number().int(),
      created_at: iso,
      runtime: z.string(),
      model: z.string(),
      explanation: Explanation,
      evidence: z.array(
        z.object({ id: z.string(), section: z.string().optional(), name: z.string().optional(), value: Scalar.optional(), source: z.string().optional() }),
      ),
      limitations: z.array(z.object({ id: z.string(), code: z.string().optional(), text: z.string() })),
      note: z.string(),
    })
    .nullable(),
  latency_ms: z.record(z.string(), z.number()),
});

export const Summary = z.object({
  api_version: z.string(),
  generated_at: iso,
  window_hours: z.number().int().nullable(),
  assessments: z.object({
    total: z.number().int(),
    by_decision: z.record(z.string(), z.number().int()),
    fallbacks: z.number().int(),
    step_up_followups: z.number().int(),
  }),
  reviews: z.object({
    by_status: z.record(z.string(), z.number().int()),
    open_by_priority: z.record(z.string(), z.number().int()),
    oldest_open_at: nullableIso,
  }),
  step_up: z.object({ requested: z.number().int(), attempts_by_result: z.record(z.string(), z.number().int()) }),
  latency_ms: z.object({
    p50: z.number().nullable(),
    p95: z.number().nullable(),
    p99: z.number().nullable(),
    samples: z.number().int(),
    scope: z.string(),
  }),
  shadow: z.object({ agree: z.number().int(), disagree: z.number().int() }),
  series: z.array(z.object({ hour: iso, by_decision: z.record(z.string(), z.number().int()) })),
});

export const SystemModel = z.object({
  ref: z.string(),
  role: z.string(),
  registered: z.boolean(),
  model_name: z.string().optional(),
  model_version: z.string().optional(),
  algorithm: z.string().nullable().optional(),
  feature_version: z.string().optional(),
  trained_at: nullableIso.optional(),
  artifact_sha256: z.string().nullable().optional(),
  signature: z
    .object({
      present: z.boolean(),
      key_id: z.string().nullable(),
      signed_at: nullableIso,
      matches_artifact: z.boolean(),
    })
    .optional(),
  loaded: z.boolean().optional(),
  verified_at_readiness: z.boolean().optional(),
});

export const System = z.object({
  api_version: z.string(),
  generated_at: iso,
  environment: z.string(),
  checks_ms: z.number(),
  policy: z
    .object({
      policy_version: z.string(),
      rules_version: z.string(),
      primary_model: z.string(),
      deployment_sequence: z.number().int().nullable(),
      activated_at: nullableIso,
      activated_by: z.string().nullable(),
      shadow_models: z.array(z.string()),
      shadow_policies: z.array(z.string()),
      bands: z.array(z.object({ lower: z.number(), risk_level: z.string(), decision: z.string() })),
      approvals_required: z.number().int(),
      promotion_required: z.boolean(),
    })
    .nullable(),
  models: z.array(SystemModel),
  migrations: z.object({ current: z.string().nullable(), head: z.string().nullable(), up_to_date: z.boolean() }),
  security: z.object({
    request_signatures_required: z.boolean(),
    signature_min_version: z.string(),
    model_signatures_required: z.boolean(),
    operator_auth_required: z.boolean(),
    state_backend: z.string(),
    key_provider: z.string(),
  }),
  audit: z.object({
    chain: z.object({ verified: z.boolean().nullable(), events: z.number().int(), reason: z.string().nullable() }),
    anchor: z
      .object({
        anchor_number: z.number().int(),
        sequence: z.number().int(),
        anchored_at: iso,
        age_minutes: z.number(),
        events_since: z.number().int(),
        key_id: z.string(),
        store: z.string().nullable(),
      })
      .nullable(),
    anchor_max_age_minutes: z.number(),
  }),
  llm: z.object({
    runtime: z.string().nullable(),
    model: z.string().nullable(),
    available: z.boolean(),
    reference_template: z.boolean(),
    note: z.string(),
  }),
  reason_catalogue: z.record(z.string(), z.string()),
});

export const Search = z.object({
  query: z.string(),
  matches: z.array(
    z.object({
      kind: z.enum(["review", "assessment", "event"]),
      id: z.string(),
      assessment_id: z.string(),
      decision: z.string().optional(),
      assessed_at: iso.optional(),
    }),
  ),
});

export const Investigation = z.object({
  assessment_id: uuid,
  investigation_id: uuid,
  explanation_version: z.number().int(),
  runtime: z.string(),
  model: z.string(),
  explanation: z.string(),
  note: z.string().optional(),
});

export const ReviewDetail = z.object({
  review: z.object({ review_id: uuid, status: z.string(), outcome: z.string().nullable() }),
  outcomes: z.array(z.object({ resolution: z.string(), reviewer: z.string().nullable().optional(), created_at: iso })),
});

export const DemoScenarios = z.object({
  synthetic: z.literal(true),
  seed: z.number(),
  users: z.number(),
  missing: z.array(z.string()),
  note: z.string(),
  scenarios: z.array(
    z.object({
      label: z.string(),
      title: z.string(),
      purpose: z.string().nullable(),
      story: z.string(),
      scenario: z.string(),
      expected_decision: z.string(),
      expected_reasons: z.array(z.string()),
      relaxed_match: z.boolean(),
      prelude_events: z.number().int(),
      event_type: z.string().nullable(),
      assessment_id: z.string().nullable(),
    }),
  ),
});

export const DemoPlay = z.object({
  label: z.string(),
  assessment_id: uuid,
  decision: z.string().nullable(),
  status: z.string(),
  expected_decision: z.string(),
});

export const DemoStatus = z.object({
  state: z.enum(["idle", "stopping", "resetting", "starting", "ready", "failed"]),
  started_at: nullableIso.optional(),
  finished_at: nullableIso.optional(),
  message: z.string().nullable().optional(),
  log: z.array(z.string()).default([]),
});

export type HealthT = z.infer<typeof Health>;
export type ReadyT = z.infer<typeof Ready>;
export type SessionT = z.infer<typeof Session>;
export type FeedItemT = z.infer<typeof FeedItem>;
export type QueueItemT = z.infer<typeof QueueItem>;
export type CaseT = z.infer<typeof Case>;
export type SummaryT = z.infer<typeof Summary>;
export type SystemT = z.infer<typeof System>;
export type SearchT = z.infer<typeof Search>;
export type TimelineItemT = z.infer<typeof TimelineItem>;
export type ModelEntryT = z.infer<typeof ModelEntry>;
export type ExplanationT = z.infer<typeof Explanation>;
export type DemoScenariosT = z.infer<typeof DemoScenarios>;
export type DemoStatusT = z.infer<typeof DemoStatus>;
