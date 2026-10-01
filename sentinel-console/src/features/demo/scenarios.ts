/**
 * Development-only explanations of the Stage 12 demo cases. They describe what each case is
 * meant to demonstrate. They are NOT model output and are shown separately from it.
 */
export const DEMO_SCENARIOS: Record<string, { title: string; purpose: string }> = {
  normal_purchase: {
    title: "Normal purchase",
    purpose: "Baseline: a long-standing customer on a known device and home network.",
  },
  legitimate_vpn: {
    title: "Legitimate VPN",
    purpose: "Shows that a VPN is a signal, not proof: a genuine VPN user should not be blocked.",
  },
  house_mover: {
    title: "House mover",
    purpose: "Shows that a new address after a real move should not, on its own, equal fraud.",
  },
  large_legitimate: {
    title: "Large legitimate purchase",
    purpose: "Shows how the system treats an unusually large basket from a genuine customer.",
  },
  high_velocity_fraud: {
    title: "High velocity fraud",
    purpose: "Repeated purchases in a short window. The stored result is shown as it is, even if missed.",
  },
  account_takeover: {
    title: "Account takeover",
    purpose: "A stolen login from a new device and network, then a purchase.",
  },
  stealth_takeover: {
    title: "Stealth takeover",
    purpose: "An attacker changing little at a time: harder for the models to separate.",
  },
  manual_review: {
    title: "Manual review",
    purpose: "Uncertain risk routed to an analyst: the review workflow end to end.",
  },
  step_up_success: {
    title: "Step-up success",
    purpose: "Moderate risk where authentication is requested (success is evidence, not proof).",
  },
  step_up_failure: {
    title: "Step-up failure",
    purpose: "Moderate risk where the authentication attempt fails.",
  },
};
