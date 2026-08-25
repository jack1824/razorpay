export type DecisionKind = "allow" | "bound" | "throttle" | "step_up" | "deny";

export interface DecisionSummary {
  seq: number;
  record_id: string;
  created_at: string;
  agent_id: string;
  decision: DecisionKind;
  reason_code: string;
  rule_fired: string | null;
  amount_paise: number | null;
  amount_display: string | null;
  latency_us: number;
  risk_score: number | null;
  /** Explicit, so the detail panel can render the literal word NULL rather than a blank
   *  cell. On a per-transaction breach that NULL is the headline artifact: it is the
   *  audit-trail proof the model was never consulted. */
  risk_score_is_null: boolean;
  degraded_mode: string[];
}

export interface DecisionDetail extends DecisionSummary {
  merchant_id: string;
  principal_id: string;
  model_version: string | null;
  injection_flag: boolean;
  budget_before: number | null;
  budget_after: number | null;
  features: Record<string, unknown>;
  policy_version: number | null;
  stages_executed: string[];
  prev_hash: string;
  payload_hash: string;
  signing_key_id: string;
  canonical_json: string;
}

export interface Agent {
  agent_id: string;
  display_name: string;
  status: string;
  mandate_id: string;
  max_total_paise: number;
  max_per_txn_paise: number;
  remaining_paise: number;
  spent_paise: number;
  remaining_display: string;
  total_display: string;
  per_txn_display: string;
  spent_fraction: number;
  decisions: number;
  denials: number;
}

export type Severity = "nominal" | "degraded" | "critical";

export interface Integration {
  mode: string;
  simulated: boolean;
}

export interface Verification {
  ok: boolean;
  merchant_id: string;
  checked: Record<string, number>;
  records: number;
  failures: string[];
  /** The seq the verifier named, when it found a break. Demo beat 6 puts this on screen. */
  broken_at_seq: number | null;
  /** Reported, never treated as a break — a Postgres outage produces denials that cannot
   *  be chained, and absence must not read as a tamper. */
  gaps: number[];
  /** Records written before an invariant was enforced, counted by violation code. Shown
   *  rather than hidden: a violation above the migration watermark is a failure. */
  legacy: Record<string, number>;
  /** Age of this result. A cached PASS read as a live one is the failure the SIMULATED
   *  badge exists to prevent, one screen over. */
  verified_ago_s: number;
  command: string;
}

export interface McpCall {
  seq: number;
  record_id: string;
  created_at: string;
  agent_id: string;
  tool: string;
  /** null means the tool is UNLISTED, which is denied — not unknown-and-allowed. */
  required_scope: string | null;
  money_direction: string | null;
  delegated: string[];
  /** NULL scopes and [] behave identically at the gate and differ in the record. */
  delegated_is_null: boolean;
  decision: DecisionKind;
  reason_code: string;
  rule_fired: string | null;
  amount_paise: number | null;
  amount_display: string | null;
  risk_score_is_null: boolean;
}

export interface Explanation {
  explanation: string | null;
  /** null means no model was called — a cache hit or the deterministic fallback. Kept
   *  distinct so the console never implies a sentence came from a model when it did not. */
  model?: string | null;
  cached?: boolean;
  generated_at?: string;
  reason?: string;
}

export interface Health {
  status: Severity;
  version: string;
  /**
   * Reported separately from `components` because integrations are not in the fail matrix.
   * `simulated` drives the SIMULATED badge, and it comes from the SERVER rather than from
   * a build-time constant — a badge a developer has to remember to set is a badge that is
   * wrong exactly when it matters.
   */
  integrations?: Record<string, Integration>;
  components: Record<
    string,
    {
      status: "up" | "down";
      severity: Severity;
      fail_mode: string;
      reason: string | null;
      rationale: string;
      checked_at: string;
      /** The risk model and the injection detector report theirs. */
      model_version?: string;
      /** The explainer only: decisions that went on being made while it was dead. */
      backlog?: number;
    }
  >;
}
