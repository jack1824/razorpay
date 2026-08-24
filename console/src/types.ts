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

export interface Health {
  status: Severity;
  version: string;
  components: Record<
    string,
    {
      status: "up" | "down";
      severity: Severity;
      fail_mode: string;
      reason: string | null;
      rationale: string;
      checked_at: string;
    }
  >;
}
