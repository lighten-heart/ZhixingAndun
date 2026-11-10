export type Decision = "allow" | "confirm" | "block";
export type Health = {
  status: string;
  version: string;
  mode: string;
  model_configured: boolean;
  model_status?: string;
  model_configuration_valid?: boolean;
  timestamp?: string;
  hermes_status: string;
  harness_status?: string;
  sandbox_available: boolean;
  auth_required: boolean;
};
export type Session = {
  authorization_version?: number;
  original_intent?: string;
  id: string;
  title: string;
  intent: string;
  scope: string;
  agent_id: string;
  created_at: string;
  status: string;
  call_count: number;
  blocked_count: number;
};
export type Finding = {
  rule_id: string;
  category: string;
  quote: string;
  start: number;
  end: number;
  reason: string;
  mapping?: string;
  linked_spans?: {
    source_id: string;
    start: number;
    end: number;
    quote?: string;
  }[];
};
export type Detection = {
  status: string;
  risk_score: number;
  findings: Finding[];
  information_gaps: string[];
  coverage: {
    checked_chars: number;
    total_chars: number;
    model_checked_chars?: number;
    global_review?: { complete: boolean; information_gaps: string[] } | null;
    session_correlation?: {
      complete: boolean;
      information_gaps: string[];
    } | null;
  };
  mode: string;
};
export type Source = {
  id: string;
  session_id: string;
  type: string;
  resource: string;
  content: string;
  normalized: string;
  version: number;
  created_at: string;
  parent_source_id?: string;
  decision: Decision;
  detection: Detection;
  sensitive: boolean;
};
export type GuardCall = {
  id: string;
  session_id: string;
  tool: string;
  args: Record<string, unknown>;
  source_ids: string[];
  plan: string;
  agent_id: string;
  parent_call_id: string | null;
  mcp_server: string;
  execution_owner?: "fixture" | "adapter";
  created_at: string;
  decision: Decision;
  risk_score: number;
  severity: string;
  reasons: string[];
  matched_rules: string[];
  information_gaps: string[];
  execution_status: string;
  latency_ms: number;
  report: {
    review_object_id: string;
    task_id: string;
    task_relation: string;
    deviation_level: string;
    reason: string;
    resources: unknown;
    evidence_refs: unknown;
    information_gaps: string[];
    alignment_coverage?: {
      complete: boolean;
      history_checked: number;
      history_total: number;
      global_review?: { complete: boolean; information_gaps: string[] };
    };
  };
  control_receipt?: { status: string; boundary: string; evidence_type: string };
  receipt?: {
    status: string;
    detail: string;
    result: unknown;
    executed_at: string;
    evidence_type?: string;
  };
  permit?: string;
  permit_expires_at?: string;
  recheck_of_call_id?: string;
  superseded_by?: string;
  policy_version: number;
  parameter_hash: string;
  approval?: {
    approved: boolean;
    comment: string;
    actor: string;
    at: string;
    policy_version: number;
  };
  resource_facts?: Record<string, unknown>;
  data_references?: unknown;
  purpose?: string;
};
export type GuardEvent = {
  id: string;
  type: string;
  session_id: string;
  call_id?: string;
  source_id?: string;
  timestamp: string;
  sequence: number;
  summary: string;
  details: unknown;
};
export type Graph = {
  nodes: {
    id: string;
    label: string;
    type: string;
    status?: string;
    detail?: string;
  }[];
  edges: { source: string; target: string; label: string; type?: string }[];
};
export type SessionDetail = Session & {
  sources: Source[];
  calls: GuardCall[];
  events: GuardEvent[];
  graph: Graph;
};
export type Dashboard = {
  stats: {
    sessions: number;
    calls: number;
    blocked: number;
    pending: number;
    allowed: number;
    avg_latency_ms: number;
  };
  trend: { date: string; allow: number; confirm: number; block: number }[];
  source_distribution: { name: string; value: number }[];
  recent_alerts: GuardCall[];
  components: { name: string; status: string; detail: string }[];
};
export type PolicyRule = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  condition: {
    tools?: string[];
    scope?: string;
    risk_min?: number;
    [key: string]: unknown;
  };
  action: Decision;
  mandatory: boolean;
};
export type Policies = { version: number; rules: PolicyRule[] };
export type Memory = {
  id: string;
  label: string;
  content: string;
  version: number;
  status: "active" | "quarantined";
  source_session_id: string;
  source_id?: string;
  created_at: string;
  detection: Detection;
};
export type Scenario = {
  id: string;
  name: string;
  category: string;
  description: string;
  expected_decision: Decision;
  steps: string[];
};
export type DemoResult = {
  session_id: string;
  scenario_id: string;
  passed: boolean;
  assertions: { name: string; passed: boolean; detail: string }[];
  duration_ms: number;
};
export type Evaluation = {
  id: string;
  created_at: string;
  total: number;
  passed: number;
  failed: number;
  duration_ms: number;
  results: DemoResult[];
  mode: string;
};
