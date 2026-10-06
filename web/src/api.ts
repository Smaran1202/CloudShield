// Types mirror src/cloudshield/api/schemas.py. Keep the two files in step.

export const API_URL: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingStatus = "OPEN" | "RESOLVED";
export type Certainty = "verified" | "heuristic" | "unknown";
export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type BlastLevel = "low" | "medium" | "high" | "unknown";
export type PatchFormat = "terraform" | "cloudformation" | "cli";

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export interface ScanError {
  service: string;
  region: string | null;
  resource: string | null;
  message: string;
}

export interface ScanOut {
  id: number;
  account_id: string;
  status: ScanStatus;
  progress: string | null;
  started_at: string | null;
  finished_at: string | null;
  regions: string[];
  resource_count: number;
  finding_count: number;
  error_count: number;
  environment_score: number | null;
  severity_counts: Record<string, number>;
  errors: ScanError[];
  failure_message: string | null;
}

export interface ResourceOut {
  resource_id: string;
  resource_type: string;
  region: string | null;
  name: string;
  attributes: Record<string, unknown>;
  last_seen_scan_id: number;
}

export interface RiskFactor {
  factor: string;
  adjustment: number;
  reason: string;
  certainty: Certainty;
}

export interface EvidenceItem {
  fact: string;
  value: unknown;
  source: string;
  certainty: Certainty;
}

export interface Evidence {
  items: EvidenceItem[];
}

export interface FindingOut {
  finding_id: string;
  rule_id: string;
  resource_id: string;
  resource_type: string;
  title: string;
  severity: Severity;
  category: string;
  status: FindingStatus;
  details: Record<string, unknown>;
  evidence: Evidence;
  risk_score: number | null;
  risk_factors: RiskFactor[];
  first_seen_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  resolution_reason: string | null;
  last_scan_id: number;
}

export interface FindingDetailOut extends FindingOut {
  resource: ResourceOut | null;
}

export interface RiskSummaryOut {
  environment_score: number;
  counts_by_severity: Record<string, number>;
  top_findings: FindingOut[];
}

export interface TrendPoint {
  scan_id: number;
  finished_at: string;
  environment_score: number;
  severity_counts: Record<string, number>;
}

export interface PatchFile {
  name: string;
  content: string;
}

export interface PatchOut {
  format: PatchFormat;
  title: string;
  content: string;
  files: PatchFile[];
  needs_input: boolean;
  inputs_needed: string[];
  instructions_only: boolean;
}

export interface BlastRadiusOut {
  level: BlastLevel;
  factors: EvidenceItem[];
  notes: string[];
}

export interface ExplanationOut {
  why_it_matters: string;
  what_changes: string;
  what_could_break: string;
  cited: string[];
  skipped_reason: string | null;
}

export interface FixOut {
  finding_id: string;
  evidence_hash: string;
  blast_radius: BlastRadiusOut;
  patches: PatchOut[];
  guidance: string[];
  pre_checks: string[];
  rollback: string;
  verify: string;
  explanation: ExplanationOut;
  generated_by: "gemini" | "template";
  model: string | null;
  generation_ms: number;
  created_at: string;
}

export interface HealthOut {
  status: string;
  version: string;
}

export class ApiError extends Error {
  status: number | null;

  constructor(message: string, status: number | null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// FastAPI sends {"detail": "text"} for errors it raises, and a list of problems for 422.
export function messageFromDetail(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string" && detail) return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((item) => (item as { msg?: unknown })?.msg).filter(Boolean);
    if (parts.length > 0) return parts.join("; ");
  }
  return `The API answered with HTTP ${status}.`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, init);
  } catch {
    throw new ApiError(`Cannot reach the API at ${API_URL}. Is it running?`, null);
  }
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok)
    throw new ApiError(messageFromDetail(body, response.status), response.status);
  return body as T;
}

export const api = {
  health: () => request<HealthOut>("/api/health"),
  scans: () => request<ScanOut[]>("/api/scans"),
  scan: (id: number) => request<ScanOut>(`/api/scans/${id}`),
  startScan: () => request<ScanOut>("/api/scans", { method: "POST" }),
  resources: () => request<ResourceOut[]>("/api/resources"),
  findings: () => request<FindingOut[]>("/api/findings"),
  finding: (id: string) =>
    request<FindingDetailOut>(`/api/findings/${encodeURIComponent(id)}`),
  riskSummary: () => request<RiskSummaryOut>("/api/risk/summary"),
  riskTrend: () => request<TrendPoint[]>("/api/risk/trend"),
  generateFix: (id: string, refresh = false) =>
    request<FixOut>(`/api/findings/${encodeURIComponent(id)}/fix?refresh=${refresh}`, {
      method: "POST",
    }),
};
