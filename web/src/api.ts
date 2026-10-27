// Types mirror src/cloudshield/api/schemas.py. Keep the two files in step.

export const API_URL: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingStatus = "OPEN" | "RESOLVED";
// "reported" means an external tool said so and CloudShield did not check it.
export type Certainty = "verified" | "heuristic" | "unknown" | "reported";
export type FindingSource = "cloudshield" | "prowler";
export type ScoreBasis = "severity only" | "context adjusted";
export type Disposition = "none" | "accepted" | "not_applicable";
export type ScanStatus = "queued" | "running" | "completed" | "failed";
export type ExtendedStatus = "ok" | "failed" | "unavailable" | "skipped";
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
  extended_status: ExtendedStatus;
  extended_message: string | null;
  extended_hint: string | null;
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

export interface Corroboration {
  source: string;
  check_id: string;
  status: "PASS" | "FAIL";
  last_imported_at: string;
}

export interface ScoreBreakdown {
  base: number;
  base_source: "scanner" | "cloudshield";
  adjustments: number;
  capped: boolean;
  basis: ScoreBasis;
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
  last_scan_id: number | null;
  source: FindingSource;
  last_imported_at: string | null;
  not_rechecked: boolean;
  score_basis: ScoreBasis;
  score_breakdown: ScoreBreakdown | null;
  merged_into: string | null;
  corroborated_by: Corroboration[];
  tools_disagree: boolean;
  disposition: Disposition;
  disposition_reason: string | null;
  disposition_until: string | null;
  disposition_at: string | null;
  dismissed: boolean;
  suggested_not_applicable: { reason: string } | null;
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

export interface StepOut {
  text: string;
  command: string | null;
}

// Steps written by CloudShield for an imported check, from the AWS documentation.
export interface CloudShieldSteps {
  check_id: string;
  summary: string;
  steps: StepOut[];
  before_you_apply: string[];
  docs_url: string;
  verified_on: string;
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
  patches: PatchOut[];
  guidance: string[];
  pre_checks: string[];
  // What CloudShield does not look at for this rule.
  not_checked: string[];
  cloudshield_steps: CloudShieldSteps | null;
  rollback: string;
  verify: string;
  explanation: ExplanationOut;
  generated_by: "gemini" | "template";
  model: string | null;
  generation_ms: number;
  created_at: string;
}

export interface DispositionBody {
  disposition: "accepted" | "not_applicable";
  disposition_reason: string;
  disposition_until: string | null;
}

export interface ImportOut {
  id: number;
  file_name: string | null;
  tool_name: string | null;
  tool_version: string | null;
  imported_at: string;
  pass_count: number | null;
  fail_count: number | null;
  findings_added: number;
  already_seen: number;
  resolved: number;
  rejected: number;
  ignored: number;
  regions_covered: string[];
  origin: "file" | "dashboard" | "upload";
  duration_seconds: number | null;
  services_used: string[] | null;
  regions_used: string[] | null;
  scan_id: number | null;
}

export interface ExtendedStatusOut {
  available: boolean;
  version: string | null;
  reason: string | null;
  hint: string | null;
  // True when an operating-system policy stops the second scanner from running here.
  blocked: boolean;
  // The commands to run it somewhere else. run_command is null when no region is set on the
  // server.
  install_command: string;
  run_command: string | null;
}

export interface ImportResultOut {
  import_id: number;
  counts: {
    imported: number;
    passed: number;
    ignored: number;
    already_seen: number;
    resolved: number;
    rejected: number;
  };
}

export const MAX_IMPORT_BYTES = 50 * 1024 * 1024;

export interface ImportedResourceOut {
  resource_id: string;
  resource_type: string;
  region: string | null;
  open_count: number;
  highest_risk: number | null;
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
  startScan: (extended = false) =>
    request<ScanOut>(
      "/api/scans",
      extended
        ? {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ extended: true }),
          }
        : { method: "POST" },
    ),
  extendedStatus: () => request<ExtendedStatusOut>("/api/extended/status"),
  // The file is sent as it is. The name travels in a header, encoded so any character is safe.
  uploadImport: (file: File) =>
    request<ImportResultOut>("/api/imports/prowler", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Filename": encodeURIComponent(file.name),
      },
      body: file,
    }),
  resources: () => request<ResourceOut[]>("/api/resources"),
  importedResources: () => request<ImportedResourceOut[]>("/api/resources/imported"),
  imports: () => request<ImportOut[]>("/api/imports"),
  findings: () => request<FindingOut[]>("/api/findings"),
  dismiss: (id: string, body: DispositionBody) =>
    request<FindingOut>(`/api/findings/${encodeURIComponent(id)}/disposition`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  undismiss: (id: string) =>
    request<FindingOut>(`/api/findings/${encodeURIComponent(id)}/disposition`, {
      method: "DELETE",
    }),
  finding: (id: string) =>
    request<FindingDetailOut>(`/api/findings/${encodeURIComponent(id)}`),
  riskSummary: () => request<RiskSummaryOut>("/api/risk/summary"),
  riskTrend: () => request<TrendPoint[]>("/api/risk/trend"),
  generateFix: (id: string, refresh = false) =>
    request<FixOut>(`/api/findings/${encodeURIComponent(id)}/fix?refresh=${refresh}`, {
      method: "POST",
    }),
};
