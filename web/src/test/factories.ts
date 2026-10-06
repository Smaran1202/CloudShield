import type {
  FindingDetailOut,
  FindingOut,
  FixOut,
  ResourceOut,
  RiskSummaryOut,
  ScanOut,
  TrendPoint,
} from "../api";

// Test data only. It is never shown outside the tests.

export function scan(overrides: Partial<ScanOut> = {}): ScanOut {
  return {
    id: 1,
    account_id: "local",
    status: "completed",
    progress: "Done",
    started_at: "2026-10-01T10:00:00Z",
    finished_at: "2026-10-01T10:00:42Z",
    regions: ["ap-southeast-2"],
    resource_count: 7,
    finding_count: 3,
    error_count: 0,
    environment_score: 97.5,
    severity_counts: { CRITICAL: 0, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 1 },
    errors: [],
    failure_message: null,
    ...overrides,
  };
}

export function finding(overrides: Partial<FindingOut> = {}): FindingOut {
  return {
    finding_id: "F-CIS-SG-001-aaaaaaaa",
    rule_id: "CIS-SG-001",
    resource_id: "sg-0abc123",
    resource_type: "Security Group",
    title: "Security group allows SSH or all traffic from the internet",
    severity: "HIGH",
    category: "Network",
    status: "OPEN",
    details: {},
    evidence: {
      items: [
        {
          fact: "Inbound rule exposes SSH (port 22)",
          value: { protocol: "tcp", from_port: 22, to_port: 22, cidrs: ["0.0.0.0/0"] },
          source: "attributes.inbound",
          certainty: "verified",
        },
        {
          fact: "Who connects to these ports",
          value: null,
          source: "flow logs are not collected",
          certainty: "unknown",
        },
        {
          fact: "Creating a new policy version",
          value: { permissions: ["iam:CreatePolicyVersion"] },
          source: "attributes.document",
          certainty: "heuristic",
        },
      ],
    },
    risk_score: 95,
    risk_factors: [
      {
        factor: "exposure",
        adjustment: 15,
        reason: "An inbound rule allows 0.0.0.0/0 or ::/0.",
        certainty: "verified",
      },
      {
        factor: "attached",
        adjustment: 0,
        reason: "EC2 data for this region is unknown.",
        certainty: "unknown",
      },
    ],
    first_seen_at: "2026-10-01T10:00:00Z",
    last_seen_at: "2026-10-01T10:00:42Z",
    resolved_at: null,
    resolution_reason: null,
    last_scan_id: 1,
    ...overrides,
  };
}

export function findingDetail(
  overrides: Partial<FindingDetailOut> = {},
): FindingDetailOut {
  return {
    ...finding(),
    resource: {
      resource_id: "sg-0abc123",
      resource_type: "Security Group",
      region: "ap-southeast-2",
      name: "web",
      attributes: { vpc_id: "vpc-1" },
      last_seen_scan_id: 1,
    },
    ...overrides,
  };
}

export function resource(overrides: Partial<ResourceOut> = {}): ResourceOut {
  return {
    resource_id: "my-bucket",
    resource_type: "S3",
    region: "us-east-1",
    name: "my-bucket",
    attributes: { versioning: "Disabled", policy: null },
    last_seen_scan_id: 1,
    ...overrides,
  };
}

export function summary(overrides: Partial<RiskSummaryOut> = {}): RiskSummaryOut {
  return {
    environment_score: 99.8,
    counts_by_severity: { CRITICAL: 0, HIGH: 2, MEDIUM: 1, LOW: 0, INFO: 4 },
    top_findings: [
      finding(),
      finding({
        finding_id: "F-CIS-S3-001-bbbbbbbb",
        rule_id: "CIS-S3-001",
        resource_id: "my-bucket",
        resource_type: "S3",
        title: "S3 bucket does not block all public access",
        risk_score: 85,
      }),
    ],
    ...overrides,
  };
}

export function trend(): TrendPoint[] {
  return [
    {
      scan_id: 1,
      finished_at: "2026-10-01T10:00:42Z",
      environment_score: 60,
      severity_counts: { HIGH: 1 },
    },
    {
      scan_id: 2,
      finished_at: "2026-10-02T10:00:42Z",
      environment_score: 99.8,
      severity_counts: { HIGH: 2 },
    },
  ];
}

export function fix(overrides: Partial<FixOut> = {}): FixOut {
  return {
    finding_id: "F-CIS-SG-001-aaaaaaaa",
    evidence_hash: "abc",
    blast_radius: {
      level: "medium",
      factors: [
        {
          fact: "Running instances using this group",
          value: ["i-1"],
          source: "resources of type EC2",
          certainty: "verified",
        },
        {
          fact: "Who connects to these ports",
          value: null,
          source: "flow logs are not collected",
          certainty: "unknown",
        },
      ],
      notes: ["Use SSM Session Manager instead of SSH."],
    },
    patches: [
      {
        format: "terraform",
        title: "Remove the open ingress rules (Terraform)",
        content:
          "Remove these ingress rules from the Terraform that defines sg-0abc123.\n",
        files: [],
        needs_input: false,
        inputs_needed: [],
        instructions_only: true,
      },
      {
        format: "cli",
        title: "Remove the open ingress rules (AWS CLI)",
        content:
          "aws ec2 revoke-security-group-ingress --group-id sg-0abc123 --ip-permissions file://sg-0abc123-rule1.json --region ap-southeast-2\n",
        files: [{ name: "sg-0abc123-rule1.json", content: '[{"IpProtocol": "tcp"}]\n' }],
        needs_input: false,
        inputs_needed: [],
        instructions_only: false,
      },
    ],
    guidance: [],
    pre_checks: ["Find out who connects to the instances today."],
    rollback:
      "To add the rules back, using the same JSON files: aws ec2 authorize-security-group-ingress",
    verify: "Rescan (POST /api/scans). This finding should resolve.",
    explanation: {
      why_it_matters: "Anyone on the internet can try to reach this port.",
      what_changes: "The open rule is removed from the group.",
      what_could_break: "People who connect through the rule lose access.",
      cited: ["e1", "e2"],
      skipped_reason: null,
    },
    generated_by: "gemini",
    model: "model-a",
    generation_ms: 900,
    created_at: "2026-10-02T10:00:00Z",
    ...overrides,
  };
}
