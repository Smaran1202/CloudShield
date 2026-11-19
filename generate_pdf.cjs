const fs = require('fs');
const path = require('path');
const { chromium } = require('./web/node_modules/@playwright/test');

const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CloudShield: Technical Stack & Subsystems Specification</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

  @page {
    size: A4;
    margin: 18mm 14mm 20mm 14mm;
    @bottom-right {
      content: counter(page);
    }
  }

  *, *::before, *::after {
    box-sizing: border-box;
  }

  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    background-color: #ffffff;
    line-height: 1.55;
    font-size: 9.8pt;
    margin: 0;
    padding: 0;
  }

  /* Cover Banner */
  .cover-banner {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #1e3a8a 100%);
    color: #ffffff;
    padding: 24px 28px;
    border-radius: 10px;
    margin-bottom: 24px;
    box-shadow: 0 4px 14px rgba(15, 23, 42, 0.12);
  }

  .cover-banner h1 {
    font-size: 22pt;
    font-weight: 800;
    margin: 0 0 6px 0;
    letter-spacing: -0.03em;
    color: #f8fafc;
  }

  .cover-banner .subtitle {
    font-size: 11pt;
    font-weight: 500;
    color: #93c5fd;
    margin-bottom: 14px;
    line-height: 1.4;
  }

  .meta-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 10px;
    padding-top: 12px;
    border-top: 1px solid rgba(255, 255, 255, 0.15);
    font-size: 8.5pt;
  }

  .meta-item strong {
    display: block;
    color: #cbd5e1;
    font-size: 7.5pt;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .meta-item span {
    color: #ffffff;
    font-weight: 600;
  }

  /* Headings */
  h2 {
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 5px;
    margin-top: 22px;
    margin-bottom: 12px;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  h2::before {
    content: '';
    display: inline-block;
    width: 4px;
    height: 16pt;
    background: #2563eb;
    border-radius: 2px;
  }

  h3 {
    font-size: 11pt;
    font-weight: 700;
    color: #1e3a8a;
    margin-top: 14px;
    margin-bottom: 6px;
    letter-spacing: -0.01em;
  }

  h4 {
    font-size: 9.8pt;
    font-weight: 600;
    color: #334155;
    margin-top: 10px;
    margin-bottom: 4px;
  }

  p {
    margin-top: 0;
    margin-bottom: 8px;
    text-align: justify;
  }

  /* Philosophy Pill Badges */
  .pill-container {
    display: flex;
    gap: 8px;
    margin: 12px 0;
  }

  .pill {
    flex: 1;
    background: #f1f5f9;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 8.5pt;
  }

  .pill strong {
    display: block;
    color: #0f172a;
    font-size: 9.5pt;
    margin-bottom: 3px;
  }

  /* Tables */
  table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    margin: 10px 0 16px 0;
    font-size: 8.8pt;
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid #e2e8f0;
  }

  th {
    background-color: #0f172a;
    color: #f8fafc;
    font-weight: 600;
    text-align: left;
    padding: 8px 10px;
    font-size: 8.5pt;
    letter-spacing: 0.02em;
  }

  td {
    padding: 7px 10px;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: top;
  }

  tr:nth-child(even) td {
    background-color: #f8fafc;
  }

  tr:last-child td {
    border-bottom: none;
  }

  /* Code Chips & Blocks */
  code {
    font-family: 'JetBrains Mono', Consolas, monospace;
    font-size: 8pt;
    background: #f1f5f9;
    color: #0f172a;
    padding: 1.5px 4.5px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
  }

  pre {
    font-family: 'JetBrains Mono', Consolas, monospace;
    background: #0f172a;
    color: #e2e8f0;
    padding: 10px 12px;
    border-radius: 6px;
    font-size: 7.8pt;
    line-height: 1.45;
    overflow-x: auto;
    margin: 8px 0;
  }

  /* Callout Cards */
  .callout {
    border-radius: 8px;
    padding: 10px 14px;
    margin: 10px 0;
    border-left: 4px solid;
    font-size: 9pt;
  }

  .callout-info {
    background: #eff6ff;
    border-left-color: #2563eb;
    color: #1e3a8a;
  }

  .callout-success {
    background: #ecfdf5;
    border-left-color: #059669;
    color: #065f46;
  }

  .callout-warning {
    background: #fffbeb;
    border-left-color: #d97706;
    color: #92400e;
  }

  .callout-danger {
    background: #fff1f2;
    border-left-color: #e11d48;
    color: #9f1239;
  }

  .callout strong {
    display: block;
    margin-bottom: 3px;
    font-size: 9.5pt;
  }

  /* Rule Grid */
  .rule-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 10px 12px;
    margin-bottom: 8px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    page-break-inside: avoid;
  }

  .rule-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
  }

  .rule-id {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    color: #1e3a8a;
    font-size: 9pt;
  }

  .badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 9999px;
    font-size: 7pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .badge-critical { background: #fee2e2; color: #991b1b; }
  .badge-high { background: #ffedd5; color: #9a3412; }
  .badge-medium { background: #fef3c7; color: #92400e; }
  .badge-info { background: #e0f2fe; color: #075985; }

  /* Math Box */
  .formula-box {
    background: #f8fafc;
    border: 1px dashed #94a3b8;
    border-radius: 6px;
    padding: 8px 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 8.5pt;
    color: #0f172a;
    margin: 8px 0;
    text-align: center;
  }

  /* Section Break */
  .page-break {
    page-break-before: always;
  }

  ul, ol {
    margin-top: 4px;
    margin-bottom: 8px;
    padding-left: 20px;
  }

  li {
    margin-bottom: 3px;
  }
</style>
</head>
<body>

  <!-- Cover Header Banner -->
  <div class="cover-banner">
    <h1>CloudShield</h1>
    <div class="subtitle">Complete Technical Stack & Subsystems Specification</div>
    <div class="meta-grid">
      <div class="meta-item">
        <strong>Domain & Architecture</strong>
        <span>AWS Cloud Security (CSPM) & IaC Remediation</span>
      </div>
      <div class="meta-item">
        <strong>Implementation Version</strong>
        <span>Release 0.9.0 (Full-Stack Monorepo)</span>
      </div>
      <div class="meta-item">
        <strong>Preparation Focus</strong>
        <span>Campus Placement & Technical Interview Guide</span>
      </div>
    </div>
  </div>

  <!-- Executive Summary -->
  <h2>1. Project Overview & Architectural Mission</h2>
  <p>
    <strong>CloudShield</strong> is an evidence-first, fix-first AWS Cloud Security Posture Management (CSPM) platform built entirely from scratch. Unlike legacy scanners that inundate engineers with abstract risk ratings or attempt dangerous black-box automated cloud changes, CloudShield establishes a transparent, safe, and verifiable human-in-the-loop workflow.
  </p>

  <div class="pill-container">
    <div class="pill">
      <strong>1. Read-Only Safety</strong>
      Inspects AWS accounts strictly through <code>Describe*</code>, <code>List*</code>, and <code>Get*</code> APIs. Never executes mutating commands.
    </div>
    <div class="pill">
      <strong>2. Fact-Based Evidence</strong>
      Every finding is rooted in raw AWS attribute paths and certainty tags (<code>verified</code>, <code>heuristic</code>, <code>unknown</code>).
    </div>
    <div class="pill">
      <strong>3. Fix-First Remediation</strong>
      Automatically authors ready-to-apply patches (Terraform, CloudFormation, AWS CLI) and safety pre-checks.
    </div>
  </div>

  <div class="callout callout-info">
    <strong>The Core Invariant: "Unknown is Not Fixed"</strong>
    A finding is <em>never</em> marked resolved because a resource or setting was absent from a scan. If an AWS API call encounters throttling, permissions denial, or network failure, CloudShield preserves the alert with an explicit note that the resource could not be evaluated.
  </div>

  <!-- Section 2: Complete Tech Stack -->
  <h2>2. Complete Technical Stack Breakdown</h2>
  <p>Every technology in CloudShield was intentionally chosen to guarantee local execution safety, strong type safety, and zero cloud lock-in.</p>

  <table>
    <thead>
      <tr>
        <th style="width: 20%;">Layer / Technology</th>
        <th style="width: 25%;">Where Used in Codebase</th>
        <th style="width: 27%;">Why It Was Selected</th>
        <th style="width: 28%;">Operational Role</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Python 3.12</strong></td>
        <td><code>src/cloudshield/</code></td>
        <td>Modern typing (<code>T | None</code>), strict performance improvements, first-class AWS SDK support.</td>
        <td>Drives the scanner, deterministic rules, risk engine, patch generator, and API server.</td>
      </tr>
      <tr>
        <td><strong>FastAPI</strong></td>
        <td><code>src/cloudshield/api/app.py</code><br><code>src/cloudshield/api/routes.py</code></td>
        <td>Asynchronous ASGI framework, native OpenAPI schemas, and declarative dependency injection.</td>
        <td>Exposes REST endpoints for scans, findings, fixes, guardrails, and Prowler imports.</td>
      </tr>
      <tr>
        <td><strong>Pydantic v2 &amp; Settings</strong></td>
        <td><code>src/cloudshield/api/schemas.py</code><br><code>src/cloudshield/config.py</code></td>
        <td>Rust-accelerated type validation, runtime validation of payloads, strict schema contracts.</td>
        <td>Enforces API schemas and validates environment variables from <code>.env</code>.</td>
      </tr>
      <tr>
        <td><strong>Boto3 &amp; Botocore</strong></td>
        <td><code>src/cloudshield/scanner/</code></td>
        <td>Official AWS SDK for Python. Adheres to standard AWS credential chains (<code>AWS_PROFILE</code>).</td>
        <td>Executes read-only discovery calls across S3, EC2, IAM, STS, and S3Control.</td>
      </tr>
      <tr>
        <td><strong>SQLAlchemy 2.0 &amp; SQLite</strong></td>
        <td><code>src/cloudshield/db/models.py</code><br><code>src/cloudshield/db/store.py</code></td>
        <td>Modern typed ORM (<code>Mapped[]</code>). SQLite requires zero external server setup.</td>
        <td>Stores scans, resources, findings, generated fixes, and passed checks with JSON attributes.</td>
      </tr>
      <tr>
        <td><strong>Alembic</strong></td>
        <td><code>alembic.ini</code><br><code>migrations/versions/</code></td>
        <td>Standard DB migration tool for SQLAlchemy. Version-controlled schema migrations.</td>
        <td>Manages database schema evolution (migrations 0001 to 0009) without data loss.</td>
      </tr>
      <tr>
        <td><strong>React 18 &amp; TypeScript 5.5</strong></td>
        <td><code>web/src/</code></td>
        <td>Declarative component-based UI. TypeScript types strictly mirror backend Pydantic models.</td>
        <td>Powers the single-page application dashboard, Kanban lanes, and interactive review panels.</td>
      </tr>
      <tr>
        <td><strong>Vite 5 &amp; Tailwind CSS v4</strong></td>
        <td><code>web/vite.config.ts</code><br><code>web/src/tokens.css</code></td>
        <td>Lightning-fast ESM development bundler and utility-first design system tokens.</td>
        <td>Builds the frontend client, hot-module reloading, dark palette, chips, and responsive grids.</td>
      </tr>
      <tr>
        <td><strong>Google Gemini API (REST)</strong></td>
        <td><code>src/cloudshield/fixes/explain.py</code></td>
        <td>Reasoning LLM with strict JSON Schema output formatting (<code>responseSchema</code>).</td>
        <td>Generates architectural explanations (Why it matters, What changes, What could break).</td>
      </tr>
      <tr>
        <td><strong>Prowler 5.44.0 (OCSF 1.5.0)</strong></td>
        <td><code>src/cloudshield/imports/</code></td>
        <td>Open-source industry security tool covering hundreds of CIS compliance checks.</td>
        <td>Parsed as supplementary "Reported" findings side-by-side with CloudShield native checks.</td>
      </tr>
      <tr>
        <td><strong>Moto (mock_aws) &amp; Pytest</strong></td>
        <td><code>tests/</code><br><code>src/cloudshield/demo/</code></td>
        <td>In-memory simulation of AWS services. Tests require zero AWS credentials or network.</td>
        <td>Enables comprehensive automated testing and seeds offline demo accounts (<code>demo.db</code>).</td>
      </tr>
      <tr>
        <td><strong>Playwright &amp; Vitest</strong></td>
        <td><code>web/src/**/*.test.tsx</code><br><code>web/e2e/</code></td>
        <td>Fast DOM-based frontend unit tests and end-to-end browser automation.</td>
        <td>Validates React UI rendering, API mock adapters, and user interaction workflows.</td>
      </tr>
    </tbody>
  </table>

  <!-- Section 3: Subsystems & Functionalities -->
  <div class="page-break"></div>
  <h2>3. In-Depth Subsystem Breakdown &amp; Core Functionalities</h2>

  <h3>3.1. Read-Only AWS Discovery Engine (<code>cloudshield.scanner</code>)</h3>
  <p>
    The discovery subsystem reads the target AWS account without ever modifying infrastructure state. It handles credential discovery automatically via the standard Boto3 chain (environment variables, AWS SSO, or <code>~/.aws/credentials</code>).
  </p>
  <ul>
    <li><strong>S3 Ingestion (<code>s3.py</code>):</strong> Discovers buckets, resolves region mappings, inspects Public Access Block configurations, server-side encryption rules, and bucket versioning statuses.</li>
    <li><strong>EC2 Ingestion (<code>ec2.py</code>):</strong> Collects instance metadata across requested regions, noting runtime state (<code>running</code>, <code>stopped</code>), public IP bindings, attached security groups, and IAM instance profile ARNs.</li>
    <li><strong>Security Group Ingestion (<code>security_groups.py</code>):</strong> Discovers VPC security groups, extracting inbound and outbound rules, port ranges, and CIDR blocks (IPv4 <code>0.0.0.0/0</code>, IPv6 <code>::/0</code>).</li>
    <li><strong>IAM Ingestion (<code>iam.py</code>):</strong> Collects customer-managed policies (<code>Scope='Local'</code>), policy version documents, attached entities (users, groups, roles), and evaluates role inline/attached policies.</li>
    <li><strong>Account Settings (<code>account.py</code>):</strong> Queries account-level configurations, such as the account-wide S3 Public Access Block via <code>s3control</code>.</li>
    <li><strong>Fault-Tolerant Attempt Mechanism (<code>common.py</code>):</strong> Distinguishes between expected absent configurations (e.g. <code>NoSuchPublicAccessBlockConfiguration</code>, which returns <code>None</code> as a valid security datum) and runtime errors (e.g., <code>AccessDenied</code>, timeouts), which are appended to the scan's error manifest.</li>
  </ul>

  <h3>3.2. Deterministic Rule Engine (<code>cloudshield.rules</code>)</h3>
  <p>CloudShield runs six tailored, deterministic rules. It does not synthesize arbitrary findings or invent external benchmark numbers.</p>

  <div class="rule-card">
    <div class="rule-header">
      <span class="rule-id">CIS-S3-001: S3 Public Access Block Incomplete</span>
      <span class="badge badge-high">High Severity</span>
    </div>
    <p>Reports any bucket where the Public Access Block is missing or where any of the 4 flags (<code>BlockPublicAcls</code>, <code>IgnorePublicAcls</code>, <code>BlockPublicPolicy</code>, <code>RestrictPublicBuckets</code>) is false.</p>
  </div>

  <div class="rule-card">
    <div class="rule-header">
      <span class="rule-id">CIS-S3-002: Default Encryption Not Using KMS</span>
      <span class="badge badge-info">Info (0 Risk Points)</span>
    </div>
    <p>Detects buckets whose default encryption is not SSE-KMS (<code>aws:kms</code>). Because AWS encrypts all new buckets with SSE-S3 by default, this check is rated as Informational and excluded from risk scoring.</p>
  </div>

  <div class="rule-card">
    <div class="rule-header">
      <span class="rule-id">CIS-S3-003: S3 Object Versioning Disabled</span>
      <span class="badge badge-medium">Medium Severity</span>
    </div>
    <p>Flags buckets where versioning status is not <code>Enabled</code>, leaving objects vulnerable to unrecoverable deletion or ransomware overwrite.</p>
  </div>

  <div class="rule-card">
    <div class="rule-header">
      <span class="rule-id">CIS-SG-001: Security Group Allows Open SSH or All Traffic</span>
      <span class="badge badge-high">High Severity</span>
    </div>
    <p>Flags inbound rules permitting public internet access (<code>0.0.0.0/0</code> or <code>::/0</code>) on port 22 (SSH) or across all protocols (protocol <code>-1</code>).</p>
  </div>

  <div class="rule-card">
    <div class="rule-header">
      <span class="rule-id">CIS-IAM-001: Wildcard Permissions in IAM Policy</span>
      <span class="badge badge-high">High / Medium</span>
    </div>
    <p>Evaluates customer-managed policies. Flags <code>Action: "*"</code> as High. Flags non-read-only actions on <code>Resource: "*"</code> as Medium. Protects sensitive read actions (e.g. <code>secretsmanager:GetSecretValue</code>, <code>s3:GetObject</code>) from being categorized as read-only.</p>
  </div>

  <div class="rule-card">
    <div class="rule-header">
      <span class="rule-id">SX-IAM-PRIVESC-001: IAM Privilege Escalation Vectors</span>
      <span class="badge badge-high">High Severity</span>
    </div>
    <p>Scans IAM policies and role documents against 15 documented privilege escalation methods from Rhino Security Labs (e.g., <code>iam:CreatePolicyVersion</code>, <code>iam:PassRole</code> + <code>ec2:RunInstances</code>, <code>iam:PutUserPolicy</code>).</p>
  </div>

  <h3>3.3. Context-Adjusted Risk Scoring &amp; Environment Math (<code>cloudshield.risk</code>)</h3>
  <p>Static severities fail to reflect actual business exposure. CloudShield adjusts risk based on live infrastructure context:</p>
  <ul>
    <li><strong>Base Scores:</strong> <code>CRITICAL: 90</code> | <code>HIGH: 70</code> | <code>MEDIUM: 40</code> | <code>LOW: 20</code> | <code>INFO: 5</code></li>
    <li><strong>Exposure Adjustment (+15):</strong> Added if an S3 bucket or security group has open internet ingress.</li>
    <li><strong>Workload Attachment Adjustment (+10):</strong> Added if a security group is attached to a <em>running</em> EC2 instance.</li>
    <li><strong>Privilege Attachment Adjustment (+10):</strong> Added if an IAM policy is currently attached to active users, groups, or roles.</li>
    <li><strong>Account-Wide Block Mitigation:</strong> If the scan confirms that account-wide S3 Public Access Block is active, the +15 exposure bonus is waived (+0), recognizing account-level defense-in-depth.</li>
  </ul>

  <div class="formula-box">
    Remaining Safety = &prod; (1 - RiskScore_i / 100)<br>
    Environment Score = round(100 &times; (1 - Remaining Safety), 1)
  </div>
  <p style="font-size: 8.5pt; color: #64748b; text-align: center;">
    Mathematically models cumulative independent probability: risks compound naturally, but the overall score never exceeds 100.
  </p>

  <!-- Section 4: Triage & Remediation -->
  <div class="page-break"></div>
  <h3>3.4. Actionable Triage Lanes (<code>web/src/lanes.ts</code>)</h3>
  <p>To eliminate alert fatigue, open findings are automatically categorized into operational triage lanes:</p>
  <ul>
    <li><strong>Fix Now (Score &ge; 80):</strong> Critical active exposures (e.g., High-severity open security group attached to a live production instance).</li>
    <li><strong>Next (Score 60 &ndash; 79):</strong> Substantial risks without immediate live attachment or public exposure.</li>
    <li><strong>Later (Score &lt; 60 or Info):</strong> Hardening measures, unused identities, or unversioned test buckets.</li>
    <li><strong>Done:</strong> Resolved alerts verified by a subsequent scan.</li>
  </ul>

  <h3>3.5. Multi-Format Patch &amp; Fix Generator (<code>cloudshield.fixes.templates</code>)</h3>
  <p>
    CloudShield is <strong>fix-first</strong>. For each native finding, it synthesizes copy-pasteable remediation code across three formats:
  </p>
  <ul>
    <li><strong>Terraform (<code>.tf</code>):</strong> Generates declarative HCL resources (e.g., <code>aws_s3_bucket_public_access_block</code>, <code>aws_s3_bucket_versioning</code>).</li>
    <li><strong>CloudFormation (<code>.yaml</code>):</strong> Produces valid AWS CloudFormation resource definitions.</li>
    <li><strong>AWS CLI (<code>.ps1</code>):</strong> Outputs single-line CLI commands compatible with PowerShell 5.1/7 and Bash.</li>
    <li><strong>Safety Pre-Checks &amp; Rollback:</strong> Every fix specifies what to inspect prior to applying (e.g. checking if a bucket hosts a static website) and provides the exact rollback command.</li>
    <li><strong>Command Injection Guard:</strong> All resource IDs, bucket names, and parameters are validated against strict regex <code>^[A-Za-z0-9._-]+$</code> before interpolation.</li>
  </ul>

  <h3>3.6. Grounded AI Fix Explanations with Safety Gates (<code>cloudshield.fixes.explain</code>)</h3>
  <p>
    When configured with a Google Gemini API key, CloudShield generates contextual explanations. To prevent AI hallucinations in security-critical code, it enforces strict multi-layer gates:
  </p>
  <ul>
    <li><strong>Rate Limiter (<code>HourlyLimit</code>):</strong> Thread-safe sliding window limiting requests (default 30 calls/hr).</li>
    <li><strong>Strict Data Redaction (<code>redact</code>):</strong> Scans input text and masks 12-digit AWS account IDs, AWS access keys (<code>AKIA...</code>), and secret strings before transmission.</li>
    <li><strong>Anti-Hallucination Gate (<code>check_explanation</code>):</strong> Automatically discards the model output and falls back to static engineering templates if the AI:
      <ul>
        <li>Uses disallowed reassurance words: <em>"safe"</em>, <em>"harmless"</em>, <em>"low risk"</em>, or <em>"zero risk"</em>.</li>
        <li>Invents ARNs, resource IDs, IP CIDRs, or port numbers that did not exist in the raw scan input.</li>
        <li>Cites evidence numbers that do not exist.</li>
        <li>Fails to mention what CloudShield did not check.</li>
      </ul>
    </li>
  </ul>

  <h3>3.7. Preventative Guardrails Catalog (<code>cloudshield.guardrails</code>)</h3>
  <p>
    While fixes repair existing issues, guardrails prevent their re-introduction:
  </p>
  <ul>
    <li><strong>Account Settings:</strong> Account-wide S3 Public Access Block. Status is shown as <code>Active</code> only when verified by a scan.</li>
    <li><strong>CI/CD Pipeline Checks:</strong> Pre-authored GitHub Actions workflows invoking Checkov (<code>CKV_AWS_21</code>, <code>CKV_AWS_24</code>) or AWS Access Analyzer to fail pull requests that introduce violations.</li>
    <li><strong>Detective Rules:</strong> AWS Config managed rules (<code>S3_BUCKET_VERSIONING_ENABLED</code>, <code>INCOMING_SSH_DISABLED</code>).</li>
    <li><strong>Organization Policies:</strong> AWS Organizations Service Control Policies (SCPs).</li>
  </ul>

  <h3>3.8. Third-Party Prowler Integration &amp; Reconciliation Engine (<code>cloudshield.imports</code>)</h3>
  <ul>
    <li><strong>OCSF 1.5.0 Parsing:</strong> Ingests JSON-OCSF outputs up to 50MB, verifying UTF-8 BOM, major schema version, and single-account integrity.</li>
    <li><strong>Execution Modes:</strong> Supports execution via local Python virtualenv or isolated Docker container (<code>toniblyx/prowler:5.44.0</code>).</li>
    <li><strong>Truthful Labeling:</strong> Prowler findings are labeled as <strong>Reported</strong>, never "Verified", maintaining clear attribution.</li>
    <li><strong>Smart Reconciliation (<code>imports/merge.py</code>):</strong>
      <ul>
        <li><em>Both Fail:</em> Prowler finding is merged into CloudShield's native finding (marked <code>corroborated_by: Prowler</code>).</li>
        <li><em>Tools Disagree:</em> If Prowler passes and CloudShield fails (or vice versa), both remain visible and a prominent <code>Tools Disagree</code> badge is displayed.</li>
      </ul>
    </li>
  </ul>

  <!-- Section 5: Research & Evaluation -->
  <div class="page-break"></div>
  <h3>3.9. Truthful Resolution Engine ("Unknown is Not Fixed") &amp; Research Experiments</h3>
  <p>
    A primary research contribution of CloudShield is eliminating <strong>silent false resolution</strong>. In standard security scanners, if an API call fails due to throttling or permission issues, the resource is missing from the scan output; naive tools assume the finding was resolved and close the alert.
  </p>
  <div class="callout callout-success">
    <strong>CloudShield Resolution Invariants:</strong>
    A finding is marked <code>RESOLVED</code> if and only if:
    <ol style="margin-top: 4px; margin-bottom: 4px;">
      <li>The scanner service for its resource type ran with <strong>zero</strong> API errors.</li>
      <li>For regional resources, its region was included in the rescan.</li>
      <li>The specific attribute required by the rule is confirmed present in the stored resource.</li>
    </ol>
  </div>

  <p>CloudShield validates this behavior through automated research benchmarks on synthetic accounts (<code>experiments/</code>):</p>
  <ul>
    <li><strong>Experiment E1 (Unknown Handling):</strong> Tested across 18 API fault injection scenarios (throttling, AccessDenied, dropped attributes). Results: <strong>CloudShield had 0 false resolutions</strong>, whereas a standard naive resolver wrongly resolved 25+ open security vulnerabilities.</li>
    <li><strong>Experiment E4 (Patch Validity):</strong> Tested all generated Terraform and CloudFormation fixes against <code>terraform validate</code> and <code>cfn-lint</code>, proving 100% syntactical deployment validity.</li>
  </ul>

  <h3>3.10. Web Security &amp; Concurrency Architecture</h3>
  <ul>
    <li><strong>Anti-CSRF Origin Validation (<code>refuse_foreign_origin</code>):</strong> Custom FastAPI middleware blocks non-GET requests whose <code>Origin</code> header does not match <code>FRONTEND_ORIGIN</code>, protecting local users from malicious cross-site scan triggers.</li>
    <li><strong>Atomic Execution Lock (<code>JobLock</code>):</strong> Ensures only one scan or file import executes at a time. Overlapping requests immediately receive an HTTP <code>409 Conflict</code>.</li>
  </ul>

  <!-- Section 6: Interview Preparation Notes -->
  <h2>4. Placement &amp; Technical Interview Quick-Reference</h2>

  <table>
    <thead>
      <tr>
        <th style="width: 25%;">Interview Question</th>
        <th style="width: 75%;">Senior-Level Model Answer Based on Real Code</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><strong>Why is CloudShield strictly read-only?</strong></td>
        <td>Automated cloud remediation (auto-fixing) in production can cause severe outages (e.g. locking out legitimate users or breaking static web hosting). CloudShield follows a "human-in-the-loop" model: it generates exact, validated patches with rollback commands, but leaves application to the infrastructure owner.</td>
      </tr>
      <tr>
        <td><strong>How does risk scoring work?</strong></td>
        <td>Scores range from 0 to 100. It starts from base severity (Critical: 90, High: 70, Medium: 40, Low: 20, Info: 5) and dynamically adds context: +15 for open internet exposure, +10 if attached to a running EC2 instance, and +10 if an IAM policy is actively attached to users/roles. Account-wide protections waive the exposure bonus.</td>
      </tr>
      <tr>
        <td><strong>How do you prevent LLM hallucinations?</strong></td>
        <td>The Gemini integration is restricted to explanations only. Prompts are redacted for secrets and account IDs. The output is validated by a strict post-generation gate: if the model calls a fix "safe", hallucinates an unmentioned ARN/port, or invents evidence IDs, the response is discarded and a static template is returned.</td>
      </tr>
      <tr>
        <td><strong>What is the "Unknown is Not Fixed" principle?</strong></td>
        <td>Conventional security tools falsely resolve findings when an API call fails or times out. CloudShield enforces that a finding only resolves when the service completes with zero errors, the region is verified, and the rule attributes are present. Missing data leaves the finding open with an "unknown" evidence tag.</td>
      </tr>
    </tbody>
  </table>

  <div style="margin-top: 24px; padding: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; text-align: center; font-size: 8pt; color: #64748b;">
    CloudShield Architectural Specification &bull; Generated from Verified Source Code &bull; Antigravity Platform
  </div>

</body>
</html>
`;

async function generatePDF() {
  const browser = await chromium.launch({
    executablePath: 'C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe',
    headless: true
  });
  const page = await browser.newPage();
  await page.setContent(htmlContent, { waitUntil: 'networkidle' });
  
  const outputPath = path.resolve(__dirname, 'CloudShield_Architecture_and_Tech_Stack.pdf');
  await page.pdf({
    path: outputPath,
    format: 'A4',
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: '<div></div>',
    footerTemplate: '<div style="font-size: 8pt; color: #94a3b8; width: 100%; text-align: right; padding-right: 14mm; font-family: sans-serif;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>',
    margin: {
      top: '14mm',
      bottom: '16mm',
      left: '12mm',
      right: '12mm'
    }
  });

  await browser.close();
  console.log('PDF generated at:', outputPath);
}

generatePDF().catch(err => {
  console.error('Error generating PDF:', err);
  process.exit(1);
});
