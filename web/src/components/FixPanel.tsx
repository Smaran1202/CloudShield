import { useEffect, useId, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type {
  CloudShieldSteps,
  FindingDetailOut,
  FixOut,
  GuardrailKind,
  GuardrailOut,
  GuardrailScope,
  PatchOut,
} from "../api";
import { useLock } from "../auth";
import { Icon } from "./Icon";
import { maskAccountIds } from "../mask";
import type { FixState } from "../useFixRequest";
import type { Verify } from "../useVerify";
import {
  Card,
  CertaintyChip,
  ErrorBox,
  GuardrailStatusChip,
  Loading,
  PRIMARY_BUTTON,
  SECONDARY_BUTTON,
  SectionTitle,
  Tag,
} from "./ui";
import { PlainWords } from "./PlainWords";
import { RichText } from "./RichText";
import { ImportedVerifyPanel, VerifyPanel } from "./VerifyPanel";

const COPIED_MS = 1400;

function Block({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2">
      <h3 className="font-display text-title font-bold">{title}</h3>
      {children}
    </section>
  );
}

function BulletList({ items }: { items: string[] }) {
  return (
    <ul className="list-disc space-y-1 pl-6 text-secondary">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

// An imported fix lists the links the external tool gave as "Reference: <url>". Only web links
// become links.
function GuidanceList({ items, rich }: { items: string[]; rich: boolean }) {
  return (
    <ul className="list-disc space-y-1 pl-6 text-secondary">
      {items.map((item) => {
        const url = item.startsWith("Reference: ")
          ? item.slice("Reference: ".length)
          : "";
        return (
          <li key={item} className="break-words">
            {/^https?:\/\//.test(url) ? (
              <>
                Reference:{" "}
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-semibold underline"
                >
                  {url}
                </a>
              </>
            ) : rich ? (
              <RichText text={item} />
            ) : (
              item
            )}
          </li>
        );
      })}
    </ul>
  );
}

// How much of a long list or text the first view shows. The rest is one click away.
const CHECKS_SHOWN = 3;
const SENTENCES_SHOWN = 2;

// A button that opens a panel. The panel is only hidden, never left out of the page, so nothing
// is removed: it can be read, searched and reached with the keyboard once it is open.
function Fold({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <div>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
        className="flex min-h-11 w-full items-center gap-2 rounded-chip border-2 border-ink bg-white px-4 text-left text-secondary font-semibold"
      >
        <Icon name="chevron" size={18} className={open ? "rotate-180" : ""} />
        {label}
      </button>
      <div id={id} hidden={!open} className="mt-4 space-y-6">
        {children}
      </div>
    </div>
  );
}

function sentencesOf(text: string): string[] {
  return text.split(/(?<=[.!?])\s+/).filter(Boolean);
}

// The idle, loading and error states of the fix, which are the same for every finding.
function GenerateStates({
  fix,
  generate,
}: {
  fix: FixState;
  generate: (refresh?: boolean) => void;
}) {
  const lock = useLock();
  return (
    <>
      {fix.status === "idle" && (
        <div className="space-y-3">
          <p className="text-secondary text-dim">
            Nothing is generated until you ask. A fix that was made before is reused while
            the evidence has not changed.
          </p>
          <button
            type="button"
            className={PRIMARY_BUTTON}
            onClick={() => generate(false)}
            disabled={lock.disabled}
            title={lock.title}
          >
            Generate fix
          </button>
        </div>
      )}
      {fix.status === "loading" && (
        <Loading label="Generating the fix. This can take a few seconds" />
      )}
      {fix.status === "error" && (
        <ErrorBox message={fix.message} onRetry={() => generate(false)} />
      )}
    </>
  );
}

export function FixTab({
  finding,
  fix,
  generate,
  verify,
}: {
  finding: FindingDetailOut;
  fix: FixState;
  generate: (refresh?: boolean) => void;
  verify: Verify;
}) {
  const props = { finding, fix, generate, verify };
  return finding.source === "prowler" ? (
    <ImportedFixTab {...props} />
  ) : (
    <OwnFixTab {...props} />
  );
}

interface FixTabProps {
  finding: FindingDetailOut;
  fix: FixState;
  generate: (refresh?: boolean) => void;
  verify: Verify;
}

// Our own finding. The first view is the action, the patch, what to check first, what could
// break, the guardrails and the Verify button. Everything else is in "More detail".
function OwnFixTab({ finding, fix, generate, verify }: FixTabProps) {
  const details = fix.status === "success" ? fix.fix : null;
  const patches = details?.patches ?? [];
  const action = details
    ? (sentencesOf(details.explanation.what_changes)[0] ??
      sentencesOf(details.explanation.why_it_matters)[0] ??
      "")
    : "";
  return (
    <div className="flex max-w-4xl flex-col gap-6">
      <Card>
        <SectionTitle>What this fix does</SectionTitle>
        <p className="mt-3 rounded-chip bg-notice p-3 text-secondary font-semibold text-ink">
          CloudShield never changes your AWS account. It writes a fix for you to read and
          apply yourself, then you rescan to check that it worked.
        </p>
        <div className="mt-6 space-y-3">
          <GenerateStates fix={fix} generate={generate} />
          {details && (
            <>
              <ExplanationBadge fix={details} />
              <p className="text-body font-semibold">{action}</p>
            </>
          )}
        </div>
      </Card>

      {details && patches.length > 0 && <PatchPanel patches={patches} />}
      {details && patches.length === 0 && details.guidance.length > 0 && (
        <GuidanceCard items={details.guidance} title="Guidance" />
      )}
      {details && details.pre_checks.length > 0 && (
        <Checklist items={details.pre_checks} limit={CHECKS_SHOWN} />
      )}
      {details && <CouldBreak text={details.explanation.what_could_break} />}
      {details && <Guardrails guardrails={details.guardrails} />}

      <Fold label="More detail: why it matters, rollback, what was not checked, evidence">
        {details && <Explanation fix={details} onRegenerate={() => generate(true)} />}
        {details && patches.length > 0 && details.guidance.length > 0 && (
          <GuidanceCard items={details.guidance} title="Guidance" />
        )}
        {details && details.not_checked.length > 0 && (
          <Card>
            <SectionTitle>CloudShield did not check</SectionTitle>
            <div className="mt-3">
              <BulletList items={details.not_checked} />
            </div>
          </Card>
        )}
        {details && (
          <Card>
            <Block title="Rollback">
              <p className="text-secondary break-words whitespace-pre-wrap">
                {details.rollback}
              </p>
            </Block>
            <div className="mt-6">
              <Block title="Verify">
                <p className="text-secondary">{details.verify}</p>
              </Block>
            </div>
          </Card>
        )}
        <EvidenceCard finding={finding} />
      </Fold>

      <VerifyPanel verify={verify} alreadyResolved={finding.status === "RESOLVED"} />
    </div>
  );
}

// An imported finding keeps its layout: the scanner's own text, what CloudShield wrote, and a
// one-line caveat. It has no patch and no AI text.
function ImportedFixTab({ finding, fix, generate, verify }: FixTabProps) {
  const details = fix.status === "success" ? fix.fix : null;
  return (
    <div className="flex flex-wrap items-start gap-8">
      <div className="flex min-w-0 flex-[1_1_580px] flex-col gap-6">
        <Card>
          <SectionTitle>What this fix does</SectionTitle>
          <p className="mt-3 text-secondary font-semibold">
            No patch for this finding. This is guidance from an imported scan.
          </p>
          <p className="mt-3 rounded-chip bg-notice p-3 text-secondary font-semibold text-ink">
            CloudShield never changes your AWS account. It writes a fix for you to read
            and apply yourself, then you rescan to check that it worked.
          </p>
          <p className="mt-3 flex items-start gap-2 rounded-chip border-2 border-ink p-3 text-secondary font-semibold">
            <Icon name="external" size={20} className="mt-[2px] shrink-0" />
            This comes from an external scanner. CloudShield did not collect this
            evidence.
          </p>
          <div className="mt-6">
            <GenerateStates fix={fix} generate={generate} />
            {details && <ReportedRisk fix={details} />}
          </div>
        </Card>
        {details?.cloudshield_steps && <WhatToDo steps={details.cloudshield_steps} />}
        {details && details.guidance.length > 0 && (
          <GuidanceCard
            items={details.guidance}
            title="What the scanner recommends"
            reported
          />
        )}
        {details && <PlainWords text={plainText(details, finding)} />}
      </div>

      <aside className="flex min-w-[340px] flex-[0_1_400px] flex-col gap-6 lg:max-w-[440px]">
        <EvidenceCard finding={finding} />
        {details && details.pre_checks.length > 0 && (
          <Checklist items={details.pre_checks} />
        )}
        {details && details.not_checked.length > 0 && (
          <Card>
            <SectionTitle>CloudShield did not check</SectionTitle>
            <div className="mt-3">
              <BulletList items={details.not_checked} />
            </div>
          </Card>
        )}
        <ImportedVerifyPanel
          verify={verify}
          alreadyResolved={finding.status === "RESOLVED"}
        />
      </aside>
    </div>
  );
}

function GuidanceCard({
  items,
  title,
  reported = false,
}: {
  items: string[];
  title: string;
  reported?: boolean;
}) {
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-3">
        <SectionTitle>{title}</SectionTitle>
        {reported && <CertaintyChip certainty="reported" />}
      </div>
      {!reported && (
        <p className="mt-2 mb-3 text-secondary text-dim">
          No patch is generated for this finding.
        </p>
      )}
      <div className="mt-3">
        <GuidanceList items={items} rich={reported} />
      </div>
    </Card>
  );
}

// The first two sentences, and the rest behind a button.
function CouldBreak({ text }: { text: string }) {
  const [more, setMore] = useState(false);
  const id = useId();
  const sentences = sentencesOf(text);
  const head = sentences.slice(0, SENTENCES_SHOWN).join(" ");
  const rest = sentences.slice(SENTENCES_SHOWN).join(" ");
  return (
    <Block title="What could break">
      <p className="text-secondary">
        {head}
        {rest && (
          <span id={id} hidden={!more}>
            {" "}
            {rest}
          </span>
        )}
      </p>
      {rest && (
        <button
          type="button"
          aria-expanded={more}
          aria-controls={id}
          onClick={() => setMore(!more)}
          className="min-h-11 text-secondary font-semibold underline"
        >
          {more ? "Show less" : "Show more"}
        </button>
      )}
    </Block>
  );
}

// Everything an imported finding says in words, so the glossary can show only the terms in it.
function plainText(fix: FixOut, finding: FindingDetailOut): string {
  const steps = fix.cloudshield_steps;
  const own = steps
    ? [steps.summary, ...steps.steps.map((s) => s.text), ...steps.before_you_apply]
    : [];
  const described = finding.evidence.items.filter((i) => typeof i.value === "string");
  return [
    ...fix.guidance,
    fix.explanation.why_it_matters,
    ...described.map((i) => String(i.value)),
    ...own,
  ].join(" ");
}

// The scanner's own description of the risk, passed on as it was written.
function ReportedRisk({ fix }: { fix: FixOut }) {
  if (!fix.explanation.why_it_matters) return null;
  return (
    <section aria-label="Risk reported by the scanner" className="space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="font-display text-title font-bold">Risk</h3>
        <CertaintyChip certainty="reported" />
      </div>
      <RichText text={fix.explanation.why_it_matters} />
    </section>
  );
}

// Steps that CloudShield wrote itself, with the AWS page they come from. They are labelled so
// nobody mistakes them for the scanner's text or for advice that is already checked.
function WhatToDo({ steps }: { steps: CloudShieldSteps }) {
  return (
    <section
      aria-label="What to do"
      className="rounded-lane border-2 border-ink bg-white p-6"
    >
      <h2 className="font-display text-h3 font-extrabold">What to do</h2>
      <p className="mt-3 inline-flex items-start gap-2 rounded-chip bg-notice p-3 text-secondary font-semibold text-ink">
        <Icon name="alert" size={20} className="mt-[2px] shrink-0" />
        <span>
          Steps written by CloudShield. Check them against the AWS documentation before
          you act.
        </span>
      </p>
      <p className="mt-3 text-secondary">{steps.summary}</p>
      <ol className="mt-4 list-decimal space-y-4 pl-6 text-secondary">
        {steps.steps.map((step, index) => (
          <li key={index} className="space-y-2">
            <p>{step.text}</p>
            {step.command && (
              <div className="rounded-chip bg-ink p-3 text-white">
                <Code text={step.command} label={`command for step ${index + 1}`} />
              </div>
            )}
          </li>
        ))}
      </ol>
      <p className="mt-4 text-secondary">
        <a
          href={steps.docs_url}
          target="_blank"
          rel="noopener noreferrer"
          className="font-semibold break-all underline"
        >
          AWS documentation
        </a>
        <span className="text-dim"> (read on {steps.verified_on})</span>
      </p>
    </section>
  );
}

function ExplanationBadge({ fix }: { fix: FixOut }) {
  if (fix.generated_by === "gemini") {
    return (
      <p className="flex flex-wrap items-center gap-2 text-secondary">
        <span className="rounded-chip bg-chip-info-bg px-3 py-1 text-secondary font-semibold text-chip-info-text">
          AI explanation
        </span>
        <span className="text-dim">written by {fix.model}</span>
      </p>
    );
  }
  const reason = fix.explanation.skipped_reason;
  return (
    <p className="flex flex-wrap items-center gap-2 text-secondary">
      <span className="rounded-chip bg-chip-unknown-bg px-3 py-1 text-secondary font-semibold text-chip-unknown-text">
        Template explanation
      </span>
      <span className="text-dim">
        {reason ? `Gemini was not used: ${reason}` : "Gemini was not used."}
      </span>
    </p>
  );
}

function Explanation({
  fix,
  onRegenerate,
}: {
  fix: FixOut;
  onRegenerate: (() => void) | null;
}) {
  const { explanation } = fix;
  const lock = useLock();
  return (
    <div className="space-y-6">
      {onRegenerate && (
        <div className="flex justify-end">
          <button
            type="button"
            className={SECONDARY_BUTTON}
            onClick={onRegenerate}
            disabled={lock.disabled}
            title={lock.title}
          >
            Regenerate explanation
          </button>
        </div>
      )}
      <Block title="Why it matters">
        <p className="text-secondary">{explanation.why_it_matters}</p>
      </Block>
      <Block title="What changes">
        <p className="text-secondary">{explanation.what_changes}</p>
      </Block>
      {explanation.cited.length > 0 && (
        <p className="flex flex-wrap items-center gap-2 text-secondary">
          Cited evidence:
          {explanation.cited.map((id) => (
            <Link
              key={id}
              to={`?tab=evidence&item=${id}`}
              className="inline-flex min-h-11 items-center"
              aria-label={id}
            >
              <Tag>{id}</Tag>
            </Link>
          ))}
        </p>
      )}
    </div>
  );
}

const KIND_LABEL: Record<GuardrailKind, string> = {
  account_setting: "Account setting",
  pipeline_check: "Pipeline check",
  detective_rule: "Detective rule",
  organization_policy: "Organization policy",
};

const SCOPE_LABEL: Record<GuardrailScope, string> = {
  resource: "One resource",
  account: "Whole account",
  organization: "Whole organization",
};

// What stops this finding coming back. Imported findings never get this section. Each guardrail
// is one compact row that opens to its details and patches. The ones CloudShield cannot read
// (status unknown, or only an organization admin can say) share one fold.
function Guardrails({ guardrails }: { guardrails: GuardrailOut[] }) {
  if (guardrails.length === 0) return null;
  const cannot = guardrails.filter(
    (g) => g.status === "unknown" || g.status === "needs_org_admin",
  );
  const known = guardrails.filter((g) => !cannot.includes(g));
  return (
    <section aria-label="Prevent it coming back" className="space-y-4">
      <SectionTitle>Prevent it coming back</SectionTitle>
      <p className="text-secondary text-dim">
        Apply the fix first, then a guardrail stops it returning. CloudShield never
        changes your account.
      </p>
      {known.map((guardrail) => (
        <GuardrailRow key={guardrail.id} guardrail={guardrail} />
      ))}
      {cannot.length > 0 && (
        <Fold
          label={`${cannot.length} ${
            cannot.length === 1 ? "guardrail" : "guardrails"
          } CloudShield cannot check`}
        >
          {cannot.map((guardrail) => (
            <GuardrailRow key={guardrail.id} guardrail={guardrail} />
          ))}
        </Fold>
      )}
    </section>
  );
}

function GuardrailRow({ guardrail }: { guardrail: GuardrailOut }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <article aria-label={guardrail.title}>
      <Card className="space-y-4">
        <h3 className="font-display text-title font-bold">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={id}
            onClick={() => setOpen(!open)}
            className="flex min-h-11 w-full flex-wrap items-center gap-3 text-left"
          >
            <Icon name="chevron" size={18} className={open ? "rotate-180" : ""} />
            <span className="min-w-0 flex-1">{guardrail.title}</span>
            <GuardrailStatusChip status={guardrail.status} />
            <Tag>{KIND_LABEL[guardrail.kind]}</Tag>
          </button>
        </h3>
        <div id={id} hidden={!open} className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Tag>{SCOPE_LABEL[guardrail.scope]}</Tag>
          </div>
          <p className="text-secondary text-dim">{guardrail.status_reason}</p>
          <p className="text-secondary">{guardrail.prevents}</p>
          <Block title="What this affects">
            <p className="text-secondary">{guardrail.affects}</p>
          </Block>
          {guardrail.cost && (
            <Block title="Cost">
              <p className="text-secondary">{guardrail.cost}</p>
            </Block>
          )}
          <PatchPanel patches={guardrail.patches} title={guardrail.title} />
          <a
            href={guardrail.docs_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block font-semibold break-all underline"
          >
            AWS documentation
          </a>
        </div>
      </Card>
    </article>
  );
}
const FORMAT_KEY = "cloudshield.patchFormat";

function savedFormat(patches: PatchOut[]): PatchOut["format"] {
  try {
    const saved = window.localStorage.getItem(FORMAT_KEY);
    const found = patches.find((p) => p.format === saved);
    if (found) return found.format;
  } catch {
    // Browser storage can be blocked. The first format is used then.
  }
  return patches[0].format;
}

function saveFormat(format: string): void {
  try {
    window.localStorage.setItem(FORMAT_KEY, format);
  } catch {
    // Not remembered when storage is blocked. Nothing else depends on it.
  }
}

// With a title it is the patches of one guardrail, so each panel has its own name.
function PatchPanel({ patches, title }: { patches: PatchOut[]; title?: string }) {
  // Only the main patch remembers the chosen format. The panel of a guardrail starts on its first.
  const [active, setActive] = useState(() =>
    title ? patches[0].format : savedFormat(patches),
  );
  const patch = patches.find((p) => p.format === active) ?? patches[0];
  const name = title ? `Patches for ${title}` : "Patches";

  return (
    <section aria-label={name} className="rounded-lane bg-ink p-6 text-white">
      {title ? (
        <h4 className="font-display text-title font-bold">Patches</h4>
      ) : (
        <h2 className="font-display text-h3 font-extrabold">Patches</h2>
      )}
      <div role="tablist" aria-label="Patch format" className="mt-4 flex flex-wrap gap-2">
        {patches.map((p) => (
          <button
            key={p.format}
            type="button"
            role="tab"
            aria-selected={p.format === patch.format}
            onClick={() => {
              setActive(p.format);
              if (!title) saveFormat(p.format);
            }}
            className={`min-h-11 rounded-chip border-2 border-white px-4 font-mono text-secondary ${
              p.format === patch.format ? "bg-white text-ink" : "text-white"
            }`}
          >
            {p.format}
          </button>
        ))}
      </div>
      <div key={patch.format} className="fade-up mt-4 space-y-4">
        <p
          role="note"
          className="rounded-chip bg-notice p-3 text-secondary font-semibold text-ink"
        >
          Review before you run it. CloudShield never changes your AWS account.
        </p>
        <h3 className="text-secondary font-semibold">{patch.title}</h3>
        {patch.needs_input && (
          <div
            role="note"
            className="rounded-chip border-2 border-dashed border-white p-3 text-secondary"
          >
            <p className="font-semibold">Needs your input before you use it</p>
            <BulletList items={patch.inputs_needed} />
          </div>
        )}
        {patch.instructions_only && (
          <p className="text-secondary">
            These are instructions, not code, because the existing definition is not
            known.
          </p>
        )}
        <Code text={patch.content} label={patch.title} />
        {patch.files.map((file) => (
          <div key={file.name} className="space-y-1">
            <p className="font-mono text-label">{file.name}</p>
            <Code text={file.content} label={file.name} />
          </div>
        ))}
      </div>
    </section>
  );
}

function Code({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState<"idle" | "done" | "failed">("idle");

  useEffect(() => {
    if (copied !== "done") return;
    const timer = setTimeout(() => setCopied("idle"), COPIED_MS);
    return () => clearTimeout(timer);
  }, [copied]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied("done");
    } catch {
      setCopied("failed");
    }
  }

  return (
    <div className="min-w-0">
      <div className="flex justify-end">
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy ${label}`}
          className="min-h-11 rounded-chip border-2 border-white px-4 text-secondary font-semibold text-white"
        >
          {copied === "done" ? "Copied" : "Copy"}
        </button>
      </div>
      {copied === "failed" && (
        <p role="alert" className="mt-1 text-secondary">
          Copy failed: this browser blocked clipboard access. Select the code and copy it
          yourself.
        </p>
      )}
      <pre
        tabIndex={0}
        className="mt-2 font-mono text-label leading-[1.8] [overflow-wrap:anywhere] whitespace-pre-wrap"
      >
        <code>{text}</code>
      </pre>
    </div>
  );
}

function EvidenceCard({ finding }: { finding: FindingDetailOut }) {
  const items = finding.evidence.items;
  return (
    <Card>
      <SectionTitle>Evidence</SectionTitle>
      {items.length === 0 ? (
        <p className="mt-2 text-secondary text-dim">
          No evidence is stored for this finding yet.
        </p>
      ) : (
        <ol className="mt-3 space-y-3">
          {items.map((item, index) => (
            <li
              key={`${item.fact}-${index}`}
              className="flex flex-wrap items-center gap-2 text-secondary"
            >
              <Link to={`?tab=evidence&item=e${index + 1}`} aria-label={`e${index + 1}`}>
                <Tag>{`e${index + 1}`}</Tag>
              </Link>
              <span className="font-semibold">{maskAccountIds(item.fact)}</span>
              <CertaintyChip certainty={item.certainty} />
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

// The ticks are local to this page: they are a reminder for you, and nothing is sent anywhere.
function Checklist({ items, limit }: { items: string[]; limit?: number }) {
  const [ticked, setTicked] = useState<Record<string, boolean>>({});
  const [all, setAll] = useState(false);
  const id = useId();
  const extra = limit !== undefined && items.length > limit;
  return (
    <Card>
      <SectionTitle>Before you apply it</SectionTitle>
      <ul id={id} className="mt-3 space-y-1">
        {items.map((item, index) => (
          <li key={item} hidden={extra && !all && index >= limit}>
            <label className="flex min-h-11 cursor-pointer items-start gap-3 text-secondary">
              <input
                type="checkbox"
                checked={ticked[item] ?? false}
                onChange={(e) => setTicked({ ...ticked, [item]: e.target.checked })}
                className="mt-1 h-5 w-5 shrink-0 accent-ink"
              />
              {item}
            </label>
          </li>
        ))}
      </ul>
      {extra && (
        <button
          type="button"
          aria-expanded={all}
          aria-controls={id}
          onClick={() => setAll(!all)}
          className="min-h-11 text-secondary font-semibold underline"
        >
          {all ? "Show fewer" : `Show all (${items.length})`}
        </button>
      )}
    </Card>
  );
}
