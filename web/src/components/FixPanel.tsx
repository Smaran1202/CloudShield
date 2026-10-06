import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type { FindingDetailOut, FixOut, PatchOut } from "../api";
import { pretty } from "../format";
import type { FixState } from "../useFixRequest";
import type { Verify } from "../useVerify";
import {
  Card,
  CertaintyChip,
  ErrorBox,
  LevelChip,
  Loading,
  PRIMARY_BUTTON,
  SECONDARY_BUTTON,
  SectionTitle,
  Tag,
} from "./ui";
import { VerifyPanel } from "./VerifyPanel";

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
  const details = fix.status === "success" ? fix.fix : null;
  return (
    <div className="flex flex-wrap items-start gap-8">
      <div className="flex min-w-0 flex-[1_1_580px] flex-col gap-6">
        <Card>
          <SectionTitle>What this fix does</SectionTitle>
          <p className="mt-3 rounded-chip bg-notice p-3 text-secondary font-semibold text-ink">
            CloudShield never changes your AWS account. It writes a fix for you to read
            and apply yourself, then you rescan to check that it worked.
          </p>
          <div className="mt-6">
            {fix.status === "idle" && (
              <div className="space-y-3">
                <p className="text-secondary text-dim">
                  Nothing is generated until you ask. A fix that was made before is reused
                  while the evidence has not changed.
                </p>
                <button
                  type="button"
                  className={PRIMARY_BUTTON}
                  onClick={() => generate(false)}
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
            {details && <Explanation fix={details} onRegenerate={() => generate(true)} />}
          </div>
        </Card>
        {details && details.patches.length > 0 && (
          <PatchPanel patches={details.patches} />
        )}
        {details && details.guidance.length > 0 && (
          <Card>
            <SectionTitle>Guidance</SectionTitle>
            <p className="mt-2 mb-3 text-secondary text-dim">
              No patch is generated for this finding.
            </p>
            <BulletList items={details.guidance} />
          </Card>
        )}
      </div>

      <aside className="flex min-w-[340px] flex-[0_1_400px] flex-col gap-6 lg:max-w-[440px]">
        <EvidenceCard finding={finding} />
        {details && <BlastCard fix={details} />}
        {details && details.pre_checks.length > 0 && (
          <Checklist items={details.pre_checks} />
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
        <VerifyPanel verify={verify} alreadyResolved={finding.status === "RESOLVED"} />
      </aside>
    </div>
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

function Explanation({ fix, onRegenerate }: { fix: FixOut; onRegenerate: () => void }) {
  const { explanation } = fix;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <ExplanationBadge fix={fix} />
        <button type="button" className={SECONDARY_BUTTON} onClick={onRegenerate}>
          Regenerate explanation
        </button>
      </div>
      <Block title="Why it matters">
        <p className="text-secondary">{explanation.why_it_matters}</p>
      </Block>
      <Block title="What changes">
        <p className="text-secondary">{explanation.what_changes}</p>
      </Block>
      <Block title="What could break">
        <p className="text-secondary">{explanation.what_could_break}</p>
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

function PatchPanel({ patches }: { patches: PatchOut[] }) {
  const [active, setActive] = useState(patches[0].format);
  const patch = patches.find((p) => p.format === active) ?? patches[0];

  return (
    <section aria-label="Patches" className="rounded-lane bg-ink p-6 text-white">
      <h2 className="font-display text-h3 font-extrabold">Patches</h2>
      <div role="tablist" aria-label="Patch format" className="mt-4 flex flex-wrap gap-2">
        {patches.map((p) => (
          <button
            key={p.format}
            type="button"
            role="tab"
            aria-selected={p.format === patch.format}
            onClick={() => setActive(p.format)}
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
    <div>
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
        className="mt-2 overflow-x-auto font-mono text-label leading-[1.8] whitespace-pre"
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
              <span className="font-semibold">{item.fact}</span>
              <CertaintyChip certainty={item.certainty} />
            </li>
          ))}
        </ol>
      )}
    </Card>
  );
}

function BlastCard({ fix }: { fix: FixOut }) {
  const blast = fix.blast_radius;
  return (
    <Card>
      <SectionTitle>Blast radius</SectionTitle>
      <p className="mt-3 flex items-center gap-2 text-secondary">
        Level <LevelChip level={blast.level} />
      </p>
      <ul className="mt-3 space-y-3 text-secondary">
        {blast.factors.map((factor) => (
          <li key={factor.fact} className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <CertaintyChip certainty={factor.certainty} />
              <span className="font-semibold">{factor.fact}</span>
            </div>
            <p className="break-all text-dim">
              {factor.value === null ? "unknown" : pretty(factor.value)}
            </p>
            <p className="font-mono text-label text-dim">{factor.source}</p>
          </li>
        ))}
      </ul>
      {blast.notes.length > 0 && (
        <div className="mt-3">
          <BulletList items={blast.notes} />
        </div>
      )}
    </Card>
  );
}

// The ticks are local to this page: they are a reminder for you, and nothing is sent anywhere.
function Checklist({ items }: { items: string[] }) {
  const [ticked, setTicked] = useState<Record<string, boolean>>({});
  return (
    <Card>
      <SectionTitle>Before you apply it</SectionTitle>
      <ul className="mt-3 space-y-1">
        {items.map((item) => (
          <li key={item}>
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
    </Card>
  );
}
