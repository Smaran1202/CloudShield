import { useEffect, useId, useRef, useState } from "react";
import { api, type FindingOut } from "../api";
import { maskAccountIds } from "../mask";
import { shortResource } from "../lanes";
import { messageOf } from "../useAsync";
import { MIN_REASON } from "./DismissDialog";
import { FIELD, PRIMARY_BUTTON, SECONDARY_BUTTON } from "./ui";

type Outcome = {
  finding: FindingOut;
  state: "dismissed" | "undone" | "failed";
  message?: string;
};

// Dismisses findings that CloudShield already suggested as not applicable, all with one reason.
// It sends one request for each finding to the same endpoint as a single dismissal, so every
// dismissal has the reason, and each one can be undone on its own.
export function BulkDismissDialog({
  findings,
  onClose,
}: {
  findings: FindingOut[];
  // Called when the dialog closes, so the list can be loaded again if anything changed.
  onClose: (changed: boolean) => void;
}) {
  const titleId = useId();
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");
  const [saving, setSaving] = useState(false);
  const [outcomes, setOutcomes] = useState<Outcome[] | null>(null);
  const length = reason.trim().length;
  const today = new Date().toISOString().slice(0, 10);
  const changed = outcomes?.some((o) => o.state !== "failed") ?? false;

  useEffect(() => reasonRef.current?.focus(), []);

  async function submit() {
    setSaving(true);
    const results: Outcome[] = [];
    for (const finding of findings) {
      try {
        await api.dismiss(finding.finding_id, {
          disposition: "not_applicable",
          disposition_reason: reason.trim(),
          disposition_until: until || null,
        });
        results.push({ finding, state: "dismissed" });
      } catch (failure) {
        results.push({ finding, state: "failed", message: messageOf(failure) });
      }
    }
    setOutcomes(results);
    setSaving(false);
  }

  async function undo(target: FindingOut) {
    if (!outcomes) return;
    try {
      await api.undismiss(target.finding_id);
      setOutcomes(
        outcomes.map((o) => (o.finding === target ? { ...o, state: "undone" } : o)),
      );
    } catch (failure) {
      setOutcomes(
        outcomes.map((o) =>
          o.finding === target ? { ...o, message: messageOf(failure) } : o,
        ),
      );
    }
  }

  const done = outcomes?.filter((o) => o.state === "dismissed").length ?? 0;
  return (
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-ink/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={(event) => event.key === "Escape" && !saving && onClose(changed)}
        className="max-h-full w-full max-w-2xl overflow-auto rounded-lane border-2 border-ink bg-paper p-6"
      >
        <h2 id={titleId} className="font-display text-h3 leading-tight font-extrabold">
          Dismiss all AWS-managed findings
        </h2>

        {outcomes === null ? (
          <>
            <p className="mt-2 text-secondary text-dim">
              These {findings.length} findings were suggested as not applicable. They
              leave the lanes and the counts, and stay in the list under Dismissed with
              your reason. Nothing is deleted, and you can undo each one.
            </p>
            <ul
              aria-label="Findings that will be dismissed"
              className="mt-4 max-h-60 space-y-2 overflow-auto rounded-chip border-2 border-ink bg-white p-3 text-secondary"
            >
              {findings.map((finding) => (
                <li key={finding.finding_id}>
                  <span className="font-semibold">{maskAccountIds(finding.title)}</span>
                  <span className="block font-mono text-label text-dim">
                    {maskAccountIds(shortResource(finding.resource_id))}
                  </span>
                  <span className="block text-label text-dim">
                    {finding.suggested_not_applicable?.reason}
                  </span>
                </li>
              ))}
            </ul>

            <label className="mt-6 flex flex-col gap-1 text-label font-semibold">
              Reason (required)
              <textarea
                ref={reasonRef}
                value={reason}
                onChange={(event) => setReason(event.target.value)}
                rows={3}
                className={`${FIELD} h-auto py-2 font-normal`}
              />
            </label>
            <p className="mt-1 text-secondary text-dim">
              {length >= MIN_REASON
                ? "Reason is long enough."
                : `At least ${MIN_REASON} characters. ${length} so far.`}
            </p>

            <label className="mt-6 flex flex-col gap-1 text-label font-semibold">
              Review date (optional)
              <input
                type="date"
                value={until}
                min={today}
                onChange={(event) => setUntil(event.target.value)}
                className={`${FIELD} w-fit`}
              />
            </label>
            <p className="mt-1 text-secondary text-dim">
              After this day the findings come back as open. The day ends at the end of
              that date in UTC.
            </p>

            <div className="mt-6 flex flex-wrap gap-3">
              <button
                type="button"
                className={PRIMARY_BUTTON}
                disabled={length < MIN_REASON || saving}
                onClick={submit}
              >
                {saving ? "Saving..." : `Dismiss ${findings.length} findings`}
              </button>
              <button
                type="button"
                className={SECONDARY_BUTTON}
                disabled={saving}
                onClick={() => onClose(false)}
              >
                Cancel
              </button>
            </div>
          </>
        ) : (
          <>
            <p role="status" className="mt-2 font-semibold">
              Dismissed {done} of {findings.length}.
            </p>
            <ul aria-label="Results" className="mt-4 space-y-3 text-secondary">
              {outcomes.map((outcome) => (
                <li
                  key={outcome.finding.finding_id}
                  className="flex flex-wrap items-center gap-3"
                >
                  <span className="min-w-0 flex-1">
                    {maskAccountIds(outcome.finding.title)}
                    {outcome.state === "failed" && (
                      <span role="alert" className="block font-semibold text-red">
                        Not dismissed: {outcome.message}
                      </span>
                    )}
                    {outcome.state === "undone" && (
                      <span className="block text-dim">Dismissal undone.</span>
                    )}
                    {outcome.state === "dismissed" && outcome.message && (
                      <span role="alert" className="block font-semibold text-red">
                        Not undone: {outcome.message}
                      </span>
                    )}
                  </span>
                  {outcome.state === "dismissed" && (
                    <button
                      type="button"
                      className={SECONDARY_BUTTON}
                      onClick={() => undo(outcome.finding)}
                    >
                      Undo dismissal of {maskAccountIds(outcome.finding.title)}
                    </button>
                  )}
                </li>
              ))}
            </ul>
            <div className="mt-6">
              <button
                type="button"
                className={PRIMARY_BUTTON}
                onClick={() => onClose(changed)}
              >
                Close
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
