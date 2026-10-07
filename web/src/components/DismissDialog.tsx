import { useEffect, useId, useRef, useState } from "react";
import { api, type FindingOut } from "../api";
import { messageOf } from "../useAsync";
import { FIELD, PRIMARY_BUTTON, SECONDARY_BUTTON } from "./ui";

export const MIN_REASON = 10;

type Kind = "accepted" | "not_applicable";

// A dialog that asks why a finding is being dismissed. Nothing is sent until the reason is long
// enough and the user presses the button.
export function DismissDialog({
  finding,
  kind,
  onClose,
  onDone,
}: {
  finding: FindingOut;
  kind: Kind;
  onClose: () => void;
  onDone: () => void;
}) {
  const titleId = useId();
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const [chosen, setChosen] = useState<Kind>(kind);
  const [reason, setReason] = useState("");
  const [until, setUntil] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const today = new Date().toISOString().slice(0, 10);
  const length = reason.trim().length;

  useEffect(() => reasonRef.current?.focus(), []);

  async function submit() {
    setSaving(true);
    setError(null);
    try {
      await api.dismiss(finding.finding_id, {
        disposition: chosen,
        disposition_reason: reason.trim(),
        disposition_until: until || null,
      });
      onDone();
    } catch (failure) {
      setError(messageOf(failure));
      setSaving(false);
    }
  }

  return (
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-ink/60 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onKeyDown={(event) => event.key === "Escape" && onClose()}
        className="max-h-full w-full max-w-xl overflow-auto rounded-lane border-2 border-ink bg-paper p-6"
      >
        <h2 id={titleId} className="font-display text-h3 leading-tight font-extrabold">
          Dismiss this finding
        </h2>
        <p className="mt-2 text-secondary text-dim">
          It leaves the lanes and the counts, and stays in the list under Dismissed with
          your reason. It is not deleted, and you can undo it.
        </p>

        <fieldset className="mt-6">
          <legend className="text-label font-semibold">Why is it dismissed?</legend>
          <div className="mt-2 flex flex-wrap gap-6">
            {(
              [
                ["accepted", "Accepted risk"],
                ["not_applicable", "Not applicable"],
              ] as const
            ).map(([value, label]) => (
              <label
                key={value}
                className="flex min-h-11 items-center gap-2 text-secondary"
              >
                <input
                  type="radio"
                  name="kind"
                  checked={chosen === value}
                  onChange={() => setChosen(value)}
                />
                {label}
              </label>
            ))}
          </div>
        </fieldset>

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
          After this day the finding comes back as open.
        </p>

        {error && (
          <p role="alert" className="mt-4 text-secondary font-semibold text-red">
            {error}
          </p>
        )}
        <div className="mt-6 flex flex-wrap gap-3">
          <button
            type="button"
            className={PRIMARY_BUTTON}
            disabled={length < MIN_REASON || saving}
            onClick={submit}
          >
            {saving ? "Saving..." : "Dismiss finding"}
          </button>
          <button type="button" className={SECONDARY_BUTTON} onClick={onClose}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
