import { useState } from "react";
import { api, type FindingOut } from "../api";
import { formatDate } from "../format";
import { messageOf } from "../useAsync";
import { DismissDialog } from "./DismissDialog";
import { Icon } from "./Icon";
import { SECONDARY_BUTTON } from "./ui";

type Kind = "accepted" | "not_applicable";

// The Dismiss button, the suggestion banner, and the way back from a dismissal. A suggestion
// never dismisses anything: it only opens the dialog, and the user has to confirm there.
export function DismissControls({
  finding,
  onChanged,
}: {
  finding: FindingOut;
  onChanged: () => void;
}) {
  const [kind, setKind] = useState<Kind | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function undo() {
    setError(null);
    try {
      await api.undismiss(finding.finding_id);
      onChanged();
    } catch (failure) {
      setError(messageOf(failure));
    }
  }

  return (
    <div className="mt-4 space-y-3">
      {finding.dismissed && (
        <div className="rounded-lane border-2 border-dashed border-dash p-4 text-secondary">
          <p className="font-semibold">
            Dismissed as{" "}
            {finding.disposition === "accepted" ? "accepted risk" : "not applicable"}
            {finding.disposition_until
              ? `, to be reviewed on ${formatDate(finding.disposition_until)}`
              : ""}
            .
          </p>
          <p className="mt-1">Reason: {finding.disposition_reason}</p>
          <button type="button" className={`mt-3 ${SECONDARY_BUTTON}`} onClick={undo}>
            Undo dismissal
          </button>
        </div>
      )}
      {finding.suggested_not_applicable && (
        <div
          role="note"
          className="flex flex-wrap items-center gap-3 rounded-lane bg-notice p-4 text-secondary font-semibold text-ink"
        >
          <Icon name="alert" size={20} />
          <span className="min-w-0 flex-1">
            {finding.suggested_not_applicable.reason} Dismiss as not applicable?
          </span>
          <button
            type="button"
            className={SECONDARY_BUTTON}
            onClick={() => setKind("not_applicable")}
          >
            Review and dismiss
          </button>
        </div>
      )}
      {finding.status === "OPEN" && !finding.dismissed && (
        <button
          type="button"
          className={SECONDARY_BUTTON}
          onClick={() => setKind("accepted")}
        >
          Dismiss
        </button>
      )}
      {error && (
        <p role="alert" className="text-secondary font-semibold text-red">
          {error}
        </p>
      )}
      {kind && (
        <DismissDialog
          finding={finding}
          kind={kind}
          onClose={() => setKind(null)}
          onDone={() => {
            setKind(null);
            onChanged();
          }}
        />
      )}
    </div>
  );
}
