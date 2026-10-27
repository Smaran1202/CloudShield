import { api } from "../api";
import { useAsync } from "../useAsync";
import type { Verify } from "../useVerify";
import { useScans } from "../ScanContext";
import { Check, SECONDARY_BUTTON, Spinner } from "./ui";

const DARK_BUTTON =
  "inline-flex min-h-12 items-center gap-2 rounded-chip bg-white px-6 text-secondary font-semibold text-ink";

export function VerifyPanel({
  verify,
  alreadyResolved,
}: {
  verify: Verify;
  alreadyResolved: boolean;
}) {
  const { runner } = useScans();
  const { state, start } = verify;

  if (state.phase === "resolved") {
    return (
      <section aria-label="Verify" className="pop rounded-lane bg-green p-6 text-white">
        <Check size={40} />
        <p className="mt-2 font-display text-h2 leading-tight font-extrabold">
          {state.fixed} fixed. {state.toGo} to go.
        </p>
        <p className="mt-2 text-secondary">The rescan no longer sees this problem.</p>
      </section>
    );
  }

  if (state.phase === "open") {
    return (
      <section
        aria-label="Verify"
        className="rounded-lane border-2 border-ink bg-lane-grey p-6 text-ink"
      >
        <p className="font-display text-title font-bold">Still open after the rescan.</p>
        <p className="mt-2 text-secondary">
          Check that you applied the patch to the right resource and region.
        </p>
        <button
          type="button"
          onClick={() => start()}
          className={`mt-4 ${SECONDARY_BUTTON}`}
        >
          Rescan to verify
        </button>
      </section>
    );
  }

  if (state.phase === "failed") {
    return (
      <section
        aria-label="Verify"
        role="alert"
        className="rounded-lane border-2 border-red bg-chip-high-bg p-6 text-chip-high-text"
      >
        <p className="font-display text-title font-bold">The rescan did not finish.</p>
        <p className="mt-2 text-secondary break-words">{state.message}</p>
        <button
          type="button"
          onClick={() => start()}
          className={`mt-4 ${SECONDARY_BUTTON}`}
        >
          Rescan to verify
        </button>
      </section>
    );
  }

  const scanning = state.phase === "scanning";
  return (
    <section aria-label="Verify" className="rounded-lane bg-ink p-6 text-white">
      <p className="font-display text-title font-bold">Rescan to verify</p>
      <p className="mt-2 text-secondary">
        {alreadyResolved
          ? "This finding is already resolved. You can rescan again at any time."
          : "After you have applied the fix yourself, rescan. This finding turns resolved when the scan no longer sees the problem."}
      </p>
      {scanning && (
        <p className="mt-3 flex items-center gap-2 text-secondary">
          <Spinner />
          <span>
            {runner.scan
              ? `Scan ${runner.scan.id} ${runner.scan.status}: ${runner.scan.progress ?? "waiting for the API"}`
              : "Starting the scan: waiting for the API"}
          </span>
        </p>
      )}
      <button
        type="button"
        onClick={() => start()}
        disabled={scanning}
        className={`mt-4 ${DARK_BUTTON}`}
      >
        {scanning ? "Scanning..." : "Rescan to verify"}
      </button>
    </section>
  );
}

// For an imported finding, the only way to check again is the full scan, which runs the extended
// checks. Nothing is shown as fixed until the finding has been fetched again and says RESOLVED.
export function ImportedVerifyPanel({
  verify,
  alreadyResolved,
}: {
  verify: Verify;
  alreadyResolved: boolean;
}) {
  const { runner } = useScans();
  const { state, start } = verify;
  const [status] = useAsync(() => api.extendedStatus());
  const scanning = state.phase === "scanning";
  const ready = status.status === "success" && status.data.available;

  if (state.phase === "resolved") {
    return (
      <section
        aria-label="Verify with a full scan"
        className="pop rounded-lane bg-green p-6 text-white"
      >
        <Check size={40} />
        <p className="mt-2 font-display text-h2 leading-tight font-extrabold">
          Resolved.
        </p>
        <p className="mt-2 text-secondary">
          The full scan shows this check passing. {state.fixed} fixed. {state.toGo} to go.
        </p>
      </section>
    );
  }

  return (
    <section
      aria-label="Verify with a full scan"
      className="rounded-lane bg-ink p-6 text-white"
    >
      <p className="font-display text-title font-bold">Run full scan to verify</p>
      <p className="mt-2 text-secondary">
        {alreadyResolved
          ? "This finding is already resolved. You can check again at any time."
          : "After you have applied the fix yourself, run the full scan. The finding is resolved only if the check runs again and passes."}
      </p>
      {state.phase === "open" && (
        <p className="mt-3 rounded-chip bg-white p-3 text-secondary font-semibold text-ink">
          Still open. The check ran in that scan and the problem is still there.
        </p>
      )}
      {state.phase === "not_rechecked" && (
        <p
          role="status"
          className="mt-3 rounded-chip bg-notice p-3 text-secondary font-semibold text-ink"
        >
          Not rechecked. This check did not run in that scan. {state.message}
        </p>
      )}
      {state.phase === "failed" && (
        <p
          role="alert"
          className="mt-3 rounded-chip bg-white p-3 text-secondary font-semibold text-red"
        >
          The scan did not finish: {state.message}
        </p>
      )}
      {scanning && (
        <p className="mt-3 flex items-center gap-2 text-secondary">
          <Spinner />
          <span>
            {runner.scan
              ? `Scan ${runner.scan.id} ${runner.scan.status}: ${runner.scan.progress ?? "waiting for the API"}`
              : "Starting the scan: waiting for the API"}
          </span>
        </p>
      )}
      <button
        type="button"
        onClick={() => start(true)}
        disabled={scanning || !ready}
        className={`mt-4 ${DARK_BUTTON}`}
      >
        {scanning ? "Scanning..." : "Run full scan to verify"}
      </button>
      {status.status === "loading" && (
        <p className="mt-2 text-secondary">Checking whether it can run here...</p>
      )}
      {status.status === "error" && (
        <p role="note" className="mt-2 text-secondary">
          Could not check: {status.message}
        </p>
      )}
      {status.status === "success" && !status.data.available && (
        <p role="note" className="mt-2 text-secondary">
          <span className="font-semibold">{status.data.reason}</span> {status.data.hint}
        </p>
      )}
      <p className="mt-4 text-secondary">Or import a newer results file yourself:</p>
      <pre className="mt-1 overflow-x-auto rounded-chip bg-white p-2 font-mono text-label text-ink">
        python -m cloudshield.imports prowler &lt;file&gt;
      </pre>
    </section>
  );
}
