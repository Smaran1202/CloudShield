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
        <button type="button" onClick={start} className={`mt-4 ${SECONDARY_BUTTON}`}>
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
        <button type="button" onClick={start} className={`mt-4 ${SECONDARY_BUTTON}`}>
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
        onClick={start}
        disabled={scanning}
        className={`mt-4 ${DARK_BUTTON}`}
      >
        {scanning ? "Scanning..." : "Rescan to verify"}
      </button>
    </section>
  );
}
