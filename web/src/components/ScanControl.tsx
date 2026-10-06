import type { Runner } from "../useScanRunner";
import { PRIMARY_BUTTON, Spinner } from "./ui";

// The progress and the outcome of the current scan, in words. The text is the backend's own.
export function ScanStatusLine({ runner }: { runner: Runner }) {
  if (runner.phase === "idle") return null;
  if (runner.phase === "running") {
    return (
      <p>
        {runner.scan
          ? `Scan ${runner.scan.id} ${runner.scan.status}: `
          : "Starting the scan: "}
        {runner.scan?.progress ?? "waiting for the API"}
      </p>
    );
  }
  if (runner.phase === "completed") return <p>Scan {runner.scan?.id} completed.</p>;
  return (
    <p role="alert" className="font-semibold text-red">
      {runner.phase === "failed" ? `Scan ${runner.scan?.id} failed: ` : ""}
      {runner.message ?? "No message was given."}
    </p>
  );
}

export function RunScanButton({
  runner,
  label = "Run scan",
}: {
  runner: Runner;
  label?: string;
}) {
  const running = runner.phase === "running";
  return (
    <button
      type="button"
      onClick={runner.start}
      disabled={running}
      className={PRIMARY_BUTTON}
    >
      {running && <Spinner />}
      {running ? "Scanning..." : label}
    </button>
  );
}

// A segment slides along a track. It never shows a percentage: the scan reports none.
export function ScanBar() {
  return (
    <div className="scan-bar h-1 overflow-hidden bg-lane-grey" aria-hidden="true">
      <span />
    </div>
  );
}
