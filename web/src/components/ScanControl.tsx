import { useEffect, useRef, useState } from "react";
import { api, type ScanOut } from "../api";
import { useScans } from "../ScanContext";
import { useAsync } from "../useAsync";
import type { Runner } from "../useScanRunner";
import { Icon } from "./Icon";
import { SECONDARY_BUTTON, Spinner } from "./ui";

// The outcome of the extended checks, in the scan's own words. A scan that did not ask for them
// says nothing.
export function ExtendedResult({
  scan,
  role = "alert",
}: {
  scan: ScanOut;
  role?: "alert" | "note";
}) {
  if (scan.extended_status === "skipped") return null;
  if (scan.extended_status === "ok") {
    return (
      <>
        <p>{scan.extended_message}</p>
        {scan.extended_hint && <p className="text-dim">{scan.extended_hint}</p>}
      </>
    );
  }
  return (
    <p role={role} className="font-semibold text-red">
      Extended checks {scan.extended_status}: {scan.extended_message}
      {scan.extended_hint && (
        <span className="block font-normal text-ink">{scan.extended_hint}</span>
      )}
    </p>
  );
}

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
  if (runner.phase === "completed" && runner.scan) {
    return (
      <>
        <p>Scan {runner.scan.id} completed.</p>
        <ExtendedResult scan={runner.scan} />
      </>
    );
  }
  return (
    <p role="alert" className="font-semibold text-red">
      {runner.phase === "failed" ? `Scan ${runner.scan?.id} failed: ` : ""}
      {runner.message ?? "No message was given."}
    </p>
  );
}

const SPLIT =
  "inline-flex min-h-12 items-center justify-center gap-2 bg-ink text-secondary font-semibold text-white disabled:cursor-not-allowed disabled:opacity-70";
const MENU_ITEM =
  "flex w-full flex-col items-start gap-1 rounded-chip p-3 text-left text-secondary hover:bg-lane-grey disabled:cursor-not-allowed disabled:opacity-60 disabled:hover:bg-transparent";

// The second choice in the menu. It asks whether the extended checks can run here, and when
// they cannot it says why and what to do, instead of failing later.
function FullScanItem({
  onPick,
  onImport,
}: {
  onPick: () => void;
  onImport: () => void;
}) {
  const [status] = useAsync(() => api.extendedStatus());
  const ready = status.status === "success" && status.data.available;
  return (
    <div>
      <button
        type="button"
        role="menuitem"
        disabled={!ready}
        onClick={onPick}
        className={MENU_ITEM}
      >
        <span className="font-semibold">Run full scan (adds extended checks)</span>
        <span className="text-dim">
          Also runs a second scanner. It can take several minutes. Its results are
          labelled Imported.
        </span>
      </button>
      {status.status === "loading" && (
        <p className="px-3 pb-2 text-secondary text-dim">
          Checking whether it can run here...
        </p>
      )}
      {status.status === "error" && (
        <p role="note" className="px-3 pb-2 text-secondary font-semibold text-red">
          Could not check: {status.message}
        </p>
      )}
      {status.status === "success" && !status.data.available && (
        <div role="note" className="px-3 pb-2 text-secondary">
          <p>
            <span className="font-semibold">{status.data.reason}</span>{" "}
            <span className="text-dim">{status.data.hint}</span>
          </p>
          {status.data.blocked && (
            <button
              type="button"
              onClick={onImport}
              className={`${SECONDARY_BUTTON} mt-2`}
            >
              Import a results file
            </button>
          )}
        </div>
      )}
    </div>
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
  const [open, setOpen] = useState(false);
  const { openImport } = useScans();
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const away = (event: MouseEvent) => {
      if (!box.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  function pick(extended: boolean) {
    setOpen(false);
    runner.start(extended);
  }

  function importFile() {
    setOpen(false);
    openImport();
  }

  return (
    <div
      ref={box}
      className="relative inline-flex"
      onKeyDown={(event) => event.key === "Escape" && setOpen(false)}
    >
      <button
        type="button"
        onClick={() => pick(false)}
        disabled={running}
        className={`${SPLIT} rounded-l-chip px-6`}
      >
        {running && <Spinner />}
        {running ? "Scanning..." : label}
      </button>
      <button
        type="button"
        aria-label="More ways to scan"
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={running}
        onClick={() => setOpen(!open)}
        className={`${SPLIT} rounded-r-chip border-l-2 border-paper px-3`}
      >
        <Icon name="chevron" size={18} className={open ? "rotate-180" : ""} />
      </button>
      {open && !running && (
        <div
          role="menu"
          aria-label="Ways to scan"
          className="absolute top-full right-0 z-30 mt-2 w-[min(22rem,90vw)] rounded-lane border-2 border-ink bg-white p-2"
        >
          <button
            type="button"
            role="menuitem"
            onClick={() => pick(false)}
            className={MENU_ITEM}
          >
            <span className="font-semibold">Run scan</span>
            <span className="text-dim">CloudShield&apos;s own checks. Quick.</span>
          </button>
          <FullScanItem onPick={() => pick(true)} onImport={importFile} />
          <button
            type="button"
            role="menuitem"
            onClick={importFile}
            className={MENU_ITEM}
          >
            <span className="font-semibold">Import a results file</span>
            <span className="text-dim">
              Add the results of a scan you ran somewhere else. Labelled Imported.
            </span>
          </button>
        </div>
      )}
    </div>
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
