import { useState } from "react";
import { api, type ScanOut } from "../api";
import { Icon } from "../components/Icon";
import { Tooltip } from "../components/Tooltip";
import {
  AsyncView,
  EmptyState,
  PageTitle,
  StatusChip,
  useMountValue,
} from "../components/ui";
import {
  ENVIRONMENT_HELP,
  formatDate,
  formatRelative,
  plural,
  scanDuration,
} from "../format";
import { useRefreshWhenScanEnds } from "../ScanContext";
import { useAsync } from "../useAsync";

// The header and every row use this one definition, so the columns always line up:
// Scan, Status, Started, Duration, Regions, Resources, Findings, Errors.
export const SCANS_GRID =
  "grid grid-cols-[64px_136px_minmax(0,1.3fr)_88px_minmax(0,1fr)_104px_96px_88px] items-center gap-4";

export function Scans() {
  const [state, reload] = useAsync(() => api.scans());
  useRefreshWhenScanEnds(reload);

  return (
    <AsyncView state={state} onRetry={reload} label="Loading scans" shape="table">
      {(scans) =>
        scans.length === 0 ? (
          <>
            <PageTitle>No scans yet.</PageTitle>
            <EmptyState title="Nothing to show">
              Start one with the button at the top.
            </EmptyState>
          </>
        ) : (
          <>
            <PageTitle sub="Every scan, newest first.">
              {plural(scans.length, "scan", "scans")}.
            </PageTitle>
            <LatestSummary scan={scans[0]} />
            <ScansTable scans={scans} />
          </>
        )
      }
    </AsyncView>
  );
}

function LatestSummary({ scan }: { scan: ScanOut }) {
  const finished = scan.finished_at ? `, ${formatRelative(scan.finished_at)}` : "";
  return (
    <p
      data-testid="latest-scan"
      className="mb-6 flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-divider pb-6 text-body"
    >
      <span className="font-semibold">Latest: Scan {scan.id}</span>
      <StatusChip status={scan.status} />
      <span className="text-dim">
        {scan.status === "completed" || scan.status === "failed"
          ? `Took ${scanDuration(scan)}${finished}. `
          : `${scan.progress}. `}
        {plural(scan.resource_count, "resource", "resources")},{" "}
        {plural(scan.error_count, "error", "errors")}.
      </span>
    </p>
  );
}

function ScansTable({ scans }: { scans: ScanOut[] }) {
  const heading = "text-label font-semibold";
  return (
    <div className="max-h-[75vh] overflow-auto rounded-lane border-2 border-ink bg-white">
      <div role="table" aria-label="Scans" className="min-w-[960px]">
        <div
          role="row"
          data-testid="scans-header"
          className={`${SCANS_GRID} sticky top-0 z-10 border-b border-ink bg-white px-4 py-3`}
        >
          {[
            "Scan",
            "Status",
            "Started",
            "Duration",
            "Regions",
            "Resources",
            "Findings",
            "Errors",
          ].map((name) => (
            <span key={name} role="columnheader" className={heading}>
              {name}
            </span>
          ))}
        </div>
        {scans.map((scan, index) => (
          <ScanRow key={scan.id} scan={scan} index={index} />
        ))}
      </div>
    </div>
  );
}

function ScanRow({ scan, index }: { scan: ScanOut; index: number }) {
  const delay = useMountValue(index * 50);
  const hasDetails = scan.errors.length > 0 || scan.failure_message !== null;
  // A failed scan opens by default so the reason is the first thing seen.
  const [open, setOpen] = useState(scan.status === "failed");
  const inProgress = scan.status === "queued" || scan.status === "running";
  return (
    <div
      className="rise border-t border-divider first:border-t-0"
      style={{ animationDelay: `${delay}ms` }}
    >
      <div role="row" className={`${SCANS_GRID} px-4 py-3 text-secondary`}>
        <span role="cell" className="font-display text-title font-bold">
          {scan.id}
        </span>
        <span role="cell">
          <StatusChip status={scan.status} />
          {inProgress && <span className="mt-1 block">{scan.progress}</span>}
        </span>
        <span role="cell" title={formatDate(scan.started_at)}>
          <span className="block font-semibold">{formatDate(scan.started_at)}</span>
          <span className="block text-label text-dim">
            {formatRelative(scan.started_at)}
          </span>
        </span>
        <span role="cell">{scanDuration(scan)}</span>
        <span role="cell" className="min-w-0 truncate" title={scan.regions.join(", ")}>
          {scan.regions.join(", ")}
        </span>
        <span role="cell">{scan.resource_count}</span>
        <span role="cell">{scan.finding_count}</span>
        <span role="cell">
          {hasDetails ? (
            <button
              type="button"
              aria-expanded={open}
              aria-label={`Details of scan ${scan.id}: ${plural(scan.errors.length, "error", "errors")}`}
              onClick={() => setOpen(!open)}
              className="inline-flex min-h-11 items-center gap-1 font-semibold underline"
            >
              {scan.errors.length}
              <Icon name="chevron" size={16} className={open ? "rotate-180" : ""} />
            </button>
          ) : (
            scan.error_count
          )}
        </span>
      </div>
      {hasDetails && open && (
        <div className="space-y-3 px-4 pb-4 text-secondary">
          {scan.failure_message && (
            <p role="alert" className="font-semibold text-red">
              Failed: {scan.failure_message}
            </p>
          )}
          {scan.errors.length > 0 && (
            <ul aria-label={`Errors in scan ${scan.id}`} className="space-y-2">
              {scan.errors.map((error, errorIndex) => (
                <li key={errorIndex} className="rounded-chip bg-paper p-3">
                  <span className="font-semibold">
                    {error.service}
                    {error.region ? ` in ${error.region}` : ""}
                    {error.resource ? `, ${error.resource}` : ""}
                  </span>
                  <span className="block break-words">{error.message}</span>
                </li>
              ))}
            </ul>
          )}
          {scan.environment_score !== null && (
            <p>
              <Tooltip text={ENVIRONMENT_HELP}>Combined score</Tooltip>{" "}
              <span className="font-mono text-label">{scan.environment_score}</span>
            </p>
          )}
        </div>
      )}
    </div>
  );
}
