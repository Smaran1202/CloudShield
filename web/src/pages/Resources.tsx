import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, type FindingOut, type ResourceOut, type ScanOut } from "../api";
import { Icon, iconForResource } from "../components/Icon";
import { ImportedResources } from "../components/ImportedSections";
import { AsyncView, EmptyState, FIELD, PageTitle, useMountValue } from "../components/ui";
import { formatDate, formatRelative, plural } from "../format";
import {
  byScoreDescending,
  LANE_DOT,
  LANE_NAME,
  laneOf,
  shortResource,
  type Lane,
} from "../lanes";
import { useRefreshWhenScanEnds, useScans } from "../ScanContext";
import { useAsync } from "../useAsync";

// The header and every row use this one definition, so the columns always line up:
// Name, Type, Region, Findings, Highest risk, Last seen.
export const RESOURCES_GRID =
  "grid grid-cols-[minmax(0,1fr)_168px_144px_120px_120px_128px] items-center gap-4";

interface ResourceRowData {
  resource: ResourceOut;
  openCount: number;
  worst: FindingOut | null;
  lastSeen: string | null;
}

export function rowData(
  resources: ResourceOut[],
  findings: FindingOut[],
  scans: ScanOut[],
): ResourceRowData[] {
  return resources.map((resource) => {
    const open = findings.filter(
      (f) => f.resource_id === resource.resource_id && f.status === "OPEN",
    );
    const scored = open.filter((f) => f.risk_score !== null).sort(byScoreDescending);
    const scan = scans.find((s) => s.id === resource.last_seen_scan_id);
    return {
      resource,
      openCount: open.length,
      worst: scored[0] ?? null,
      lastSeen: scan?.finished_at ?? null,
    };
  });
}

export function Resources() {
  const [state, reload] = useAsync(async () => {
    const [resources, findings] = await Promise.all([api.resources(), api.findings()]);
    return { resources, findings };
  });
  useRefreshWhenScanEnds(reload);
  const { scans } = useScans();
  const scanList = scans.status === "success" ? scans.data : [];
  const [type, setType] = useState("");
  const [query, setQuery] = useState("");

  return (
    <>
      <AsyncView state={state} onRetry={reload} label="Loading resources" shape="table">
        {({ resources, findings }) => {
          if (resources.length === 0) {
            return (
              <>
                <PageTitle>No resources yet.</PageTitle>
                <EmptyState title="Nothing to show">
                  Run a scan with the button at the top to collect them.
                </EmptyState>
              </>
            );
          }
          const types = [...new Set(resources.map((r) => r.resource_type))].sort();
          const needle = query.trim().toLowerCase();
          const all = rowData(resources, findings, scanList);
          const visible = all.filter(
            ({ resource: r }) =>
              (!type || r.resource_type === type) &&
              (!needle || `${r.name} ${r.resource_id}`.toLowerCase().includes(needle)),
          );
          return (
            <>
              <PageTitle sub="The latest known state of what the scanner found in your account.">
                {plural(resources.length, "resource", "resources")}.
              </PageTitle>
              <div
                className="mb-6 flex flex-wrap gap-2"
                role="group"
                aria-label="Resource type"
              >
                <TypeChip
                  label="All"
                  count={resources.length}
                  pressed={type === ""}
                  onClick={() => setType("")}
                />
                {types.map((t) => (
                  <TypeChip
                    key={t}
                    label={t}
                    icon={<Icon name={iconForResource(t)} size={18} />}
                    count={resources.filter((r) => r.resource_type === t).length}
                    pressed={type === t}
                    onClick={() => setType(t)}
                  />
                ))}
              </div>
              <div className="mb-8 flex flex-wrap items-end gap-4">
                <label className="flex flex-col gap-1 text-label font-semibold">
                  Search
                  <input
                    type="search"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Name or id"
                    className={`${FIELD} min-w-[240px]`}
                  />
                </label>
              </div>
              <p role="status" className="mb-2 text-secondary text-dim">
                Showing {visible.length} of {resources.length} resources
              </p>
              {visible.length === 0 ? (
                <EmptyState title="No resources match these filters" />
              ) : (
                <ResourceTable rows={visible} />
              )}
            </>
          );
        }}
      </AsyncView>
      <ImportedResources />
    </>
  );
}

function TypeChip({
  label,
  icon,
  count,
  pressed,
  onClick,
}: {
  label: string;
  icon?: ReactNode;
  count: number;
  pressed: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      className={`inline-flex min-h-11 items-center gap-2 rounded-chip border-2 border-ink px-4 text-secondary font-semibold ${
        pressed ? "bg-ink text-white" : "bg-white text-ink hover:bg-lane-grey"
      }`}
    >
      {icon}
      {label}
      <span className="font-mono tabular-nums">{count}</span>
    </button>
  );
}

function ResourceTable({ rows }: { rows: ResourceRowData[] }) {
  const heading = "text-label font-semibold";
  return (
    <div className="max-h-[75vh] overflow-auto rounded-lane border-2 border-ink bg-white">
      <div role="table" aria-label="Resources" className="min-w-[900px]">
        <div
          role="row"
          data-testid="resources-header"
          className={`${RESOURCES_GRID} sticky top-0 z-10 border-b border-ink bg-white px-4 py-3`}
        >
          <span role="columnheader" className={heading}>
            Name
          </span>
          <span role="columnheader" className={heading}>
            Type
          </span>
          <span role="columnheader" className={heading}>
            Region
          </span>
          <span role="columnheader" className={heading}>
            Findings
          </span>
          <span role="columnheader" className={heading}>
            Highest risk
          </span>
          <span role="columnheader" className={heading}>
            Last seen
          </span>
        </div>
        {rows.map((data, index) => (
          <Row key={data.resource.resource_id} data={data} index={index} />
        ))}
      </div>
    </div>
  );
}

function Row({ data, index }: { data: ResourceRowData; index: number }) {
  const delay = useMountValue(index * 50);
  const { resource, openCount, worst, lastSeen } = data;
  const lane: Lane | null = worst ? laneOf(worst) : null;
  return (
    <div
      role="row"
      className={`board-row rise ${RESOURCES_GRID} relative border-t border-divider px-4 py-3 first:border-t-0`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <span role="cell" className="min-w-0">
        <Link
          to={`/resources/${encodeURIComponent(resource.resource_id)}`}
          className="font-display text-title leading-tight font-bold after:absolute after:inset-0 after:content-['']"
        >
          {resource.name}
        </Link>
        <span
          className="block truncate font-mono text-label"
          title={resource.resource_id}
        >
          {shortResource(resource.resource_id)}
        </span>
      </span>
      <span role="cell" className="flex items-center gap-2 text-secondary">
        <Icon name={iconForResource(resource.resource_type)} size={18} />
        {resource.resource_type}
      </span>
      <span role="cell" className="text-secondary">
        {resource.region ?? "global"}
      </span>
      <span role="cell" className="flex items-center gap-2 text-secondary font-semibold">
        {lane && (
          <>
            <span
              aria-hidden="true"
              className={`h-3 w-3 rounded-full ${LANE_DOT[lane]}`}
            />
            <span className="sr-only">{LANE_NAME[lane]}</span>
          </>
        )}
        {openCount === 0 ? "-" : openCount}
      </span>
      <span
        role="cell"
        className="font-display text-h3 leading-none font-extrabold tabular-nums"
      >
        {worst?.risk_score ?? "-"}
      </span>
      <span role="cell" className="text-secondary" title={formatDate(lastSeen)}>
        {formatRelative(lastSeen)}
      </span>
    </div>
  );
}
