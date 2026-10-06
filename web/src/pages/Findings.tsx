import { Link, useSearchParams } from "react-router-dom";
import { api, SEVERITIES, type FindingOut } from "../api";
import { Icon } from "../components/Icon";
import {
  AsyncView,
  EmptyState,
  FIELD,
  PageTitle,
  SelectField,
  statusText,
  Tag,
  useMountValue,
} from "../components/ui";
import { formatDate, formatRelative, plural, ruleOptions } from "../format";
import {
  byScoreDescending,
  countLanes,
  LANE_DOT,
  LANE_NAME,
  LANES,
  laneOf,
  shortResource,
  type Lane,
} from "../lanes";
import { useRefreshWhenScanEnds } from "../ScanContext";
import { useAsync } from "../useAsync";

// The header and every row use this one definition, so the columns always line up:
// lane dot, Risk, Finding, Rule, Status, Last seen, arrow.
export const FINDINGS_GRID =
  "grid grid-cols-[20px_88px_minmax(0,1fr)_200px_112px_120px_28px] items-center gap-4";

export interface Filters {
  q: string;
  severity: string;
  lane: Lane | "open" | "all";
  rule: string;
  type: string;
  sort: "risk" | "seen";
  order: "desc" | "asc";
}

function readFilters(params: URLSearchParams): Filters {
  const lane = params.get("lane");
  return {
    q: params.get("q") ?? "",
    severity: params.get("severity") ?? "",
    lane: LANES.includes(lane as Lane) ? (lane as Lane) : lane === "all" ? "all" : "open",
    rule: params.get("rule") ?? "",
    type: params.get("type") ?? "",
    sort: params.get("sort") === "seen" ? "seen" : "risk",
    order: params.get("order") === "asc" ? "asc" : "desc",
  };
}

export function applyFilters(rows: FindingOut[], filters: Filters): FindingOut[] {
  const needle = filters.q.trim().toLowerCase();
  const matching = rows.filter((row) => {
    if (filters.lane === "open" && row.status !== "OPEN") return false;
    if (
      filters.lane !== "all" &&
      filters.lane !== "open" &&
      laneOf(row) !== filters.lane
    ) {
      return false;
    }
    if (filters.severity && row.severity !== filters.severity) return false;
    if (filters.rule && row.rule_id !== filters.rule) return false;
    if (filters.type && row.resource_type !== filters.type) return false;
    if (!needle) return true;
    const text = [
      row.title,
      row.rule_id,
      row.resource_id,
      row.resource_type,
      row.category,
    ];
    return text.join(" ").toLowerCase().includes(needle);
  });
  // Resolved findings always come after every open one.
  return [
    ...sortRows(
      matching.filter((r) => r.status === "OPEN"),
      filters,
    ),
    ...sortRows(
      matching.filter((r) => r.status === "RESOLVED"),
      filters,
    ),
  ];
}

function sortRows(
  rows: FindingOut[],
  filters: Pick<Filters, "sort" | "order">,
): FindingOut[] {
  if (filters.sort === "seen") {
    const newest = [...rows].sort(
      (a, b) => new Date(b.last_seen_at).getTime() - new Date(a.last_seen_at).getTime(),
    );
    return filters.order === "desc" ? newest : newest.reverse();
  }
  const sorted = [...rows].sort(byScoreDescending);
  if (filters.order === "desc") return sorted;
  // Lowest score first, but findings without a score are still last.
  const scored = sorted.filter((r) => r.risk_score !== null).reverse();
  return [...scored, ...sorted.filter((r) => r.risk_score === null)];
}

export function Findings() {
  const [state, reload] = useAsync(() => api.findings());
  useRefreshWhenScanEnds(reload);
  const [params, setParams] = useSearchParams();
  const filters = readFilters(params);

  function change(name: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(name, value);
    else next.delete(name);
    setParams(next, { replace: true });
  }

  // Pressing the heading of the column that is already sorted flips the direction.
  function sortBy(sort: Filters["sort"]) {
    const next = new URLSearchParams(params);
    const flip = filters.sort === sort && filters.order === "desc";
    if (sort === "risk") next.delete("sort");
    else next.set("sort", sort);
    if (flip) next.set("order", "asc");
    else next.delete("order");
    setParams(next, { replace: true });
  }

  return (
    <AsyncView state={state} onRetry={reload} label="Loading findings" shape="table">
      {(rows) => {
        if (rows.length === 0) {
          return (
            <>
              <PageTitle>No findings yet.</PageTitle>
              <EmptyState title="Nothing to show">
                Run a scan with the button at the top. Findings appear here once a scan
                has completed.
              </EmptyState>
            </>
          );
        }
        const counts = countLanes(rows);
        const open = rows.length - counts.done;
        const visible = applyFilters(rows, filters);
        const types = [...new Set(rows.map((r) => r.resource_type))].sort();
        return (
          <>
            <PageTitle
              sub={`${open} open, ${counts.done} fixed. Ordered by what to fix first.`}
            >
              {plural(rows.length, "finding", "findings")}.
            </PageTitle>

            <div className="mb-6 flex flex-wrap gap-2" role="group" aria-label="Lane">
              <LaneChip
                label="Open"
                count={open}
                pressed={filters.lane === "open"}
                onClick={() => change("lane", "")}
              />
              {LANES.map((lane) => (
                <LaneChip
                  key={lane}
                  lane={lane}
                  label={LANE_NAME[lane]}
                  count={counts[lane]}
                  pressed={filters.lane === lane}
                  onClick={() => change("lane", lane)}
                />
              ))}
              <LaneChip
                label="All"
                count={rows.length}
                pressed={filters.lane === "all"}
                onClick={() => change("lane", "all")}
              />
            </div>

            <div className="mb-8 flex flex-wrap items-end gap-4">
              <label className="flex flex-col gap-1 text-label font-semibold">
                Search
                <input
                  type="search"
                  value={filters.q}
                  onChange={(e) => change("q", e.target.value)}
                  placeholder="Title, rule or resource"
                  className={`${FIELD} min-w-[240px]`}
                />
              </label>
              <SelectField
                label="Severity"
                value={filters.severity}
                onChange={(v) => change("severity", v)}
                options={[
                  ["", "All severities"],
                  ...SEVERITIES.map((s): [string, string] => [s, s]),
                ]}
              />
              <SelectField
                label="Rule"
                value={filters.rule}
                onChange={(v) => change("rule", v)}
                options={[
                  ["", "All rules"],
                  ...ruleOptions(rows).map((r): [string, string] => [r, r]),
                ]}
              />
              <SelectField
                label="Resource type"
                value={filters.type}
                onChange={(v) => change("type", v)}
                options={[
                  ["", "All types"],
                  ...types.map((t): [string, string] => [t, t]),
                ]}
              />
            </div>

            <p
              role="status"
              className="mb-2 flex flex-wrap items-center gap-4 text-secondary text-dim"
            >
              Showing {visible.length} of {rows.length} findings
              {params.toString() !== "" && (
                <button
                  type="button"
                  className="font-semibold text-ink underline"
                  onClick={() => setParams({})}
                >
                  Clear filters
                </button>
              )}
            </p>
            {visible.length === 0 ? (
              <EmptyState title="No findings match these filters" />
            ) : (
              <FindingsTable rows={visible} filters={filters} onSort={sortBy} />
            )}
          </>
        );
      }}
    </AsyncView>
  );
}

function LaneChip({
  lane,
  label,
  count,
  pressed,
  onClick,
}: {
  lane?: Lane;
  label: string;
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
      {lane && (
        <span
          aria-hidden="true"
          className={`h-2.5 w-2.5 rounded-full ${LANE_DOT[lane]} ${pressed ? "ring-2 ring-white" : ""}`}
        />
      )}
      {label}
      <span className="font-mono tabular-nums">{count}</span>
    </button>
  );
}

function SortHeader({
  label,
  sort,
  filters,
  onSort,
}: {
  label: string;
  sort: Filters["sort"];
  filters: Filters;
  onSort: (sort: Filters["sort"]) => void;
}) {
  const active = filters.sort === sort;
  const direction = active
    ? filters.order === "desc"
      ? "descending"
      : "ascending"
    : "none";
  return (
    <span role="columnheader" aria-sort={direction}>
      <button
        type="button"
        onClick={() => onSort(sort)}
        className="inline-flex min-h-11 items-center gap-1 text-label font-semibold whitespace-nowrap"
      >
        {label}
        <Icon
          name={active && filters.order === "asc" ? "arrow-up" : "arrow-down"}
          size={14}
        />
      </button>
    </span>
  );
}

function FindingsTable({
  rows,
  filters,
  onSort,
}: {
  rows: FindingOut[];
  filters: Filters;
  onSort: (sort: Filters["sort"]) => void;
}) {
  return (
    <div className="max-h-[75vh] overflow-auto rounded-lane border-2 border-ink bg-white">
      <div role="table" aria-label="Findings" className="min-w-[900px]">
        <div
          role="row"
          data-testid="findings-header"
          className={`${FINDINGS_GRID} sticky top-0 z-10 border-b border-ink bg-white px-4`}
        >
          <span role="columnheader" className="sr-only">
            Lane
          </span>
          <SortHeader label="Risk" sort="risk" filters={filters} onSort={onSort} />
          <span role="columnheader" className="text-label font-semibold">
            Finding
          </span>
          <span role="columnheader" className="text-label font-semibold">
            Rule
          </span>
          <span role="columnheader" className="text-label font-semibold">
            Status
          </span>
          <SortHeader label="Last seen" sort="seen" filters={filters} onSort={onSort} />
          <span role="columnheader" className="sr-only">
            Open
          </span>
        </div>
        {rows.map((row, index) => (
          <Row key={row.finding_id} row={row} index={index} />
        ))}
      </div>
    </div>
  );
}

function Row({ row, index }: { row: FindingOut; index: number }) {
  const delay = useMountValue(index * 50);
  const lane = laneOf(row);
  return (
    <div
      role="row"
      data-muted={row.severity === "INFO"}
      data-lane={lane}
      className={`board-row rise ${FINDINGS_GRID} relative border-t border-divider px-4 py-3 first:border-t-0`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <span role="cell">
        <span
          aria-hidden="true"
          className={`block h-3 w-3 rounded-full ${LANE_DOT[lane]}`}
        />
        <span className="sr-only">{LANE_NAME[lane]}</span>
      </span>
      <span
        role="cell"
        className="font-display text-score-row leading-none font-extrabold tabular-nums"
      >
        {row.risk_score ?? "-"}
      </span>
      <span role="cell" className="min-w-0">
        <Link
          to={`/findings/${encodeURIComponent(row.finding_id)}`}
          className="font-display text-title leading-tight font-bold after:absolute after:inset-0 after:content-['']"
        >
          {row.title}
        </Link>
        <span className="block truncate font-mono text-label" title={row.resource_id}>
          {shortResource(row.resource_id)}
        </span>
      </span>
      <span role="cell">
        <Tag>{row.rule_id}</Tag>
      </span>
      <span role="cell" className="text-secondary font-semibold">
        {statusText(row.status)}
      </span>
      <span role="cell" className="text-secondary" title={formatDate(row.last_seen_at)}>
        {formatRelative(row.last_seen_at)}
      </span>
      <span role="cell" aria-hidden="true">
        <Icon name="arrow" size={20} className="arrow" />
      </span>
    </div>
  );
}
