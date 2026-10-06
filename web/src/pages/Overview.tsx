import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  api,
  type EvidenceItem,
  type FindingOut,
  type RiskSummaryOut,
  type ScanOut,
} from "../api";
import { CopyButton } from "../components/CopyButton";
import { Icon } from "../components/Icon";
import { Tooltip } from "../components/Tooltip";
import {
  AsyncView,
  Card,
  Check,
  EmptyState,
  PRIMARY_BUTTON,
  SectionTitle,
  SeverityChip,
  Tag,
  useMountValue,
} from "../components/ui";
import {
  ENVIRONMENT_HELP,
  formatDate,
  formatRelative,
  plural,
  scanDuration,
} from "../format";
import {
  byScoreDescending,
  countLanes,
  highestRiskOpen,
  LANE_BACKGROUND,
  LANE_EMPTY,
  LANE_HINT,
  LANE_NAME,
  LANE_THRESHOLDS,
  laneOf,
  shortResource,
  type Lane,
} from "../lanes";
import { useRefreshWhenScanEnds, useScans } from "../ScanContext";
import { useAsync } from "../useAsync";

const HEADLINE =
  "font-display text-display leading-[0.95] font-extrabold tracking-[-0.045em]";

const CHART_BARS = 8;
const CHART_HEIGHT = 128;

function MaskLine({ children, delay }: { children: string; delay: number }) {
  return (
    <span className="mask-line">
      <span style={{ animationDelay: `${delay}ms` }}>{children}</span>
    </span>
  );
}

export function Overview() {
  const { scans, reloadScans } = useScans();
  return (
    <AsyncView state={scans} onRetry={reloadScans} label="Loading scans" shape="board">
      {(list) => <OverviewBody scans={list} />}
    </AsyncView>
  );
}

function OverviewBody({ scans }: { scans: ScanOut[] }) {
  const latest = scans[0];
  if (!scans.some((s) => s.status === "completed")) {
    return (
      <div>
        <h1 className={HEADLINE}>
          <MaskLine delay={0}>No scan yet. Run a scan.</MaskLine>
        </h1>
        <p
          className="rise mt-6 max-w-2xl text-body text-dim"
          style={{ animationDelay: "300ms" }}
        >
          {latest
            ? "Nothing has completed yet, so there are no results to show."
            : "CloudShield only shows results from a real scan of your account."}
        </p>
        {latest?.failure_message && (
          <p role="alert" className="mt-4 text-body font-semibold text-red">
            The last scan failed: {latest.failure_message}
          </p>
        )}
      </div>
    );
  }
  return <Board scans={scans} />;
}

function Board({ scans }: { scans: ScanOut[] }) {
  const [findings, reloadFindings] = useAsync(() => api.findings());
  const [summary, reloadSummary] = useAsync(() => api.riskSummary());
  useRefreshWhenScanEnds(() => {
    reloadFindings();
    reloadSummary();
  });

  return (
    <div className="space-y-16">
      <AsyncView
        state={findings}
        onRetry={reloadFindings}
        label="Loading findings"
        shape="board"
      >
        {(rows) => <BoardBody rows={rows} scans={scans} />}
      </AsyncView>
      <LastScanFacts scan={scans[0]} summary={summary} />
    </div>
  );
}

// "3 verified, 1 unknown": how much of the evidence was read straight from AWS.
export function certaintySummary(items: EvidenceItem[]): string {
  const parts = (["verified", "heuristic", "unknown"] as const)
    .map(
      (kind) => [items.filter((item) => item.certainty === kind).length, kind] as const,
    )
    .filter(([count]) => count > 0)
    .map(([count, kind]) => `${count} ${kind}`);
  return parts.length > 0 ? parts.join(", ") : "No evidence stored yet";
}

function BoardBody({ rows, scans }: { rows: FindingOut[]; scans: ScanOut[] }) {
  const counts = countLanes(rows);
  const open = rows.filter((r) => r.status === "OPEN");
  const top = highestRiskOpen(rows);
  const scoredOpen = open.filter((r) => r.risk_score !== null).sort(byScoreDescending);
  const inLane = (lane: Lane) => scoredOpen.filter((r) => laneOf(r) === lane);
  const noScore = open.filter((r) => r.risk_score === null);
  const resolved = rows.filter((r) => r.status === "RESOLVED");
  const fallback =
    open.length > 0 ? "Only informational findings are open." : "Nothing is open.";

  return (
    <div className="space-y-16">
      <div
        data-testid="hero"
        className={`grid gap-12 ${top ? "min-[1100px]:grid-cols-[1.4fr_1fr]" : ""}`}
      >
        <div>
          <h1 className={HEADLINE}>
            <MaskLine delay={0}>{`${resolved.length} fixed.`}</MaskLine>
            <MaskLine delay={130}>{`${open.length} to go.`}</MaskLine>
          </h1>
          <p className="rise mt-6 text-h3" style={{ animationDelay: "400ms" }}>
            {top ? (
              <>
                Start with{" "}
                <Link
                  to={`/findings/${encodeURIComponent(top.finding_id)}`}
                  className="font-bold underline decoration-2 underline-offset-4"
                >
                  {top.title}
                </Link>
                .
              </>
            ) : (
              fallback
            )}
          </p>
          <p
            className="rise mt-3 max-w-3xl text-secondary text-dim"
            style={{ animationDelay: "500ms" }}
          >
            Fix now is a risk score of {LANE_THRESHOLDS.fixNow} or more, Next is{" "}
            {LANE_THRESHOLDS.next} to {LANE_THRESHOLDS.fixNow - 1}, and Later is below{" "}
            {LANE_THRESHOLDS.next}. CloudShield never changes your AWS account: you apply
            every fix yourself.
          </p>
        </div>
        {top && <FixNextCard finding={top} />}
      </div>

      <div className="flex flex-wrap items-start gap-6">
        <LaneColumn lane="now" count={counts.now} delay={450} pulse={counts.now > 0}>
          {inLane("now").map((f, i) => (
            <Tile key={f.finding_id} finding={f} lane="now" index={i} />
          ))}
        </LaneColumn>
        <LaneColumn lane="next" count={counts.next} delay={600}>
          {inLane("next").map((f, i) => (
            <Tile key={f.finding_id} finding={f} lane="next" index={i} />
          ))}
        </LaneColumn>
        <LaneColumn
          lane="later"
          count={counts.later}
          delay={750}
          extra={
            noScore.length > 0 && (
              <li className="rounded-chip border-2 border-dashed border-dash p-4 text-secondary">
                {noScore.length === 1
                  ? "1 informational finding with no risk score."
                  : `${noScore.length} informational findings with no risk score.`}{" "}
                <Link to="/findings?lane=later" className="font-semibold underline">
                  See them
                </Link>
              </li>
            )
          }
        >
          {inLane("later").map((f, i) => (
            <Tile key={f.finding_id} finding={f} lane="later" index={i} />
          ))}
        </LaneColumn>
      </div>

      <DoneStrip resolved={resolved} />

      <div className="grid items-start gap-12 min-[900px]:grid-cols-2">
        <ProgressCard resolved={resolved} total={rows.length} />
        <ScansChart scans={scans} />
      </div>
    </div>
  );
}

function FixNextCard({ finding }: { finding: FindingOut }) {
  const lane = laneOf(finding);
  return (
    <section
      aria-label="Fix next"
      className="rise self-start rounded-lane border-2 border-ink bg-white p-6"
      style={{ animationDelay: "300ms" }}
    >
      <h2 className="text-label font-semibold tracking-wide text-dim uppercase">
        Fix next
      </h2>
      <div className="mt-4 flex gap-6">
        <div
          data-lane={lane}
          className={`flex h-[140px] w-[140px] shrink-0 items-center justify-center rounded-lane ${LANE_BACKGROUND[lane]}`}
        >
          <span className="font-display text-score-tile leading-none font-extrabold tabular-nums">
            {finding.risk_score}
          </span>
        </div>
        <div className="min-w-0">
          <h3 className="font-display text-title leading-tight font-bold">
            {finding.title}
          </h3>
          <p
            className="mt-2 truncate font-mono text-label text-dim"
            title={finding.resource_id}
          >
            {shortResource(finding.resource_id)}
          </p>
          <p className="mt-3 text-secondary">
            {certaintySummary(finding.evidence.items)}
          </p>
        </div>
      </div>
      <Link
        to={`/findings/${encodeURIComponent(finding.finding_id)}?tab=fix`}
        className={`mt-6 ${PRIMARY_BUTTON}`}
      >
        Open fix <Icon name="arrow" size={18} />
      </Link>
    </section>
  );
}

function LaneColumn({
  lane,
  count,
  delay,
  pulse = false,
  extra,
  children,
}: {
  lane: Lane;
  count: number;
  delay: number;
  pulse?: boolean;
  extra?: ReactNode;
  children: ReactNode[];
}) {
  const empty = children.length === 0 && !extra;
  return (
    <section
      aria-label={LANE_NAME[lane]}
      className={`rise flex-[1_1_300px] self-start rounded-lane p-6 ${LANE_BACKGROUND[lane]}`}
      style={{ animationDelay: `${delay}ms` }}
    >
      <header className="flex items-center gap-3">
        <h2 className="font-display text-h2 leading-none font-extrabold">
          {LANE_NAME[lane]}
        </h2>
        <span className="font-display text-h2 leading-none font-extrabold tabular-nums">
          {count}
        </span>
        {pulse && (
          <span aria-hidden="true" className="pulse-dot h-3 w-3 rounded-full bg-white" />
        )}
      </header>
      <p className="mt-1 mb-6 text-secondary font-medium">{LANE_HINT[lane]}</p>
      <ul className="flex flex-col gap-4">
        {children}
        {extra}
        {empty && <li className="text-secondary font-medium">{LANE_EMPTY[lane]}</li>}
      </ul>
    </section>
  );
}

function Tile({
  finding,
  lane,
  index,
}: {
  finding: FindingOut;
  lane: Lane;
  index: number;
}) {
  const delay = useMountValue(550 + 120 * index);
  const big = lane === "now";
  return (
    <li
      className="tile rise relative rounded-chip border-2 border-ink bg-paper p-6 text-ink"
      style={{ animationDelay: `${delay}ms` }}
    >
      <span
        className={`block font-display leading-none font-extrabold tabular-nums ${
          big ? "text-score-lane" : "text-score-tile"
        }`}
      >
        {finding.risk_score}
      </span>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Tag>{finding.rule_id}</Tag>
        <SeverityChip severity={finding.severity} />
      </div>
      <h3 className="mt-3 line-clamp-3 font-display text-title leading-tight font-bold">
        <Link
          to={`/findings/${encodeURIComponent(finding.finding_id)}`}
          className="after:absolute after:inset-0 after:content-['']"
        >
          {finding.title}
        </Link>
      </h3>
      <div className="mt-2 flex items-center gap-1">
        <span
          className="min-w-0 flex-1 truncate font-mono text-label text-dim"
          title={finding.resource_id}
        >
          {shortResource(finding.resource_id)}
        </span>
        <CopyButton text={finding.resource_id} label={`Copy ${finding.resource_id}`} />
      </div>
      <span
        aria-hidden="true"
        className="mt-3 inline-flex items-center gap-2 text-secondary font-semibold"
      >
        Open fix <Icon name="arrow" size={18} className="arrow" />
      </span>
    </li>
  );
}

function DoneStrip({ resolved }: { resolved: FindingOut[] }) {
  if (resolved.length === 0) return null;
  const latest = latestResolved(resolved);
  return (
    <section
      aria-label="Done"
      className="done-strip flex flex-wrap items-center gap-4 rounded-lane bg-green p-6 text-white"
    >
      <Check size={36} />
      <div className="min-w-0 flex-1">
        <p className="font-display text-h3 font-extrabold">Fixed: {latest.title}</p>
        <p className="truncate font-mono text-label" title={latest.resource_id}>
          {shortResource(latest.resource_id)}, resolved {formatDate(latest.resolved_at)}
        </p>
      </div>
      <Link
        to={`/findings/${encodeURIComponent(latest.finding_id)}`}
        className="inline-flex min-h-11 items-center gap-2 font-semibold underline"
      >
        See the finding <Icon name="arrow" size={18} />
      </Link>
    </section>
  );
}

function latestResolved(resolved: FindingOut[]): FindingOut {
  return [...resolved].sort(
    (a, b) =>
      new Date(b.resolved_at ?? 0).getTime() - new Date(a.resolved_at ?? 0).getTime(),
  )[0];
}

function ProgressCard({ resolved, total }: { resolved: FindingOut[]; total: number }) {
  const percent = total === 0 ? 0 : (resolved.length / total) * 100;
  const latest = resolved.length > 0 ? latestResolved(resolved) : null;
  return (
    <Card>
      <SectionTitle>Progress</SectionTitle>
      <div
        role="img"
        aria-label={`${resolved.length} of ${total} resolved`}
        className="mt-6 flex h-3 overflow-hidden rounded-chip bg-lane-grey"
      >
        <span className="bg-green" style={{ width: `${percent}%` }} />
      </div>
      <p className="mt-3 text-body font-semibold">
        {resolved.length} of {total} resolved
      </p>
      <div className="mt-6 border-t border-divider pt-6 text-secondary">
        {latest ? (
          <p>
            Latest:{" "}
            <Link
              to={`/findings/${encodeURIComponent(latest.finding_id)}`}
              className="font-semibold underline"
            >
              {latest.title}
            </Link>
            , resolved {formatDate(latest.resolved_at)} (
            {formatRelative(latest.resolved_at)}).
          </p>
        ) : (
          <p className="text-dim">Nothing has been resolved yet.</p>
        )}
      </div>
    </Card>
  );
}

// One bar for each of the last scans that completed, from the finding count each reported.
export function ScansChart({ scans }: { scans: ScanOut[] }) {
  const completed = scans
    .filter((s) => s.status === "completed")
    .sort((a, b) => a.id - b.id)
    .slice(-CHART_BARS);
  if (completed.length < 2) return null;
  const max = Math.max(...completed.map((s) => s.finding_count), 1);
  return (
    <Card>
      <SectionTitle>Findings per scan</SectionTitle>
      <p className="mt-1 text-secondary text-dim">
        {plural(completed.length, "scan", "scans")}, newest on the right.
      </p>
      <ol aria-label="Findings per scan" className="mt-6 flex items-end gap-3">
        {completed.map((s) => (
          <li key={s.id} className="flex min-w-0 flex-1 flex-col items-center gap-1">
            <div
              className="flex w-full flex-col items-center justify-end"
              style={{ height: CHART_HEIGHT + 24 }}
            >
              <span className="font-mono text-label tabular-nums">{s.finding_count}</span>
              <span
                className="w-full rounded-t-chip bg-ink"
                style={{
                  height: Math.max(4, Math.round((s.finding_count / max) * CHART_HEIGHT)),
                }}
              />
            </div>
            <span className="border-t border-ink pt-1 text-label text-dim">
              <span className="sr-only">Scan </span>#{s.id}
            </span>
          </li>
        ))}
      </ol>
    </Card>
  );
}

function LastScanFacts({
  scan,
  summary,
}: {
  scan: ScanOut;
  summary: ReturnType<typeof useAsync<RiskSummaryOut>>[0];
}) {
  const facts: [string, string][] = [
    ["Last scan", `Scan ${scan.id}`],
    ["Finished", formatRelative(scan.finished_at)],
    ["Took", scanDuration(scan)],
    ["Resources", String(scan.resource_count)],
    ["Errors", String(scan.error_count)],
  ];
  return (
    <dl className="flex flex-wrap items-end gap-x-12 gap-y-4 border-t border-divider pt-6 text-secondary">
      {facts.map(([label, value]) => (
        <div key={label}>
          <dt className="text-label text-dim">{label}</dt>
          <dd
            className="font-semibold"
            title={label === "Finished" ? formatDate(scan.finished_at) : undefined}
          >
            {value}
          </dd>
        </div>
      ))}
      <div>
        <dt className="text-label text-dim">
          <Tooltip text={ENVIRONMENT_HELP}>Combined environment score</Tooltip>
        </dt>
        <dd className="font-mono text-label">
          {summary.status === "success" && summary.data.environment_score}
          {summary.status === "loading" && "..."}
          {summary.status === "error" && `unavailable: ${summary.message}`}
        </dd>
      </div>
    </dl>
  );
}

export { EmptyState };
