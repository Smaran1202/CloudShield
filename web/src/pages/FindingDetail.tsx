import { useEffect } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, type FindingDetailOut } from "../api";
import { DismissControls } from "../components/DismissControls";
import { FixTab } from "../components/FixPanel";
import { Stepper, stepStates } from "../components/Stepper";
import { Tabs } from "../components/Tabs";
import {
  AsyncView,
  Card,
  CertaintyChip,
  Check,
  EmptyState,
  disagreement,
  FindingFlags,
  NotRechecked,
  SeverityChip,
  StatusChip,
} from "../components/ui";
import { formatDate, pretty } from "../format";
import { LANE_BACKGROUND, laneOf, shortResource } from "../lanes";
import { useRefreshWhenScanEnds } from "../ScanContext";
import { useAsync } from "../useAsync";
import { useFixRequest } from "../useFixRequest";
import { useVerify } from "../useVerify";

const TABS = [
  { id: "summary", label: "Summary" },
  { id: "evidence", label: "Evidence" },
  { id: "risk", label: "Risk" },
  { id: "fix", label: "Fix" },
];

export function FindingDetail() {
  const { findingId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const [state, reload] = useAsync(() => api.finding(findingId), [findingId]);
  useRefreshWhenScanEnds(reload);
  const { state: fix, generate } = useFixRequest(findingId);
  const verify = useVerify(findingId, reload);
  const requested = params.get("tab") ?? "summary";
  const tab = TABS.some((t) => t.id === requested) ? requested : "summary";

  function selectTab(id: string) {
    const next = new URLSearchParams(params);
    next.set("tab", id);
    next.delete("item");
    setParams(next, { replace: true });
  }

  return (
    <AsyncView state={state} onRetry={reload} label="Loading finding">
      {(finding) => (
        <>
          <nav aria-label="Breadcrumb" className="mb-4 font-mono text-secondary text-dim">
            <Link to="/findings" className="font-semibold text-ink underline">
              Findings
            </Link>{" "}
            / {finding.rule_id}
          </nav>
          <div className="rise mb-8 flex flex-wrap items-start justify-between gap-8">
            <div className="min-w-0 flex-1 basis-[420px]">
              <h1 className="font-display text-detail leading-none font-extrabold tracking-[-0.03em]">
                {finding.title}
              </h1>
              <div className="mt-4 flex flex-wrap items-center gap-2">
                <StatusChip status={finding.status} />
                <span
                  className="max-w-full truncate rounded-chip border-2 border-ink px-3 py-1 font-mono text-label"
                  title={finding.resource_id}
                >
                  {shortResource(finding.resource_id)}
                </span>
                <SeverityChip severity={finding.severity} />
                <FindingFlags finding={finding} />
                {finding.evidence.items.some((i) => i.certainty === "verified") && (
                  <span className="rounded-chip bg-chip-ok-bg px-3 py-1 text-secondary font-semibold text-chip-ok-text">
                    Verified evidence
                  </span>
                )}
              </div>
              {finding.not_rechecked && (
                <p className="mt-3">
                  <NotRechecked finding={finding} />
                </p>
              )}
              {finding.tools_disagree && (
                <p className="mt-3 text-secondary text-dim">{disagreement(finding)}</p>
              )}
              <DismissControls finding={finding} onChanged={reload} />
            </div>
            <ScoreTile finding={finding} />
          </div>

          <Stepper
            states={stepStates({
              fixShown: fix.status === "success",
              rescanning: verify.state.phase === "scanning",
              resolved: finding.status === "RESOLVED",
            })}
          />

          <Tabs tabs={TABS} active={tab} onChange={selectTab}>
            {tab === "summary" && <Summary finding={finding} />}
            {tab === "evidence" && (
              <Evidence finding={finding} highlighted={params.get("item")} />
            )}
            {tab === "risk" && <Risk finding={finding} />}
            {tab === "fix" && (
              <FixTab finding={finding} fix={fix} generate={generate} verify={verify} />
            )}
          </Tabs>
        </>
      )}
    </AsyncView>
  );
}

function ScoreTile({ finding }: { finding: FindingDetailOut }) {
  const lane = laneOf(finding);
  if (lane === "done") {
    return (
      <div className="w-[220px] rounded-lane bg-green p-6 text-white" data-lane="done">
        <Check size={36} />
        <p className="mt-2 font-display text-title leading-tight font-extrabold">
          Fixed, last score {finding.risk_score ?? "none"}
        </p>
      </div>
    );
  }
  if (finding.risk_score === null) {
    return (
      <div className="w-[220px] rounded-lane bg-lane-grey p-6 text-ink" data-lane={lane}>
        <p className="font-display text-title font-extrabold">No risk score</p>
        <p className="mt-1 text-secondary">
          Informational findings do not count toward risk.
        </p>
      </div>
    );
  }
  return (
    <div
      className={`w-[220px] rounded-lane p-6 ${LANE_BACKGROUND[lane]}`}
      data-lane={lane}
    >
      <p className="font-display text-score-lane leading-none font-extrabold tabular-nums">
        {finding.risk_score}
      </p>
      <p className="mt-2 text-secondary font-semibold">Risk score</p>
    </div>
  );
}

function Summary({ finding }: { finding: FindingDetailOut }) {
  const rows: [string, string][] = [
    ["Rule", finding.rule_id],
    ["Category", finding.category],
    ["Resource", finding.resource_id],
    ["Resource type", finding.resource_type],
    ["Region", finding.resource?.region ?? "-"],
    ["First seen", formatDate(finding.first_seen_at)],
    ["Last seen", formatDate(finding.last_seen_at)],
  ];
  if (finding.source === "prowler") {
    rows.splice(1, 0, ["Source", "Imported"]);
    rows.push(["Last import", formatDate(finding.last_imported_at)]);
  }
  if (finding.status === "RESOLVED") {
    rows.push(["Resolved", formatDate(finding.resolved_at)]);
    rows.push(["Why resolved", finding.resolution_reason ?? "-"]);
  }
  return (
    <Card>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-8 gap-y-3 text-secondary">
        {rows.map(([label, value]) => (
          <div key={label} className="contents">
            <dt className="text-dim">{label}</dt>
            <dd className="break-all">{value}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

function Evidence({
  finding,
  highlighted,
}: {
  finding: FindingDetailOut;
  highlighted: string | null;
}) {
  const items = finding.evidence.items;

  useEffect(() => {
    if (highlighted)
      document.getElementById(`evidence-${highlighted}`)?.scrollIntoView?.();
  }, [highlighted]);

  if (items.length === 0) {
    return (
      <EmptyState title="No evidence is stored for this finding yet">
        It was saved before evidence was collected. Rescan to fill it in.
      </EmptyState>
    );
  }
  return (
    <>
      {finding.source === "prowler" && (
        <p className="mb-4 text-secondary font-semibold">
          Reported by an imported scan, not verified by CloudShield.
        </p>
      )}
      <ol className="space-y-4">
        {items.map((item, index) => {
          const id = `e${index + 1}`;
          return (
            <li
              key={id}
              id={`evidence-${id}`}
              className={`rounded-lane border-2 bg-white p-6 ${
                highlighted === id ? "border-blue ring-4 ring-blue" : "border-ink"
              }`}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-[4px] border-[1.5px] border-ink px-2 py-1 font-mono text-label">
                  {id}
                </span>
                <span className="font-semibold">{item.fact}</span>
                <CertaintyChip certainty={item.certainty} />
              </div>
              <pre className="mt-3 overflow-x-auto font-mono text-secondary break-words whitespace-pre-wrap">
                {item.value === null ? "no value" : pretty(item.value)}
              </pre>
              <p className="mt-3 text-secondary text-dim">
                Source: <code className="font-mono">{item.source}</code>
              </p>
            </li>
          );
        })}
      </ol>
    </>
  );
}

function Risk({ finding }: { finding: FindingDetailOut }) {
  if (finding.risk_score === null) {
    return (
      <EmptyState title="This finding does not count toward risk">
        Informational findings have no risk score and no risk factors.
      </EmptyState>
    );
  }
  if (finding.risk_factors.length === 0) {
    return (
      <EmptyState title="No risk factors are stored for this finding">
        The score is the base score for its severity. Rescan to store the factors.
      </EmptyState>
    );
  }
  return (
    <Card>
      <p className="mb-4 text-secondary">
        Score {finding.risk_score}: the base score for {finding.severity} plus these
        adjustments, capped at 100.
      </p>
      <ul className="divide-y-2 divide-divider">
        {finding.risk_factors.map((factor) => (
          <li key={factor.factor} className="flex flex-wrap items-center gap-4 py-3">
            <span className="w-24 font-semibold capitalize">{factor.factor}</span>
            <span className="w-12 font-mono tabular-nums">
              {factor.adjustment > 0 ? `+${factor.adjustment}` : factor.adjustment}
            </span>
            <CertaintyChip certainty={factor.certainty} />
            <span className="min-w-0 flex-1 text-secondary">{factor.reason}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}
