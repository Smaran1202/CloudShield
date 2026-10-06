import type { FindingOut } from "./api";

// The only place the lane thresholds are written down.
export const LANE_THRESHOLDS = { fixNow: 80, next: 60 } as const;

export type Lane = "now" | "next" | "later" | "done";
export const LANES: Lane[] = ["now", "next", "later", "done"];

// Open findings are placed by risk score. A finding with no score (INFO) goes to Later.
// A resolved finding is Done, whatever its last score was.
export function laneOf(finding: Pick<FindingOut, "status" | "risk_score">): Lane {
  if (finding.status === "RESOLVED") return "done";
  if (finding.risk_score === null) return "later";
  if (finding.risk_score >= LANE_THRESHOLDS.fixNow) return "now";
  if (finding.risk_score >= LANE_THRESHOLDS.next) return "next";
  return "later";
}

export const LANE_NAME: Record<Lane, string> = {
  now: "Fix now",
  next: "Next",
  later: "Later",
  done: "Done",
};

export const LANE_HINT: Record<Lane, string> = {
  now: `Risk score ${LANE_THRESHOLDS.fixNow} or more`,
  next: `Risk score ${LANE_THRESHOLDS.next} to ${LANE_THRESHOLDS.fixNow - 1}`,
  later: `Risk score below ${LANE_THRESHOLDS.next}, or no score`,
  done: "Resolved by a rescan",
};

export const LANE_EMPTY: Record<Lane, string> = {
  now: `Nothing is open at ${LANE_THRESHOLDS.fixNow} or above.`,
  next: `Nothing is open between ${LANE_THRESHOLDS.next} and ${LANE_THRESHOLDS.fixNow - 1}.`,
  later: `Nothing scored below ${LANE_THRESHOLDS.next} is open.`,
  done: "Nothing has been fixed yet.",
};

// Tailwind classes for each lane, from the tokens.
export const LANE_BACKGROUND: Record<Lane, string> = {
  now: "bg-red text-white",
  next: "bg-blue text-white",
  later: "bg-lane-grey text-ink",
  done: "bg-green text-white",
};

export const LANE_DOT: Record<Lane, string> = {
  now: "bg-red",
  next: "bg-blue",
  later: "bg-later-dot",
  done: "bg-green",
};

export const LANE_BORDER: Record<Lane, string> = {
  now: "border-red",
  next: "border-blue",
  later: "border-later-dot",
  done: "border-green",
};

export function countLanes(findings: Pick<FindingOut, "status" | "risk_score">[]) {
  const counts: Record<Lane, number> = { now: 0, next: 0, later: 0, done: 0 };
  for (const finding of findings) counts[laneOf(finding)] += 1;
  return counts;
}

export function byScoreDescending(a: FindingOut, b: FindingOut): number {
  // Findings without a score always come last.
  if (a.risk_score === null || b.risk_score === null) {
    return a.risk_score === b.risk_score ? 0 : a.risk_score === null ? 1 : -1;
  }
  return b.risk_score - a.risk_score || a.rule_id.localeCompare(b.rule_id);
}

export function highestRiskOpen(findings: FindingOut[]): FindingOut | null {
  const open = findings.filter((f) => f.status === "OPEN" && f.risk_score !== null);
  return [...open].sort(byScoreDescending)[0] ?? null;
}

// "arn:aws:iam::123456789012:policy/name" is shown as "...:policy/name".
export function shortResource(id: string): string {
  if (!id.startsWith("arn:")) return id;
  const tail = id.split(":").slice(5).join(":");
  return tail ? `...:${tail}` : id;
}
