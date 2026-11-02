import { describe, expect, it } from "vitest";
import {
  byScoreDescending,
  countLanes,
  inLane,
  LANE_HINT,
  LANE_THRESHOLDS,
  laneOf,
  shortResource,
  startWith,
} from "./lanes";
import { finding } from "./test/factories";

describe("laneOf", () => {
  it("puts an open finding at the Fix now threshold in Fix now, and one point below in Next", () => {
    expect(laneOf({ status: "OPEN", risk_score: 80 })).toBe("now");
    expect(laneOf({ status: "OPEN", risk_score: 79 })).toBe("next");
  });

  it("puts an open finding at the Next threshold in Next, and one point below in Later", () => {
    expect(laneOf({ status: "OPEN", risk_score: 60 })).toBe("next");
    expect(laneOf({ status: "OPEN", risk_score: 59 })).toBe("later");
  });

  it("puts the highest and the lowest scores in the right lanes", () => {
    expect(laneOf({ status: "OPEN", risk_score: 100 })).toBe("now");
    expect(laneOf({ status: "OPEN", risk_score: 0 })).toBe("later");
  });

  it("puts an open finding with no score in Later", () => {
    expect(laneOf({ status: "OPEN", risk_score: null })).toBe("later");
  });

  it("puts every resolved finding in Done, whatever its last score was", () => {
    expect(laneOf({ status: "RESOLVED", risk_score: 95 })).toBe("done");
    expect(laneOf({ status: "RESOLVED", risk_score: 20 })).toBe("done");
    expect(laneOf({ status: "RESOLVED", risk_score: null })).toBe("done");
  });

  it("reads its thresholds from one constant", () => {
    expect(LANE_THRESHOLDS).toEqual({ fixNow: 80, next: 60 });
    expect(LANE_HINT.now).toBe("Risk score 80 or more");
    expect(LANE_HINT.next).toBe("Risk score 60 to 79");
    expect(LANE_HINT.later).toBe("Risk score below 60, or no score");
    expect(LANE_HINT.done).toBe("Resolved by a rescan or a newer import");
  });
});

describe("countLanes", () => {
  it("counts findings per lane", () => {
    const counts = countLanes([
      { status: "OPEN", risk_score: 90 },
      { status: "OPEN", risk_score: 80 },
      { status: "OPEN", risk_score: 61 },
      { status: "OPEN", risk_score: null },
      { status: "RESOLVED", risk_score: 99 },
    ]);

    // A finding with no score is in no lane.
    expect(counts).toEqual({ now: 2, next: 1, later: 0, done: 1 });
  });
});

describe("startWith", () => {
  it("is the highest score among findings that are not dismissed or suggested as not applicable", () => {
    const rows = [
      finding({ finding_id: "A", risk_score: 99, dismissed: true }),
      finding({
        finding_id: "B",
        risk_score: 95,
        suggested_not_applicable: { reason: "AWS owns this policy." },
      }),
      finding({ finding_id: "C", risk_score: 90, merged_into: "D" }),
      finding({ finding_id: "D", risk_score: 85 }),
      finding({ finding_id: "E", risk_score: 70 }),
    ];

    expect(startWith(rows)?.finding_id).toBe("D");
  });

  it("falls back to Next when nothing is in Fix now", () => {
    const rows = [
      finding({ finding_id: "A", risk_score: 50 }),
      finding({ finding_id: "B", risk_score: 65 }),
    ];

    expect(startWith(rows)?.finding_id).toBe("B");
    expect(countLanes(rows).now).toBe(0);
  });

  it("puts a CloudShield finding before an imported one on a tie", () => {
    const rows = [
      finding({ finding_id: "I", risk_score: 85, source: "prowler", rule_id: "A-first" }),
      finding({
        finding_id: "O",
        risk_score: 85,
        source: "cloudshield",
        rule_id: "Z-last",
      }),
    ];

    expect(startWith(rows)?.finding_id).toBe("O");
  });

  it("ignores resolved and unscored findings", () => {
    const rows = [
      finding({ finding_id: "F-1", risk_score: 99, status: "RESOLVED" }),
      finding({ finding_id: "F-2", risk_score: null, severity: "INFO" }),
      finding({ finding_id: "F-3", risk_score: 40 }),
    ];

    expect(startWith(rows)?.finding_id).toBe("F-3");
  });

  it("is null when nothing scored is left", () => {
    expect(startWith([finding({ risk_score: null })])).toBeNull();
    expect(startWith([])).toBeNull();
  });
});

describe("Fix now count", () => {
  it("is the number of open, undismissed, unmerged, scored findings at 80 or more, from any source", () => {
    const rows = [
      finding({ finding_id: "A", risk_score: 80 }),
      finding({ finding_id: "B", risk_score: 99, source: "prowler" }),
      finding({ finding_id: "C", risk_score: 79 }),
      finding({ finding_id: "D", risk_score: 90, dismissed: true }),
      finding({ finding_id: "E", risk_score: 90, merged_into: "A" }),
      finding({ finding_id: "F", risk_score: 90, status: "RESOLVED" }),
      finding({ finding_id: "G", risk_score: null, severity: "INFO" }),
    ];

    expect(countLanes(rows).now).toBe(2);
    expect(inLane(rows, "now")).toHaveLength(2);
  });
});

describe("byScoreDescending", () => {
  it("sorts by score, high to low, with findings without a score last", () => {
    const rows = [
      finding({ finding_id: "A", risk_score: null }),
      finding({ finding_id: "B", risk_score: 40 }),
      finding({ finding_id: "C", risk_score: 95 }),
    ];

    expect(rows.sort(byScoreDescending).map((r) => r.finding_id)).toEqual([
      "C",
      "B",
      "A",
    ]);
  });
});

describe("shortResource", () => {
  it("shortens an ARN to its last part", () => {
    expect(shortResource("arn:aws:iam::123456789012:policy/deploy")).toBe(
      "...:policy/deploy",
    );
    expect(shortResource("arn:aws:iam::123456789012:role/app/web")).toBe(
      "...:role/app/web",
    );
  });

  it("leaves other ids as they are", () => {
    expect(shortResource("sg-0abc123")).toBe("sg-0abc123");
    expect(shortResource("my-bucket")).toBe("my-bucket");
  });
});
